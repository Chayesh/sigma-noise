"""
Splunk connector -- runs a search job via Splunk's REST API
(/services/search/jobs) and pulls raw results back as JSON, same
design as the Wazuh/Sentinel connectors: we do NOT compile the Sigma
rule into SPL. We pull a broad time-windowed set of raw events and run
them through the SAME local matcher used for EVTX/Wazuh/Sentinel data.
This keeps one evaluator for every backend instead of maintaining a
Sigma-to-SPL compiler in parallel (pySigma does ship a Splunk backend --
pysigma-backend-splunk -- if you ever want to switch to server-side
filtering for very large indexes where pulling everything raw isn't
practical; that's a reasonable v3 optimization, not needed for
backtesting-sized time windows).

LIVE-TESTED against a real Splunk Enterprise 10.2.2 instance (Windows,
Sysmon + Splunk Windows TA feeding a real index). First live run
returned every field as null despite the raw event text clearly
containing them -- root cause: Splunk's REST /results endpoint does not
include every search-time-extracted field by default the way Splunk
Web's table view does. Fixed by explicitly forcing field selection with
`| table <fields>` in the SPL (see _SELECT_FIELDS below). After the fix,
a real triggered osk.exe execution was correctly detected end to end.

Auth: Splunk REST API takes either a session token (from /services/auth/login)
or a pre-generated auth token issued in Settings -> Tokens. This connector
uses username/password login for simplicity -- swap to a static token if
you have one (see the `token` param).

Usage:
    conn = SplunkConnector(
        base_url="https://localhost:8089",   # management port, NOT 8000 (the web UI port)
        username="admin",
        password="changeme",
        verify_ssl=False,   # Splunk's default cert is self-signed
    )
    ok, msg = conn.test_connection()
    events = conn.fetch_events(lookback_hours=24)
"""
import time
import requests
from xml.etree import ElementTree as ET
from .base import SIEMConnector


class SplunkConnector(SIEMConnector):
    name = "splunk"

    def __init__(
        self,
        base_url: str,
        username: str | None = None,
        password: str | None = None,
        token: str | None = None,
        index: str = "*",
        search_filter: str = "",
        verify_ssl: bool = False,
    ):
        """
        base_url: the Splunk MANAGEMENT API endpoint, e.g. https://localhost:8089
                  (this is a different port from the web UI, which is usually 8000)
        index: which index to search, default "*" (all). Narrow this for speed
               on a real instance, e.g. "index=wineventlog" or "index=main".
        search_filter: extra SPL appended after the index clause, e.g.
               'sourcetype=WinEventLog:Sysmon/Operational' to scope further.
               We're still pulling raw events, not compiling the Sigma rule --
               this is just a coarse pre-filter to keep the pull small.
        token: a static Splunk auth token (Settings -> Tokens in Splunk Web).
               If given, skips the username/password login step.
        """
        self.base_url = base_url.rstrip("/")
        self.username = username
        self.password = password
        self.index = index
        self.search_filter = search_filter
        self.verify_ssl = verify_ssl
        self._token = token
        if not verify_ssl:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def _login(self) -> str:
        if self._token:
            return self._token
        resp = requests.post(
            f"{self.base_url}/services/auth/login",
            data={"username": self.username, "password": self.password},
            verify=self.verify_ssl,
            timeout=15,
        )
        resp.raise_for_status()
        # Splunk returns XML: <response><sessionKey>...</sessionKey></response>
        root = ET.fromstring(resp.text)
        session_key = root.findtext("sessionKey")
        if not session_key:
            raise RuntimeError(f"Splunk login succeeded but no sessionKey in response: {resp.text[:200]}")
        self._token = session_key
        return session_key

    def _auth_header(self) -> dict:
        token = self._login()
        # Static tokens (Settings->Tokens) use "Bearer"; session keys use "Splunk"
        scheme = "Bearer" if self.username is None else "Splunk"
        return {"Authorization": f"{scheme} {token}"}

    def test_connection(self) -> tuple[bool, str]:
        try:
            resp = requests.get(
                f"{self.base_url}/services/server/info",
                headers=self._auth_header(),
                params={"output_mode": "json"},
                verify=self.verify_ssl,
                timeout=15,
            )
            resp.raise_for_status()
            version = resp.json()["entry"][0]["content"].get("version", "unknown")
            return True, f"Connected. Splunk version {version}"
        except requests.RequestException as e:
            return False, f"Connection failed: {e}"
        except (KeyError, IndexError, ET.ParseError) as e:
            return False, f"Connected but couldn't parse response ({e}) -- check base_url points to the management port (usually 8089, not 8000)"

    # Fields to explicitly select via `| table`. This matters because
    # Splunk's REST /results endpoint does NOT include every search-time
    # extracted field by default the way Splunk Web's table view does --
    # it only returns a limited default field set unless you explicitly
    # select fields in the search itself. Discovered empirically: a real
    # Sysmon-sourced search returned EventCode/Image/User/etc as null over
    # REST despite those fields being visible and populated in the Splunk
    # Web search UI for the exact same event.
    _SELECT_FIELDS = [
        "_time", "_raw", "host", "source", "sourcetype",
        "EventCode", "EventID", "EventType", "TaskCategory",
        "ComputerName", "Computer",
        "Image", "CommandLine", "ParentImage", "ParentCommandLine",
        "User", "ProcessId", "ProcessGuid", "UtcTime",
    ]

    def fetch_events(self, lookback_hours: int = 24, limit: int = 5000) -> list[dict]:
        headers = self._auth_header()
        spl = f"search index={self.index} earliest=-{lookback_hours}h latest=now"
        if self.search_filter:
            spl += f" {self.search_filter}"
        spl += f" | head {min(limit, 10000)}"
        spl += f" | table {', '.join(self._SELECT_FIELDS)}"

        # 1. Kick off the search job
        job_resp = requests.post(
            f"{self.base_url}/services/search/jobs",
            headers=headers,
            data={"search": spl, "output_mode": "json", "exec_mode": "normal"},
            verify=self.verify_ssl,
            timeout=30,
        )
        job_resp.raise_for_status()
        sid = job_resp.json()["sid"]

        # 2. Poll until done (searches are async in Splunk's REST API)
        status_url = f"{self.base_url}/services/search/jobs/{sid}"
        for _ in range(60):  # up to ~60s, plenty for a bounded head-N search
            status_resp = requests.get(
                status_url, headers=headers,
                params={"output_mode": "json"}, verify=self.verify_ssl, timeout=15,
            )
            status_resp.raise_for_status()
            content = status_resp.json()["entry"][0]["content"]
            if content.get("isDone"):
                break
            time.sleep(1)
        else:
            raise TimeoutError(f"Splunk search job {sid} did not finish in time")

        # 3. Pull results
        results_resp = requests.get(
            f"{status_url}/results",
            headers=headers,
            params={"output_mode": "json", "count": min(limit, 10000)},
            verify=self.verify_ssl,
            timeout=30,
        )
        results_resp.raise_for_status()
        results = results_resp.json().get("results", [])
        return [self._normalize(r) for r in results]

    @staticmethod
    def _normalize(event: dict) -> dict:
        """Splunk's raw result fields vary a LOT by sourcetype/TA (Windows
        TA, Sysmon TA, CIM-normalized fields, etc). This maps the common
        cases; keep the raw fields too so rules referencing sourcetype-
        specific field names still have something to match against."""
        flat = dict(event)
        flat["EventID"] = event.get("EventCode") or event.get("EventID") or event.get("event_id")
        flat["UtcTime"] = event.get("_time") or event.get("UtcTime")
        flat["Computer"] = event.get("Computer") or event.get("ComputerName") or event.get("host")
        flat["Image"] = event.get("Image") or event.get("process") or event.get("process_name")
        flat["CommandLine"] = event.get("CommandLine") or event.get("process_exec") or event.get("cmdline")
        flat["User"] = event.get("User") or event.get("user")
        flat["ParentImage"] = event.get("ParentImage") or event.get("parent_process")
        flat["_source"] = "splunk"
        return flat

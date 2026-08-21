"""
Wazuh connector -- queries the Wazuh INDEXER (OpenSearch), not the manager
API on port 55000. Reasoning: the manager API is for managing
agents/rules/config, and alert search there is limited/paginated for
operational use. The indexer holds the actual `wazuh-alerts-*` documents
with full field fidelity, and OpenSearch's query DSL lets us pull a whole
time window of raw alerts in one request -- exactly what we need to feed
into our own local matcher.

NOT TESTED LIVE from this sandbox -- the sandbox's network allowlist only
covers package registries and github.com, and a home-lab Wazuh instance
on a VM isn't internet-reachable anyway. Test this against your own
Wazuh Indexer from your host machine or wherever this code actually runs.

Usage:
    conn = WazuhConnector(
        indexer_url="https://localhost:9200",
        username="admin",
        password="<your indexer password>",
        verify_ssl=False,   # Wazuh's default indexer cert is self-signed
    )
    ok, msg = conn.test_connection()
    events = conn.fetch_events(lookback_hours=24)
"""
import requests
from datetime import datetime
from .base import SIEMConnector


class WazuhConnector(SIEMConnector):
    name = "wazuh"

    def __init__(
        self,
        indexer_url: str,
        username: str,
        password: str,
        index_pattern: str = "wazuh-alerts-*",
        verify_ssl: bool = False,
    ):
        self.indexer_url = indexer_url.rstrip("/")
        self.auth = (username, password)
        self.index_pattern = index_pattern
        self.verify_ssl = verify_ssl
        if not verify_ssl:
            # Wazuh ships a self-signed indexer cert by default; suppress
            # the noisy warning since the insecure choice is explicit here.
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def test_connection(self) -> tuple[bool, str]:
        try:
            resp = requests.get(
                f"{self.indexer_url}/_cluster/health",
                auth=self.auth,
                verify=self.verify_ssl,
                timeout=10,
            )
            resp.raise_for_status()
            return True, f"Connected: {resp.json().get('status', 'unknown')} cluster status"
        except requests.RequestException as e:
            return False, f"Connection failed: {e}"

    def fetch_events(self, lookback_hours: int = 24, limit: int = 5000) -> list[dict]:
        start, end = self.time_window(lookback_hours)
        query = {
            "size": min(limit, 10000),  # OpenSearch default max is 10k without scroll/PIT
            "sort": [{"@timestamp": {"order": "asc"}}],
            "query": {
                "range": {
                    "@timestamp": {
                        "gte": start.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
                        "lte": end.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
                    }
                }
            },
        }
        resp = requests.post(
            f"{self.indexer_url}/{self.index_pattern}/_search",
            json=query,
            auth=self.auth,
            verify=self.verify_ssl,
            timeout=30,
        )
        resp.raise_for_status()
        hits = resp.json().get("hits", {}).get("hits", [])
        return [self._normalize(h["_source"]) for h in hits]

    @staticmethod
    def _normalize(src: dict) -> dict:
        """Maps common Wazuh alert fields to our Sysmon-style flat schema.

        Wazuh alert docs are nested (data.win.eventdata.image, etc. for
        Sysmon-sourced alerts via the Windows agent). Flatten the fields
        our matcher/scorer actually look at; keep everything else too so
        rules referencing raw Wazuh fields (e.g. rule.description,
        agent.name) still have something to match against.
        """
        data = src.get("data", {}) or {}
        win = data.get("win", {}) or {}
        eventdata = win.get("eventdata", {}) or {}
        system = win.get("system", {}) or {}

        flat = dict(src)  # keep original fields for rules that reference them directly
        flat["EventID"] = system.get("eventID") or data.get("id")
        flat["UtcTime"] = src.get("@timestamp") or system.get("systemTime")
        flat["Computer"] = system.get("computer") or src.get("agent", {}).get("name")
        flat["Image"] = eventdata.get("image") or data.get("win", {}).get("eventdata", {}).get("image")
        flat["CommandLine"] = eventdata.get("commandLine")
        flat["User"] = eventdata.get("user") or src.get("agent", {}).get("name")
        flat["ParentImage"] = eventdata.get("parentImage")
        flat["_source"] = "wazuh"
        return flat

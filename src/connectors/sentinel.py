"""
Microsoft Sentinel connector -- queries the Log Analytics workspace REST
API directly with requests (no azure-identity/azure-monitor-query SDK
dependency, to keep this lightweight and dependency-free beyond what we
already need). Uses OAuth2 client-credentials flow against an Azure AD
app registration.

We pull a broad table for a time window (default: DeviceProcessEvents,
since that's what most process-creation Sigma rules target in Defender/
Sentinel-fed workspaces -- swap to SecurityEvent if your workspace uses
the legacy Windows Security Events connector instead) and normalize into
our flat Sysmon-style schema, then run the SAME local matcher used for
EVTX and Wazuh data. We are not compiling the Sigma rule to KQL.

NOT TESTED LIVE -- this sandbox has no network path to login.microsoft
online.com or *.ods.opinsights.azure.com. Test against your own tenant
and workspace once you have an app registration with
"Log Analytics Reader" role on the workspace.

Setup you'll need (this is the SC-200-relevant part):
    1. App registration in Entra ID -> generate a client secret
    2. Grant that app "Log Analytics Reader" (or Monitoring Reader) role
       on your Sentinel workspace's resource
    3. tenant_id, client_id, client_secret, workspace_id (the Log
       Analytics workspace ID, a GUID -- not the resource name)

Usage:
    conn = SentinelConnector(
        tenant_id="...", client_id="...", client_secret="...",
        workspace_id="...",
    )
    ok, msg = conn.test_connection()
    events = conn.fetch_events(lookback_hours=24)
"""
import requests
from .base import SIEMConnector

TOKEN_URL_TMPL = "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
QUERY_URL_TMPL = "https://api.loganalytics.io/v1/workspaces/{workspace_id}/query"
LOG_ANALYTICS_SCOPE = "https://api.loganalytics.io/.default"


class SentinelConnector(SIEMConnector):
    name = "sentinel"

    def __init__(
        self,
        tenant_id: str,
        client_id: str,
        client_secret: str,
        workspace_id: str,
        table: str = "DeviceProcessEvents",
    ):
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.client_secret = client_secret
        self.workspace_id = workspace_id
        self.table = table
        self._token = None

    def _get_token(self) -> str:
        if self._token:
            return self._token
        resp = requests.post(
            TOKEN_URL_TMPL.format(tenant_id=self.tenant_id),
            data={
                "grant_type": "client_credentials",
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "scope": LOG_ANALYTICS_SCOPE,
            },
            timeout=15,
        )
        resp.raise_for_status()
        self._token = resp.json()["access_token"]
        return self._token

    def test_connection(self) -> tuple[bool, str]:
        try:
            token = self._get_token()
        except requests.RequestException as e:
            return False, f"Auth failed: {e}"
        try:
            resp = requests.post(
                QUERY_URL_TMPL.format(workspace_id=self.workspace_id),
                headers={"Authorization": f"Bearer {token}"},
                json={"query": f"{self.table} | take 1"},
                timeout=15,
            )
            resp.raise_for_status()
            return True, f"Connected. Query against {self.table} succeeded."
        except requests.RequestException as e:
            return False, f"Query test failed (check workspace_id / table / role assignment): {e}"

    def fetch_events(self, lookback_hours: int = 24, limit: int = 5000) -> list[dict]:
        token = self._get_token()
        kql = (
            f"{self.table} "
            f"| where TimeGenerated > ago({lookback_hours}h) "
            f"| take {min(limit, 5000)}"  # Log Analytics API hard-caps ~500k rows/64MB per response
        )
        resp = requests.post(
            QUERY_URL_TMPL.format(workspace_id=self.workspace_id),
            headers={"Authorization": f"Bearer {token}"},
            json={"query": kql},
            timeout=60,
        )
        resp.raise_for_status()
        result = resp.json()
        table = result["tables"][0]
        columns = [c["name"] for c in table["columns"]]
        rows = table["rows"]
        return [self._normalize(dict(zip(columns, row))) for row in rows]

    def _normalize(self, row: dict) -> dict:
        """Maps DeviceProcessEvents columns to our flat Sysmon-style schema.
        If you switch `table` to SecurityEvent (legacy WEF-based connector),
        adjust this mapping -- that table uses different column names
        (NewProcessName, SubjectUserName, CommandLine, etc, closer to raw
        Windows Security event fields)."""
        flat = dict(row)
        flat["EventID"] = 1  # DeviceProcessEvents is inherently process-creation
        flat["UtcTime"] = row.get("TimeGenerated")
        flat["Computer"] = row.get("DeviceName")
        flat["Image"] = row.get("FolderPath") or row.get("FileName")
        flat["CommandLine"] = row.get("ProcessCommandLine")
        flat["User"] = row.get("AccountName")
        flat["ParentImage"] = row.get("InitiatingProcessFolderPath")
        flat["_source"] = "sentinel"
        return flat

"""
Mock connector -- generates synthetic events shaped like Wazuh/Sentinel
output so we can prove the fetch -> normalize -> match -> score pipeline
works end to end without needing a live, internet-reachable SIEM. This is
what we CAN test in this sandbox; the real Wazuh/Sentinel connectors need
to be run against your actual instances from your own machine.
"""
import random
from datetime import datetime, timedelta
from .base import SIEMConnector

_NOISY_PROCS = ["svchost.exe", "conhost.exe", "logonui.exe", "dllhost.exe"]
_NORMAL_PROCS = ["chrome.exe", "explorer.exe", "notepad.exe", "outlook.exe"]
_SUSPICIOUS_PROCS = ["osk.exe", "utilman.exe"]
_HOSTS = ["WKS-01", "WKS-02", "WKS-03", "DC-01"]
_USERS = ["alice", "bob", "svc_backup", "SYSTEM"]


class MockConnector(SIEMConnector):
    name = "mock"

    def __init__(self, seed: int = 42):
        self._rng = random.Random(seed)

    def test_connection(self) -> tuple[bool, str]:
        return True, "mock connector always connects"

    def fetch_events(self, lookback_hours: int = 24, limit: int = 5000) -> list[dict]:
        start, end = self.time_window(lookback_hours)
        events = []
        n = min(limit, 400)
        for i in range(n):
            ts = start + timedelta(seconds=self._rng.randint(0, int((end - start).total_seconds())))
            pool = self._rng.choices(
                [_NOISY_PROCS, _NORMAL_PROCS, _SUSPICIOUS_PROCS],
                weights=[0.5, 0.45, 0.05],
            )[0]
            proc = self._rng.choice(pool)
            events.append({
                "EventID": 1,
                "UtcTime": ts.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                "Computer": self._rng.choice(_HOSTS),
                "User": self._rng.choice(_USERS),
                "Image": f"C:\\Windows\\System32\\{proc}",
                "CommandLine": f'"{proc}"',
                "_source": "mock",
            })
        return sorted(events, key=lambda e: e["UtcTime"])

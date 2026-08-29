"""
Abstract interface for a "live" log source connector.

The whole point: whatever the backend (Wazuh, Sentinel, a mock, a future
Splunk connector), it hands back a list of event dicts in the SAME shape
our local EVTX parser produces (flat dict, Sysmon-style field names where
possible: Image, CommandLine, User, Computer, EventID, UtcTime, ...).

That means sigma_eval.py and noise_score.py don't need to know or care
where the data came from -- one matcher, one scorer, any backend. We are
NOT compiling Sigma rules into KQL or Wazuh query syntax here; that's a
second rule-compiler we'd have to build and maintain in parallel with our
own evaluator. Instead we pull raw events for the requested time window
and run them through the same AST-walking matcher used for local EVTX.
"""
from __future__ import annotations
from abc import ABC, abstractmethod
from datetime import datetime, timedelta


class SIEMConnector(ABC):
    """Base class for a live log source. Subclasses implement fetch_events."""

    name: str = "base"

    @abstractmethod
    def test_connection(self) -> tuple[bool, str]:
        """Returns (ok, message). Should be cheap -- auth + a trivial query."""
        raise NotImplementedError

    @abstractmethod
    def fetch_events(
        self,
        lookback_hours: int = 24,
        limit: int = 5000,
    ) -> list[dict]:
        """Fetch and normalize events from the last `lookback_hours`.

        Returns a list of flat dicts. Every implementation MUST at minimum
        populate, where available: EventID, UtcTime, Computer, Image (or
        equivalent process/executable field), CommandLine, User.
        Unmapped source fields should still be included under their
        original name so specific Sigma rules that reference them can
        still match -- just don't rely on them for the noise-score's own
        entity/process extraction logic (see noise_score.py's field lists).
        """
        raise NotImplementedError

    def time_window(self, lookback_hours: int) -> tuple[datetime, datetime]:
        end = datetime.utcnow()
        start = end - timedelta(hours=lookback_hours)
        return start, end

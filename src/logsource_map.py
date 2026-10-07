"""
Maps a Sigma rule's `logsource` block (category/product/service) onto the
set of Windows Event IDs that category can plausibly come from.

Why this exists: sigma_eval.py's matcher only checks whether field VALUES
match -- it never checks whether the EVENT ITSELF is the right kind of
event for the rule to apply to. A `process_creation` rule checking the
`Image` field will happily match against a `process_termination` event
(Sysmon EventID 5) if that event happens to also have an `Image` field
with the right value -- which it usually does, since Sysmon logs Image on
both creation and termination. That's a real false match, not a modeling
error in the scorer: the rule was never meant to apply to that event type
at all.

This module is intentionally narrow in scope: it only understands Windows
event logs (Sysmon + native Security channel), because that's what every
connector and sample dataset in this project actually produces. A rule
whose `product` isn't "windows", or whose `category` isn't in the map
below, is NOT filtered -- we fail open (apply the rule to everything)
rather than silently dropping events for a category we don't have mapping
data for. Silently over-filtering is worse than not filtering: it would
hide real matches without any visible sign that it happened.
"""

# category -> set of Windows Event IDs that category can originate from.
# Where both a Sysmon ID and a native Security-log ID exist for the same
# semantic event, both are included (OR'd) since we don't reliably know
# which channel produced a given normalized event without deeper
# provider/channel inspection most of our data sources don't expose.
WINDOWS_CATEGORY_EVENT_IDS: dict[str, set[int]] = {
    "process_creation": {1, 4688},
    "process_termination": {5},
    "process_access": {10},
    "process_tampering": {25},
    "image_load": {7},
    "driver_load": {6},
    "create_remote_thread": {8},
    "raw_access_thread": {9},
    "network_connection": {3},
    "dns_query": {22},
    "file_event": {11},
    "file_delete": {23, 26},
    "file_delete_detected": {26},
    "file_block_executable": {27},
    "file_block_shredding": {28},
    "file_executable_detected": {29},
    "file_change": {2},
    "create_stream_hash": {15},
    "registry_event": {12, 13, 14},
    "registry_add": {12},
    "registry_set": {13},
    "registry_delete": {12, 14},
    "registry_rename": {14},
    "pipe_created": {17, 18},
    "wmi_event": {19, 20, 21},
    "clipboard_capture": {24},
    "sysmon_status": {4, 16},
    "logon": {4624},
    "failed_logon": {4625},
    "logoff": {4634},
    "account_lockout": {4740},
}

# Narrows a category's EventID set further when the rule also specifies
# `service:`. Only covers the common Sysmon-vs-Security-log ambiguity.
SERVICE_NARROWING: dict[str, dict[str, set[int]]] = {
    "process_creation": {
        "sysmon": {1},
        "security": {4688},
    },
}


def expected_event_ids(logsource) -> set[int] | None:
    """Returns the set of Windows EventIDs this rule's logsource implies,
    or None if the logsource isn't one we have mapping data for (meaning:
    don't filter -- fail open)."""
    if logsource is None:
        return None
    product = (getattr(logsource, "product", None) or "").lower()
    category = (getattr(logsource, "category", None) or "").lower()
    service = (getattr(logsource, "service", None) or "").lower()

    if product and product != "windows":
        # We only have Windows EventID mapping data. A rule targeting
        # another product (linux, aws, azure, ...) is never filtered here.
        return None
    if not category:
        return None

    base = WINDOWS_CATEGORY_EVENT_IDS.get(category)
    if base is None:
        return None

    if service and category in SERVICE_NARROWING:
        narrowed = SERVICE_NARROWING[category].get(service)
        if narrowed:
            return base & narrowed

    return base


def event_matches_logsource(event: dict, logsource) -> bool:
    """True if the event's EventID is consistent with the rule's logsource,
    OR if we don't have mapping data for this logsource (fail open)."""
    expected = expected_event_ids(logsource)
    if expected is None:
        return True
    event_id = event.get("EventID")
    if event_id is None:
        # No EventID on the event at all (e.g. a non-Windows source, or a
        # connector that didn't populate it) -- can't apply the filter,
        # so don't silently drop the event.
        return True
    try:
        return int(event_id) in expected
    except (TypeError, ValueError):
        return True

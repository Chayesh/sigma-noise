"""
Parses EVTX files into normalized flat dicts (Sysmon/Security field names)
that our matcher and pySigma-driven detection logic can evaluate against.
"""
import xml.etree.ElementTree as ET
from Evtx.Evtx import Evtx

NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"


def _parse_record_xml(xml_str: str) -> dict:
    root = ET.fromstring(xml_str)
    system = root.find(f"{NS}System")
    event_data = root.find(f"{NS}EventData")

    rec = {}

    if system is not None:
        eid = system.find(f"{NS}EventID")
        if eid is not None:
            rec["EventID"] = int(eid.text)
        computer = system.find(f"{NS}Computer")
        if computer is not None:
            rec["Computer"] = computer.text
        time_created = system.find(f"{NS}TimeCreated")
        if time_created is not None:
            rec["UtcTime"] = time_created.get("SystemTime")
        provider = system.find(f"{NS}Provider")
        if provider is not None:
            rec["Provider"] = provider.get("Name")

    if event_data is not None:
        for data in event_data.findall(f"{NS}Data"):
            name = data.get("Name")
            if name:
                rec[name] = data.text if data.text is not None else ""

    return rec


def parse_evtx(path: str, max_records: int | None = None) -> list[dict]:
    """Returns a list of normalized event dicts from an EVTX file.

    max_records caps how many records are parsed -- python-evtx is pure
    Python and slow on large (100MB+) files, so for big baseline logs it's
    often better to sample the first N records than block for minutes.
    """
    records = []
    with Evtx(path) as log:
        for record in log.records():
            if max_records is not None and len(records) >= max_records:
                break
            try:
                rec = _parse_record_xml(record.xml())
                rec["_source_file"] = path
                records.append(rec)
            except ET.ParseError:
                continue
    return records


def load_events(path: str) -> list[dict]:
    """Loads events from either a raw .evtx file or a pre-parsed .json cache
    (list of event dicts, as produced by parse_evtx + json.dump). JSON
    caching matters for large baseline logs -- python-evtx is pure Python
    and slow, so re-parsing a 100MB+ operational log on every run is
    wasteful once you've already extracted a sample."""
    if path.endswith(".json"):
        import json
        with open(path, "r") as f:
            return json.load(f)
    return parse_evtx(path)


if __name__ == "__main__":
    import sys
    import json

    recs = parse_evtx(sys.argv[1])
    print(f"Parsed {len(recs)} records from {sys.argv[1]}")
    if recs:
        print(json.dumps(recs[0], indent=2))

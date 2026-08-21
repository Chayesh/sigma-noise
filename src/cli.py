#!/usr/bin/env python3
"""
Sigma rule backtesting / false-positive estimation CLI.

Usage:
    python3 -m src.cli --rule data/rules/my_rule.yml --logs data/logs/

Takes a Sigma rule and a directory (or list) of EVTX log files, runs the
rule against them, and reports a tiered noise score so you know what a
rule will do to an analyst's queue BEFORE it goes live.
"""
import argparse
import glob
import os
import sys
import json

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.evtx_parser import parse_evtx, load_events
from src.sigma_eval import load_rule, run_rule_against_events
from src.noise_score import compute_noise_score

TIER_ICON = {"green": "\U0001F7E2", "yellow": "\U0001F7E1", "red": "\U0001F534"}


def collect_log_files(logs_arg: list[str]) -> list[str]:
    files = []
    for entry in logs_arg:
        if os.path.isdir(entry):
            files.extend(sorted(glob.glob(os.path.join(entry, "*.evtx"))))
            files.extend(sorted(glob.glob(os.path.join(entry, "*.json"))))
        elif os.path.isfile(entry):
            files.append(entry)
        else:
            print(f"Warning: {entry} not found, skipping", file=sys.stderr)
    return files


def print_report(report, verbose: bool = True):
    icon = TIER_ICON.get(report.tier, "")
    print()
    print(f"{icon}  {report.tier.upper()} NOISE  —  {report.rule_title}")
    print(f"    composite score: {report.composite_score}  (0=clean, 1=firehose)")
    print(f"    {report.tier_reason}")
    print()
    print(f"    matches:            {report.total_matches} / {report.total_events_scanned} events scanned")
    print(f"    est. rate:          {report.matches_per_day}/day over {report.time_span_days} day(s) of sample data")
    print(f"    distinct entities:  {report.distinct_entities}  (concentration: {report.entity_concentration})")
    print(f"    temporal spread:    {report.temporal_spread_score}  (higher = more evenly spread = more background-noise-like)")
    print(f"    known-noisy hits:   {report.known_noisy_hits}/{report.total_matches} ({report.known_noisy_ratio:.0%})")
    if report.baseline_used:
        flag = "⚠️  MATCHED BENIGN TRAFFIC" if report.baseline_matches else "clean against baseline"
        print(f"    baseline check:     {report.baseline_matches}/{report.baseline_total_events} benign events matched ({report.baseline_match_rate:.2%})  [{flag}]")
    if report.top_noisy_indicators:
        print(f"    noisy indicators:   {', '.join(report.top_noisy_indicators)}")
    if verbose and report.top_entities:
        print(f"    top firing entities:")
        for e in report.top_entities:
            print(f"      - {e}")
    if report.suggested_exclusions:
        print(f"    suggested tuning:")
        for s in report.suggested_exclusions:
            print(f"      - {s}")
    print()


def main():
    parser = argparse.ArgumentParser(description="Backtest a Sigma rule against sample logs and estimate FP noise.")
    parser.add_argument("--rule", required=True, help="Path to a Sigma rule YAML file")
    parser.add_argument("--source", choices=["local", "mock", "wazuh", "sentinel", "splunk"], default="local",
                         help="Where to pull events from. 'local' reads --logs files (default). "
                              "'mock' generates synthetic data to test the pipeline. "
                              "'wazuh'/'sentinel'/'splunk' hit a live SIEM (see the matching --<name>-* args).")
    parser.add_argument("--logs", nargs="+", help="Log file(s) or directory of .evtx/.json files (required when --source local)")
    parser.add_argument("--baseline", nargs="+", help="Log file(s) or directory of KNOWN-BENIGN .evtx/.json files. If given, this becomes the strongest FP signal in the score.")
    parser.add_argument("--lookback-hours", type=int, default=24, help="For live sources: how far back to pull events (default 24h)")
    parser.add_argument("--json", action="store_true", help="Output raw JSON instead of a formatted report")

    wazuh_group = parser.add_argument_group("wazuh (indexer/OpenSearch)")
    wazuh_group.add_argument("--wazuh-url", help="e.g. https://localhost:9200")
    wazuh_group.add_argument("--wazuh-user")
    wazuh_group.add_argument("--wazuh-pass")

    sentinel_group = parser.add_argument_group("sentinel (Log Analytics)")
    sentinel_group.add_argument("--sentinel-tenant-id")
    sentinel_group.add_argument("--sentinel-client-id")
    sentinel_group.add_argument("--sentinel-client-secret")
    sentinel_group.add_argument("--sentinel-workspace-id")

    splunk_group = parser.add_argument_group("splunk (REST API)")
    splunk_group.add_argument("--splunk-url", help="Management API URL, e.g. https://localhost:8089 (not the 8000 web port)")
    splunk_group.add_argument("--splunk-user")
    splunk_group.add_argument("--splunk-pass")
    splunk_group.add_argument("--splunk-token", help="Static auth token instead of user/pass (Settings > Tokens)")
    splunk_group.add_argument("--splunk-index", default="*", help="Index to search, default '*' (all)")
    splunk_group.add_argument("--splunk-filter", default="", help="Extra SPL appended after the index clause, e.g. 'sourcetype=WinEventLog:Sysmon/Operational'")

    args = parser.parse_args()

    if args.source == "local":
        if not args.logs:
            print("--logs is required when --source local", file=sys.stderr)
            sys.exit(1)
        log_files = collect_log_files(args.logs)
        if not log_files:
            print("No log files found.", file=sys.stderr)
            sys.exit(1)
        all_events = []
        for f in log_files:
            all_events.extend(load_events(f))
        source_desc = f"{len(log_files)} local file(s)"
    else:
        from src.connectors import MockConnector, WazuhConnector, SentinelConnector, SplunkConnector

        if args.source == "mock":
            connector = MockConnector()
        elif args.source == "wazuh":
            if not (args.wazuh_url and args.wazuh_user and args.wazuh_pass):
                print("--wazuh-url, --wazuh-user, --wazuh-pass are required for --source wazuh", file=sys.stderr)
                sys.exit(1)
            connector = WazuhConnector(args.wazuh_url, args.wazuh_user, args.wazuh_pass)
        elif args.source == "sentinel":
            required = [args.sentinel_tenant_id, args.sentinel_client_id, args.sentinel_client_secret, args.sentinel_workspace_id]
            if not all(required):
                print("--sentinel-tenant-id, --sentinel-client-id, --sentinel-client-secret, --sentinel-workspace-id are all required for --source sentinel", file=sys.stderr)
                sys.exit(1)
            connector = SentinelConnector(
                args.sentinel_tenant_id, args.sentinel_client_id,
                args.sentinel_client_secret, args.sentinel_workspace_id,
            )
        elif args.source == "splunk":
            if not args.splunk_url:
                print("--splunk-url is required for --source splunk", file=sys.stderr)
                sys.exit(1)
            if not args.splunk_token and not (args.splunk_user and args.splunk_pass):
                print("either --splunk-token or --splunk-user + --splunk-pass are required for --source splunk", file=sys.stderr)
                sys.exit(1)
            connector = SplunkConnector(
                args.splunk_url, username=args.splunk_user, password=args.splunk_pass,
                token=args.splunk_token, index=args.splunk_index, search_filter=args.splunk_filter,
            )

        ok, msg = connector.test_connection()
        print(f"[{connector.name}] {msg}", file=sys.stderr)
        if not ok:
            sys.exit(1)
        all_events = connector.fetch_events(lookback_hours=args.lookback_hours)
        source_desc = f"{connector.name} (last {args.lookback_hours}h)"

    baseline_events = []
    if args.baseline:
        baseline_files = collect_log_files(args.baseline)
        for f in baseline_files:
            baseline_events.extend(load_events(f))

    rule = load_rule(args.rule)
    matches = run_rule_against_events(rule, all_events)
    baseline_matches = run_rule_against_events(rule, baseline_events) if baseline_events else []
    report = compute_noise_score(
        rule.title, all_events, matches,
        baseline_total_events=len(baseline_events),
        baseline_matched_events=baseline_matches,
    )

    if args.json:
        print(json.dumps(report.__dict__, indent=2))
    else:
        print(f"Scanned {len(all_events)} events from {source_desc}")
        print_report(report)


if __name__ == "__main__":
    main()

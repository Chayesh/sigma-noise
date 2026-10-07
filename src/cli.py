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
from src.sigma_eval import load_rule, run_rule_against_events, run_rule_against_events_detailed
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


def collect_rule_files(path: str) -> list[str]:
    if os.path.isdir(path):
        return sorted(glob.glob(os.path.join(path, "*.yml")) + glob.glob(os.path.join(path, "*.yaml")))
    if os.path.isfile(path):
        return [path]
    return []


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
    if report.logsource_status:
        print(f"    logsource filter:   {report.logsource_status}" + (f"  ({report.logsource_filtered_out} wrong-type events excluded)" if report.logsource_filtered_out else ""))
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


def print_batch_summary(results: list[dict], load_errors: list[tuple]):
    tier_order = {"red": 0, "yellow": 1, "green": 2}
    ranked = sorted(results, key=lambda r: (tier_order.get(r["report"].tier, 3), -r["report"].composite_score))

    print()
    print(f"{'='*100}")
    print(f"RULESET NOISE TRIAGE  —  {len(results)} rule(s) scored" + (f", {len(load_errors)} skipped" if load_errors else ""))
    print(f"{'='*100}")
    print()
    header = f"{'':3} {'SCORE':>6}  {'MATCHES':>9}  {'BASELINE':>10}  RULE"
    print(header)
    print("-" * len(header))
    for r in ranked:
        rep = r["report"]
        icon = TIER_ICON.get(rep.tier, "")
        baseline_col = "-"
        if rep.baseline_used:
            baseline_col = f"{rep.baseline_matches}/{rep.baseline_total_events}"
            if rep.baseline_matches:
                baseline_col += "!"
        title = rep.rule_title[:60]
        print(f"{icon}   {rep.composite_score:>6.3f}  {rep.total_matches:>9}  {baseline_col:>10}  {title}")

    red = [r for r in ranked if r["report"].tier == "red"]
    yellow = [r for r in ranked if r["report"].tier == "yellow"]
    green = [r for r in ranked if r["report"].tier == "green"]
    print()
    print(f"  🔴 {len(red)} red   🟡 {len(yellow)} yellow   🟢 {len(green)} green")
    if load_errors:
        print(f"\n  Skipped {len(load_errors)} rule(s) that failed to load/evaluate:")
        for f, err in load_errors:
            print(f"    - {os.path.basename(f)}: {err}")

    if red or yellow:
        print(f"\n  Worst offenders (deploy these last, or not without tuning):")
        for r in (red + yellow)[:5]:
            rep = r["report"]
            reason = rep.suggested_exclusions[0] if rep.suggested_exclusions else rep.tier_reason
            print(f"    - {rep.rule_title[:70]}")
            print(f"        {reason}")
    print()


def main():
    parser = argparse.ArgumentParser(description="Backtest a Sigma rule against sample logs and estimate FP noise.")
    parser.add_argument("--rule", help="Path to a single Sigma rule YAML file")
    parser.add_argument("--rules-dir", help="Directory of Sigma rule YAML files to batch-score against the same log/baseline data "
                                             "-- ranks the whole ruleset worst-to-best instead of checking one rule at a time. "
                                             "Mutually exclusive with --rule.")
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

    if not args.rule and not args.rules_dir:
        print("Either --rule (single rule) or --rules-dir (batch mode) is required", file=sys.stderr)
        sys.exit(1)
    if args.rule and args.rules_dir:
        print("--rule and --rules-dir are mutually exclusive -- pick one", file=sys.stderr)
        sys.exit(1)

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

    if args.rule:
        rule = load_rule(args.rule)
        detailed = run_rule_against_events_detailed(rule, all_events)
        matches = detailed["matches"]
        baseline_matches = run_rule_against_events(rule, baseline_events) if baseline_events else []
        report = compute_noise_score(
            rule.title, all_events, matches,
            baseline_total_events=len(baseline_events),
            baseline_matched_events=baseline_matches,
            logsource_status=detailed["logsource_status"],
            logsource_filtered_out=detailed["logsource_filtered_out"],
        )
        if args.json:
            print(json.dumps(report.__dict__, indent=2))
        else:
            print(f"Scanned {len(all_events)} events from {source_desc}")
            print_report(report)
    else:
        rule_files = collect_rule_files(args.rules_dir)
        if not rule_files:
            print(f"No .yml/.yaml rule files found in {args.rules_dir}", file=sys.stderr)
            sys.exit(1)

        results = []
        load_errors = []
        for rf in rule_files:
            try:
                rule = load_rule(rf)
                detailed = run_rule_against_events_detailed(rule, all_events)
                matches = detailed["matches"]
                baseline_matches = run_rule_against_events(rule, baseline_events) if baseline_events else []
                report = compute_noise_score(
                    rule.title, all_events, matches,
                    baseline_total_events=len(baseline_events),
                    baseline_matched_events=baseline_matches,
                    logsource_status=detailed["logsource_status"],
                    logsource_filtered_out=detailed["logsource_filtered_out"],
                )
                results.append({"rule_file": rf, "report": report})
            except Exception as e:
                load_errors.append((rf, str(e)))

        if args.json:
            print(json.dumps({
                "scanned_events": len(all_events),
                "source": source_desc,
                "results": [{"rule_file": r["rule_file"], **r["report"].__dict__} for r in results],
                "load_errors": [{"rule_file": f, "error": e} for f, e in load_errors],
            }, indent=2))
        else:
            print(f"Scanned {len(all_events)} events from {source_desc}")
            print_batch_summary(results, load_errors)


if __name__ == "__main__":
    main()

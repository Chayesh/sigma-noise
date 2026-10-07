"""
Computes a tiered noise/false-positive-risk score for a Sigma rule based on
its matches against a sample log set.

Factors:
  1. Match volume, normalized by time span covered by the data
  2. Entity diversity (distinct hosts/users/processes / total matches)
  3. Temporal clustering (bursty vs evenly-spread-out matches)
  4. Known-noisy-pattern flag (matches cluster on common LOLBins/system procs)
  5. Baseline evidence, if a known-benign dataset is supplied -- dominates
     the composite when present, since it's real evidence not inference.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime
from collections import Counter
import statistics

KNOWN_NOISY_INDICATORS = {
    "svchost.exe", "logonui.exe", "consent.exe", "taskhostw.exe",
    "backgroundtaskhost.exe", "dllhost.exe", "conhost.exe", "wmiprvse.exe",
    "searchindexer.exe", "runtimebroker.exe", "sihost.exe",
}

ENTITY_FIELDS = ["Computer", "User", "TargetUserName", "SubjectUserName"]
PROCESS_FIELDS = ["Image", "TargetImage", "NewProcessName"]

WEIGHTS = {
    "volume": 0.30,
    "entity_diversity": 0.25,
    "temporal_spread": 0.20,
    "known_noisy": 0.25,
}

BASELINE_WEIGHT = 0.5


@dataclass
class NoiseReport:
    rule_title: str
    total_events_scanned: int
    total_matches: int
    time_span_days: float
    matches_per_day: float
    distinct_entities: int
    entity_concentration: float
    temporal_spread_score: float
    known_noisy_hits: int
    known_noisy_ratio: float
    top_noisy_indicators: list
    composite_score: float
    tier: str
    tier_reason: str
    top_entities: list
    suggested_exclusions: list = field(default_factory=list)
    baseline_used: bool = False
    baseline_total_events: int = 0
    baseline_matches: int = 0
    baseline_match_rate: float = 0.0
    logsource_status: str = ""
    logsource_filtered_out: int = 0


def _extract_timestamp(event: dict) -> datetime | None:
    ts = event.get("UtcTime")
    if not ts:
        return None
    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(ts, fmt)
        except ValueError:
            continue
    return None


def _extract_entity(event: dict) -> str | None:
    for f in ENTITY_FIELDS:
        v = event.get(f)
        if v:
            return f"{f}:{v}"
    return None


def _extract_process(event: dict) -> str | None:
    for f in PROCESS_FIELDS:
        v = event.get(f)
        if v:
            return v.split("\\")[-1].lower()
    return None


def _normalize(value: float, low: float, high: float) -> float:
    if high == low:
        return 0.0
    return max(0.0, min(1.0, (value - low) / (high - low)))


def compute_noise_score(
    rule_title: str,
    all_events: list[dict],
    matched_events: list[dict],
    baseline_total_events: int = 0,
    baseline_matched_events: list[dict] | None = None,
    logsource_status: str = "",
    logsource_filtered_out: int = 0,
) -> NoiseReport:
    total_matches = len(matched_events)
    total_scanned = len(all_events)
    baseline_used = baseline_total_events > 0
    baseline_matches = len(baseline_matched_events) if baseline_matched_events else 0
    baseline_match_rate = (
        baseline_matches / baseline_total_events if baseline_total_events else 0.0
    )

    if total_matches == 0 and baseline_matches == 0:
        return NoiseReport(
            rule_title=rule_title,
            total_events_scanned=total_scanned,
            total_matches=0,
            time_span_days=0.0,
            matches_per_day=0.0,
            distinct_entities=0,
            entity_concentration=1.0,
            temporal_spread_score=0.0,
            known_noisy_hits=0,
            known_noisy_ratio=0.0,
            top_noisy_indicators=[],
            composite_score=0.0,
            tier="green",
            tier_reason="No matches against the sample data -- rule did not fire at all.",
            top_entities=[],
            baseline_used=baseline_used,
            baseline_total_events=baseline_total_events,
            baseline_matches=0,
            baseline_match_rate=0.0,
            logsource_status=logsource_status,
            logsource_filtered_out=logsource_filtered_out,
        )

    scoring_events = matched_events if matched_events else (baseline_matched_events or [])
    scoring_count = len(scoring_events)

    timestamps = sorted(t for t in (_extract_timestamp(e) for e in scoring_events) if t)
    if len(timestamps) >= 2:
        span_seconds = (timestamps[-1] - timestamps[0]).total_seconds()
        time_span_days = max(span_seconds / 86400.0, 1.0 / 24.0)
    else:
        time_span_days = 1.0 / 24.0
    matches_per_day = scoring_count / time_span_days
    volume_score = _normalize(matches_per_day, 0, 100)

    entities = [_extract_entity(e) for e in scoring_events]
    entities = [e for e in entities if e]
    entity_counts = Counter(entities)
    distinct_entities = len(entity_counts)
    entity_concentration = 1.0 - _normalize(distinct_entities, 1, scoring_count or 1)

    temporal_spread_score = 0.0
    if len(timestamps) >= 3:
        gaps = [
            (timestamps[i + 1] - timestamps[i]).total_seconds()
            for i in range(len(timestamps) - 1)
        ]
        gaps = [g for g in gaps if g >= 0]
        if gaps and statistics.mean(gaps) > 0:
            cov = (statistics.pstdev(gaps) / statistics.mean(gaps)) if len(gaps) > 1 else 0
            temporal_spread_score = _normalize(1.0 / (1.0 + cov), 0, 1)

    processes = [_extract_process(e) for e in scoring_events]
    processes = [p for p in processes if p]
    noisy_hits = [p for p in processes if p in KNOWN_NOISY_INDICATORS]
    known_noisy_ratio = len(noisy_hits) / scoring_count if scoring_count else 0.0
    top_noisy = [item for item, _ in Counter(noisy_hits).most_common(5)]

    baseline_score = _normalize(baseline_match_rate, 0, 0.05)

    if baseline_used:
        remaining = 1.0 - BASELINE_WEIGHT
        composite = (
            BASELINE_WEIGHT * baseline_score
            + remaining * WEIGHTS["volume"] * volume_score
            + remaining * WEIGHTS["entity_diversity"] * (1 - entity_concentration)
            + remaining * WEIGHTS["temporal_spread"] * temporal_spread_score
            + remaining * WEIGHTS["known_noisy"] * known_noisy_ratio
        )
    else:
        composite = (
            WEIGHTS["volume"] * volume_score
            + WEIGHTS["entity_diversity"] * (1 - entity_concentration)
            + WEIGHTS["temporal_spread"] * temporal_spread_score
            + WEIGHTS["known_noisy"] * known_noisy_ratio
        )

    if composite < 0.33:
        tier = "green"
    elif composite < 0.66:
        tier = "yellow"
    else:
        tier = "red"

    reasons = []
    if baseline_used and baseline_matches > 0:
        reasons.append(
            f"FIRED ON BENIGN BASELINE DATA: {baseline_matches}/{baseline_total_events} "
            f"goodware events matched ({baseline_match_rate:.2%}) -- this is real FP evidence, not inference"
        )
    if volume_score > 0.5:
        reasons.append(f"high match volume ({matches_per_day:.1f}/day)")
    if entity_concentration < 0.4:
        reasons.append(f"spread across {distinct_entities} distinct entities")
    if temporal_spread_score > 0.5:
        reasons.append("evenly spread over time (background noise pattern, not a burst)")
    if known_noisy_ratio > 0.3:
        reasons.append(f"{known_noisy_ratio:.0%} of matches involve known-noisy processes")
    tier_reason = "; ".join(reasons) if reasons else "low volume, concentrated, bursty -- clean signal"

    suggested_exclusions = []
    if baseline_used and baseline_matches > 0:
        suggested_exclusions.append(
            "This rule matched confirmed-benign traffic in the baseline set -- do not deploy without "
            "narrowing the selection (add a parent-process or command-line constraint) before going live"
        )
    if top_noisy:
        pct = known_noisy_ratio
        suggested_exclusions.append(
            f"{pct:.0%} of matches are from {', '.join(top_noisy[:3])} -- consider excluding these as a parent/image filter"
        )
    top_entity_pairs = entity_counts.most_common(5)
    if top_entity_pairs and scoring_count and top_entity_pairs[0][1] / scoring_count > 0.5:
        suggested_exclusions.append(
            f"{top_entity_pairs[0][1]}/{scoring_count} matches come from a single entity ({top_entity_pairs[0][0]}) -- verify if expected/legit before deploying"
        )

    return NoiseReport(
        rule_title=rule_title,
        total_events_scanned=total_scanned,
        total_matches=total_matches,
        time_span_days=round(time_span_days, 2),
        matches_per_day=round(matches_per_day, 2),
        distinct_entities=distinct_entities,
        entity_concentration=round(entity_concentration, 3),
        temporal_spread_score=round(temporal_spread_score, 3),
        known_noisy_hits=len(noisy_hits),
        known_noisy_ratio=round(known_noisy_ratio, 3),
        top_noisy_indicators=top_noisy,
        composite_score=round(composite, 3),
        tier=tier,
        tier_reason=tier_reason,
        top_entities=[f"{k} ({v}x)" for k, v in top_entity_pairs],
        suggested_exclusions=suggested_exclusions,
        baseline_used=baseline_used,
        baseline_total_events=baseline_total_events,
        baseline_matches=baseline_matches,
        baseline_match_rate=round(baseline_match_rate, 5),
        logsource_status=logsource_status,
        logsource_filtered_out=logsource_filtered_out,
    )

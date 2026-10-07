"""
Evaluates a parsed pySigma rule directly against normalized log event dicts.

pySigma is built to compile rules into backend query languages (Splunk SPL,
KQL, etc), not to evaluate them in-memory against Python objects. So this
module walks pySigma's parsed condition AST (ConditionAND/OR/NOT and
ConditionFieldEqualsValueExpression leaves) ourselves and does the actual
field matching. pySigma has already resolved modifiers like `contains`,
`startswith`, `endswith` into wildcard patterns (e.g. `*value*`) by the time
we see them here, so all we need is one glob matcher.
"""
import re
import fnmatch
import ipaddress
from sigma.collection import SigmaCollection
from sigma.types import (
    SigmaString,
    SigmaNumber,
    SigmaBool,
    SigmaNull,
    SigmaRegularExpression,
    SigmaCIDRExpression,
    SigmaCompareExpression,
    SigmaExpansion,
    CompareOperators,
)
from sigma.conditions import (
    ConditionAND,
    ConditionOR,
    ConditionNOT,
    ConditionFieldEqualsValueExpression,
    ConditionValueExpression,
)
from src.logsource_map import event_matches_logsource, expected_event_ids


def _glob_match(pattern: str, value: str) -> bool:
    """Sigma wildcard match: * = any chars, ? = single char. Case-insensitive."""
    regex = fnmatch.translate(pattern)
    return re.match(regex, value, re.IGNORECASE) is not None


def _value_matches(sigma_value, field_value) -> bool:
    if field_value is None:
        return False
    field_str = str(field_value)

    if isinstance(sigma_value, SigmaExpansion):
        # base64offset and other modifiers that fan out into multiple
        # candidate patterns -- Sigma semantics are OR across the expansion.
        return any(_value_matches(v, field_value) for v in sigma_value.values)
    if isinstance(sigma_value, SigmaRegularExpression):
        try:
            pattern = sigma_value.to_plain()
            return re.search(pattern, field_str, re.IGNORECASE) is not None
        except re.error:
            return False
    if isinstance(sigma_value, SigmaCIDRExpression):
        try:
            return ipaddress.ip_address(field_str) in sigma_value.network
        except ValueError:
            return False
    if isinstance(sigma_value, SigmaCompareExpression):
        try:
            field_num = float(field_str)
            target = float(str(sigma_value.number))
        except ValueError:
            return False
        op = sigma_value.op
        if op == CompareOperators.LT:
            return field_num < target
        if op == CompareOperators.LTE:
            return field_num <= target
        if op == CompareOperators.GT:
            return field_num > target
        if op == CompareOperators.GTE:
            return field_num >= target
        if op == CompareOperators.NEQ:
            return field_num != target
        return False
    if isinstance(sigma_value, SigmaString):
        pattern = str(sigma_value)
        if "*" in pattern or "?" in pattern:
            return _glob_match(pattern, field_str)
        return pattern.lower() == field_str.lower()
    if isinstance(sigma_value, SigmaNumber):
        try:
            return float(field_str) == float(str(sigma_value))
        except ValueError:
            return False
    if isinstance(sigma_value, SigmaBool):
        return str(sigma_value).lower() == field_str.lower()
    if isinstance(sigma_value, SigmaNull):
        return field_value is None or field_str == ""
    # Fallback: plain equality on string form
    return str(sigma_value).lower() == field_str.lower()


def _eval_node(node, event: dict) -> bool:
    if isinstance(node, ConditionAND):
        return all(_eval_node(arg, event) for arg in node.args)
    if isinstance(node, ConditionOR):
        return any(_eval_node(arg, event) for arg in node.args)
    if isinstance(node, ConditionNOT):
        return not _eval_node(node.args[0], event)
    if isinstance(node, ConditionFieldEqualsValueExpression):
        field_value = event.get(node.field)
        return _value_matches(node.value, field_value)
    if isinstance(node, ConditionValueExpression):
        # Keyword search with no field: value must appear in ANY field
        return any(
            _value_matches(node.value, v)
            for v in event.values()
            if v is not None
        )
    raise NotImplementedError(f"Unsupported condition node type: {type(node)}")


class CompiledSigmaRule:
    def __init__(self, rule):
        self.rule = rule
        self.title = rule.title
        self.rule_id = str(rule.id) if rule.id else None
        self.level = str(rule.level) if rule.level else "unknown"
        self.logsource = rule.logsource
        # A rule can have multiple conditions (multiple `condition:` entries);
        # match if ANY of them match (this is standard Sigma semantics).
        self._condition_trees = [c.parsed for c in rule.detection.parsed_condition]

    def matches(self, event: dict) -> bool:
        return any(_eval_node(tree, event) for tree in self._condition_trees)

    def logsource_filter_status(self) -> str:
        """Reports whether logsource-based pre-filtering is actually being
        applied for this rule, so callers (the CLI, the noise scorer) can
        be honest about it rather than silently filtering or silently not."""
        expected = expected_event_ids(self.logsource)
        if expected is None:
            product = getattr(self.logsource, "product", None)
            category = getattr(self.logsource, "category", None)
            if not category:
                return "no category in rule -- not filtered"
            if product and str(product).lower() != "windows":
                return f"product '{product}' not supported -- not filtered"
            return f"category '{category}' not in mapping -- not filtered"
        return f"filtered to EventID in {sorted(expected)}"


def load_rule(path: str) -> CompiledSigmaRule:
    with open(path, "r") as f:
        yaml_text = f.read()
    collection = SigmaCollection.from_yaml(yaml_text)
    rule = list(collection.rules)[0]
    return CompiledSigmaRule(rule)


def run_rule_against_events(rule: CompiledSigmaRule, events: list[dict]) -> list[dict]:
    """Matches a rule against events, pre-filtering by logsource first.

    The logsource filter runs BEFORE field matching: an event whose
    EventID doesn't belong to the rule's declared category (e.g. a
    process_termination event reaching a process_creation rule) never
    reaches the field matcher at all. This fixes a real false-match class
    -- Sysmon logs fields like `Image` on multiple event types, so a
    category-blind matcher can match a rule against the wrong kind of
    event entirely. See logsource_map.py for what is and isn't covered;
    an unmapped category means this filter does nothing for that rule
    (fail open), which run_rule_against_events_detailed reports explicitly.
    """
    candidates = [e for e in events if event_matches_logsource(e, rule.logsource)]
    return [e for e in candidates if rule.matches(e)]


def run_rule_against_events_detailed(rule: CompiledSigmaRule, events: list[dict]) -> dict:
    """Same as run_rule_against_events, but also reports how many events
    were excluded by the logsource filter and whether the filter was even
    applicable for this rule -- so a caller can show "N events scanned,
    M excluded as wrong event type, X matched" instead of a bare count."""
    candidates = [e for e in events if event_matches_logsource(e, rule.logsource)]
    matches = [e for e in candidates if rule.matches(e)]
    return {
        "matches": matches,
        "total_events": len(events),
        "logsource_filtered_out": len(events) - len(candidates),
        "logsource_status": rule.logsource_filter_status(),
    }


if __name__ == "__main__":
    import sys
    sys.path.insert(0, ".")
    from src.evtx_parser import parse_evtx

    rule = load_rule(sys.argv[1])
    print(f"Loaded rule: {rule.title} (level={rule.level})")

    all_events = []
    for log_path in sys.argv[2:]:
        all_events.extend(parse_evtx(log_path))
    print(f"Loaded {len(all_events)} events from {len(sys.argv) - 2} file(s)")

    matches = run_rule_against_events(rule, all_events)
    print(f"Matches: {len(matches)}")
    for m in matches[:5]:
        print(" -", m.get("UtcTime"), m.get("Computer"), m.get("Image"), m.get("CommandLine"))

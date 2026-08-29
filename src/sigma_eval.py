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
        # A rule can have multiple conditions (multiple `condition:` entries);
        # match if ANY of them match (this is standard Sigma semantics).
        self._condition_trees = [c.parsed for c in rule.detection.parsed_condition]

    def matches(self, event: dict) -> bool:
        return any(_eval_node(tree, event) for tree in self._condition_trees)


def load_rule(path: str) -> CompiledSigmaRule:
    with open(path, "r") as f:
        yaml_text = f.read()
    collection = SigmaCollection.from_yaml(yaml_text)
    rule = list(collection.rules)[0]
    return CompiledSigmaRule(rule)


def run_rule_against_events(rule: CompiledSigmaRule, events: list[dict]) -> list[dict]:
    return [e for e in events if rule.matches(e)]


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

# sigma-noise

[![CI](https://github.com/Chayesh/sigma-noise/actions/workflows/ci.yml/badge.svg)](https://github.com/Chayesh/sigma-noise/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)

A CLI tool that backtests a Sigma detection rule against log data — local
sample files or a live SIEM — and estimates how noisy it'll be **before**
you deploy it. Answers the question every analyst asks a week too late:
*"how many false positives is this rule actually going to generate?"*

---

## ⚠️ Correction (v1.2) — please read if you've seen earlier numbers from this project

Earlier versions of this README and the accompanying FYP report cited a
headline result of **"155/6,000 (2.58%) baseline events matched"** as
evidence that the test rule needed tuning. That number was **partly
wrong**, and the correction is itself the most important thing this
version adds.

The matcher previously checked only whether an event's **field values**
matched a rule's selection — it never checked whether the **event type**
itself belonged to the rule's declared category. Sysmon logs the `Image`
field (which process a value belongs to) on far more event types than
process creation: it's also present on DLL/image loads (EventID 7),
registry changes (12/13), and raw disk reads (9), among others. A
`process_creation` rule checking `Image|contains: LogonUI.exe` was
therefore matching every time `LogonUI.exe` loaded a DLL, touched the
registry, or did anything else Sysmon logs with an `Image` field — not
just when it actually executed.

Re-checked directly: of the original 155 baseline "matches," **136 were
EventID 7 (image load), 11 were registry events, 2 were raw-access reads,
and only 2 were genuine EventID 1 process-creation events.** The true
false-positive evidence for this rule against this baseline is **2/6,000
(0.03%)**, not 155/6,000. The rule is real, and `LogonUI.exe` genuinely
does execute at every login — the evidence just wasn't anywhere near as
strong as originally reported.

This is now fixed (see "Logsource filtering" below) and the numbers
throughout this README and the "Validated results" section are the
corrected ones. The earlier FYP report submission is not retroactively
editable, so if you're reading this alongside that report: **this README
is the current, correct source of truth; treat the 155/6,000 figure in
the original report as superseded by this finding.**

---

## Why this exists

Analysts write Sigma rules, push them live, and find out days later that a
rule fires 400 times a day because some legitimate background process
happens to match it. This tool backtests a rule against real log data —
ideally including known-benign "baseline" traffic — and produces a tiered
🟢/🟡/🔴 noise score with a plain-English breakdown of *why* it's noisy and
what to tune, before it ever hits a production queue.

---

## How it works

1. **Parse** the Sigma rule with [pySigma](https://github.com/SigmaHQ/pySigma)
2. **Filter by logsource** — before any field is checked, an event is
   rejected outright if its EventID doesn't belong to the rule's declared
   `logsource.category` (see below). This runs first, not as an afterthought.
3. **Evaluate** surviving events against the rule by walking pySigma's
   parsed condition AST directly (`ConditionAND`/`OR`/`NOT`, field-match
   leaves) — a real evaluator, not string matching against YAML
4. **Score** the matches on four factors: match volume (normalized by time
   span), entity diversity, temporal clustering, and known-noisy-process
   flags — plus, if a benign baseline is supplied, real corroborated
   false-positive evidence, which dominates the score
5. **Report** a tier (green/yellow/red), the composite score, and specific
   tuning suggestions

Event data can come from local `.evtx` files, a pre-parsed JSON cache, or a
**live SIEM connector** (Splunk, Wazuh, Sentinel). Every source normalizes
into the same flat event schema and feeds the same matcher and scorer —
one evaluator, any backend.

---

## Logsource filtering (new)

`src/logsource_map.py` maps a rule's `logsource.category` (and, where
specified, `service`) onto the Windows Event IDs that category can
plausibly originate from — `process_creation` → `{1, 4688}`,
`image_load` → `{7}`, `registry_event` → `{12, 13, 14}`, and so on for
every Sysmon/Security category this project's data sources produce.
Before an event ever reaches the field matcher, it's checked against this
mapping; an event whose `EventID` doesn't belong to the rule's category is
excluded, full stop, regardless of whether its field values would
otherwise have matched.

**This fails open, deliberately.** If a rule's `product` isn't `windows`,
or its `category` isn't in the mapping table, nothing is filtered — the
rule applies to every event, same as before this feature existed. Silent
over-filtering (dropping events for a category we don't actually have
mapping data for) would be worse than not filtering at all, because it
would hide genuine matches with no visible sign it happened. Every report
states explicitly whether the filter was applied or skipped, and why —
see the `logsource filter:` line in the CLI output.

### Why this matters, concretely

Running the same test rule against the same real Sysmon capture:

| | Before this fix | After this fix |
|---|---|---|
| Matches (local capture) | 48 | **36** |
| Events excluded as wrong type | — | 62 (registry + file-create events where `Image` happened to match) |
| Baseline matches (6,000 goodware events) | 155 (2.58%) | **2 (0.03%)** |
| Resulting tier | Yellow | **Green** |

The 12 extra local-capture matches were Sysmon FileCreate events
(EventID 11) where `osk.exe` created a temp file — a `file_event`, not a
`process_creation`, but the `Image` field was present either way. The
baseline correction is detailed in the box above.

---

## Quick start

```bash
pip install pysigma pysigma-backend-splunk pysigma-pipeline-sysmon python-evtx requests

# no setup needed — synthetic data, proves the pipeline works
python -m src.cli --rule data/rules/test_accessibility_tools.yml --source mock

# real sample data included in this repo
python -m src.cli --rule data/rules/test_accessibility_tools.yml \
    --logs data/logs/persistence_shim_appfix.evtx

# with a benign baseline for real FP evidence (the main feature)
python -m src.cli --rule data/rules/test_accessibility_tools.yml \
    --logs data/logs/persistence_shim_appfix.evtx \
    --baseline data/baseline/sysmon_baseline_sample.json
```

> `data/logs/*.evtx` are stripped from the packaged zip to keep it small —
> see [Downloading sample data](#downloading-sample-data) below.

---

## Usage

```
python -m src.cli (--rule RULE.yml | --rules-dir DIR) [--logs PATH...] [--baseline PATH...]
                   [--source {local,mock,wazuh,sentinel,splunk}]
                   [--lookback-hours N] [--json]
```

| Flag | Meaning |
|---|---|
| `--rule` | Path to a single Sigma rule YAML file. Mutually exclusive with `--rules-dir`. |
| `--rules-dir` | Directory of Sigma rule YAML files — batch-scores the whole ruleset against the same data and ranks worst-to-best. |
| `--logs` | `.evtx`/`.json` file(s) or a directory of them. Required when `--source local` (the default). |
| `--baseline` | Same, but for **known-benign** traffic. Any match here is treated as real FP evidence and dominates the score. |
| `--source` | Where events come from: `local` (default), `mock`, `wazuh`, `sentinel`, `splunk` |
| `--lookback-hours` | For live sources, how far back to pull (default 24) |
| `--json` | Machine-readable output instead of the formatted report |

### Batch mode: ruleset triage

```bash
python -m src.cli --rules-dir data/rules/batch_test \
    --logs data/logs/persistence_shim_appfix.evtx \
    --baseline data/baseline/sysmon_baseline_sample.json
```

```
====================================================================================================
RULESET NOISE TRIAGE  —  5 rule(s) scored
====================================================================================================

     SCORE    MATCHES    BASELINE  RULE
---------------------------------------
🟢    0.201         36      2/6000!  Accessibility Tool Execution (osk/LogonUI/utilman family)
🟢    0.036          1      0/6000  Whoami.EXE Execution Anomaly
🟢    0.000          0      0/6000  PowerShell Download and Execution Cradles
🟢    0.000          0      0/6000  Process Execution From A Potentially Suspicious Folder
🟢    0.000          0      0/6000  Suspicious New Service Creation

  🔴 0 red   🟡 0 yellow   🟢 5 green
```

Rules that fail to parse or evaluate are skipped with a reason shown at
the end, rather than crashing the whole batch.

### Live SIEM connectors

```bash
# Splunk — LIVE-TESTED, see below
python -m src.cli --rule data/rules/test_accessibility_tools.yml --source splunk \
    --splunk-url https://localhost:8089 --splunk-user admin --splunk-pass '...' \
    --splunk-index main --lookback-hours 24

# Wazuh Indexer (OpenSearch) — normalization unit-tested, live calls unverified
python -m src.cli --rule data/rules/test_accessibility_tools.yml --source wazuh \
    --wazuh-url https://<indexer-host>:9200 --wazuh-user admin --wazuh-pass '...'

# Microsoft Sentinel (Log Analytics) — normalization unit-tested, live calls unverified
python -m src.cli --rule data/rules/test_accessibility_tools.yml --source sentinel \
    --sentinel-tenant-id ... --sentinel-client-id ... \
    --sentinel-client-secret ... --sentinel-workspace-id ...
```

---

## What's proven, and how

### Core matcher & noise scorer
- Sigma modifiers (`contains`/`startswith`/`endswith`/exact/numeric/`re`/`cidr`/
  `base64offset`/`gt`/`gte`/`lt`/`lte`) validated against synthetic events
  built to isolate each one.
- **Logsource filtering validated against real data**: confirmed the
  before/after match-count and baseline-rate change documented above by
  direct inspection of which EventIDs contributed the excluded matches —
  not inferred, directly checked record by record.
- Real SigmaHQ rule used as a negative control: 0 matches, green tier.

### Batch mode
Ran `--rules-dir` against 5 real rules (1 custom + 4 unmodified SigmaHQ
rules). After the logsource fix, all 5 score green against this
particular capture and baseline — a materially different, and more
accurate, picture than the pre-fix run. Error handling was separately
verified: a rule with an unsupported modifier was skipped by filename and
error without affecting the other 5.

### Live SIEM — Splunk (fully tested against real infrastructure)
Set up a real Splunk Enterprise 10.2.2 instance (Windows, Sysmon + Windows
TA). First live fetch returned every field null despite the raw event
containing them — root cause: Splunk's REST `/results` endpoint doesn't
include every search-time-extracted field by default. Fixed with explicit
`| table <fields>` in the SPL. After the fix, a real triggered `osk.exe`
execution was detected end-to-end: 6 matches, live, on real infrastructure.

### Live SIEM — Wazuh & Sentinel (partially tested)
`_normalize()` methods unit-tested against realistic fake API response
shapes and confirmed to produce events that match correctly. The actual
live network calls have not been executed against real instances.

---

## Known limitations

- **Logsource filtering only covers Windows EventID-based categories.**
  Non-Windows products (linux, aws, azure, etc.) and categories not in
  `logsource_map.py`'s table are not filtered at all — this is a
  deliberate fail-open design, not an oversight, but it does mean a rule
  for an unmapped category gets zero benefit from this fix.
- **The `service:` disambiguation (Sysmon vs. native Security log) is only
  implemented for `process_creation`.** Other categories that could
  plausibly come from either channel aren't narrowed further.
- Day-rate normalization assumes one coherent, continuously-captured time
  window.
- The bundled baseline sample is 6,000 of ~124MB available in the full
  NextronSystems dataset (parser speed constraint).
- `re`/`cidr`/`base64offset` proven against synthetic cases, not yet
  against a real SigmaHQ rule using them in combination with other logic.
- `base64` (no offset), `fieldref`, `cased` modifiers not implemented.
- Wazuh/Sentinel connectors unverified against live infra.
- No automated regression test suite yet — validation has been empirical
  (real runs against real/live data), not asserted in a committed `pytest`
  suite that CI checks.

---

## Downloading sample data

```bash
cd data/logs
curl -L "https://raw.githubusercontent.com/sbousseaden/EVTX-ATTACK-SAMPLES/master/Persistence/persistence_sysmon_11_13_1_shime_appfix.evtx" -o persistence_shim_appfix.evtx
cd ../..
```

The baseline (`data/baseline/sysmon_baseline_sample.json`) ships in the
repo already. To regenerate it from the full dataset yourself:
```bash
curl -L "https://github.com/NextronSystems/evtx-baseline/releases/latest/download/win7-x86.tgz" -o /tmp/win7-x86.tgz
tar xzf /tmp/win7-x86.tgz -C /tmp
python -c "
from src.evtx_parser import parse_evtx
import json
recs = parse_evtx('/tmp/win7-x86/Microsoft-Windows-Sysmon%4Operational.evtx', max_records=6000)
json.dump(recs, open('data/baseline/sysmon_baseline_sample.json', 'w'))
"
```

---

## Project layout

```
src/
  evtx_parser.py       -- EVTX -> normalized dict, + JSON cache load/save
  sigma_eval.py          -- pySigma AST walker + matcher + logsource pre-filter
  logsource_map.py        -- Windows category -> EventID mapping (new)
  noise_score.py            -- scoring engine (volume/entity/temporal/noisy-pattern/baseline)
  cli.py                     -- entry point, --rule / --rules-dir / --source dispatch
  connectors/
    base.py                   -- SIEMConnector abstract interface
    mock.py                     -- synthetic data connector (tested, works end to end)
    splunk.py                    -- Splunk REST API connector (LIVE-TESTED)
    wazuh.py                      -- Wazuh Indexer/OpenSearch connector (unit-tested, live untested)
    sentinel.py                    -- Microsoft Sentinel/Log Analytics connector (unit-tested, live untested)
data/
  logs/                 -- sample EVTX (sbousseaden/EVTX-ATTACK-SAMPLES; re-download, see above)
  rules/                 -- test rule + real SigmaHQ rules
  rules/batch_test/       -- 5-rule set used to validate --rules-dir batch mode
  baseline/                -- goodware baseline sample (NextronSystems/evtx-baseline)
```

---

## Roadmap

- [x] Batch mode (`--rules-dir`)
- [x] Logsource-aware pre-filtering (v1.2)
- [ ] Automated `pytest` regression suite, asserted in CI (not just smoke-tested)
- [ ] Live-test the Wazuh and Sentinel connectors against real instances
- [ ] Larger/incremental baseline dataset (full 124MB NextronSystems set)
- [ ] Validate `re`/`cidr`/`base64offset` against a real SigmaHQ rule
- [ ] `base64`, `fieldref`, `cased` modifier support
- [ ] Secrets handling for live connectors (currently plaintext CLI args)
- [ ] Pagination for live connectors beyond the current per-call cap
- [ ] Optional: compile-to-query mode (SPL/KQL) for very large indexes

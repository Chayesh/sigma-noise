# sigma-noise

[![CI](https://github.com/YOUR-USERNAME/sigma-noise/actions/workflows/ci.yml/badge.svg)](https://github.com/YOUR-USERNAME/sigma-noise/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)

A CLI tool that backtests a Sigma detection rule against log data — local
sample files or a live SIEM — and estimates how noisy it'll be **before**
you deploy it. Answers the question every analyst asks a week too late:
*"how many false positives is this rule actually going to generate?"*

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
2. **Evaluate** it against events by walking pySigma's parsed condition AST
   directly (`ConditionAND`/`OR`/`NOT`, field-match leaves) — a real
   evaluator, not string matching against YAML
3. **Score** the matches on four factors: match volume (normalized by time
   span), entity diversity, temporal clustering, and known-noisy-process
   flags — plus, if a benign baseline is supplied, real corroborated
   false-positive evidence, which dominates the score
4. **Report** a tier (green/yellow/red), the composite score, and specific
   tuning suggestions (e.g. "83% of matches are `svchost.exe` — exclude
   this parent process")

Event data can come from local `.evtx` files, a pre-parsed JSON cache, or a
**live SIEM connector** (Splunk, Wazuh, Sentinel). Every source normalizes
into the same flat event schema and feeds the same matcher and scorer —
one evaluator, any backend. Connectors deliberately do **not** compile the
Sigma rule into SPL/KQL/DSL; they pull raw events for the time window and
let the same local matcher decide. One less compiler to build and
maintain.

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
python -m src.cli --rule RULE.yml [--logs PATH...] [--baseline PATH...]
                   [--source {local,mock,wazuh,sentinel,splunk}]
                   [--lookback-hours N] [--json]
```

| Flag | Meaning |
|---|---|
| `--rule` | Path to a Sigma rule YAML file (required) |
| `--logs` | `.evtx`/`.json` file(s) or a directory of them. Required when `--source local` (the default). |
| `--baseline` | Same, but for **known-benign** traffic. Any match here is treated as real FP evidence and dominates the score. |
| `--source` | Where events come from: `local` (default), `mock`, `wazuh`, `sentinel`, `splunk` |
| `--lookback-hours` | For live sources, how far back to pull (default 24) |
| `--json` | Machine-readable output instead of the formatted report |

### Live SIEM connectors

```bash
# Splunk — LIVE-TESTED, see below
python -m src.cli --rule data/rules/test_accessibility_tools.yml --source splunk \
    --splunk-url https://localhost:8089 --splunk-user admin --splunk-pass '...' \
    --splunk-index main --lookback-hours 24
# or with a static token instead of user/pass: --splunk-token '...'

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

This section is deliberately specific about what was actually run vs. what
was only unit-tested or designed but not yet exercised. No claim below is
inferred — everything is a real, reproduced result.

### Core matcher & noise scorer
- **Sigma modifiers**: `contains`/`startswith`/`endswith`/exact/numeric-equals/
  keyword-search (original build), plus `re` (regex), `cidr`, `base64offset`,
  and numeric comparisons `gt`/`gte`/`lt`/`lte` — all validated against
  synthetic events built to isolate exactly one modifier each; each matched
  precisely the events it should and rejected the rest. `base64offset`
  specifically was confirmed to actually base64-decode and find a target
  string inside an encoded command line, not just match by string luck.
- **Deliberately noisy test rule** (`test_accessibility_tools.yml`, matches
  `osk.exe`/`LogonUI.exe`/`sethc.exe`/`utilman.exe` — classic sticky-keys
  backdoor detection, T1546.008) run against a real Sysmon capture from
  [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES):
  48/237 events matched, correctly scored **yellow**, 193 matches/day.
- **Real SigmaHQ rule** (`susp_execution_path.yml`) run as a negative
  control against the same data: **0 matches, green tier** — confirms the
  tool doesn't just flag everything.

### Baseline false-positive checking
- Pulled a real goodware baseline from
  [NextronSystems/evtx-baseline](https://github.com/NextronSystems/evtx-baseline)
  (the same dataset SigmaHQ itself uses for its own FP regression testing),
  cached 6,000 parsed events to JSON.
- The noisy test rule fired on **155/6,000 (2.58%)** of confirmed-benign
  traffic — driven by `LogonUI.exe`, which legitimately runs on every
  login. Real, corroborated evidence this rule needs tuning before
  deployment, not an inference.
- The control rule stayed green with zero false matches against the
  baseline too.

### Live SIEM — Splunk (fully tested against real infrastructure)
Set up a real Splunk Enterprise 10.2.2 instance (Windows) with Sysmon and
the Splunk Windows TA feeding a live index, then ran the connector against
it for real:

1. `test_connection()` — auth + version check succeeded against the live
   instance.
2. First `fetch_events()` run came back with **every field null** across
   all 5,000 events, despite the raw event clearly containing
   `EventCode=5` and a populated `Image` field. Root cause: Splunk's REST
   `/results` endpoint does **not** include every search-time-extracted
   field by default — unlike Splunk Web's table view, which does
   extraction on demand for display. This is a genuine, documented gotcha,
   not a bug in our matcher.
3. Fixed by explicitly forcing field selection with `| table <fields>` in
   the SPL query (see `SplunkConnector._SELECT_FIELDS`).
4. Triggered a real On-Screen Keyboard (`osk.exe`) execution on the test
   machine, re-ran the full CLI end to end: **6 real matches**, correctly
   scored yellow, correctly identified `logonui.exe` as 33% of the noise
   and flagged the single-entity concentration for review.

This is the strongest evidence in the project: real infra, a real bug
found and fixed by reading the data rather than assuming the code was
wrong, and a real detection of real activity on a real machine.

### Live SIEM — Wazuh & Sentinel (partially tested)
`WazuhConnector._normalize()` and `SentinelConnector._normalize()` were
unit-tested against realistic fake API response shapes (a Wazuh Sysmon
alert document, a `DeviceProcessEvents` row) and confirmed to produce
events that match correctly through the real Sigma evaluator. The actual
`requests` calls to a live Wazuh Indexer or Sentinel Log Analytics
workspace have **not** been executed. Given what the Splunk connector
needed once it hit real data, assume something analogous — a field-mapping
mismatch, an auth-flow edge case, a pagination limit — is waiting in each
until proven otherwise.

---

## Known limitations

Stated plainly, not hidden, because an honest limitations section is more
useful than a tool that quietly gets things wrong:

- **Day-rate normalization assumes one coherent, continuously-captured
  time window.** Feeding it several unrelated demo EVTX files stitched
  from different scenarios dilutes the volume score toward green
  regardless of real match density, because the gaps between unrelated
  captures get counted as elapsed time. Point it at one real capture or a
  live SIEM export covering one continuous window.
- **The bundled baseline sample is only 6,000 of ~124MB available** in the
  full NextronSystems dataset — `python-evtx` is pure Python and too slow
  to parse the whole file in this environment in one pass. A larger or
  incrementally-cached baseline would give a more reliable FP estimate.
  `evtx_parser.load_events()` already supports reading back a cached JSON
  sample so re-parsing cost isn't paid twice.
- **`re`/`cidr`/`base64offset` modifiers are proven against synthetic test
  cases, not yet against a real-world SigmaHQ rule using them.** Worth
  doing before calling them fully battle-tested.
- **`base64` (without offset), `fieldref`, and `cased` modifiers are not
  implemented.**
- **Wazuh and Sentinel connectors are unverified against live infra** (see
  above) — treat as "should work, pending the same kind of debugging
  Splunk needed" rather than "proven."

---

## Downloading sample data

The packaged release strips `data/logs/*.evtx` to keep the download small.
Re-fetch them from the same public dataset:

```bash
cd data/logs
curl -L "https://raw.githubusercontent.com/sbousseaden/EVTX-ATTACK-SAMPLES/master/Persistence/persistence_sysmon_11_13_1_shime_appfix.evtx" -o persistence_shim_appfix.evtx
curl -L "https://raw.githubusercontent.com/sbousseaden/EVTX-ATTACK-SAMPLES/master/Privilege%20Escalation/privesc_unquoted_svc_sysmon_1_11.evtx" -o privesc_unquoted_svc.evtx
curl -L "https://raw.githubusercontent.com/sbousseaden/EVTX-ATTACK-SAMPLES/master/Discovery/discovery_meterpreter_ps_cmd_process_listing_sysmon_10.evtx" -o discovery_meterpreter.evtx
curl -L "https://raw.githubusercontent.com/sbousseaden/EVTX-ATTACK-SAMPLES/master/Discovery/discovery_bloodhound.evtx" -o discovery_bloodhound.evtx
curl -L "https://raw.githubusercontent.com/sbousseaden/EVTX-ATTACK-SAMPLES/master/Discovery/4799_remote_local_groups_enumeration.evtx" -o discovery_4799_groups.evtx
cd ../..
```

On Windows PowerShell, use `Invoke-WebRequest -Uri ... -OutFile ...` if
`curl.exe` isn't available.

`data/baseline/sysmon_baseline_sample.json` (the goodware baseline) ships
in the repo already — no download needed.

---

## Project layout

```
src/
  evtx_parser.py       -- EVTX -> normalized dict, + JSON cache load/save
  sigma_eval.py         -- pySigma AST walker + matcher (all modifiers)
  noise_score.py         -- scoring engine (volume/entity/temporal/noisy-pattern/baseline)
  cli.py                 -- entry point, --source dispatch
  connectors/
    base.py               -- SIEMConnector abstract interface
    mock.py                 -- synthetic data connector (tested, works end to end)
    splunk.py                -- Splunk REST API connector (LIVE-TESTED)
    wazuh.py                  -- Wazuh Indexer/OpenSearch connector (unit-tested, live untested)
    sentinel.py                -- Microsoft Sentinel/Log Analytics connector (unit-tested, live untested)
data/
  logs/                 -- sample EVTX (sbousseaden/EVTX-ATTACK-SAMPLES; re-download, see above)
  rules/                 -- test rule + real SigmaHQ rules
  baseline/                -- goodware baseline sample (NextronSystems/evtx-baseline)
```

---

## Roadmap

- [ ] Live-test the Wazuh and Sentinel connectors against real instances
- [ ] Larger/incremental baseline dataset (full 124MB NextronSystems set)
- [ ] Validate `re`/`cidr`/`base64offset` against a real SigmaHQ rule
- [ ] `base64`, `fieldref`, `cased` modifier support
- [ ] Optional: compile-to-query mode (SPL/KQL) for very large indexes
      where pulling raw events isn't practical — a v3 optimization, not
      needed at backtesting-sized time windows

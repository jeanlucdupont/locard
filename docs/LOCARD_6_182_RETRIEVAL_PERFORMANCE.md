# Locard 6.182 — Forensic retrieval performance

Implementation for manual acceptance, 2026-11-26. Baseline: committed 6.181, HEAD `93e8337` at start. Version authority: `pyproject.toml`. No reference case or provider was accessed. This release preserves 6.181 discovery, scoring and reasoning.

## Confirmed causes and changes

| Operation | Observed 6.181 plan/cost | Correction |
|---|---|---|
| Registry exact-ID eligibility, hence show/verify | `MATERIALIZE locard_times`, scanning `evidence_timestamps` even with an outer exact EID predicate. The union includes persisted timestamps, legacy UserAssist times and inherited key times | Build an authorized candidate ID set and containing-key target set. Restrict **every** union branch to that set. Original eligibility, supporting-key checks and source ambiguity checks still run |
| Registry key searches | Correlated key/value relationship test across the time-selected population; selective `registry_path` access was not the starting point | Indexed matching keys plus their values through `registry_key_values`, then scoped timestamp evaluation. Exact NOCASE, escaped literal substring and key-plus-values semantics unchanged |
| Value-name searches | Expensive time union before selective value eligibility; raw/decoded UserAssist names both participate | Reuse candidate-restricted timestamp projection. Value-name predicates and decoded-name behavior are unchanged; there is no new value-name index |
| MFT path/time | Per-record object and timestamp correlation; normalized path access did not first narrow the candidate set | Indexed normalized-object superset, followed by the original exact path/volume-context/role predicate; bounded timestamp range selects eligible IDs |
| MFT narrow timeline | Planner could start with artifact records and perform timestamp probes across unrelated records | Timestamp-first `CROSS JOIN`, using existing `artifact_time` range index, then exact record/source resolution |
| Repeated timeline slots | Same original record hydrated repeatedly for different timestamp slots | Invocation-local reuse **only inside an active read transaction**, including trusted scoped loaders. Each timestamp observation, slot, meaning, stable ordering and pagination remains present |

A `NOT MATERIALIZED` hint alone was measured and **did not solve Registry inspection**: SQLite still evaluated a compound timestamp co-routine over unrelated rows. Explicit candidate restriction is the substantive fix. No timeout, quota or evidence-content relaxation is used.

Code: `retrieval/evidence.py:EvidenceQueries._where/search`, `artifacts/userassist.py:timeline_cte`, `conversational_ai/tools.py:Tools.eligible/original/execute` (paths relative to `forensic_assistant/`). Existing `get_evidence` retained-record construction remains authoritative. The large Registry inspection delay was in eligibility rather than a need to redesign Registry raw hydration or parent reconstruction.

## Query plans and contracts

Previous Registry ID plan: primary-key record lookup followed by full timestamp-union materialization/scan and temporary indexes. New plan: materialize the small `locard_candidates`/`locard_target` ID sets, then `SEARCH evidence_timestamps ... (evidence_id=?)`; UserAssist branches retain their registered interpretation and persisted-slot deduplication. Exact keys use `registry_path (key_path=?)`, and values use `registry_key_values (key_id=?)`. Substring matching still scans key paths because leading-wildcard matching is not B-tree-selective; it is not silently converted to prefix or exact matching.

MFT path candidates use `object_path (normalized=?)`. An absolute drive path admits both its normalized absolute form and volume-relative suffix as candidates. The original volume assertion, role, path-kind and context predicate remains the final eligibility test. No new authoritative path is reconstructed. Basename discovery is unchanged.

Timestamp-first timelines use `artifact_time (timestamp_utc>? AND timestamp_utc<?)` and evidence identity lookup. Narrow search uses the same timestamp range to build IDs. Search ordering still uses the established minimum persisted timestamp excluding `UserAssist.LastExecution`; it is not changed to an internal execution timestamp. All time values, unknown-time behavior and SI/FN distinctions remain unchanged. Core retrieval retains inclusive end semantics; the conversational/diagnostic boundary converts its authorized **exclusive** end using the existing function.

No index additions, schema migration, maintenance command, reingestion or dependency installation are required. Existing case databases benefit on read. No case is modified merely by opening it.

## Profiling and counts

`retrieval/performance.py:measured` and existing SQL profiling provide optional phase timings:

- Scope resolution/query construction.
- Combined identity/source/time eligibility.
- Exact counting, when explicitly requested.
- SQL page selection and parameterized SQL/query plans.
- Retained-record hydration and complete original construction.
- Field extraction, projection and total tool duration.
- Diagnostic result serialization.

Nested phase durations overlap and must not be summed. Source membership and time evaluation within a SQL statement are reported together, not assigned fabricated individual durations. Parameters and forensic values are not included in phase diagnostics. Plans contain schema identifiers. Evidence IDs and result digests in the diagnostic report are sensitive derived metadata.

Conversational searches already used bounded page-plus-lookahead instead of exact counts in 6.181; that behavior is retained. CLI/full-count users retain exact counting. Diagnostic `--exact-count` explicitly selects the existing exact path. `total=null` with `total_exact=false` is not an estimated exact total. No new cache of populations, authorizations or model interpretations is introduced. The only new hydration reuse ends with the query and is bounded by its existing result-page limit; verification never reads from it.

## Independent production-path diagnostic

`scripts/benchmark_forensic_retrieval.py` uses `ReadView`, `authorize/check`, `Tools` and `EvidenceQueries`; it makes no model requests. It is a direct diagnostic of production services, **not a measurement of worker startup/IPC**. Production worker containment/cancellation is unchanged. The script uses the read-only authorizer and pinned transaction, checks identity before/after operations, supports an optional SQLite deadline and Ctrl+C, and closes its view in `finally`. It does not initialize a case. A long diagnostic can pin WAL history; avoid concurrent ingestion and use `--seconds` if needed.

Exact-ID diagnostics first inspect the explicitly analyst-selected eligible record. Verification establishes a bounded original-field disclosure and then performs the normal independent verification. That setup duration is separately reported as `preparation_seconds`; it is not hidden inside the measured verification. Redacted/truncated/provenance-only fields still cannot be verified. `--timestamp-meaning` must match exactly for timestamp verification. Wrong values are rejected.

Options: required `--db`, `--source`, `--start`, `--end`, `--operation search|timeline|show|verify`; optional `--artifact`, `--registry-key`, `--registry-key-contains`, `--value-name`, `--value-name-contains`, `--path`, `--object-basename`, `--hostname`, `--evidence-id`, `--field`, `--value-json`, `--timestamp-meaning`, `--repeat`, `--limit`, `--offset`, `--seconds`, `--exact-count`, `--diagnostics`, `--json`.

Repeat requests share one pinned view but not a cross-operation evidence cache. Output reports timings, EIDs, canonical result digest, coverage/pagination/count status and view binding. `--diagnostics` adds phase timings and SQL plans. No raw record content or SQL parameters are printed by default. First-run versus repeat timing is reported honestly: these are **not proven cold OS-cache runs**; no cache flushing or system-setting changes are performed.

## Synthetic measurements

`tests/retrieval_performance_fixtures.py` generates retained tables from synthetic parser fixtures. `tests/benchmark_retrieval_6182.py` loads the committed baseline query implementation using read-only `git show` and compares it with the working tree on the same database and read transaction. Its baseline must be a 6.181 checkout; after release commits, preserve the baseline revision explicitly before repeating the historical comparison.

Population: 200,007 Registry keys, 200,002 values, 100,003 MFT records and 1,000,031 timestamps. Database: **773,812,224 bytes**, with existing indexes only. The benchmark gives ten generated MFT records timestamps in a 20-second window and selective normalized paths. It compares full canonical result digests, not merely record counts. All compared result digests matched.

| Operation | 6.181 first / repeat seconds | 6.182 first / repeat seconds |
|---|---:|---:|
| Registry exact-ID scoped retrieval | 2.4490 / 2.2235 | 0.0053 / 0.0025 |
| Exact Registry key | 2.9016 / 2.8539 | 0.0063 / 0.0034 |
| Selective Registry substring | 2.8467 / 2.8069 | 0.2498 / 0.3418 |
| Selective MFT path/time | 0.3051 / 0.3052 | 0.0066 / 0.0018 |
| Populated narrow MFT timeline | 0.4855 / 0.5166 | 0.0034 / 0.0034 |
| Production-adapter Registry show | 2.5797 / 2.5738 | 0.0040 / 0.0038 |
| Production-adapter Registry verify | 2.5753 / 2.5075 | 0.0047 / 0.0039 |

The show/verify comparison used the same retained record, original value and authorization; outputs matched exactly. These are local synthetic measurements, not promises about the 2.9-million-record case or the user's 24–28-second baseline. The synthetic case contains fewer records, fewer source relationships and less varied data. Broad substring matching, broad time intervals, exact totals and sorting can remain expensive. No isolated native-memory peak comparison was made; do not infer measured memory savings. The new hydration cache is invocation-local, while whole-population caches remain deferred. Database/index size is unchanged by retrieval.

## Correctness and validation

New tests compare authorized Registry IDs, complete original hydration, deterministic repeated pages, exact versus bounded counts, independent MFT timestamp SQL, timestamp pagination, repeated field verification, wrong-value rejection, identity query plans, diagnostic read-view binding and unchanged synthetic case bytes. A pinned-timeline test verifies that multiple timestamp observations survive while the original record is loaded once. Existing suites cover UserAssist legacy/persisted time semantics, dirty hives, source/host restrictions, reconstructed paths, cancellation, worker recovery, evidence-state changes and conversational integration.

Existing UserAssist tests still invoked retired top-level `ingest-registry`, `search`, `show` and `around`; their invocation syntax was updated to the current `evidence` command family. Existing EVTX content CLI testing similarly used retired top-level `search`. Their forensic assertions were preserved. These failures predated the optimization; no obsolete product command was restored.

The authorization display now derives its tool names from `contracts.catalog()`, including `discover_execution_behaviors`. No model tool contract or reasoning prompt was changed.

Recorded focused runs:

- Initial relevant set: 119 passed, 10 setup errors from obsolete UserAssist CLI syntax.
- After fixture command correction: UserAssist 39 passed.
- Expanded artifact/retrieval/conversation set: 223 passed, 3 failed (new cache-test fixture assumption and two obsolete compatibility-shim invocations). No production semantic failure was identified in this set.
- Corrected performance/resilience/EVTX set: **34 passed in 33.86 s**.
- Final UserAssist plus derived-only CTE and diagnostic-verification checks: **41 passed in 29.27 s**.
- The standalone EVTX CLI fixture also required its obsolete command spelling updated; its forensic content assertions remain unchanged.
- `git diff --check` passed. Version authority verified as **6.182**.

Runs overlap; these are not additive unique totals. Pytest emitted a local cache-write warning. All observed test failures were corrected and the affected tests passed. No complete test suite, live provider call or reference-case inspection was performed.

Changed production files: `forensic_assistant/retrieval/evidence.py`, new `retrieval/performance.py`, `artifacts/userassist.py`, `conversational_ai/tools.py`, `conversational_ai/cli.py`, and `pyproject.toml`. Added `scripts/benchmark_forensic_retrieval.py`, this document, `tests/retrieval_performance_fixtures.py`, `tests/benchmark_retrieval_6182.py`, and `tests/test_retrieval_performance_6182.py`. Updated stale invocations/shim in `tests/test_userassist.py`, `tests/test_evtx_content.py`, and `tests/test_retrieval_resilience.py`; `.gitignore` allows the new script/document. No commit or push was performed.

## Manual Windows acceptance

The analyst handles commit/push, checkout update and installation. Use the existing environment, with no pip command required:

```powershell
Set-Location C:\tmp\locard
python locard.py --version
# Expected: Locard 6.182
$db = 'D:\Locard\Cases\KFI-5070790-V2\case.db'
$source = 'src-d3c195d3068e4906a805082df44c1a57'
$start = '2026-11-17T06:00:00.000000000Z'
$end = '2026-11-18T06:00:00.000000000Z'
$common = @('--db',$db,'--source',$source,'--start',$start,'--end',$end,'--repeat','2','--diagnostics','--json')
```

A — Repeat exact and substring Registry controls using the same analyst-selected keys as 6.181:

```powershell
$key = Read-Host 'Exact retained Run or RunMRU key path from the previous run'
python scripts\benchmark_forensic_retrieval.py @common --operation search --artifact registry --registry-key $key
$part = Read-Host 'Same literal key substring used previously'
python scripts\benchmark_forensic_retrieval.py @common --operation search --artifact registry --registry-key-contains $part
# Explicit exact total, where needed:
python scripts\benchmark_forensic_retrieval.py @common --operation search --artifact registry --registry-key $key --exact-count
# Continue with identical filters and the returned --offset.
```

B — Original Registry inspection:

```powershell
$eid = Read-Host 'Known Registry evidence ID'
python scripts\benchmark_forensic_retrieval.py @common --operation show --evidence-id $eid
python locard.py --db $db evidence show $eid --json
```

C — Independent verification (supply exact retained scalar JSON, not explanatory prose):

```powershell
$field = Read-Host 'Original field pointer, e.g. /detail/value_name'
$value = Read-Host 'Expected scalar as JSON, including quotes for a string'
python scripts\benchmark_forensic_retrieval.py @common --operation verify --evidence-id $eid --field $field --value-json $value
# For an original timestamp pointer, also supply its exact displayed meaning:
$meaning = Read-Host 'Exact timestamp meaning for the selected timestamp field'
# Run this only with the corresponding timestamp field/value:
python scripts\benchmark_forensic_retrieval.py @common --operation verify --evidence-id $eid --field $field --value-json $value --timestamp-meaning $meaning
```

D — Existing MFT path and basename controls (path retains exact normalized-path semantics, not new recursive directory semantics):

```powershell
$path = Read-Host 'Same MFT path used in the previous investigation'
python scripts\benchmark_forensic_retrieval.py @common --operation search --artifact mft --path $path
$basename = Read-Host 'Exact basename control'
python scripts\benchmark_forensic_retrieval.py @common --operation search --artifact mft --object-basename $basename
```

E — Same 20-second MFT window, explicitly within the approved day:

```powershell
$narrowStart = Read-Host 'Original 20-second window start (full UTC timestamp)'
$narrowEnd = Read-Host 'Original exclusive end (full UTC timestamp)'
python scripts\benchmark_forensic_retrieval.py --db $db --source $source --start $narrowStart --end $narrowEnd --operation timeline --artifact mft --repeat 2 --diagnostics --json
# Repeat with --offset from the returned continuation, or --exact-count.
```

F — Provider-free discovery regression:

```powershell
python scripts\discover_execution_behaviors.py --db $db --source $source --start $start --end $end --json
python scripts\benchmark_forensic_retrieval.py @common --operation search --artifact evtx
python scripts\benchmark_forensic_retrieval.py @common --operation search --artifact browser
```

Compare original IDs/fields, timestamp slots and meanings, source/time scope, pagination and completeness with 6.181. Measure duration separately from correctness. No cloud-backed investigation is required for this deterministic acceptance.

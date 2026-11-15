# Locard 6.148 — CLI responsiveness

## Scope

Baseline: `8e110dd` (6.147, clean tree). This document describes uncommitted 6.148 work. `pyproject.toml` remains the version authority. No original evidence, live case, provider, transcript or permission was accessed/changed. No full suite, commit or push.

## Status diagnosis and optimization

The interactive path is `Shell.run` (existing case validation) → CLI audit/dispatch boundary → `open_existing` schema check → `v2_cli.dispatch(status)` → `Queries.coverage`, error details, source coverage, browser counts, artifact counts and timeline count → text-only `status_display.context` → `status_display.render`.

- `Queries.coverage` counts EVTX events and NULL timestamps and loads ingestion attempts; it does not load millions of evidence records into Python.
- `database.sources.coverage` calls `listing`/`summary` for up to 100 sources. Each source reconstructs membership for artifact counts and distinct hostnames. Schema 5 browser occurrence membership remains distinct from other file membership. The joins/UNIONs and temporary sorting recur per source. Other queries count unassigned files, unfinished batches and unknown analyst hosts.
- Artifact and browser counts use grouping over `evidence_records`. Timeline counting previously ran the persisted timestamps through the same UNION ALL coroutine as legacy UserAssist fallback.
- Human context loads artifact-run parameters and small grouped hive/error summaries. Rendering formats these existing results, not all evidence rows.
- Case validation checks paths/schema. Identity validation reads briefing/assessment sidecars; audit overhead depends on the actual history and storage. Neither may be bypassed. These costs are not established for the analyst's real case by this synthetic exercise.

The narrow optimization is `artifacts.userassist.timeline_count`: count persisted non-NULL timestamps directly through the existing `artifact_time` covering index, then add the unchanged legacy UserAssist fallback union with the persisted branch disabled. Original rows, NULL exclusion, inherited key times, existing-slot suppression and recognized UserAssist semantics are preserved. All other timeline callers keep the original default CTE. No schema/index/PRAGMA/cache change.

Source coverage is the dominant measured stage. Optimizing its repeated membership and host aggregates is deferred to separately reviewed query work with multi-source/browser provenance fixtures. The current release does not simplify those relationships for speed. The original 2.59-million-record case was not opened, so these measurements identify source-confirmed work and a synthetic bottleneck, not an exact attribution of its observed delay.

## Measurements

Disposable schema-5 SQLite fixture: 100,000 MFT-typed evidence records, 400,000 timestamp rows (300,000 non-NULL), 20 retained files and five analyst-assigned sources. No raw MFT parsing. File size: **82,137,088 bytes**. The same fixture/connection was used for before/after; timings are single local measurements with warm-cache/order effects, not calibrated throughput promises.

| Stage | Seconds |
|---|---:|
| Event coverage/ingestion metadata | 0.001211 |
| Source coverage | 1.199726 |
| Artifact counts | 0.011088 |
| Previous timeline count | 0.078809 |
| Optimized timeline count | 0.016183 |
| Human context | 0.001160 |
| Error detail loading | 0.000291 |
| Previous total status dispatch | 1.281646 |
| Optimized total status dispatch | 1.119621 |
| Rendering plus human context | 0.005910 |
| Separate path/schema validation | 0.037077 |
| Separate identity checks (no saved history) | 0.075920 |

The complete structured status results compared exactly equal. Timestamp count was 300,000 in both. Total dispatch improved about 12.6% in this fixture; timeline counting improved about 79.5%. Rendering is not the measured bottleneck. Display layout intentionally changes, but values/caveats and JSON do not.

`EXPLAIN QUERY PLAN`: the previous timeline query uses `CO-ROUTINE locard_times`, UNION ALL and a final scan of that coroutine; the persisted branch already uses `artifact_time`, but returns each counted row through the union. The new persisted aggregate uses `SEARCH evidence_timestamps USING COVERING INDEX artifact_time (timestamp_utc>?)`. Legacy fallback still resolves recognized Registry values and missing slots. Source aggregate plans contain membership co-routines, UNION/temp B-trees, indexed batch/occurrence lookups, a covering `evidence_type` scan and an automatic partial covering membership index. Full measured plans are appended below.

## Shared progress and lifecycle

`terminal_activity.operation` is a presentation context over the existing `ActivityIndicator`, with a 500 ms delay and 100 ms repaint interval. Services do not draw terminal output. Its context ends before result output, errors, paging or questions. Animation is suppressed for JSON, file/append/page output, redirected/noninteractive terminals, unsupported terminals and existing debug-mode policy.

The existing infrastructure starts one waiting thread even for fast interactive operations; it does not paint if the operation finishes within 500 ms. No thread is started for suppressed output. A nonblocking shared ownership lock prevents nested ActivityIndicators from competing. Thread-start failure leaves the operation usable. Unicode frames have an ASCII fallback. Context exit stops/joins and clears on success, exceptions and Ctrl+C; frame and clear writes explicitly suppress session capture. Existing operation/outcome audit records remain authoritative. No new event encoding or recorder.

Applied at silent boundaries: status retrieval, evidence search, case discovery, case activation validation, audit verification/session enumeration and report bundle verification. It is not a watchdog and does not cancel SQLite or change timeouts. A completely unresponsive terminal write remains an operating-system limitation of the existing rendering/thread join mechanism.

Recorded-history reconstruction and investigation/ingestion workflows are not blanket-wrapped: they have different output/approval/progress lifecycles. No competing spinner is introduced there. Case activation's initial validation is covered; later existing sidecar/audit work retains its original lifecycle. General asynchronous jobs and automatic audit verification are out of scope.

## Alignment and presentation

`terminal.field` retains its string-compatible representation and explicit label/value/role metadata. `terminal.aligned_lines` consumes only these typed fields, never searches rendered strings for labels/status words. It calculates the value column from safe plain labels, wraps values underneath and switches to stacked layout when labels would consume over half the terminal. ANSI/plain projections have equal text; control escaping stays active. Single inline fields and complex tables/narratives retain their existing representation.

Used for case status, startup/detailed AI status, audit summaries/details, case clone details, findings summary headers, source details and report-generation summaries. Related fields share a column within the view, not globally. Labels remain `label`; values retain neutral or explicit status roles.

The empty/populated-case limitations already used `forensic_note`. The observed white output came from the conservative capability fallback. Windows consoles with verified VT support now use the existing indexed brown, alongside Windows Terminal/256-color/truecolor environments. Unsupported extended-color contexts retain neutral fallback; plain mode has no ANSI. Recorded ingestion errors have an explicit error role, without message keyword classification. Limitation headings remain bright white.

`case list` now shows names and neutral origin classifications. `case list --details` includes paths and existing discovery metadata. Known missing/replaced registrations remain warnings; duplicate entries are preserved and existing opening ambiguity validation remains enforced. Discovery does not open every database. JSON remains the same `{cases: ...}` structure regardless of `--details`.

`audit verify` stops at counters on normal success. It no longer repeats the success sentence or generic recording-policy footer. Actual integrity failures, positively known current recording failures and unknown incomplete states remain visible. Policy limitations remain in details/JSON and persisted records. No hash-chain or lifecycle change.

## Changed files

- `terminal.py`: typed alignment metadata/renderer and Windows brown capability.
- `terminal_activity.py`: delayed operation facade, ownership, ASCII fallback, capture suppression.
- `artifacts/userassist.py`, `v2_cli.py`: indexed timestamp aggregate plus unchanged fallback.
- `cli.py`, `interactive/shell.py`, `workflow_cli.py`, `reporting/cli.py`: bounded presentation integration and `case list --details`.
- `retrieval/status_display.py`, `ai/cli.py`, `source_cli.py`, `session_recording.py`: aligned human views and explicit classifications.
- `pyproject.toml`: 6.148.
- Focused tests, this document, command reference, README and documentation allowlist.

## Validation

- `test_cli_responsiveness.py`, `test_terminal_activity.py`, `test_cli_refinement.py`: **38 passed in 6.92 s** after correcting an import-placement bug and declaring the synthetic terminal's Unicode encoding.
- Status human/JSON + partial/legacy metadata tests from `test_registry_ux.py`; lightweight discovery and CLI-path tests from `test_case_management.py`; responsiveness and terminal-activity tests: **28 passed in 11.89 s**. This overlaps the prior set; counts are not additive unique tests.
- Two final targeted tests for ASCII/thread-start fallback and current recording failure: **2 passed in 0.65 s**.
- Timeline equivalence includes empty cases, both supported synthetic UserAssist binary formats and missing persisted execution slots. Database dumps remain unchanged during status queries. Existing Registry status JSON assertions remain intact. Older spacing assertions allow column padding without changing expected counts, limitations or state.
- Final narrow-label wrapping/audit presentation check: **2 passed in 0.72 s**.
- No skips/exclusions in these selections. `git diff --check` passed. No broad regression suite or provider tests were run.

## Manual acceptance

After installing the updated checkout:

```powershell
.\.venv\Scripts\python.exe -m pip install -e .
.\.venv\Scripts\python.exe locard.py --version
.\.venv\Scripts\python.exe locard.py
```

Expected version: 6.148. In the shell:

```text
case list
case list --details
case list --json
case status
case status --json
ai status
audit verify
audit verify --json
settings color off
case status
settings color on
```

Use the analyst-selected large case to assess responsiveness, and an empty/disposable case for the empty limitation. Check aligned values, narrow-window stacking, brown limitations in a capable Windows terminal, concise successful audit output and preservation of detail in JSON. During a slow status query press Ctrl+C; confirm the indicator clears and the shell returns using the existing interrupt handler. Fast operations should show no frame. Verify redirected output:

```powershell
.\.venv\Scripts\python.exe locard.py --db '<case.db>' case status --json > status.json
.\.venv\Scripts\python.exe locard.py --db '<case.db>' case status > status.txt
```

No spinner frames or ANSI should appear in either redirected file. These are manual acceptance instructions, not executions performed against analyst evidence.

## Measured query plans

### old

```text
2 parent=0 CO-ROUTINE locard_times
3 parent=2 COMPOUND QUERY
4 parent=3 LEFT-MOST SUBQUERY
6 parent=4 SEARCH evidence_timestamps USING COVERING INDEX artifact_time (timestamp_utc>?)
15 parent=3 UNION ALL
19 parent=15 SEARCH k USING INDEX registry_path (key_path>? AND key_path<?)
29 parent=15 SEARCH v USING COVERING INDEX registry_key_values (key_id=?)
41 parent=15 CORRELATED SCALAR SUBQUERY 3
45 parent=41 SEARCH t USING COVERING INDEX sqlite_autoindex_evidence_timestamps_1 (evidence_id=? AND slot=?)
64 parent=3 UNION ALL
71 parent=64 SEARCH k USING INDEX registry_path (key_path>? AND key_path<?)
81 parent=64 SEARCH v USING COVERING INDEX registry_key_values (key_id=?)
89 parent=64 SEARCH t USING INDEX sqlite_autoindex_evidence_timestamps_1 (evidence_id=?)
100 parent=64 CORRELATED SCALAR SUBQUERY 5
104 parent=100 SEARCH own USING COVERING INDEX sqlite_autoindex_evidence_timestamps_1 (evidence_id=? AND slot=?)
124 parent=0 SCAN locard_times
```

### new_persisted

```text
3 parent=0 SEARCH evidence_timestamps USING COVERING INDEX artifact_time (timestamp_utc>?)
```

### source_aggregate

```text
2 parent=0 CO-ROUTINE m
4 parent=2 MERGE (UNION)
6 parent=4 LEFT
8 parent=6 CO-ROUTINE m
10 parent=8 MERGE (UNION)
12 parent=10 LEFT
16 parent=12 SCAN b
20 parent=12 SEARCH r USING COVERING INDEX ingestion_batch_runs (batch_id=? AND file_sha256>?)
40 parent=12 USE TEMP B-TREE FOR LAST TERM OF ORDER BY
54 parent=10 RIGHT
58 parent=54 SCAN a
62 parent=54 SEARCH f USING COVERING INDEX sqlite_autoindex_source_assignment_files_1 (assignment_id=?)
80 parent=54 USE TEMP B-TREE FOR LAST TERM OF ORDER BY
129 parent=6 SCAN e USING INDEX sqlite_autoindex_evidence_records_1
147 parent=6 SEARCH m USING AUTOMATIC PARTIAL COVERING INDEX (source_id=? AND file_sha256=?)
167 parent=6 USE TEMP B-TREE FOR LAST TERM OF ORDER BY
181 parent=4 RIGHT
189 parent=181 SCAN o USING COVERING INDEX sqlite_autoindex_browser_record_occurrences_1
191 parent=181 SEARCH r USING INTEGER PRIMARY KEY (rowid=?)
194 parent=181 SEARCH b USING INDEX sqlite_autoindex_ingestion_batches_1 (batch_id=?)
218 parent=181 USE TEMP B-TREE FOR DISTINCT
219 parent=181 USE TEMP B-TREE FOR LAST TERM OF ORDER BY
270 parent=0 SCAN e USING COVERING INDEX evidence_type
285 parent=0 SEARCH m USING AUTOMATIC PARTIAL COVERING INDEX (source_id=? AND evidence_id=?)
```

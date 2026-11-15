# Locard 6.149 — Evidence exploration

## Scope and baseline

Baseline: `4cfefee` (6.148, clean working tree). This document describes the uncommitted 6.149 implementation. `pyproject.toml` remains the application-version authority. No live case, original transcript, provider, permissions, evidence hashes or stored timestamps were modified. No commit/push or full regression suite.

## A. Source performance and progress

`evidence source list/show` → CLI source dispatch → `database.sources.listing/detail/summary`. Previously each source independently joined the canonical evidence-membership relation twice: artifact counts and distinct artifact hostnames. Schema-5 membership combines non-browser file membership with explicit browser occurrences; file membership alone does not establish browser context. UNION deduplication is necessary.

`_record_aggregates` now selects the requested source IDs and materializes that **same** relation once per operation. It returns grouped artifact counts and the first 101 sorted distinct hostnames per source (100 displayed plus the existing truncation/conflict sentinel). Listing shares these aggregates across its bounded page. Detail uses the same aggregation for one source. Existing batch counts, distinct-file counts, retrospective history, ambiguity rules, host assertion comparison and pagination remain unchanged. No persistent cache, schema, index or PRAGMA change. Python receives aggregates/bounded hostname lists, not every evidence row. SQLite may use temporary storage for materialization and sorting.

On SQLite versions supporting it, `AS MATERIALIZED` ensures reuse; older SQLite omits the optimizer hint. Existing window-function support is required for bounded per-source hostname ranking. Very large membership sets can still be expensive. The remaining per-source file/batch/ambiguity queries are deferred rather than replacing provenance with approximations.

### Measurements

Reused disposable schema-5 fixture from 6.148: **82,137,088 bytes**, **100,000 MFT-typed evidence rows**, 400,000 timestamp rows, 20 retained files, five sources assigned retrospectively. No new large case copy. Before/after list and complete detail dictionaries compared **exactly equal**. Timings are single local runs; cache/order effects apply.

| Operation | Before | After |
|---|---:|---:|
| Full source listing | 0.845512 s | 0.408754 s |
| Full source detail | 0.205013 s | 0.164591 s |

A separate instrumented list run counted **48 statements before / 30 after**, including schema-version checks. Its three slowest old statements took 0.120471, 0.116363 and 0.116224 seconds; these were repeated record/hostname membership aggregates. Afterward the single shared aggregate took 0.380499 s; the next two statements took 0.000664 and 0.000472 s. Instrumented fetch timings are separate from the table above.

Plans retain necessary membership UNION/temp B-trees and existing batch/browser indexes. The new plan explicitly materializes `linked` once, then scans it for counts and ranked distinct hostnames. The old plan reconstructed membership repeatedly and searched evidence by primary/covering indexes. Significant plans are appended below. These measurements do **not** establish the exact improvement on the analyst's 2.59-million-record case.

The correctness fixtures separately cover duplicate browser ingestions, Chrome/Edge context separation, multiple batches for identical bytes, retrospective/ambiguous membership, conflicting hostnames, 101-host truncation and unassigned files. No inference from file hashes replaces browser occurrence membership.

### Progress

The existing 500 ms delayed operation indicator wraps source list/show and interactive mutation-preview retrieval, ending before output/selection/confirmation. The shared `progress` role colors the spinner cyan; the message uses `label`. Fast operations draw nothing. JSON, redirected output and noninteractive terminals remain animation-free. Existing cancellation, single-line ownership and frame-recording suppression are retained. No timeout or source-mutation confirmation changes.

## B. Case and source usability

- `case status`: case name, inventory, timestamp counts, attempt outcomes, recorded error total, source count and significant qualifications. Default rendering avoids raw parser exception messages and administrative source identifiers.
- `case status --details`: source IDs/assertions, hostnames, detailed Registry/companion caveats and recorded ingestion errors grouped by original stage and message. Error groups are bounded to 100 with an explicit JSON pointer for additional groups; source display retains its existing five-source bound. JSON retains all existing fields and values.
- Default human status avoids loading full ingestion error rows and their grouped diagnostic queries. Bounded hive warnings/dirty counts and source coverage remain necessary for caveats. It still calculates source coverage; this release does not claim the default status path is constant-time.
- Complete/partial/failed refer to stored ingestion **attempt** outcomes. Recorded errors count parser/ingestion diagnostics. A partial attempt can retain evidence; multiple diagnostics can occur in one attempt. Errors are not a count of lost records and historical diagnostics are not a newly failing CLI operation.
- Unknown source identity is stated plainly. Conflicting observations are not resolved by choosing a hostname. Registry recovery wording uses the actual dirty-hive count and does not claim each companion log belongs to those hives.
- `case list` shows names only. `--details` adds Location. Known registration problems remain warnings; root classification/discovery metadata remain in JSON. No database validation scan or case migration was added.
- `evidence source list` shows row number, readable name, retained files and evidence records. The exact application-generated label is presented as `Unnamed source`; stored names are untouched. `--ids` retains copyable canonical identifiers; JSON is unchanged. Existing limit/offset bounds and footer remain.
- `evidence source show` with no ID in the interactive shell lists a bounded page and accepts its number, N for the next page, or Enter to cancel. The local selection resolves to the exact canonical ID, rechecks that source and is discarded after the command. Invalid numbers fail explicitly; no hostname/name inference or implicit first-source selection. JSON/scripts require an exact ID. Mutations still require their existing exact IDs and confirmations.
- Default source detail shows counts by family, analyst-asserted hostname, observed hostnames and source limitations, using shared aligned fields. It requests `summary`, avoiding unused paginated histories. `--details`/JSON retain administrative IDs and history counts; complete paginated history payloads remain in JSON. Analyst assertions are not independently verified identities.

## C. Evidence presentation

Search warning consolidation keys the **exact message plus source hash, complete acquisition provenance and source context**. Unknown/truncated provenance prevents merging across records. Labels identify only the affected displayed row numbers. Distinct wording or provenance stays separate, and original record JSON is not changed. Existing artifact-specific warning handlers remain; the change targets the generic shared annotation path, including native MFT acquisition caveats. Human pagination quantities use thousands separators; IDs/timestamps/Event IDs do not.

Compact timeline rendering in `mixed_display.compact_timeline` consumes the existing retrieved/paginated groups. It shows exact UTC timestamp text (including submillisecond digits), artifact type and observation. Existing MFT/EVTX ID-and-exact-time grouping and other-artifact observation identity remain intact. No record is dropped to fit the table. Long observation cells may have explicit ellipses; `--details` uses existing verbose renderers, and JSON/raw retains original slots, timestamp meaning, source/host context and IDs. Warnings remain visible. Timeline grouping does not mean one original evidence record per row. The existing 10,000-observation grouped-text guard is unchanged; its error now suggests narrowing/filtering or JSON pagination.

EVTX descriptions use existing provider-qualified normalization/interpretation first. If no normalized mapping exists, `human_detail` shows `<original provider> — Event <original ID>`, or explicitly identifies missing provider/ID metadata. The same helper drives search, timeline and evidence detail. This identifies a record; it does not invent execution, maliciousness or causality. No normalization, stored observation or model contract changes.

## D. Analyst UTC shorthand

`cli_time.absolute_utc` parses analyst input into an aware UTC datetime for whole-second conversion and preserves the separately validated original fraction (up to nine digits). `LocardParser.parse_args` applies it only to the CLI's absolute start/end/since fields and timeline timestamp/around fields, **before** existing service validation and authorization. Date hints for time-only natural-language questions, durations, IDs, tokens, signed grants and imported/stored payloads are untouched.

| Input | Normalized CLI value |
|---|---|
| `2026-09-30` | `2026-09-30T00:00:00Z` |
| `2026-09-30T03` | `2026-09-30T03:00:00Z` |
| `2026-09-30T03:00` | `2026-09-30T03:00:00Z` |
| `2026-09-30T03:00:00` | `2026-09-30T03:00:00Z` |
| `2026-09-30T03:00Z` | `2026-09-30T03:00:00Z` |
| `2026-09-30T03:00-05:00` | `2026-09-30T08:00:00Z` |
| `2026-09-30T00:03` | `2026-09-30T00:03:00Z` |

Date-only end means midnight, never end-of-day. Missing timezone is UTC, never workstation time or DST adjustment. Bad calendar dates, clocks, offsets and excess fractional precision are rejected. Existing maximum windows, endpoint inclusivity and grant checks still execute on normalized timestamps. Direct forensic/service `utc_timestamp`/`required_time` behavior remains strict. Authorization receives the explicit normalized range, not an expanded inferred day.

## Validation and limitations

Provider-free focused runs (overlapping selections, not additive unique counts):

- Source history/browser context baseline: **3 passed, 4.71 s**.
- Source/presentation/time tests plus EVTX grouping/precision, bounded EVTX date filtering and investigation scope rejection: **67 passed, 7.81 s**.
- Additional original-EVTX fallback integration initially exposed a real column-sizing bug: the table sized the new fallback using old `Unmapped event` text. It now sizes the actual human observation. Targeted fallback + EVTX regression: **35 passed, 6.19 s**.
- Final new exploration tests plus prior case-list/status boundaries: **27 passed, 9.36 s**. Two stale assertions were adjusted for names-only case listing and explicit status details; evidence, source-history, JSON, database-dump and count assertions remain intact.
- Progress lifecycle tests passed in the focused selections, including nesting, redirected/JSON suppression and Ctrl+C/exception cleanup. Synthetic test setup errors were corrected (required ingestion-error schema fields); no production behavior was weakened to accommodate them.
- `git diff --check` passed. No full suite, provider requests or original-case inspection. No tests skipped in these selected runs.

Synthetic results do not validate real-terminal appearance, real-case elapsed times or analyst acceptance. Source aggregation still scans/materializes selected memberships and can require temporary SQLite resources; no cheap constant-time guarantee. Status's source coverage remains bounded by its existing list limit. Browser/source administrative history payloads remain bounded/paginated. CLI shorthand does not alter independently entered prompts outside CLI argument parsing. Older SQLite optimizer behavior can be slower when the materialization hint is unavailable.

Changed production areas: `database/sources`, `source_cli`, `interactive/sources`, CLI/parser/help metadata, `cli_time`, status/search/mixed timeline/presentation/layout, grouped-limit messages, terminal activity/role and `pyproject.toml`. Documentation and focused tests accompany them. Authorization, AI routing, findings, audit encodings and historical report/transcript contracts are unchanged.

## Manual Windows acceptance

After reviewing/committing in the development checkout and installing in the test checkout:

```powershell
.\.venv\Scripts\python.exe -m pip install -e .
.\.venv\Scripts\python.exe locard.py --version
.\.venv\Scripts\python.exe locard.py
```

Expected version: 6.149. In the shell, select your intended case and run:

```text
case list
case list --details
case list --json
case status
case status --details
case status --json
evidence source list
evidence source list --ids
evidence source list --limit 10 --offset 0
evidence source show
```

Choose a displayed number. For scriptable/detail inspection, substitute its actual ID:

```text
evidence source show <source-id>
evidence source show <source-id> --details
evidence source show <source-id> --json
evidence search --artifact mft --limit 3 --ids
evidence timeline --start 2026-09-30T13:30 --end 2026-09-30T13:33 --text
evidence timeline --start 2026-09-30T13:30 --end 2026-09-30T13:33 --text --details
evidence timeline --start 2026-09-30T13:30 --end 2026-09-30T13:33 --json
```

Those dates are input examples, not an assertion of evidence coverage. Use a relevant bounded interval for your case. Confirm shared acquisition notes identify only displayed rows, fallback labels preserve provider/ID, timestamps retain precision and JSON contains original provenance. Compare the offset equivalent of a UTC window to verify equal results. Press Ctrl+C during a slow human source query and verify the spinner clears. JSON deliberately shows no animation. Check plain mode and narrow terminal output. No provider request is needed for this acceptance.

## Significant measured plan steps

From the slowest statement in each instrumented run; numeric planner IDs and uninformative setup rows omitted.

### before

```sql
SELECT e.source_type,count(*) FROM evidence_records e
        JOIN (SELECT e.evidence_id,m.source_id FROM evidence_records e JOIN (SELECT b.source_id,r.file_sha256 FROM ingestion_batches b
    JOIN ingestion_runs r USING(batch_id) WHERE r.file_sha256 IS NOT NULL
    UNION SELECT a.source_id,f.file_sha256 FROM source_assignments a
    JOIN source_assignment_files f USING(assignment_id)) m USING(file_sha256) WHERE e.source_type<>'browser' UNION SELECT DISTINCT o.evidence_id,b.source_id FROM browser_record_occurrences o
 JOIN ingestion_runs r ON r.id=o.run_id JOIN ingestion_batches b USING(batch_id)) m USING(evidence_id) WHERE m.source_id=? GROUP BY e.source_type
```

```text
CO-ROUTINE m
MERGE (UNION)
CO-ROUTINE m
MERGE (UNION)
SCAN b
SEARCH r USING COVERING INDEX ingestion_batch_runs (batch_id=? AND file_sha256>?)
USE TEMP B-TREE FOR LAST TERM OF ORDER BY
SCAN a
SEARCH f USING COVERING INDEX sqlite_autoindex_source_assignment_files_1 (assignment_id=?)
USE TEMP B-TREE FOR LAST TERM OF ORDER BY
SCAN e USING INDEX sqlite_autoindex_evidence_records_1
SEARCH m USING AUTOMATIC PARTIAL COVERING INDEX (source_id=? AND file_sha256=?)
USE TEMP B-TREE FOR LAST TERM OF ORDER BY
SCAN o USING COVERING INDEX sqlite_autoindex_browser_record_occurrences_1
SEARCH r USING INTEGER PRIMARY KEY (rowid=?)
SEARCH b USING INDEX sqlite_autoindex_ingestion_batches_1 (batch_id=?)
USE TEMP B-TREE FOR DISTINCT
USE TEMP B-TREE FOR LAST TERM OF ORDER BY
SCAN e USING COVERING INDEX evidence_type
SEARCH m USING AUTOMATIC PARTIAL COVERING INDEX (source_id=? AND evidence_id=?)
```

### after

```sql
WITH linked AS MATERIALIZED (SELECT m.source_id,e.source_type,e.hostname FROM evidence_records e JOIN (SELECT e.evidence_id,m.source_id FROM evidence_records e JOIN (SELECT b.source_id,r.file_sha256 FROM ingestion_batches b
    JOIN ingestion_runs r USING(batch_id) WHERE r.file_sha256 IS NOT NULL
    UNION SELECT a.source_id,f.file_sha256 FROM source_assignments a
    JOIN source_assignment_files f USING(assignment_id)) m USING(file_sha256) WHERE e.source_type<>'browser' UNION SELECT DISTINCT o.evidence_id,b.source_id FROM browser_record_occurrences o
 JOIN ingestion_runs r ON r.id=o.run_id JOIN ingestion_batches b USING(batch_id)) m USING(evidence_id) WHERE m.source_id IN (?,?,?,?,?)), hosts AS (SELECT source_id,hostname,row_number() OVER (PARTITION BY source_id ORDER BY hostname) n FROM (SELECT DISTINCT source_id,hostname FROM linked WHERE hostname IS NOT NULL)) SELECT source_id,'artifact',source_type,count(*) FROM linked GROUP BY source_id,source_type UNION ALL SELECT source_id,'host',hostname,n FROM hosts WHERE n<=101 ORDER BY 1,2,4,3
```

```text
MERGE (UNION ALL)
MATERIALIZE linked
CO-ROUTINE m
MERGE (UNION)
CO-ROUTINE m
MERGE (UNION)
SCAN r USING COVERING INDEX ingestion_batch_runs
SEARCH b USING INDEX sqlite_autoindex_ingestion_batches_1 (batch_id=?)
USE TEMP B-TREE FOR ORDER BY
SCAN f
SEARCH a USING INDEX sqlite_autoindex_source_assignments_1 (assignment_id=?)
USE TEMP B-TREE FOR ORDER BY
SCAN e USING INDEX sqlite_autoindex_evidence_records_1
SEARCH m USING AUTOMATIC PARTIAL COVERING INDEX (file_sha256=?)
USE TEMP B-TREE FOR LAST TERM OF ORDER BY
SCAN o USING COVERING INDEX sqlite_autoindex_browser_record_occurrences_1
SEARCH r USING INTEGER PRIMARY KEY (rowid=?)
SEARCH b USING INDEX sqlite_autoindex_ingestion_batches_1 (batch_id=?)
USE TEMP B-TREE FOR DISTINCT
USE TEMP B-TREE FOR LAST TERM OF ORDER BY
SCAN e
SEARCH m USING AUTOMATIC PARTIAL COVERING INDEX (evidence_id=?)
SCAN linked
USE TEMP B-TREE FOR GROUP BY
USE TEMP B-TREE FOR ORDER BY
CO-ROUTINE hosts
CO-ROUTINE (subquery-10)
CO-ROUTINE (subquery-6)
SCAN linked
USE TEMP B-TREE FOR DISTINCT
SCAN (subquery-6)
USE TEMP B-TREE FOR ORDER BY
SCAN (subquery-10)
SCAN hosts
USE TEMP B-TREE FOR ORDER BY
```

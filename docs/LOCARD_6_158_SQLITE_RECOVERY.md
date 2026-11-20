# Locard 6.158 — Forensic SQLite snapshot recovery

Implementation and synthetic validation, 2026-11-18. Based on committed 6.157
(`6bc6a6d`); the changes described here are uncommitted. Manual acceptance is pending.

## Problem and eligibility

6.157 correctly refused an initial zero-magic, nonzero-content rollback journal:
that may be an unfinished pre-sync transaction. This observation does not prove
that the journal is hot or recoverable. **6.158 still rejects that initial state.**
This release adds recovery for a narrower, validated acquisition set, not a way
to force the reported Edge database to ingest.

| Acquired state | Behavior |
|---|---|
| No journal, empty journal, validated inactive PERSIST journal | Existing read-only validation and Browser extraction |
| Complete synchronized rollback journal | Validate geometry, complete page records and checksums; attempt SQLite rollback on a second copy |
| Multiple synchronized segments | Require consistent geometry and valid records throughout |
| Final unsynchronized segment after synchronized material | Accept only complete, checksummed original-page images identical to the current main-file pages; otherwise reject |
| Initial pre-sync/indeterminate header | Reject; do not infer safe recovery |
| Truncated records/database, bad checksum, duplicate/invalid page number | Reject before writable SQLite access |
| Super-journal references or unexpected tails | Unsupported; never follow external paths |
| Nonempty WAL/SHM alongside rollback recovery | Unsupported/conflicting; do not mix recovery modes |
| WAL-only acquisition | Existing WAL-aware private-copy validation; no new WAL recovery mechanism |
| Missing required companions, changing source, unsupported format | Fail closed with a recorded diagnostic |

The preflight implements format checks, **not rollback**. SQLite's own first
schema read performs rollback. No journal is deleted to bypass it. The derived
database must then pass read-only `integrity_check`.

Format references: [SQLite file format](https://www.sqlite.org/fileformat.html),
[hot-journal processing](https://www.sqlite.org/lockingv3.html), and
[copying databases safely](https://www.sqlite.org/howtocorrupt.html).

## Service and execution boundaries

`forensic_assistant/artifacts/sqlite_recovery.py` provides `inventory`, `acquire`,
`eligible`, `recover`, `recover_worker` and `release`. It returns structured data;
CLI parsing and Browser normalization remain outside it. Browser-specific identity
adaptation remains in `artifacts/browser.py::copy_snapshot`.

```text
source paths: regular-file/redirect checks → hashes and file identities
  → private acquisition copy → copy hashes + source recheck
  → supervised read-only SQLite validation
  → if eligible rollback is required: durable audit intent/start
  → pin unchanged acquisition → supervised recovery worker
  → second private working copy → SQLite-native rollback → integrity_check
  → verify derived identity → durable recovery completion
  → existing Browser extraction worker → verify derived hash and remove working set
  → required cleanup audit → existing source recheck/publication
```

Original files are never opened by SQLite. Recovery uses `mode=rw` only on the
fixed `sqlite-working/History` path. Acquired main/journal files remain pinned
against writes during recovery; their hashes are rechecked. Private directories
use existing ownership/DACL protection and directory guards. Source and companion
paths reject symlinks/reparse redirection, hard-link aliases and unsafe local paths.
Unexpected working companions prevent confirmed cleanup/publication.

SQLite validation runs in the existing contained worker with a 30-second limit;
recovery (including eligibility and second-copy work) has a 120-second parent
deadline. Existing worker memory containment is retained. Recovery staging is
limited to 8 GiB, with preflight copy-size and free-space checks (64 MiB headroom),
plus parent size monitoring. Journal inspection is bounded to one million pages.
These limits do not change MFT/EVTX timeout policy. Source hashing and first-copy
filesystem I/O remain parent-side operations: these are not a new end-to-end
deadline guarantee for arbitrary blocked filesystem I/O.

Cancellation and timeout use existing process containment. The outer ingestion
temporary-directory owner removes remaining acquired/working files after failures.
Successful derived-file removal is explicitly audited before publication. Worker
cleanup confirmation is distinct from proof of filesystem deletion; cleanup
exceptions are not silently treated as successful recovery.

## Consistency and provenance

Matching acquisition hashes, journal checksums and SQLite logical consistency do
**not** prove a coherent historical filesystem instant. The recorded limitation is:

> Source freeze was not established; stable copies and SQLite consistency do not prove a single filesystem instant.

This limitation accompanies recovered Browser records. Observable contradictions
fail closed. No historical acquisition assurance is inferred from SQLite opening.

Existing `artifact_runs.parameters_json` retains `sqlite-recovery-v1`:

| Group | Recorded information |
|---|---|
| Acquisition | Original main/companion sizes and hashes, path, device/inode/mtime identity, acquisition reference, source ID, batch and run |
| Transformation | Method, SQLite version, UTC start/end, validated geometry, outcome and validation method |
| Derived | Derived main hash/size, disposable-copy declaration, journal disposition, limitations |
| Lifecycle | Worker cleanup status and required cleanup audit event |

The source hash/size still describe the original database, not the recovered file.
Existing browser contexts and run-specific occurrences link records to that run.
Only recovered snapshot identity adds the versioned `sqlite-derived-context-v1`
input (original identity, journal identity, derived identity). This is necessary
because identical main bytes with different undo journals need not yield identical
records. Ordinary snapshot identity is unchanged. Identical recovered retries
deduplicate records while recording additional occurrences and attempts. No case
schema extension, new evidence source or historical rewrite is introduced.

Recovered databases are temporary and discarded after extraction. Durable
transformation metadata documents them; it is not a permanent recovered-file cache.

## Audit and presentation

Recovery requires an existing bound mandatory activity session. It records
`SQLITE_RECOVERY` intent/completion or failure and `SQLITE_RECOVERY_START`, followed
by `SQLITE_RECOVERY_CLEANUP` on successful removal. Existing ingestion auditing
records publication. Failure of mandatory intent, start, completion or cleanup
auditing prevents derived-record publication. Existing session rotation is reused.

`ingest/presentation.py::diagnostics` attaches a bounded preview of up to three
persisted errors; `v2_cli._ingest_sources` uses it for all artifact families.
Failed outcomes show `Reason` immediately after `Outcome`. Partial results show
bounded forensic limitations. Nonzero error counts and failure reasons use the
central red error role; limitations use brown. Full errors remain in case history.
JSON receives structured diagnostics, never presentation ANSI.

Diagnostic categories include `journal_active_or_hot` (recovery required),
`recovery_succeeded`, `recovery_unsupported`, `journal_indeterminate`,
`journal_malformed`, `journal_incomplete`, `missing_required_companion`,
`inconsistent_acquisition`, `snapshot_consistency_not_established`,
`sqlite_recovery_failed`, `derived_validation_failed`, `resource_limit`,
`recovery_cancelled` and `filesystem_io_failure`. Inactive acceptance is represented
by `sqlite_validation.rollback_journal=inactive`. Bounded exception classes/error
codes are retained where available; normal output does not print tracebacks.

## Validation and performance

Synthetic fixtures create real SQLite hot journals by terminating a separate
writer with an uncommitted spilling transaction. Tests verify rollback contents,
original/acquired hashes, derived provenance, visits/downloads/timestamps, repeated
ingestion/source reuse, preserved failed attempts, invalid journals/companions,
redirect refusal, audit failures, timeout/cancellation containment and presentation.
No real evidence, case databases, providers or original audit records were accessed.

Focused suites: `test_sqlite_recovery`, `test_browser_journal`,
`test_browser_parser`, `test_browser_safety`, `test_browser_integration`,
`test_browser_schema`, `test_ingestion_results`: **95 passed in 95.79 seconds**
after the last production edit. Selected audit reservation/rotation and Browser
discovery/private-copy/empty-case regressions: **7 passed in 32.93 seconds**.
`git diff --check` passed. No full regression suite is authorized or run.

Synthetic measurements on this Windows development environment (SQLite 3.53.1):

| Path | Measurement |
|---|---:|
| 6.157 normal copy/hash/inline validation, 958,464-byte DB, 50,001 visits | 0.0215 s median of three |
| 6.158 same normal acquisition with supervised validation | 0.8332 s median of three |
| Small hot-journal acquisition, audited recovery and validation | 1.6943 s |
| Hot fixture acquired DB + journal | 132,616 bytes |
| Acquisition + working-copy allocation upper bound | 265,232 bytes, excluding small control/audit files |
| Temporary bytes observed after rollback | 206,386 bytes, including control files |
| Derived DB | 73,728 bytes |

Normal ingestion makes no extra main-database copy for recovery. Its measured
~0.812-second overhead comes primarily from process startup for bounded validation.
Recovery requires the second copy and additional hashes. These small synthetic
measurements do not predict performance of a large real browser database.

## Manual Windows acceptance

After the analyst transfers the reviewed changes into the test checkout:

```powershell
Set-Location C:\tmp\locard260927\locard
.\.venv\Scripts\python.exe -m pip install -e .
.\.venv\Scripts\python.exe locard.py --version
.\.venv\Scripts\python.exe locard.py
```

Confirm version **6.158**. In the Locard shell:

```text
case open "D:\Locard\Cases\KFI-5070790-V2\case.db"
evidence ingest browser "E:\Users\sonita.haynes\AppData\Local\Microsoft\Edge\User Data\Default\History" --browser edge --profile Default --source src-d3c195d3068e4906a805082df44c1a57
case status --details
audit verify
```

Do not reingest other families. Verify their supplied baseline counts remain:
MFT 918,450; Registry 1,233,068; EVTX 490,032; Prefetch 337. Browser starts at zero,
total 2,641,887. Prior failures must remain, the source must be reused, and audit
verification must retain zero integrity failures. If recovery succeeds, inspect
the recorded original/derived transformation and limitations; an identical retry
must not add duplicate evidence records. If the initial pre-sync state persists,
an explicit failed attempt remains the correct result. Do not delete companions
or force writable access to the original database.

Manual acceptance remains necessary; no claim is made that this particular Edge
acquisition is recoverable. No commit or push was performed.

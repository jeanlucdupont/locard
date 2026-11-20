# Locard 6.159 — Best-effort Browser ingestion

Implemented 2026-11-19; synthetic validation only. Manual acceptance is pending.

## Change from 6.158

6.158 refused an initial zero-magic/nonzero rollback header even when the main
database might be readable. The 6.159 policy separates accessibility, consistency
and completeness: independently readable, safely normalized records may be retained
without asserting transactional consistency or complete Browser coverage.

Normal validated processing and eligible 6.158 hot-journal recovery remain first.
After an initial `journal_indeterminate`, `snapshot_consistency_not_established`,
`missing_required_companion` or `sqlite_validation_failed` refusal, the service may
prepare a second, main-file-only immutable copy. Invalid main headers, invalid page
geometry, resource failures and changed sources still fail. Malformed/incomplete
rollback-journal classifications remain outside this fallback. Failed hot-journal
recovery does not silently switch to main-file extraction.

## Paths and security

`artifacts/sqlite_recovery.py::_acquire` retains the original acquisition and routes
eligible fallback to `artifacts/sqlite_immutable.py::prepare`. The existing
supervised worker runs `prepare_worker` to create `sqlite-immutable/History` beneath
the protected private acquisition directory. Original companions remain acquired
and hashed; none is deleted to make SQLite open.

Only the second main-file copy is opened, using `mode=ro&immutable=1`, explicit URI
handling, extension loading disabled, trusted schema disabled and query-only mode.
SQLite 3.22 or later is required; there is no writable fallback. The parser also
uses a SELECT/READ-only SQLite authorizer. Source files are never SQLite inputs.

Immutable access bypasses SQLite locking and journal handling. It does **not**
replay rollback/WAL transactions or prove that the main file contains the latest
committed state. See [SQLite URI semantics](https://www.sqlite.org/uri.html).

Existing path/reparse/hard-link checks, protected directories and process containment
are retained. Preparation has a 120-second parent limit, a 10-second VM budget for
`quick_check(1)`, 8-GiB preparation staging checks and free-space headroom. Browser
parsing retains its existing worker timeout, memory and stage-size controls.
Acquisition hashing/copying remains parent-side filesystem I/O; this change does
not promise a hard timeout for an arbitrary blocked OS read.

The immutable working file is pinned during parsing, rehashed after extraction,
and removed before publication. Unexpected companions or modified bytes cause
cleanup/identity failure. The parent-owned temporary directory handles remaining
files after cancellation or failure. No new evidence schema is introduced.

## Structural checks and partial records

The main header must have a valid signature, supported page size and journal-mode
bytes, with an aligned physical file length. Declared/physical page-count mismatch
is recorded, not repaired. Trailing pages are not carved.

`quick_check` may pass, fail or be incomplete. Failed checks do not by themselves
discard independently readable tables; their status is retained. Full
`integrity_check` is recorded as not performed on the best-effort path. Existing
normal/recovery integrity validation remains unchanged.

`artifacts/browser_best_effort.py::parse` independently queries visits/URLs and
downloads, reusing `browser.pack` and `browser.timestamp`. It requires stable
primary row identity, rejects views/virtual tables and unsupported legacy download
epochs, checks required types and references, and bounds URL chains. A malformed
record produces a recorded rejection. A SQLite iteration error ends that query,
records incomplete coverage, and permits an independent supported query to run.
No page carving or resumption within a corrupt table is attempted.

URL tables are read for referenced visit/download rows, not exhaustively scanned
for orphan entries. Missing optional tables and unsupported/unreadable tables are
recorded distinctly. Counts do not estimate how many rows corruption concealed.

| Outcome | Meaning |
|---|---|
| Complete | Existing normal/recovered ingestion success criteria; not a claim of all historical Browser activity |
| Partial | Best-effort records or duplicates retained, regardless of a successful quick check; material uncertainty persists |
| Partial, empty-readable | Supported queries completed with no relevant records and no parse errors; explicit empty coverage, not fabricated evidence |
| Failed | No safely extracted records and extraction errors/unsupported required structure, or publication/audit conditions not satisfied |

## Provenance, audit and downstream access

`artifact_runs.parameters_json.extraction` stores the versioned
`browser-extraction-v1` object for best effort:

- Mode, journal classification and original normal-path refusal.
- Original path, file identities, main/companion hashes, source ID, batch/run and
  private acquisition reference.
- Main-only working-copy hash/size, SQLite version and preparation timestamps.
- Explicit `recovery_applied=false`, transaction/acquisition consistency not
  established, check results, page counts and limitations.
- Per-table/query coverage, extracted/rejected/staged counts, actual newly retained
  records, duplicates and errors. Empty-readable status is separate.

The working main hash equals the acquired main hash; no rollback transformation
is claimed. Best-effort Browser contexts use a versioned main-only identity so they
cannot collide with normal/WAL/recovered contexts. Within that mode identical main
bytes/profile/product deduplicate, even if an unused companion changes. Every run
still retains its own companion manifest. Existing normal and recovered identities
are unchanged; original source IDs and historical attempts are preserved.

Existing `database/browser.py::provenance` exposes this structured object through
each record's run occurrences. Consumers need not parse warning text. Record-level
warnings also identify main-only extraction and coverage uncertainty; this does not
label an individual event false.

Mandatory `SQLITE_IMMUTABLE_PREPARE` and `SQLITE_IMMUTABLE_EXTRACT` intent/completion
events bind the inputs, mode, validation and extraction counts. Required cleanup
recording and extraction completion precede case publication. Failure of these
audit operations blocks publication. Existing INGEST auditing records actual
publication counts and the selected mode. Existing transaction and session-rotation
contracts are retained. No raw browsing records are added to audit payloads.

## Presentation

The shared renderer shows `Extraction mode: Best-effort immutable`, an amber
Partial outcome, brown limitations and red nonzero error counts. Empty-readable
results have a separate coverage line. Failed attempts retain the immediate Reason
line. JSON includes `extraction_mode` and the structured best-effort extraction
object without ANSI styling. Normal/recovered validation metadata also records mode
and acquisition/transactional-consistency limitations.

## Validation

Synthetic tests exercise actual CLI parsing, ingestion service, private subprocess
execution and publication. Fixtures include normal/inactive/hot/WAL paths,
indeterminate journals, extra physical pages, corrupt download pages (failed
quick_check with valid visits), invalid row fields, missing tables, empty tables,
iteration failure, immutable open failure and mandatory audit failures. Tests also
cover repeated ingestion, ignored-companion changes, source identity, original
hashes, provenance retrieval, process timeout/cancellation and cleanup.

Focused Browser/recovery/journal/parser/safety/integration/presentation regressions:
**115 passed in 169.05 seconds**. Final mode, audit, best-effort and missing-WAL
integration checks: **15 passed in 61.42 seconds** (overlapping coverage, including
the additional missing-WAL case). Final pre-mode failure reporting was checked
separately. `git diff --check` passed. No full suite, real evidence ingestion,
provider requests, commit or push is part of this task.

## Manual Windows acceptance

After transferring the reviewed changes into the test checkout:

```powershell
Set-Location C:\tmp\locard260927\locard
.\.venv\Scripts\python.exe -m pip install -e .
.\.venv\Scripts\python.exe locard.py --version
.\.venv\Scripts\python.exe locard.py
```

Confirm **6.159**, then in the Locard shell:

```text
case open "D:\Locard\Cases\KFI-5070790-V2\case.db"
evidence ingest browser "E:\Users\sonita.haynes\AppData\Local\Microsoft\Edge\User Data\Default\History" --browser edge --profile Default --source src-d3c195d3068e4906a805082df44c1a57
case status --details
audit verify
```

Do not reingest other artifact families. Their supplied counts must remain MFT
918,450; Registry 1,233,068; EVTX 490,032; Prefetch 337. Historical Browser failures
must remain and the source must be reused. Readable best-effort output must be
Partial with explicit limitations. An identical retry must produce duplicates,
not new records. A failed extraction must give a reason rather than claim success.
There is no guarantee that the real database will be readable.

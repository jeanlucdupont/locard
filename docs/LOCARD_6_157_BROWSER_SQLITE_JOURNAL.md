# Locard 6.157 — Safe Browser SQLite rollback-journal handling

2026-11-18. Implementation baseline: `4fba8c3`, version 6.156. This is an
uncommitted 6.157 change awaiting manual acceptance. Version authority remains
`pyproject.toml`.

## Root cause and acquisition path

Previously, `artifacts/browser.py::inventory` rejected every nonempty
`History-journal`, including SQLite's normal retained, zero-header PERSIST
journals. A journal's existence alone does not prove corruption or pending recovery.

Guided discovery (`interactive/discovery.py`) identifies explicit Chromium profile
History candidates. Generic discovery uses the contained `browser_probe.check`
worker. Both probing and ingestion reuse `browser.copy_snapshot`. Ingestion
(`artifacts/ingest.py::ingest_artifact`) creates a private temporary directory,
copies the source set, invokes the existing browser worker, rechecks original
hashes, and publishes validated stage records transactionally.

Inventory still records SHA-256 and size for History, WAL, SHM and rollback journal.
It never connects SQLite to original evidence. Copying now retains the journal
alongside History and WAL in the private directory. Original SHM is hashed for
provenance; SQLite continues to rebuild its index only in the private directory.
Each copied file is checked against the initial hash; the original inventory is
checked again after copying and after parsing. Symlink/regular-file and per-file
8 GiB checks remain. No new database copy or persistent cache is introduced.

## State handling

`artifacts/browser_journal.py::validate` runs only on the acquired private copy.

| Acquired state | Decision |
|---|---|
| No journal | Validate the database and applicable WAL; ordinary absence-of-WAL limitation remains |
| Empty journal | Preserve it, record `empty`, validate database/WAL |
| Canonical inactive journal | Accept only with all checks below; preserve bytes and provenance |
| Valid nonzero rollback magic and compatible geometry | Reject `journal_active_or_hot`; no recovery |
| Truncated header/sector | Reject `journal_incomplete` |
| Invalid nonzero header or incompatible geometry | Reject `journal_malformed` |
| Zero magic but nonzero remaining header | Reject `journal_indeterminate`; may be an unfinished pre-sync transaction |
| Small zero-filled file | Reject `journal_indeterminate`; size/zero bytes alone are insufficient |
| Rollback/WAL-mode conflict or changed file set | Reject `snapshot_consistency_not_established` |
| WAL-mode SHM without nonempty WAL | Reject `missing_required_companion` |
| Invalid SQLite/integrity check or validation deadline | Reject `sqlite_validation_failed` |

Inactive acceptance requires **all** of:

1. Stable before/copy/after acquisition hashes, including the journal and original SHM.
2. A journal larger than 512 bytes with the complete first 28 bytes zeroed,
   compatible with SQLite's PERSIST invalidation convention.
3. Main database read/write version bytes both identifying rollback mode; no
   nonempty WAL mixed into this set.
4. Valid SQLite header and page size, matching change-counter/version-valid-for
   fields, nonzero header page count, and exact file length matching that count.
5. Successful `PRAGMA integrity_check(1)` through a private `mode=ro` connection,
   with extensions disabled, trusted schema off and query-only enabled.
6. Existing supported browser schema and record validation during parsing.

PERSIST is connection configuration, not a persistent label that can be recovered
reliably from the main header. Locard describes an inactive journal compatible
with that convention; it does not claim to know the original connection settings.
Old journal payload is preserved, not interpreted as current evidence or replayed.

Original locks and super-journal state are not acquired. A valid nonzero header is
therefore classified **active or hot**, not asserted to be definitely hot.
Locard does not open it for recovery, delete it, repair it, or attempt a second
connection in writable mode. Super-journal-dependent cases remain unsupported.

WAL validation checks mode, header/version/page size, frame geometry and header
checksum. SQLite retains authority over committed WAL frame visibility; there is
no new WAL carving/recovery engine. WAL-mode main files without WAL/SHM can be
fully checkpointed and are not automatically rejected. Absence of an unprovided
WAL cannot prove that uncheckpointed activity never existed.

**A valid standalone database does not prove historical point-in-time coherence
of independently supplied companions.** Stable hashes establish the bytes copied,
not authenticity or acquisition history. The accepted inactive journal has no
applicable undo state under the supported convention; original file membership
and this limitation remain recorded. Arbitrarily mismatched but structurally valid
files cannot always be detected from SQLite bytes alone. An uncertain or failed
set must be consistently reacquired by the analyst, not repaired by this release.

SQLite semantics: [rollback journals and commit invalidation](https://www.sqlite.org/fileformat2.html),
[hot-journal conditions](https://www.sqlite.org/lockingv3.html),
[journal modes](https://www.sqlite.org/pragma.html#pragma_journal_mode).

## Diagnostics and forensic contracts

`SnapshotError` uses bounded category/reason text with artifact `browser`,
`recovery_performed=false`, and the acquired companion hash/size manifest.
Existing `artifact_errors.locator_json` and ingestion history persist it without
a schema change. No raw journal bytes, SQLite error payload or arbitrary source
contents are included. Successful acquisition adds `sqlite_validation` to existing
run parameters. Inactive-journal records carry a concise forensic note and the
acquisition limitation through existing warning/JSON presentation.

Snapshot identity is still computed from History and WAL only. Inactive journal
and SHM hashes remain provenance, not a new evidence-ID ingredient. Product,
profile, source bindings, browser occurrences, timestamp units/precision, record
normalization and duplicate handling are unchanged. Each retry creates a new run;
failed attempts remain intact. Existing context manifests preserve first-seen
context provenance, and each new run's parameters retain its own complete manifest.

No MFT, worker-timeout, publication, audit, AI, case-schema or time-zone behavior
was changed. Source time zone remains analyst-supplied metadata.

## Validation and performance

All tests use disposable SQLite files and synthetic records; no real case,
browser files, evidence volume or provider was accessed. Tests cover actual
PERSIST transactions; an abandoned hot journal produced by an exiting SQLite
writer; empty/absent/malformed/incomplete/pre-sync journals; mismatched database
counters and size; SQLite corruption; valid/missing/invalid WAL; unchanged source
bytes/hashes; read-only source attributes on Windows; private-only SQLite
connections; copy-time source changes; validation interruption; journal provenance;
retained failed attempts; deduplicated retries; timestamps, JSON, sources and audit.

One pre-existing integration assertion expected unaligned single-space status
labels. It was reproduced using the committed browser module and corrected only
for whitespace; exact counts remain asserted. Four browser UX tests invoked
removed top-level commands. Their invocations/completion prefix now use the
existing `evidence` command family; forensic, persistence, authorization and JSON
assertions were retained. No production CLI change was made.

Recorded final focused results:

- `pytest tests/test_browser_journal.py tests/test_browser_parser.py tests/test_browser_safety.py tests/test_browser_integration.py tests/test_browser_schema.py tests/test_browser_ux.py -q --tb=short -p no:cacheprovider --basetemp <fresh-temp>`:
  **68 passed in 67.80 seconds**.
- Four corrected browser UX tests plus audit rotation linkage, nested durable
  intent/completion and completion reservation tests: **7 passed, 43 deselected
  in 40.32 seconds**. The four UX tests also appear in the final browser run;
  there are **71 distinct passing tests** across these final sets.
- `git diff --check`: passed. No full-suite run.

Changed production files: `artifacts/browser.py`, new `artifacts/browser_journal.py`,
and `pyproject.toml`. Test files: new `tests/test_browser_journal.py`,
`tests/test_browser_integration.py`, `tests/test_browser_ux.py`. This document and
its `.gitignore` allowlist entry complete the change set.

Synthetic timing on this Windows host, 50,001 visit rows and a 958,464-byte
database (five runs each, median): previous copy/hash path **0.013228 s**;
corrected copy/hash/validation path **0.019808 s**, an additional **6.58 ms**.
This is a small-fixture measurement, not a large-browser throughput claim.
Journal-bearing acquisition additionally copies and hashes the journal once;
it does not add another main-database copy or additional main-file hash pass.

Header checks are fixed-size reads. SQLite integrity validation adds a database
scan, capped cooperatively at 30 seconds via a VM progress handler, a 200 ms lock
timeout, a single integrity error result and the existing 16 MiB value limit.
Slow/corrupt databases fail closed. This is not an OS-level deadline for blocked
filesystem I/O; existing acquisition copying/hashing and worker supervision remain
unchanged. Large real-browser performance and manual acceptance remain unmeasured.

## Exact Windows acceptance: Browser only

After the analyst transfers the development changes into the separate checkout:

```powershell
Set-Location C:\tmp\locard260927\locard
.\.venv\Scripts\python.exe -m pip install -e .
.\.venv\Scripts\python.exe locard.py --version
.\.venv\Scripts\python.exe locard.py
```

Confirm **6.157**. Then, in the Locard shell:

```text
case open "D:\Locard\Cases\KFI-5070790-V2\case.db"
case status --details
evidence source show src-d3c195d3068e4906a805082df44c1a57 --details --json
evidence ingest browser "E:\Users\sonita.haynes\AppData\Local\Microsoft\Edge\User Data\Default\History" --browser edge --profile Default --source src-d3c195d3068e4906a805082df44c1a57
case status --details
evidence source show src-d3c195d3068e4906a805082df44c1a57 --details --json
```

Verify the supplied source ID and current E: mapping before running. This explicit
file command retries only Edge Default History. Do not run guided all-artifact
ingestion or recreate the source. Confirm the earlier failed Browser run remains,
the new attempt's status and companion metadata, browser records and exact profile,
and any inactive-journal warning. Repeating an unchanged successful snapshot should
add occurrences/history while retaining normal evidence deduplication.

If the acquired set is still active, malformed or indeterminate, rejection is the
expected safe result. Preserve diagnostics and acquire a consistent set separately;
do not delete journals or request automatic recovery. No manual retry was executed
during development. No full suite, commit or push was performed.

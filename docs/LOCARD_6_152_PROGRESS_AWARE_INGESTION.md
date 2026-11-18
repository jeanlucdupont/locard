# Progress-aware MFT ingestion

Implementation date: 2026-11-17. Baseline: `40b43d8` (6.151). Changes are uncommitted; application version is resolved from `pyproject.toml` (6.152).

## Failure mechanism and scope

Previously `artifacts/ingest.worker` applied `now - started > timeout` to the entire MFT subprocess, defaulting to 300 seconds. Actual advancement could not extend this limit. Native acquisition had already finished before the worker started. This explains the reported timeout category; no real source or case was opened to establish its last parser operation.

`artifacts/native_mft.ingest` still performs read-only acquisition to owned temporary storage, then calls `ingest_artifact`. Source hashing precedes worker launch. The worker stages records, reconstructs paths and commits its private database. After successful worker completion, the parent checks source integrity and publishes through the existing transaction. Acquisition, hashing and parent publication are **not** included in the worker deadlines. This release does not add supervision around those operations or redesign their cancellation.

## Policy matrix

| Family / boundary | Startup | Without advancement | Absolute limit | Change |
|---|---|---|---|---|
| MFT, native or supplied file | 60 seconds, until initialized worker enters parsing | 900 seconds | 21,600 seconds (6 hours) | New |
| EVTX | Included in existing stall clock | 300 seconds; verified parser position | 21,600 seconds | Unchanged |
| Registry | Included in absolute clock | None | 300 seconds | Unchanged |
| Prefetch | Included in absolute clock | None | 300 seconds | Unchanged |
| Browser parser | Included in absolute clock; snapshot preparation separate | None | 300 seconds | Unchanged |

MFT `--parser-timeout` now means inactivity, range 1..3600. `--mft-startup-timeout` accepts 1..300; `--mft-hard-timeout` accepts 1..86400. Explicit short values can deliberately terminate valid work. The emergency ceiling is independent and progress cannot extend it. Startup and emergency clocks begin before process creation; an OS-blocked process-creation call itself cannot be interrupted by this polling loop.

CLI, native and guided MFT defaults are identical. Other families keep 300-second defaults; explicit `--parser-timeout` on mixed ingestion applies the selected value with each family's documented meaning. The earlier one-shot `LOCARD_GUIDED_MFT_PARSER_TIMEOUT=3600` override remains supported, but now extends MFT **inactivity**, not overall runtime. It is consumed by one guided execution and leaves other families unchanged.

Registry native library operations and post-processing, Prefetch's opaque single-file parse, and Browser snapshot/query operations lack complete reliable long-phase signals. Extending their deadlines based on partial instrumentation would mask hangs. Their fixed deadlines remain a documented limitation. EVTX retains its existing progress protocol, partial-record accounting and separate ceiling.

## Signals and phases

`artifacts/progress.py` supplies a versioned ephemeral JSON snapshot (`mft-progress-v1`), never evidence or publication authority. Worker snapshots are atomically replaced in the private stage directory. Maximum read/frame size is 1,024 bytes; duplicate fields, invalid schema, decreasing counters, phase regression, oversized input positions and redirected/aliased snapshots are rejected. There is no new thread, heartbeat or unbounded message queue. Parent polling remains every 250 ms; normal snapshot updates are coalesced to one per second, with immediate phase transitions.

| Phase | Meaningful advancement | Bound |
|---|---|---|
| initialization | Worker setup reaches parsing | Startup limit |
| parsing | Completed input slots and corresponding bytes, including invalid/empty slots | Inactivity + emergency |
| staging | Entry after parsing; buffered writes complete before reconstruction starts | Inactivity + emergency |
| reconstruction | Completed name/path entries, after existing updates | Inactivity + emergency |
| finalizing | Entry before final commit; completion only after database closure | Inactivity + emergency |
| complete | Successful private worker result ready | Existing parent integrity/publication checks |

Record-slot counts are not retained-evidence counts. Reconstruction counts are processed name entries, not unique files or necessarily resolved paths. Counter collection adds no SQL. Unchanged counters, process liveness and stage-file growth do not renew the clock. Finite forward phase transitions renew it; opaque flush/commit operations must finish within the configured inactivity interval. No record count is invented while SQLite is busy.

Timer checks occur before accepting new progress; a late report cannot revive an expired worker. A successful process exit also requires the final complete snapshot. Per-record parse errors retain their existing partial-result semantics; timeout, communication failure and unfinished reconstruction cannot authorize publication.

## Containment, diagnostics and audit

Existing memory limits, parent permission handshake, job/process containment, stage-size cap (8 GiB), output caps, free-space checks and cleanup remain active. Timeout/cancellation rejects the private MFT stage; prior committed runs remain intact. Ctrl+C uses the existing interruption path. Unconfirmed cleanup stays fatal rather than being described as success.

`artifact_runs.parameters_json` records the effective supervision policy. Failure metadata in `artifact_errors.locator_json`, linked to the existing source/run, includes available phase, previous observed completed phase, elapsed/idle time, last observed advancement UTC, slot/byte/path counters, termination code and process-cleanup status. Categories include startup timeout/failure, progress inactivity, emergency ceiling, worker crash, parser exception, progress communication, resource limit, cancellation and cleanup failure. Generic parent failures include a sanitized exception class. Raw child output is not included in routine MFT failure messages. Missing information is not invented; cleanup failure can have fewer phase details. TemporaryDirectory owns stage and acquisition deletion; tests verify removal, separately from the recorded process-cleanup status.

No audit contracts, rotation limits or hash-chain formats changed. Existing INGEST intent/completion and interruption records remain. Guided progress uses FileProgress; direct MFT ingestion uses the existing ActivityIndicator. MFT progress uses cyan's semantic `progress` role, reports phase/count/elapsed time, and does not create a new spinner. Known file-count percentages retain their old meaning; no parsing percentage is invented. Repaints remain excluded from session capture. JSON/noninteractive scripted output has no new animation; guided redirected output retains its compact completed-file updates. No worker internals or source paths are added to ordinary progress text.

## Validation and performance

Synthetic only; no provider, real evidence, case database or original audit/transcript accessed.

- Broad focused MFT/staging/native/observation/audit subset: **96 passed, 4 deselected, 73.08 s**. Exclusions were CLI-labelled tests, not a full-suite run.
- After final startup/cleanup and fallback creation-path changes: **60 passed, 3 deselected, 13.43 s** across progress, guided timeout, observation and native MFT tests. Exclusions are old CLI presentation tests outside this change.
- New tests exercise simulated healthy operation beyond 300 seconds, reconstruction advancement, unchanged counters, startup/inactivity/emergency expiry, malformed and nonmonotonic IPC, crashes, exit without completion, resource cap, sanitized startup failure and fatal cleanup failure.
- Actual synthetic worker hangs during reconstruction are terminated on inactivity and Ctrl+C. Child exit, temporary-stage removal, zero publication and unchanged source bytes are checked.
- Existing MFT regressions cover successful publication, SI/FN timestamps, IDs, reconstructed paths, raw values, duplicate ingestion and source-change rejection. Native fixtures cover acquisition provenance and read-only access flags. Guided tests check default isolation and one-shot override consumption.
- Final presentation/audit and parser-command checks: **13 passed in 5.18 s**. Both Prefetch and MFT repaint suppression retained durable outcomes and verifiable audit records. A separate canonical CLI synthetic ingestion JSON check: **1 passed in 4.71 s**. These sets overlap; counts must not be summed as unique tests.
- `git diff --check`: passed. Full regression suite intentionally not run.

Bounded in-process benchmark: 1,024 synthetic MFT records, three alternating baseline `_run` and instrumented `run` executions. Baseline seconds: 1.187394, 1.067893, 1.233503. Instrumented: 1.146652, 1.376088, 1.097314. Medians 1.187394 vs 1.146652 (about 3.4% lower, ordinary measurement noise; not a speedup claim). All timestamp, object and reconstructed-name rows matched exactly. The three instrumented runs wrote 15 bounded snapshots total. No measurable material slowdown in this small workload; this does not establish large-volume performance or validate the proposed defaults against the real case.

## Manual acceptance and safe retry

These commands are for the analyst; they were not executed against the case. Use the intended test checkout and its installed environment. Install as usual, then verify:

```powershell
.\.venv\Scripts\python.exe locard.py --version
.\.venv\Scripts\python.exe locard.py --db 'D:\Locard\Cases\KFI-5070790\case.db' evidence source list --ids
.\.venv\Scripts\python.exe locard.py --db 'D:\Locard\Cases\KFI-5070790\case.db' audit verify
```

Confirm version 6.152. Review the source identity corresponding to the earlier mounted volume and record the inventory before retrying. Do not create another source implicitly. Substitute its **exact** ID:

```powershell
$sourceId = '<existing source ID from evidence source list --ids>'
.\.venv\Scripts\python.exe locard.py --db 'D:\Locard\Cases\KFI-5070790\case.db' evidence source show $sourceId --details
.\.venv\Scripts\python.exe locard.py --db 'D:\Locard\Cases\KFI-5070790\case.db' evidence ingest mft E: --source $sourceId --parser-timeout 900 --mft-startup-timeout 60 --mft-hard-timeout 21600
.\.venv\Scripts\python.exe locard.py --db 'D:\Locard\Cases\KFI-5070790\case.db' evidence source show $sourceId --details --json
.\.venv\Scripts\python.exe locard.py --db 'D:\Locard\Cases\KFI-5070790\case.db' audit verify
```

Review final ingestion status, inserted/duplicate/error counts and source run history; retain the original failed run. Review inventory through `case status` before and after. Existing Registry 1,233,068 and Prefetch 221 are user-reported baseline counts, not counts verified during this implementation. The command retries **only MFT** and preserves earlier evidence and failed history. Existing hash/ID deduplication prevents duplicate identical records; it does not merge changed evidence into older records.

Native acquisition uses a new temporary derived artifact and does not overwrite an original acquisition. A live E: volume may produce different bytes and evidence IDs on reacquisition. If an independently preserved acquired MFT is available and is the intended retry source, substitute its exact quoted file path for `E:`; do not overwrite that artifact. A different hash must not be presented as byte-identical to the previous acquisition. Ensure sufficient temporary and case storage outside E: and the normal read-only native acquisition privileges. Do not retry automatically or raise limits without reviewing any recorded stall phase.

Acceptance remains pending: observe advancement during a real long run, successful reconstruction/publication, final retained counts and audit verification. No full suite, commit or push was performed for this implementation.

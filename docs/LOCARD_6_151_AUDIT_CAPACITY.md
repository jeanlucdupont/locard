# Locard 6.151 — Bounded audit rotation for long ingestion

Implemented against 6.150 (`5eac508`), November 17, 2026. Manual acceptance is
pending. `pyproject.toml` remains the application-version authority.

## Root cause and diagnostic boundary

The former recorder admitted mutations without reserving their completion capture.
Its fixed 2 MiB segment could fill after SQLite publication but before required
completion auditing. The earlier synthetic diagnostic completed 378 file operations
and failed on operation 379 with 2,030,835 persisted session bytes. The exception
chain ended in `Session size limit reached` and reproduced both reported messages.
This proves a capacity defect; it does **not** establish the historical cause in
case KFI-5070790. That case and its original records were not accessed here.

The MFT parser's cumulative timeout is a separate issue. No worker timeout, parser,
normalization, source provenance, database transaction or publication code changes
are part of this release.

## Recording and integrity contract

New recordings use `session-record-v2`. Activity JSONL remains audit version 1.
Historical `session-record-v1` files and anchors remain readable and are never
rewritten. The session-review rows still identify individual recording files;
the added logical/chain identifiers let callers associate those segments.

| Identity or link | Meaning |
|---|---|
| `application_session_id` | One logical application execution; unchanged across rotation and case switches. |
| `chain_id` | One recording attachment to a case/application destination. A case switch closes this chain and starts another, retaining the logical application identity. |
| `segment_index` | Zero-based contiguous position in that attachment's chain. |
| `session_id` / `recording_id` | Unique physical segment identity and filename, as in historical review APIs. |
| `previous_segment` | Exact prior segment ID, terminal sequence, hash and byte count, or null for index zero. |
| `next_segment` | Successor ID committed in the prior segment's rotation seal and its activity anchor. |
| `operation_id` | Existing command correlation retained across segments; activity references also retain the mutation's operation ID. |

Every new event carries the immutable segment binding. Activity anchors commit the
same binding, terminal prefix hash/sequence/byte count, case binding and successor.

Rotation lifecycle:

1. Flush pending segment events durably.
2. Allocate the next exclusive, bounded file under directory quota admission.
3. Append a `session_end` rotation seal naming the successor and anchor it in the
   activity chain.
4. Start the successor with the exact previous terminal commitment, same logical
   identity/chain, and next index.
5. Durably anchor its start before admitting further work.

The two files are not atomically published together. A crash between these steps
leaves a detectable missing/unverified successor, not a manufactured successful
handoff. Interrupted rotation breaks the current recorder and blocks new required
actions. No automatic recovery or repair rewrites that history.

Verification checks per-file hashes and sequence, stable segment bindings,
reciprocal links, indices, logical/case identity and activity-anchor ordering.
A historical successor promise cannot be erased by a later anchor. Events or
anchors after a segment seal are invalid. Missing/corrupted/reordered files fail
verification; a valid unfinished tail remains incomplete. `linked_integrity`
describes the checked chain separately from each segment's completion.

Verification is provider-free and does not open the forensic database. File review
remains bounded and segment-addressed. A valid hash chain proves recorded integrity,
not truth of forensic assertions or completion of an operation lacking a completion
record. Concurrent changes during verification require a retry rather than a
success based on mixed snapshots. A `corrupt` linked-chain result can indicate
inconsistent/missing dependencies; it does not by itself establish malicious byte
alteration. Inspect its per-segment limitations and missing/unverifiable successor.

## Capacity reservation and durable mutations

`activity.mutation` obtains a **128 KiB reservation per active mutation** before its
durable intent. Nested mutations hold separate reservations. This conservative
allowance covers bounded pending stdout/stderr capture, required audit checks,
completion/failure references and their serialization overhead. The existing
64 KiB terminal reserve remains separate.

Ordinary events cannot spend held completion capacity. Only the completing thread
may spend its own reservation; another thread or nested operation cannot borrow it.
The reservation remains held until the durable completion/failure path finishes.
If the current segment cannot accommodate admission, it rotates first. Excessive
nesting that cannot fit a fresh segment is refused before the nested mutation.

Required activity references are flushed and checkpointed before a successful
required record returns. No mandatory event is deleted to free space. Optional
capture retains the existing explicit payload/output limits and gap records.

This does **not** make SQLite publication and audit files one transaction. I/O or
quota failures remain possible during an operation. The application does not undo
already-committed evidence to disguise an audit failure.

| Outcome | Behavior |
|---|---|
| Admission/intent fails | Action refused before execution; body is not entered. |
| Body returns and required completion succeeds | Action completed and audited. |
| Body returns but completion fails | Explicit completed-action/audit-failure message and `completed_audit_failed`; inspect authoritative provenance before retrying. |
| Body raises and failure auditing also fails | Explicit `unknown` outcome; partial commits cannot be inferred away. |
| Cancellation with functioning audit | Existing cancelled result is durably recorded, then cancellation propagates. |

A recorded intent establishes admission and intended work. It is not evidence
that execution started, finished, committed, or rolled back. Likewise, a completed
ingestion action can have a failed/partial forensic result; inspect its recorded
status and counts.

## Storage and performance policy

The limits remain:

- 2 MiB per physical segment; 64 KiB terminal reserve.
- 64 KiB captured output per existing operation boundary; rotation does not reset it.
- 100 MiB per recording directory and 1,000 directory entries.
- Existing bounded event payloads and activity entry limits.

Directory admission is serialized with the activity-file lock. Closed segments
are charged at actual size; unfinished or empty segments reserve a full segment
envelope. This prevents concurrent sessions from overcommitting remaining quota.
It is deliberately conservative: abandoned incomplete segments retain reserved
capacity. They are not silently deleted or reclassified. Many simultaneous
unfinished segments can exhaust admission before physical bytes reach 100 MiB.

Directory scanning occurs only at attachment/rotation. Normal events retain
bounded buffering and tail-based appends; there is no per-event historical rehash,
new background writer or weakened fsync requirement. Full chain verification is
an explicit review operation.

## Ingestion capture and diagnostics

`FileProgress` frame writes and clears now use `session_recording.suspended`, the
same capture policy as the delayed activity spinner. The suppression is entered
inside the rendering thread. Redirected periodic summaries, final family summaries,
errors, warnings, durable ingestion intent/completion, source IDs, artifact family,
counts and cancellation outcomes remain recorded. Animation does not consume the
output allowance or create capture-gap records.

Bounded reason codes distinguish session capacity, rotation failure/interruption,
directory quota, permissions, file identity, lock timeout and write/flush/fsync
failure. Failure markers retain the exception class, segment byte accounting,
and underlying rotation reason/class where available. These fields contain no
provider payloads, credentials or evidence text. If the independent activity
channel also fails, the visible warning remains; no successful diagnostic write
is claimed.

The old nested `action not authorized` phrase is removed from the generic recorder
failure. Mutation admission and post-action completion failures have separate
messages and structured outcome codes. No approval requirement is bypassed.

## Validation

Final focused selection: **126 passed, 2 deselected in 172.53 seconds**. The two
excluded tests were the separately executed long durability workload and hard-link
test. After the final sanitized-message change, its focused failure-path subset
passed **7 tests in 10.06 seconds** (overlapping checks, not seven additional unique
tests). No full suite or live provider requests were run. All test evidence,
session files and tamper fixtures are disposable. `git diff --check` passed.

```powershell
.\.venv\Scripts\python.exe -m pytest -q -p no:cacheprovider `
  tests/test_session_rotation.py tests/test_session_recording.py tests/test_activity.py `
  tests/test_guided_feedback.py tests/test_terminal_activity.py `
  tests/test_activity_integrations.py::test_discovery_activity_stops_before_next_prompt `
  tests/test_activity_integrations.py::test_discovery_and_file_progress_never_overlap `
  -k 'not 400_real and not hardlink_audit_alias'
```

The full 400-operation audit workload passed separately in **547.51 seconds**:

| Measurement | Result |
|---|---:|
| File operations | 400 |
| Nested mutation identities | 800 |
| Mandatory intent/completion events | 1,600, exactly paired |
| Recording segments | 2 |
| Rotations | 1 |
| Persisted session bytes | 3,206,107 total; each segment below 2 MiB |
| Timed workload including close | 527.891 seconds |
| Time inside rotation | 0.281 seconds |
| Verification | Passed |
| Synthetic case database byte comparison | Unchanged |

```powershell
.\.venv\Scripts\python.exe -m pytest -q -s -p no:cacheprovider `
  tests/test_session_rotation.py::test_400_real_durable_operations_rotate_without_evidence_mutation
```

These are real fsync-backed audit writes, not a parsing-throughput benchmark. Other
focused tests ran concurrently. Rotation itself was approximately 0.053% of the
timed workload; this does not establish the total release overhead relative to the
old recorder. Immediate durable completion references add writes, and v2 metadata
adds bytes. There was no controlled before/after throughput comparison. The old
diagnostic stopped at operation 379; this run passed that point without increasing
the segment limit or disabling admission/durability.

Coverage includes linked sequence integrity, reservation/nesting, missing and
altered segments, erased-successor promises, interrupted rotation, Ctrl+C, case
switching, old-format complete/incomplete histories, quota admission, permissions,
lock timeout, fsync failure, spinner exclusion, retained outcomes, post-commit audit
failure and original-database byte equality. A 400-file synthetic workload uses
the real mandatory checks and durable writes; it does not disable fsync or bypass
audit admission.

Two old tests asserted obsolete audit-summary spacing/capitalization. Only those
presentation expectations were aligned with the committed UI. The hard-link
security test required an unsandboxed disposable workspace directory because the
sandbox denied hard-link creation; its security assertion was not weakened.
That test passed: **1 passed in 0.38 seconds**. The first unsandboxed attempt was
blocked by the shared pytest temporary directory's permissions, so the passing run
used a new disposable workspace directory without altering any ACL.

An exploratory broader UI selection returned **125 passed, 5 failed, 1 error,
2 deselected**. All six problems were in unchanged `test_activity_integrations.py`
or its `test_dump.py` fixture: three advisory tests and the inventory fake conflicted
with existing spinner construction/wording, and two paths used retired top-level
`ingest`/`investigate-ai` commands. These unrelated tests remain unchanged and are
reported, not counted as passes. The focused selection above retains the applicable
discovery/ingestion-spinner integration checks. No production behavior was restored
to satisfy those obsolete expectations.

## Changed files

- `forensic_assistant/session_recording.py`: v2 segments, quota admission,
  reservations, linking, verification and reason codes.
- `forensic_assistant/activity.py`: reservation-aware mutation lifecycle, durable
  required references and sanitized failure outcomes.
- `forensic_assistant/interactive/setup_display.py`: repaint suppression only.
- `pyproject.toml`: the single version increment, 6.150 to 6.151.
- `tests/test_session_rotation.py`: new synthetic and durability regressions.
- `tests/test_session_recording.py`, `tests/test_activity.py`: two stale audit-summary
  presentation assertions, preserving the existing integrity assertions.
- This document and `.gitignore`: technical report and documentation allowlist.

## Manual Windows acceptance

Install the reviewed checkout using your normal workflow, then:

```powershell
.\.venv\Scripts\python.exe locard.py --version
.\.venv\Scripts\python.exe locard.py
```

Expect 6.151. Use a **disposable acceptance case** and approved test artifacts for
the first long ingestion. Keep its database/temp/audit storage off the evidence
source volume. Do not use KFI-5070790 as the implementation test fixture.

In the shell:

```text
evidence ingest prefetch <approved-test-directory>
audit verify --json
audit sessions --json
audit session show <recording-id> --json --limit 1000
audit activity --json --limit 1000
case status --json
```

Replace placeholders with actual acceptance paths/IDs. For hundreds of files,
expect multiple segment IDs sharing the same logical application/chain identity,
contiguous indices, verified reciprocal links and no quota failure merely because
one segment filled. An active tail is incomplete until clean shutdown. Restart
and verify again after exit. Inspect each segment by its recording ID; `latest`
selects one segment, not every event in the logical session.

Confirm that animation frames are absent from session output while file outcomes
and final counts remain. Repeat cancellation on a disposable ingestion and verify
that the result is honestly recorded. Do not simulate corruption, permission or
disk failures against existing forensic cases; automated fixtures cover those paths.

## Safe reconciliation of the existing partial case

1. Preserve the existing case and its audit files, including the incomplete session.
   Do not remove, regenerate, or mark that session complete.
2. Review its durable `INGEST` and `INGEST_BATCH` intents and completions by operation
   ID. Use complete exported records if bounded CLI pages omit the relevant prefix.
3. Compare affected source paths, source/batch/run IDs, file hashes, final run status,
   inserted/duplicate counts and committed inventory. A missing completion is an
   unresolved operation, not proof of data loss or permission to replay everything.
4. Verify fresh-session audit functionality after installing the accepted correction.
5. Only the analyst chooses which remaining files to ingest. Preserve intended source
   identity and understand existing deduplication. Retrying writes new run/audit
   history even when retained records deduplicate.
6. Treat MFT timing separately. This release changes no MFT timeout and initiates no
   ingestion or recovery at startup. Reacquiring a live volume can produce different
   bytes and evidence IDs.

No commit/push or historical-case repair is performed by this change set.

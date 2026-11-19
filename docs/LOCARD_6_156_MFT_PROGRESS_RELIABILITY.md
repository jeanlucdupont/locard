# Locard 6.156 — MFT progress communication reliability

Date: 2026-11-18. Starting commit: `b8eae35` (6.155). This document describes
the uncommitted 6.156 change, ready for manual acceptance. `pyproject.toml`
remains the application version authority.

## Defect and correction

The MFT worker's `Reporter.update` writes a complete bounded JSON snapshot to
`stage.db.progress.tmp` and replaces `stage.db.progress`. The parent polls it
every 250 ms. An ordinary Windows Python read handle can block replacement;
the original collision was reproduced with disposable files (WinError 5).
The recorded historical failure does not retain enough detail to prove its
individual underlying OS error retrospectively.

Testing established that adding delete sharing to the reader alone is
insufficient for Python's Windows `os.replace` operation on this machine.
`ReplaceFileW` allowed an already-open reader, but the repeated concurrent test
observed a transient missing destination. Neither candidate was accepted.

The implemented Windows transport uses:

- `CreateFileW` with `FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE`,
  `OPEN_EXISTING`, and `FILE_FLAG_OPEN_REPARSE_POINT` for a pinned reader.
- Handle-based attribute checks reject reparse points and directories; `fstat`
  rejects nonregular files and multiple hard links. Zero links on a reader are
  allowed because atomic replacement may already have unlinked its pinned old
  snapshot. The handle never follows the newly published pathname.
- `SetFileInformationByHandle(FileRenameInfoEx)` with
  `FILE_RENAME_FLAG_REPLACE_IF_EXISTS | FILE_RENAME_FLAG_POSIX_SEMANTICS` to
  atomically replace subsequent snapshots. Initial publication does not permit
  replacing an existing target. The writer opens and validates the temporary
  file by handle, with DELETE access and the same no-reparse policy.
- Deterministic descriptor ownership and closure on success and exceptions.
  No retry, fallback replacement, copy/delete sequence, sleep, or polling change.
- The portable branch retains `os.replace`, with a bounded regular-file reader
  using `O_NOFOLLOW` and `O_NONBLOCK` where available.

The existing private staging directory remains the transport's containment
boundary. This is not a general arbitrary-path file replacement service.
Unsupported Windows rename semantics/filesystems fail closed with OS codes;
there is no silent fallback to the failing transport. Native Windows acceptance
was performed on this host, not every supported Windows/filesystem combination.
Portable-branch behavior was simulated on Windows; native Linux/macOS was not run.

API references: [FILE_RENAME_INFO](https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-file_rename_info),
[SetFileInformationByHandle](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-setfileinformationbyhandle),
and [FILE_INFO_BY_HANDLE_CLASS](https://learn.microsoft.com/en-us/windows/win32/api/minwinbase/ne-minwinbase-file_info_by_handle_class).

## Lifecycle, integrity, and final completion

`artifacts/ingest.py::worker` launches the guarded worker, establishes containment,
permits parsing, observes snapshots, validates the final worker result, and reaps
the process. `artifacts/worker.py::run` wraps `_run` with progress reporting and
publishes `complete` only after `_run` returns. That final publication uses the
same corrected transport as all earlier phases.

Progress remains ephemeral diagnostic state, never evidence or publication
authority. Frames remain limited to 1,024 bytes (reads are at most 1,025 bytes).
Exact contract keys, allowed phases, integer ranges, monotonic counters,
source-size bounds, and fixed-phase semantics remain enforced. Normal updates
remain coalesced to once per second; phase changes remain immediate.

The parent still requires a successful permitted worker, complete progress,
valid result and independently verified stage before transactional publication.
A final progress error still rejects even a committed private stage. No retained
evidence is inferred merely from a stage existing. Cleanup and cancellation retain
their existing containment behavior and explicit unconfirmed-cleanup failure.

Unchanged: startup 60 seconds, meaningful-progress inactivity 900 seconds,
emergency ceiling 21,600 seconds, 8 GiB stage cap, memory and diagnostic limits,
parser algorithms, reconstruction, source hashes/provenance, deduplication,
publication transactions, native read-only acquisition, audit formats/rotation,
Browser handling and AI behavior.

## Diagnostics

Stable outer failure categories are retained. `ProgressError` adds allowlisted
`progress_operation` (`open`, `read`, `write`, `replace`, `decode`, `validate`) and
`progress_failure` codes, including invalid JSON, oversized frame, duplicate field,
unsafe file, invalid semantics, counter regression and phase regression.
OS failures retain bounded integer `errno` and `winerror` when available.
WinError 32/33 identifies a sharing/locking violation; WinError 5 is access denied
and alone does not prove sharing was its cause.

Worker diagnostics cross the existing bounded result channel through an allowlist.
Parent read/validation errors use the same codes. No arbitrary worker fields,
source paths, frame contents or new unbounded exception text are persisted.
`worker_exit_code_before_cleanup` distinguishes a process already exited from one
still running when failure handling starts; the existing post-cleanup exit code
and cleanup status remain. Existing startup, crash, incomplete-progress,
inactivity, hard-ceiling and cancellation categories remain distinct.

## Changed files

| File | Change |
|---|---|
| `forensic_assistant/artifacts/progress.py` | Sharing-compatible atomic transport, pinned readers, bounded diagnostics |
| `forensic_assistant/artifacts/ingest.py` | Preserve safe progress diagnostics and pre-cleanup exit status |
| `forensic_assistant/artifacts/worker.py` | Include safe progress codes in failed worker result |
| `tests/test_mft_progress_transport.py` | Synthetic transport, concurrency, failure, handle and publication regressions |
| `pyproject.toml` | 6.155 → 6.156 |
| `.gitignore` | Allow this release document in the existing documentation allowlist |
| This document | Implementation, validation and acceptance instructions |

## Focused validation

No real MFT, case database, audit history or evidence volume was accessed.
No provider requests, full suite, commit or push were performed.
Tests used fresh temporary application-data roots and disposable fixtures.
Windows sharing/hard-link and contained-child tests ran outside sandbox filesystem
restrictions; no permissions were changed.

| Invocation | Recorded result |
|---|---|
| `python -m pytest tests/test_mft_progress_transport.py tests/test_mft_progress.py -q --tb=short -p no:cacheprovider --basetemp <fresh-temp>` | **47 passed, 12.68 seconds** |
| `python -m pytest tests/test_session_rotation.py -k "rotation_linkage or damaged_linked or capacity_reserved or spinner_suppressed or completion_keeps or partial_commit or rotation_failure" -q --tb=short -p no:cacheprovider --basetemp <fresh-temp>` | **12 passed, 14 deselected, 33.87 seconds** |

`git diff --check` passed. Total final focused coverage: **59 passed**; no skips
in these runs. The working tree contains only the seven files listed above.

Coverage includes the original sharing failure; held readers through rapid phases
and `complete`; 1,000 concurrent reads against 504 replacements; a separate
publisher process; pinned old snapshot bytes; closed descriptors; actual hard-link
and symlink substitution; simulated Windows open/attribute/descriptor/rename
failure; portable branch; bounded corrupt frames; counter/phase regression;
successful synthetic worker ingestion; simulated deadlines/crash; real hung-child
cancellation and reaping; failure of final completion publication with zero
retained records; and stage cleanup. Audit tests preserve chain verification,
rotation, durable intents/completions, exactly one completion per operation, and
exclusion of progress frames from session recording.

## Synthetic performance observations

On this Windows host (wall-clock, disposable local files):

| Workload | Ordinary implementation | Corrected implementation |
|---|---:|---:|
| 10,000 reads with JSON decode | 1.059910 s | 3.432341 s |
| 1,000 forced writes/replacements, no coalescing | 0.905857 s | 6.932782 s |

The corrected reader averages 0.343 ms: about 1.37 ms of measured read work per
second at four polls/second. Forced publication averages 6.93 ms; ordinary
production counters publish at most once/second, with extra phase transitions.
The safer transport is measurably slower per operation; synthetic results suggest
small overhead at production frequency, not an end-to-end MFT throughput guarantee.
The benchmark overlapped the independent audit test process and is indicative.

A separate isolated run performed three batches of 2,000 reads and 100 forced
publications. Durations were 1.24, 1.38 and 1.38 seconds. After collection, process
handle counts were **172 → 172 → 172 → 172**. The first benchmark had a one-handle
variation; repeated isolated batches showed no accumulating leak. Frame size was
87 bytes in the benchmark, with the unchanged 1,024-byte ceiling in production.

## Manual Windows acceptance and safe retry

After the analyst transfers/installs this checkout into the test checkout:

```powershell
Set-Location C:\tmp\locard260927\locard
.\.venv\Scripts\python.exe -m pip install -e .
.\.venv\Scripts\python.exe locard.py --version
.\.venv\Scripts\python.exe locard.py
```

Confirm version **6.156**. In the Locard shell:

```text
case open "D:\Locard\Cases\KFI-5070790-V2\case.db"
case status --details
evidence source list --ids
evidence source show <existing-V2-source-id> --json
evidence ingest mft E:\ --source <existing-V2-source-id>
case status --details
evidence source show <existing-V2-source-id> --details --json
```

Replace the placeholder with the exact existing source ID verified in **this V2
case** as belonging to the mounted evidence volume. Do not assume the earlier
case's `src-38c22138d0f446bf807f2d58e5974cb7` is valid here. The current V2 source ID
has not been read during development. Verify the current E: mapping before starting.
Use the same native-acquisition access privileges already required by Locard.
No extended timeout flag is needed; existing 60/900/21,600 defaults apply.

This explicitly authorized retry appends ingestion history and preserves earlier
failed attempts and already committed Registry/Prefetch/EVTX evidence. Normal
hash/identity deduplication still applies. A live volume can yield different
acquisition bytes; the transport correction does not freeze it or promise the
same hash. Do not remove failed attempts or edit historical records.

Observe progress through parsing/reconstruction and completion, retained MFT
counts, elapsed time, final status and limitations. Partial parsing can still
produce a legitimate partial result; this fix does not remove parser limitations.
If it fails, retain the detailed per-attempt diagnostic including operation,
OS codes, phase, pre/post-cleanup exit status and cleanup result. Do not raise
timeouts or bypass audit/stage checks to force success. Browser rollback-journal
ingestion remains unchanged and requires its separate remediation.

Real-volume acceptance remains pending. The retry above was not executed.

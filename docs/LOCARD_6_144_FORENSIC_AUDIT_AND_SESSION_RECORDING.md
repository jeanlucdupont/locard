# Locard 6.144 — forensic process audit and session recording

Implementation review: 2026-11-14. Starting revision: `0994853`, branch `main`.
This describes the uncommitted working tree. Version is sourced only from
`pyproject.toml`. Manual acceptance, including performance acceptance, is pending.

## Architecture and authority

`activity.py` remains the authoritative forensic **process** audit. Historical
version-1 canonical serialization, hashes, sequences, verification and mutation
intent/completion semantics remain unchanged. New event types extend that chain;
old entries are not migrated. `append_batch` provides the same locked, synchronized
append and failed-append rollback for a bounded batch. Single-entry `append` delegates
to it. Existing investigation transcripts, findings decisions, reports and evidence
retain their own formats and authority.

Previously, activity recorded command execution, case activation, source/ingestion
mutations and output publication, but omitted many prompts, displayed results,
invalid commands, pre-case failures and Python logging.

`session_recording.py` adds bounded derived interaction history. It cannot authorize
tools, ground conclusions, change findings or replace original evidence. Existing
activity entries are referenced by hash/sequence, with operation IDs where available.

## Storage and identity

| Record | Location |
|---|---|
| Case activity | `<case.db>.audit.jsonl`, unchanged |
| Case recording | `<case directory>/logs/<database filename>/sessions/<32-hex ID>.jsonl` |
| Pre-case activity | `%LOCALAPPDATA%/Locard/logs/application.audit.jsonl` |
| Pre-case recording | `%LOCALAPPDATA%/Locard/logs/sessions/<32-hex ID>.jsonl` |
| Diagnostics | Typed events inside the same session chain, not a duplicate daily file |

The database filename namespace isolates multiple databases in one directory.
New directories use the established private-directory creator. Existing ACLs are
never changed. Local-path validation rejects network paths, traversal and reparse
redirection. Directory guards protect publication; files must be unaliased regular
files. Existing directory protection remains the filesystem owner's responsibility,
as with existing private Locard stores.

`cli.main → execution()` establishes an application-session UUID and scoped capture.
`Recorder.open` validates the case schema and existing briefing/assessment identity,
records path/device/inode, and rejects incompatible existing session bindings.
A copied audit is not silently attached to a different file identity. This binding
is not an evidence fingerprint, source identity, read-view epoch, authenticated
analyst identity or findings-workspace identity.

Case changes close the prior segment and open a new validated segment. The application
session ID links them. `activity.Session.record/start` associates creation/ingestion
events with their case. Recorded-history/findings/workspace commands remain detached
from the active case; their process recording is application-level while their own
stores retain their identities. Normal shutdown closes the last segment. Exceptions
and cancellation record classified completion when possible. A killed process does
not manufacture an end event.

## Contracts and integrity

Detailed entries reuse the activity chain envelope: audit version, append UTC,
session ID, sequence, action, outcome, previous hash and current hash. They add:

| Field | Meaning |
|---|---|
| `contract: session-record-v1` | Supplemental process recording |
| `event_id` | Application-generated event UUID |
| `application_session_id` | Cross-segment execution correlation |
| `operation_id` | Logical command/operation correlation, when available |
| `observed_utc` | Capture time, distinct from buffered append time |
| `data` | Sanitized bounded metadata/text |

The existing authority records `SESSION_RECORD_START`,
`SESSION_RECORD_CHECKPOINT` and `SESSION_RECORD_END`, containing recording ID,
sequence, prefix hash, exact prefix bytes, case binding and version. The detailed
prefix is synchronized before its authority checkpoint. Its latest trusted head
commits all preceding links. Security/input, command and close boundaries checkpoint
the recording. A failed checkpoint can leave an unanchored suffix, never a false
durable commitment.

When possible, `SESSION_CAPTURE_FAILURE` records loss of the supplemental channel
in the authority. If both channels fail, a fixed visible warning remains.
SQLite, session files, audit files and provider effects are **not one transaction**.
Existing completed-but-unaudited mutation errors remain explicit.

Verification separately reports:

| Status | Meaning |
|---|---|
| verified | Closed recording agrees with terminal authority commitment |
| incomplete | Available chain valid, no matching terminal commitment |
| missing | Authority refers to an absent recording |
| corrupt | Invalid chain, identity, prefix bytes or anchored hash |
| unverifiable | No usable authority reference |

Verification does not open the evidence database. Review rejects corrupt/missing/
unverifiable sessions and rechecks the chain/head while reading to detect replacement
or append races. Incomplete review reports records beyond the last authority checkpoint.
Historical audit chains without session anchors remain independently verifiable.

Locally computed chains provide tamper evidence relative to trusted checkpoints.
An administrator can replace and recompute both layers. There is no external
notarization, authenticated nonrepudiation, or proof of forensic conclusion correctness.

## Capture matrix

| Channel | Coverage | Tested boundary |
|---|---|---|
| Submitted shell commands, including invalid commands | Captured with limits | Logical `ReaderProxy`; secret options redacted; no OS keystroke interception |
| Prompts, accept/refuse, blank input and cancellation | Captured with limits | Shared reader and scoped `builtins.input` |
| Application defaults | Captured with limits | Blank response explicit; actual default resolution stays application-owned; existing command audit contains parsed parameters |
| Scripted arguments | Captured with limits | Dispatcher metadata; parser errors also captured on stderr |
| Briefing text/JSON file and editor imports | Captured with limits | Path, bytes and SHA-256 of bounded imported bytes |
| External editor keystrokes | Not captured | Imported result only, explicit editor flag |
| `Output.write/json` | Captured with limits | Logical result/file/pager channel before presentation; field-aware secret registration before rendered capture |
| Direct Python stdout/stderr and print | Captured with limits | Scoped stream adapters, bounded framing/buffering |
| Pager | Captured with limits | Offered content once; navigation/redraw excluded; no claim every row was viewed |
| Progress | Captured with limits | Visible text shares output cap; registered investigation phases also emit logical events |
| ANSI/Unicode | Captured with limits | Recognized ANSI removed; Unicode preserved within byte bounds |
| Python application logging | Captured with limits | `forensic_assistant` namespace INFO+, opt-in DEBUG; exception frame file/line/function, no locals/source-code dump |
| Provider/runtime diagnostics | Captured with limits | Existing sanitized parent-context hooks; not raw request/response capture |
| Workers and parsers | Captured with limits | Parent-visible output, errors, phase notifications and existing audit references |
| Independent child stdout/loggers | Not comprehensively captured | No claim that parent logging installs itself in every process |
| Raw AI debug display | Not captured | Explicit gap; raw capture is never enabled by session logging |
| Audit-review output | Not captured recursively | Explicit gap prevents endlessly copying old recordings |
| Binary descriptor writes/external consoles | Not captured | No OS-level interception |
| Library calls outside `execution()` | Not captured by new service | Existing audit/transcript mechanisms remain; future application adapters install the explicit scope |

Neither imported-document hashes nor displayed evidence text become evidence authority.
No raw provider logging or third-party logger is enabled. Logging configuration and
standard streams are restored on exit. `LOCARD_AUDIT_LEVEL=DEBUG` enables verbose
application diagnostics; there is no background service or automatic upload.

## Secrets and sensitive content

Redaction occurs before persistence, not in a later cleanup pass. It covers nested
credential fields, secret-bearing options, secret prompts, credential environment
values and registered classified values echoed in output or exceptions. Additional
filters cover Authorization headers, credential assignments and common key patterns.
No unredacted temporary logging file is created; removed secrets have no persisted
digest. Whole imported-document hashes identify analyst documents, not credentials.

Analyst narrative and displayed forensic output remain sensitive even after credential
redaction. Arbitrary unlabeled secrets cannot be reliably discovered by pattern matching:
application callers must classify secret fields/prompts. This is not a claim of universal
secret detection in arbitrary evidence payloads.

## Bounds, failure and durability policy

| Control | Policy |
|---|---|
| Detailed event | Payload above 8 KiB canonical size replaced by explicit omitted-size gap |
| Output | 64 KiB original UTF-8 budget per operation; measurable omitted bytes reported |
| Unterminated stream | Above 8,192 characters omitted with an explicit framing gap |
| Framed stream buffer | Less than 4 KiB per stdout/stderr channel |
| Event buffer | Approximately 16 KiB, no more than 100 events per batch |
| Segment | 2 MiB, ordinary events exclude a 64 KiB reserve |
| Storage admission | 100 MiB/session directory, 1,000-file scan ceiling; requires another segment plus reserve free space |
| Review | Last 1–1,000 matching records, default 100; omitted count explicit |

Admission is a point-in-time quota check, **not a cross-process space reservation**.
Concurrent writers can consume free space; write failures still fail safely. No old
recording or authority record is automatically deleted. A full segment becomes visibly
degraded; it does not grow without limit.

Noncritical buffers flush at input, command, required-audit and shutdown boundaries.
They can be lost during abrupt process termination; such sessions remain incomplete.
Affirmative/default input is synchronized and anchored before returning to the caller.
Required activity mutations and parent provider entry points check again. Child
authorization/journal controls are unchanged.

Known read-only query/review commands may continue with visible degraded coverage.
Other dispatched operations require durable admission. Refusal, cancellation,
shell command entry and audit review remain possible when capture fails. A new
validated segment/execution can retry storage; there is no silent repair. Failure
after an operation is not reported as rollback; existing required mutation completion
errors still identify already-completed actions.

## CLI

```text
audit activity --limit 50 --json
audit verify [--json] [--application]
audit sessions [--json] [--application]
audit session show [latest|ID] [--limit 100] [--since ISO_TIME] [--operation-id ID] [--json] [--application]
audit diagnostics [latest|ID] [--severity ERROR] [--limit 100] [--since ISO_TIME] [--operation-id ID] [--json] [--application]
```

Default scope is the selected database. `--application` selects pre-case history.
`latest` sorts by start UTC then ID; application review excludes its own new segment
when older history exists. Use exact IDs for reproducible comparison. `--since`
requires a timezone. Severity choices: DEBUG, INFO, WARNING, ERROR, CRITICAL.
Unclassified gaps are available without a severity filter. JSON preserves independent
activity/session integrity and capture limitations. No new database migration exists.

## Performance

Provider-free synthetic Windows measurements, five iterations after warm-up, medians.
Baseline calls the common application body without the recording scope, not a separately
installed old release. In-memory output sinks isolate recording cost from terminal speed.

| Probe | Scope disabled | Recording enabled | Added median |
|---|---:|---:|---:|
| Startup/version entry | 48.754 ms | 362.595 ms | 313.841 ms |
| Fresh-invocation empty-case status | 143.654 ms | 1,079.597 ms | 935.943 ms |
| Empty-case status with an already-open session, parser included | 85.915 ms | 324.281 ms | 238.366 ms |
| 1,000,001 bytes output, lifecycle included | 0.410 ms | 711.148 ms | 710.738 ms |

Initial line-by-line synchronized capture took about 3.38 seconds on the output probe.
Bounded batching reduced this to about 0.71 seconds without relaxing required durability.
Remaining cost is **not negligible for short commands** and needs manual acceptance.
These measurements do not establish large-case ingestion performance. No real ingestion
or investigation was rerun.

## Validation

Focused synthetic tests exercise lifecycle, case isolation, invalid/replaced/copied
bindings, prompts/defaults/refusals/cancellation, output, pager/import boundaries,
Unicode/ANSI, redaction and credential boundary cuts, parent provider admission failure,
limits, concurrency, anchored corruption/deletion/reordering, historical audit bytes,
and degraded versus fail-closed behavior.

Final combined focused run: **319 passed, 0 failed, 0 skipped in 197.14 seconds**.
Command (with LOCALAPPDATA/USERPROFILE isolated under the checkout):

```powershell
.\.venv\Scripts\python.exe -m pytest -q -p no:cacheprovider --basetemp .pytest-6144-final tests/test_session_recording.py tests/test_activity.py tests/test_cli_consolidation.py tests/test_case_management.py tests/test_terminal_initialization.py tests/test_provider_diagnostics.py tests/test_ai_providers.py tests/test_recorded_history.py tests/test_findings_identity.py tests/test_recorded_reporting.py --tb=short
```

This covers activity mutations, workspaces, terminal launchers, mock providers,
historical investigation reconstruction, findings identity and recorded report
publication/verification. Earlier development runs found and corrected header/option
redaction and invalid-database error handling defects. No unresolved failure remains
in this selected set. `git diff --check` passed. The full suite was not executed.

Initial failures included sandbox restrictions on hard links, PowerShell and supervised
workers. Those checks use disposable test data outside the sandbox, without modifying
existing permissions. Stale activity/provider test command paths were updated for the
6.142 command consolidation; security and forensic assertions were retained.

No full suite, live provider call, protected-case inspection, commit or push.

## Manual Windows acceptance

After the user installs the development checkout into `C:\tmp\locard`:

```powershell
Set-Location C:\tmp\locard
.\.venv\Scripts\python.exe locard.py --version
$savedLocalAppData = $env:LOCALAPPDATA
$savedUserProfile = $env:USERPROFILE
$auditLab = Join-Path $env:TEMP ('locard-audit-' + [guid]::NewGuid().ToString('N'))
$env:LOCALAPPDATA = Join-Path $auditLab 'App'
$env:USERPROFILE = Join-Path $auditLab 'User'
$env:LOCARD_AUDIT_LEVEL = 'DEBUG'
$env:LOCARD_TEST_API_KEY = 'SYNTHETIC-DO-NOT-USE'
.\.venv\Scripts\python.exe locard.py
```

Create an empty `Audit-A` case (choose skip ingestion), then enter:

```text
case status
evidence search --limit 1
evidence show NOT-AN-EVIDENCE-ID
help
audit sessions
audit session show latest --limit 100
audit diagnostics latest
audit verify
case new Audit-B
```

Confirm creation, skip ingestion and activate Audit-B. Run `case status`, then
`case open Audit-A`. Confirm each recording directory contains only its own case
results. Refuse one confirmation and submit one blank default during these flows.
The invalid-ID command is a safe handled error. Internal diagnostic filters may
legitimately return no entries; displayed errors remain output records. Finish with
`quit`, restart and review completed segments. Do not configure/check an AI provider.

```powershell
$dbA = Join-Path $env:USERPROFILE 'Locard\Cases\Audit-A\case.db'
.\.venv\Scripts\python.exe locard.py --db $dbA audit sessions --json
.\.venv\Scripts\python.exe locard.py --db $dbA audit verify --json
.\.venv\Scripts\python.exe locard.py audit sessions --application
.\.venv\Scripts\python.exe locard.py audit verify --application
# Classified synthetic credential in a safe malformed command:
.\.venv\Scripts\python.exe locard.py unsupported --api-key SYNTHETIC-DO-NOT-USE
Get-ChildItem $auditLab -Recurse -Filter '*.jsonl' |
  Select-String -SimpleMatch 'SYNTHETIC-DO-NOT-USE'
# Expected: no matching log line. Keep these disposable logs for review.
$env:LOCALAPPDATA = $savedLocalAppData
$env:USERPROFILE = $savedUserProfile
Remove-Item Env:LOCARD_AUDIT_LEVEL, Env:LOCARD_TEST_API_KEY
```

Use exact IDs from `audit sessions` for repeated comparisons. Active sessions are
incomplete until close. Do not copy, clone or open the large original case for this test.


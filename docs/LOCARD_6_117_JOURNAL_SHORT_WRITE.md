# Locard 6.117 — Manifest short-write publication correction

Implementation date: 2026-11-09. Narrow correction only; D1b is not implemented.
The sole application-version declaration remains `pyproject.toml`.

## Root cause and reproduced failure

`forensic_assistant/investigation_ai/transcript.py:Transcript._manifest` opens
`manifest.tmp` in exclusive binary mode (`xb`). Previously it ignored the return
value of `stream.write`. A synthetic zero-byte write without an exception could
therefore reach flush/fsync, replace the valid manifest with empty content, and
allow `append()` to return and mark publication confirmed.

Before changing production code, the new regression
`test_exact_write_result[zero-manifest]` failed against 6.116:
`Failed: DID NOT RAISE JournalPublicationError` (1 failed, 0.82s).
This reproduces the original injected defect, not an observed real-case incident.

## Correction and adjacent-boundary audit

The private `_write_complete(stream, raw)` helper makes exactly one binary write.
It requires `type(written) is int` and `written == len(raw)`. Zero, partial, None,
negative, oversized, Boolean and floating-point results fail immediately with
`OSError`. No write-all loop or application-level retry is introduced.

Both event writes and manifest writes use the helper. Manifest JSON is encoded to
UTF-8 first, so the comparison measures bytes, not Unicode characters. Existing
serialization, hashes and successful journal bytes are unchanged.

| Boundary | Inspection / handling |
|---|---|
| Event serialization | Existing canonical JSON and byte limits unchanged. |
| Event append | Already compared the returned count with the byte length. Equality alone could accept an equal-valued float; now the exact integer contract is enforced too. |
| Event flush/fsync | Exceptions still enter 6.116 uncertainty handling. No count-return contract applies. |
| Manifest temporary creation | Exclusive binary creation unchanged; no overwrite or repair fallback. |
| Manifest write | Full count now checked before explicit flush/fsync or replacement. Closing a failed temporary file may flush partial buffered data, but it remains uncommitted temporary content. |
| Manifest flush/fsync | Existing exception handling retained; tested with injected failures. |
| Manifest replacement | Not reached after a short write. Existing bounded Windows sharing-error replacement retries remain unchanged; they do not retry an event append. |
| Parent-directory synchronization | Not implemented in the existing sequence; none added here. |
| Confirmation | Still occurs only after the event and manifest publication sequence returns successfully. |

## Publication states and limits

For a short manifest write during append, the event may already be persisted. The
existing `journal-publication-v1` machinery marks the writer uncertain, preserves
last-confirmed application counters separately from the attempted append, closes
best-effort and raises fatal `JournalPublicationError`. Subsequent append/finish
attempts are refused without further filesystem mutation.

The old manifest is not replaced by the partial temporary file. Its prefix can
therefore disagree with the extra event tail. The strict loader continues to reject
that disagreement; there is no automatic prefix salvage, tail truncation, manifest
repair, restart authorization or report-import expansion.

An initial manifest short write prevents successful construction of a journal.
A short write in the separate terminal-status manifest update preserves the prior
confirmed terminal append but reports the status update uncertain. It does not
retroactively erase that event or claim a successful final status publication.

All journal/event ceilings, terminal reservations, model/tool allocations,
deadlines and supervisor containment are unchanged. No authority rules changed.
Successful write counts and fsync establish the existing application-level
publication contract, not immunity from power loss, faulty devices or a writer
that falsely claims to have accepted bytes it did not accept. Event/manifest
publication remains two filesystem operations, not an atomic two-file transaction.

## Validation

`tests/test_journal_short_write.py` tests both binary boundaries with zero,
partial, invalid and complete return values; exactly one write attempt; unchanged
previous manifest/counters; refusal of subsequent appends; UTF-8 data; strict
rejection of malformed manifests or extra tails; ordinary replay; manifest flush
failure; initial creation and terminal-status publication.

Existing publication regressions additionally cover write exceptions, event and
manifest fsync failures, manifest replacement failures, cancellation, dependent
commit failure and real supervisor containment using synthetic processes.
The C1 final-anchor regression remains a normal test with its strict assertion.

The broader focused persistence/replay run passed **126 tests in 73.13s**, including
publication uncertainty, C1 finalization/organization, B2 persistence, strict replay,
completion deadlines and supervisor containment. After adding initial-creation and
terminal-status cases, the final short-write suite passed **20 tests in 4.62s**.
These runs overlap and are not 146 distinct tests. `git diff --check` passed.
No full suite or paid/live provider test was run.

## Historical compatibility

The accepted readable copy
`C:\tmp\locard-diagnostics\6.111-b2\ec81a1af5b1f471ca4f3a4c0bb917fa2`
was reconstructed read-only with provider and SQLite entry points blocked.
Results remain 21 observations, one Defender ASR interpretation, seven current
and three historical-only relationships, four B2 proposals and original S3
`NOT_ASSESSABLE`. No successful script-execution conclusion is added.

The 61-statement canonical digest remains
`0a449bb4cde578094d5f6145769ca0a0c5cf34eb984299eccdb4c1441b62ca5a`;
the seven-page display digest remains
`79bb708cbcca853cd8d4c3b168150353d5ad0cdd32c4ead34fc427af911297da`.
Copied manifest/events SHA-256 values were unchanged before/after inspection.
No live case database, original transcript, evidence or permissions were modified.

## Provider-free manual acceptance

After installing the checkout, run from the repository root:

```powershell
.\locard.ps1 --version
# Expected: 6.117
$root = 'C:\tmp\locard-diagnostics\6.111-b2'
$run = 'ec81a1af5b1f471ca4f3a4c0bb917fa2'
.\.venv\Scripts\python.exe -B -m forensic_assistant.investigation_ai.synthesis $root $run --organization --json
.\.venv\Scripts\python.exe -B -m forensic_assistant.investigation_ai.synthesis $root $run --explanation

# Optional repeat of the isolated short-write regressions:
$testRoot = Join-Path (Get-Location) ('.test-b2-' + [guid]::NewGuid().ToString('N'))
.\.venv\Scripts\python.exe -m pytest tests/test_journal_short_write.py -q --tb=short -p no:cacheprovider --basetemp=$testRoot
```

These commands do not require a new investigation or provider request. Never test
fault injection against a real transcript. Changes are left uncommitted for review;
no push or D1b work was performed.

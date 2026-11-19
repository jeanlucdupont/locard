# Locard 6.153 — Ingestion results, diagnostics and elapsed time

Implemented 2026-11-18 against `main` at `947242f` (6.152). Changes are uncommitted. `pyproject.toml` remains the application version authority.

## Problem and retained semantics

The reported overnight retry retained 918,450 MFT records and recorded 2,451 errors. Those are analyst-reported values; this implementation did not access that case. The former native-MFT human summary combined “parsing failed or was incomplete” with a live-volume caveat. This made a partial retained result look like total failure. It also omitted total elapsed time.

| Concept | Existing meaning, unchanged |
|---|---|
| Processed slots / bytes / paths | Worker progress measurements, not evidence inventory |
| Staged records | Private parser output; not yet published case evidence |
| `inserted` | Newly committed records reported by the ingestion service |
| `duplicates` | Existing records recognized during publication; separate from new retained records |
| `errors` | Recorded diagnostics; not a count of lost evidence records |
| `complete` | File attempt completed under its existing parser/publication rules; not proof of exhaustive forensic recovery |
| `partial` | Incomplete parsing/coverage; may retain substantial evidence, or no records |
| `failed` / `changed` | Existing unsuccessful/rejected outcome; do not infer retention from progress output |
| Cancelled/interrupted | Prior committed work remains; no invented current-file count |
| Audit/persistence failure | Completion is uncertain; nonzero counts do not override mandatory auditing |

No parser, timeout, publication, deduplication, source attribution, database schema, evidence-ID or audit-format changes were made.

## Shared human result projection

`ingest/presentation.py` supplies duration formatting, structured outcome roles, native limitation projection and aligned results. `v2_cli.render_native_ingestion` is retained as a compatibility entry point and delegates to this shared renderer for all direct ingestion families, including `all`. Each file result remains identifiable by family and its existing outcome/counters; JSON retains individual source/run details.

Illustrative layout (duration is measured at runtime, not taken from this example):

```text
MFT INGESTION

Outcome:                 Partial — incomplete evidence coverage
Records retained (new):  918,450
Duplicates:              0
Recorded errors:         2,451
Acquisition time:        <measured acquisition duration, when available>

Limitations
  MFT parsing coverage is incomplete; inspect recorded diagnostics.
  Source volume was live and not frozen during acquisition. Metadata may have changed while the artifact was being read.

Elapsed time:            <measured total>
```

“Recorded errors” is deliberate: not every diagnostic is a parser exception. No assertion is made that all EOF errors indicate corruption, that they represent 2,451 lost records, or that live acquisition caused them. Actual acquisition failures use a separate red failure detail. Native JSON retains its existing limitation string; only the human projection separates it into appropriate meanings.

Guided ingestion retains its compact progress line and category summaries. `setup.Progress` and legacy `creation.IngestionProgress` use the same limitation projection and structured outcome roles. Partial completion is amber. Counts say “records retained” and remain neutral. The selection workflow, metadata prompts, progress instrumentation and future wizard color/time-zone work are unchanged.

| Content | Semantic role |
|---|---|
| Section heading | `heading` (bright white) |
| Label / original historical diagnostic | `label` (normal white) |
| Count / duration | `value` (cyan) |
| Completed outcome | `success` (green) |
| Partial outcome / cancellation | `warning` (amber) |
| Operational failure / unconfirmed audit completion | `error` (red) |
| Forensic limitation | `forensic_note` (existing brown-capable rendering) |
| Unavailable duration | `unknown` (gray) |

The existing terminal capability and NO_COLOR behavior is preserved, including plain-text output and the established limited-terminal forensic-note fallback. Roles derive from structured status, not words in exception text.

## Historical diagnostics

`retrieval/status_display.render` keeps default `case status` concise: attempt totals, recorded-error totals and significant forensic limitations. It does not print raw parser exceptions or the recurring “error counts do not measure lost records” explanation.

`case status --details` includes **Ingestion diagnostics**. Groups are keyed by the recorded artifact family, attempt status, stage and original message. Missing artifact metadata is explicitly unclassified. Counts are cyan; original messages are neutral white. The original message remains intact after safe terminal escaping, not reinterpreted as a corruption diagnosis. Up to 100 groups are displayed with an explicit omission notice; `case status --json` retains all existing error details.

Live-volume notes come from native acquisition provenance. Dirty hives, unsupported Registry log replay, uncertain hive identity and coverage notes retain their forensic-note role. Historical exceptions are no longer mixed into that brown limitations section. Guided historical diagnostic summaries likewise use neutral text/cyan counts for technical errors.

## Timing boundaries and compatibility

- Direct commands start a monotonic timer before the command's existing validation/audit/dispatch path. Successful result measurement ends after `ingest_sources` returns, including discovery, acquisition, hashing, worker parsing, reconstruction, publication and the service's INGEST/INGEST_BATCH completion auditing. Formatting, paging and subsequent outer COMMAND/session finalization are outside the successful result measurement. Calling `v2_cli.dispatch` directly starts at that service entry instead.
- Failure/cancellation paths report elapsed time at interruption. A shared reporting flag avoids printing the same failure duration twice through nested handlers. Existing exceptions and return codes propagate unchanged. Preflight failures also report elapsed time. Audit completion failures explicitly say the outcome is uncertain and committed evidence may remain.
- Guided creation/addition preserves its existing post-confirmation start and summary-inclusive successful timing boundary. Analyst selection/navigation is excluded. Exception and cancellation exits now also print elapsed time. No second spinner or per-frame audit recording was introduced.
- Human durations use whole seconds: `8s`, `4m 32s`, `1h 18m 05s`. Subsecond work displays `0s`; there is no invented fractional precision in human output.
- Direct result JSON adds **`elapsed_seconds`**, a nonnegative monotonic duration rounded to milliseconds, alongside the unchanged `results` and `status`. Existing per-file keys and meanings remain intact. No ANSI is added. Exception diagnostics remain on stderr rather than corrupting stdout JSON. Saved human output includes the result duration.
- Native acquisition already records `acquisition.elapsed_seconds`; it is displayed when available. This release does not invent separate parsing, reconstruction or publication times from worker timestamps.
- Existing audit COMMAND events already record monotonic `duration_ms`. Their format and persistence are unchanged. No duration column, migration or ingestion-history rewrite was added.
- Historical per-attempt durations remain **unavailable (not recorded)**. Wall-clock start/end timestamps are not subtracted to fabricate a monotonic duration. An existing matching completed COMMAND audit record may independently contain the earlier command's duration; inspect that record rather than assuming it applies to a particular file attempt.

## Validation

Synthetic fixtures and mock clocks only; no provider calls or live-case/evidence access.

- Focused presentation/timing/history/native-MFT/audit selection: **58 passed, 7 deselected, 36.79 s**.
- After separating operational acquisition failures from forensic notes: **34 passed, 28 deselected, 11.40 s** (unrelated wizard tests excluded by the selection).
- Updated compact guided-summary color/duration assertion: **1 passed, 2.86 s**.
- These sets overlap and should not be summed as unique test counts. No full suite was run.

Coverage includes whole-second formatting, simulated multi-hour totals, monotonic dispatch accounting, cancellation and exception propagation, single failure-duration reporting, audit-outcome uncertainty, retained/duplicate/error counts, source bytes unchanged in guided synthetic failures, failed history followed by complete/partial retries, exact JSON status/counter compatibility, ANSI-free JSON, brown forensic notes, neutral historical diagnostics, aligned fields, audit repaint suppression and existing audit verification. The historical-status fixture compares the complete database dump before and after rendering.

Earlier broad focused exploration also exposed three unrelated problems left untouched: the sandbox denied junction creation; an old case-new help assertion expects wording absent from the current baseline; and an EVTX verification fixture did not produce its expected parser diagnostic groups. The latter occurs before presentation in unchanged parser/fixture paths and was not resolved by weakening its semantic assertion. This release does not claim those suites are wholly green. The approved stale presentation expectations for partial colors, neutral counts and duration format were updated; no forensic assertion was relaxed.

`git diff --check` passed. Worker/supervisor, ingestion persistence, native acquisition and audit implementation files remain unchanged.

## Manual Windows acceptance

Install into the test checkout using your normal workflow, then:

```powershell
.\.venv\Scripts\python.exe locard.py --version
```

Expected version: `6.153`.

In the existing case's Locard shell, review without reingestion:

```text
case status
case status --details
case status --json
audit verify
audit activity --limit 20 --json
```

Confirm the historical failed attempt and newer partial attempt remain separate; default status hides raw exceptions; details preserve them neutrally; the live-acquisition caveat remains. A matching completed COMMAND record in the activity JSON may contain the overnight operation's `duration_ms`. This implementation has not inspected it and makes no claim about that run's actual duration. Do not rerun the large ingestion merely to obtain timing.

For a new timed acceptance run, use a **disposable case and small extracted test artifact**, not the original evidence volume:

```text
evidence source list --ids
evidence ingest mft C:\tmp\locard-test-fixtures\sample.mft --source <existing-test-source-id>
evidence ingest mft C:\tmp\locard-test-fixtures\sample.mft --source <existing-test-source-id> --json
audit verify
```

Replace the sample path/ID with existing test values. The second identical ingestion should report duplicates separately. Repeat with the other artifact family commands or `evidence ingest wizard` as appropriate; use an explicit browser product/profile for Browser ingestion. Verify elapsed time for success, a safe invalid synthetic file, and Ctrl+C during a disposable test run. Do not intentionally break mandatory audit storage on a real case.

## Remaining limitations

The real overnight duration and the causes of its 2,451 EOF diagnostics have not been established by this presentation task. Detailed status may still perform expensive existing coverage calculations. Per-file phase timing is not newly instrumented. Result formatting cannot guarantee delivery if the terminal/output stream itself fails. All mandatory audit failure behavior remains fail-closed.

Changes are ready for manual review; no commit or push was performed.

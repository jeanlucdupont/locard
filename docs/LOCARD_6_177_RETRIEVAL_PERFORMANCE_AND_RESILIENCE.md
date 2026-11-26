# Locard 6.177 — Retrieval performance and resilience

Development date: 2026-11-26. Starting revision: `ffab4e3` (6.176, clean tree). This document describes uncommitted 6.177 changes; manual acceptance is pending.

## Diagnosis and measured performance

The analyst reported a 6.176 investigation ending after 75.007 active seconds with one attempted operation, no retained evidence and a generic WorkerError. Its configured tool deadline was 60 seconds. That makes timeout plausible, **not proven**: the historical error detail was discarded. The separately measured live browser query took **51.882 seconds for 20 records** on approximately 2.65 million records. Development did not open that case or call a provider.

Source-confirmed costs in `retrieval/evidence.py::EvidenceQueries.search/_where` and `conversational_ai/tools.py::Tools.execute/eligible/original`:

- Exact counting preceded every page, including conversational exploration.
- Non-Registry searches materialized a timestamp UNION containing inherited Registry values.
- Source filtering expanded file membership into membership for all non-browser records, even for a browser-only request.
- A 20-record conversational page repeated eligibility searches 40 times. Those exact-ID searches omitted the artifact family and could activate Registry/UserAssist processing.
- Ordering still requires minimum timestamps and a SQLite sort before LIMIT; this is retained to preserve ordering. LIMIT alone does not make arbitrary searches cheap.

### Synthetic measurements

Fixture: 20,032 evidence rows, including 32 browser records with occurrence-backed source membership and 20,000 background rows/timestamps. Browser seed records came from the repository's Chromium fixture. Background rows are deliberately simple membership/timestamp load, **not representative complete MFT parser output**. Same disposable database, same source, same time scope, same limit of 20. No schema/index changes. Single samples, affected by caching and concurrent development work; not a production speed guarantee.

| Path | Committed 6.176 | Working 6.177 | Result |
|---|---:|---:|---|
| Direct exact-count query | 0.807 s | 0.061 s | 20 records; identical serialized record hash |
| Conversational adapter | 7.581 s | 0.052 s | 20 records; identical serialized record hash |
| Protected worker, including startup/closure | 10.737 s | 0.638 s | 20 records; identical adapter record hash |

Direct query statements remained 125, while the adapter fell from **325 to 124**. The reduction in query cost matters as much as statement count. Direct and adapter serialization have different projections, but each independently matches its baseline byte-for-byte after canonical JSON encoding, including record ordering.

Earlier isolated baseline phase measurements: count 0.174741 s, page selection 0.179426 s. A subsequent optimized profile measured count 0.0009 s, page 0.0005 s, hydration 0.0031 s. Optimized bounded retrieval was 0.0072 s; adapter 0.0442 s (projection 0.0366 s); worker 0.5134 s (startup 0.4398 s). These are separate samples, not additive to the first table.

Baseline EXPLAIN plans had 48 count nodes and 53 page nodes, including `CO-ROUTINE selected`, compound UNION/temp processing, Registry values and expanded record membership. Optimized browser plans had 18/23 nodes: browser occurrence membership and evidence-ID timestamp lookups, with the existing ordering sort retained. Source membership and timestamp cost are part of SQLite selection execution; they are **not independently timed SQL phases**. Query construction, profiling overhead and startup/import cost remain in total/residual elapsed time. The diagnostic exposes plans without SQL parameter values or evidence content.

## Retrieval correction

- `EvidenceQueries.search(exact_count=True)` retains the existing exact-count return contract and JSON structure by default.
- Explicit `exact_count=False` uses limit+1 lookahead, trims before hydration, returns `total: null`, `total_exact: false`, `has_more`, and `next_offset`. It does not estimate an exact total. Existing bounded EventData/object searches retain their specialized coverage/cursor contracts.
- Known non-Registry families use their own original timestamp predicates. Registry and mixed-family queries retain inherited and derived UserAssist behavior.
- Schema-5 browser queries retain explicit occurrence/run membership. Non-browser families use the same canonical file membership at its natural file-hash key. Ambiguous multi-source attribution remains excluded for source_scope.
- The trusted scoped selector supplies ordinary search IDs directly to original hydration. Standalone inspection still checks eligibility. Object discovery retains a separate eligibility check because its candidate selection is intentionally broader. Supporting-evidence eligibility remains enforced.
- Original IDs, values, chronology, SI/FN meanings, browser context, source uncertainty and provenance are unchanged. No authorization cache crosses a scope or read view.

Existing cases need **no migration, new index or reingestion**. This is not a guarantee that all large Registry, mixed-family, temporal, substring or deep-offset searches will be fast. The correlated ordering and complex Registry projections remain possible bottlenecks.

## Operation lifecycle

`conversational_ai/supervision.py::ChatWorker` is a conversation-specific extension of the existing process/job containment lifecycle. Legacy `investigation_ai/runner.py` is unchanged.

- Default conversational `tool_seconds` is explicitly `None`. There is no substituted enormous integer or hidden 60-second retrieval deadline.
- `--tool-seconds N` remains an explicit analyst-selected deadline (existing technical validation ceiling: 600 seconds). Optional active-session budgets also constrain operation admission.
- Startup/read-view initialization remains bounded (60 seconds in the conversation service). This is a startup safeguard, not a query limit.
- The parent checks process termination, IPC framing and the existing 64 MiB WAL growth allowance while waiting. Worker read-only authorizer, memory protection, scope checks and original pinned transaction remain in effect.
- The worker listens separately for cancellation messages bound to the active operation ID. Cancellation invokes SQLite interrupt and a progress-handler flag. Deadline checks use monotonic time. Cancellation is checked again after non-SQL result preparation.
- Confirmed interruption rolls back provisional known/disclosed-field additions. A healthy read-view acknowledgement permits subsequent operations in the **same** transaction.
- A nonresponsive operation gets up to five seconds to acknowledge cancellation, then the existing bounded process/job closure runs. This grace is containment time, not more execution authorization.
- If success races cancellation, the parent cannot prove undisclosed-field rollback and conservatively suspends that read view. It does not grant verification authority from a discarded page.

### Recovery and accounting

A recoverable query, projection or explicit-deadline error becomes a corresponding tool response. Later independent calls can run when the worker confirms the same pinned view. Cancellation skips all remaining calls in that response with their original call IDs. Completed earlier results, observations and notes survive.

Worker death, invalid protocol, failed integrity/authorization, unconfirmed cancellation, or a lost read view suspends the conversation. No automatic worker reopen or replacement epoch is attempted. `/status` and `/exit` remain available. Continuing retrieval requires exiting and creating a freshly authorized session; historical notebook observations are not silently rebound to a new transaction. Full restart recovery is deferred.

Failure counters increment before suspension. Safe categories distinguish cancellation, explicit deadline, database error, process termination, communication, protocol, authorization, integrity, projection and resource protection. Notebook and session diagnostic records retain code, operation, stage, timeout and read-view confirmation. Raw SQLite/evidence error strings are not exposed. Abrupt exits cannot necessarily establish whether memory protection caused the exit; they remain `WORKER_TERMINATED` rather than an invented memory diagnosis.

Provider requests retain existing configurable transport timeouts (default 180 seconds, maximum 600). Ctrl+C uses the existing provider subprocess cleanup, pauses rather than closes the notebook, records unknown usage/outcome, and never automatically retries a potentially billable/disclosing request. No provider integration or local inference capability was added.

## Activity and analyst controls

`conversational_ai/activity.py::Activity` emits UI-independent start, slow, waiting, completed, interrupted or failed events, with monotonic elapsed seconds and `computational_progress: unavailable`. The CLI renders them; future UI clients can consume the same events. It does not claim query advancement, a completion percentage or an ETA.

Descriptions identify artifact searches, timeline retrieval, original inspection/authorization, field verification and AI waiting. The elapsed search interval covers authorization, selection, hydration and result preparation; it does not pretend to measure those as live subphase progress. Default updates are every 30 seconds, configurable with `--progress-seconds`. The first slow notice and subsequent notices never cancel the operation or require repeated approval.

Ctrl+C during a query interrupts current work. If the pinned transaction survives, redirect at `Analyst>`. If not, the UI explicitly reports suspension and the need for fresh authorization. `/exit` ends the conversation. Ctrl+C/EOF while idle still exits. `Session.cancel()` supports current forensic-operation cancellation for application clients; provider cancellation currently uses the synchronous caller's interrupt rather than a new asynchronous provider API.

Retained limits are technical protections, not mandatory short investigation quotas: request/result size, field/page bounds, provider transport timeout, memory, IPC framing, WAL growth, notebook capacity and bounded cleanup. Existing context capacity and ten-minute active-turn checkpoints remain; the checkpoint is examined between operations and does not terminate a long query. No mandatory cumulative session duration, request, operation, distinct-record or token ceiling was reintroduced.

## Validation

Only focused synthetic/mock tests were run; no full suite or live provider requests. See the final recorded results below. Tests cover readonly bytes, same-view cancellation, deadline recovery, pending-call suppression, worker death/protocol/communication, rollback after failed projection, correct call IDs/counters, elapsed notices with a simulated 75-second clock advance, default deadline absence, exact/bounded equivalence, source occurrence semantics, UserAssist and legacy behavior.

The existing UserAssist fixture uses the removed top-level `ingest-registry` command. Its resulting setup failure (and nine cascade errors) reproduces on committed 6.176. New 6.177 tests adapt only fixture setup to the current command and execute the original identity/timestamp assertions for versions 3 and 5. An existing `test_invalid_time[2026-01-01T24]` failure also reproduces on 6.176. Neither unrelated production behavior was changed.

## Manual acceptance — no installation required

No dependencies or packaging changed; LiteLLM remains 1.111.0. After reviewing and performing your own Git workflow, run from the updated test checkout with its existing environment:

```powershell
cd C:\tmp\locard260927\locard
.\.venv\Scripts\python.exe locard.py --version
```

Expected version: **6.177**. No pip command is needed for the direct source launcher.

### Provider-free measurements

This script opens SQLite with `mode=ro`, `uri=True`, `query_only=ON`, and a read transaction. The worker mode additionally uses the production read-view/authorizer/process boundary. It creates no conversation notebook, does not ingest, and does not contact an AI provider. End is exclusive; the exact-count path subtracts one nanosecond to reproduce the original inclusive benchmark end.

```powershell
$profileArgs = @(
  '--db', 'D:\Locard\Cases\KFI-5070790-V2\case.db',
  '--source', 'src-d3c195d3068e4906a805082df44c1a57',
  '--start', '2026-11-17T06:00:00.000000000Z',
  '--end', '2026-11-18T06:00:00.000000000Z',
  '--limit', '20'
)
.\.venv\Scripts\python.exe scripts\profile_retrieval.py @profileArgs --artifact browser --mode all
foreach ($family in @('evtx','mft','prefetch','registry')) {
  .\.venv\Scripts\python.exe scripts\profile_retrieval.py @profileArgs --artifact $family --mode all
}
```

Compare returned counts and `ordered_ids_sha256` across exact/bounded/adapter/worker runs. The script emits plans and elapsed phases, not original evidence values. If records or ordering change while comparing separate invocations on a changing case, investigate the distinct read views; do not assume a retrieval defect. Ctrl+C closes the diagnostic's current connection/worker. `--tool-seconds N` is optional. Slow-query profiling may itself cost time; phase timings exclude EXPLAIN execution while totals include it.

### Synthetic progress demonstration

No database or provider is opened:

```powershell
.\.venv\Scripts\python.exe scripts\profile_retrieval.py --demo-seconds 75 --progress-seconds 5
```

Allow it to complete once, then repeat and press Ctrl+C. This demonstrates presentation/caller interruption only. Real SQLite cancellation, preserved earlier work and multi-call recovery are covered by the disposable-worker tests, not claimed from this sleep demo:

```powershell
.\.venv\Scripts\python.exe -m pytest tests\test_retrieval_resilience.py -q -p no:cacheprovider
```

### Live conversation (analyst only)

```powershell
.\.venv\Scripts\python.exe locard.py --db 'D:\Locard\Cases\KFI-5070790-V2\case.db'
```

In the shell:

```text
investigation chat --source src-d3c195d3068e4906a805082df44c1a57 --start 2026-11-17T06:00:00.000000000Z --end 2026-11-18T06:00:00.000000000Z
```

Use the original blind question:

> Analyze the evidence discovered within the authorized November 17, 2026 time window. Identify potentially suspicious user activity, unusual process execution, browser navigation, downloads, file changes and persistence indicators. Correlate evidence across artifact families, establish a supported chronology, and propose specific follow-up investigations. Distinguish observed evidence from hypotheses. Do not assume that a security incident occurred.

Approve only the intended scope/provider. Check `/status`, exact error codes, independent tool continuation and no absence claims from failures. Interrupt a slow query and verify either continued same-view work or explicit suspension. Review the notebook for matching call IDs and failure accounting. Live performance and investigative usefulness remain pending your acceptance.

### Recorded test runs

| Focused run | Result |
|---|---|
| Final `test_retrieval_resilience.py`, `test_conversational_ai.py`, `test_conversation_resources.py` | **85 passed, 98.91 s** |
| Expanded retrieval/browser/source/UserAssist/timeline run (173 collected) | 162 passed, 1 failed, 10 setup errors, 120.88 s; old-command fixture and time expectation failures described above |
| Provider, LiteLLM continuation, pinned read-view, session audit | 78 passed, 1 failed, 71.35 s; failed semantic-index test lacked NumPy in the isolated provider environment |
| Existing NumPy environment: that semantic-index test plus advisory-context suites | Semantic-index test passed; aggregate 10 passed, 25 failed, 26.92 s |
| Committed 6.176 archive: same two advisory-context suites | 9 passed, **same 25 failed**, 34.69 s; `command_catalog` failures, untouched by this release |
| Committed 6.176: representative removed-command UserAssist setup and invalid-time test | Same setup error and assertion failure reproduced, 3.36 s |

These run totals overlap and must not be added as a unique-test count. No unrelated baseline failures were repaired. The final 85-test run includes 13 new retrieval/resilience tests. Existing shutdown/forensic/security assertions were retained; only two cancellation/timeout lifecycle assertions and default timeout assertions were updated for the explicitly requested new behavior.

### Changed files

- `pyproject.toml`: source version only, 6.177; dependency pins unchanged.
- `forensic_assistant/retrieval/evidence.py`, `queries.py`: optimized scoped selectors, optional bounded-count result and opt-in profiling.
- `forensic_assistant/conversational_ai/tools.py`: trusted scoped hydration, artifact-aware identity checks and projection profiling.
- `forensic_assistant/conversational_ai/contracts.py`: explicit optional tool deadline; legacy v1 validation retains its deadline requirement.
- `forensic_assistant/conversational_ai/service.py`, `cli.py`: activity events, recoverable tool responses, suspension, cancellation and diagnostics.
- `forensic_assistant/conversational_ai/supervision.py`, `worker.py`: operation-bound cancellation/acknowledgement and conversation-only supervision.
- `forensic_assistant/conversational_ai/activity.py`: UI-independent periodic elapsed reporting.
- `scripts/profile_retrieval.py`: provider-free diagnostic and synthetic progress demo.
- `tests/test_retrieval_resilience.py`, `test_conversational_ai.py`, `test_conversation_resources.py`: focused new regressions and intentional lifecycle expectation updates.
- This document and `.gitignore`: track the requested guide/diagnostic without including private benchmark artifacts.

No live case/evidence/transcript inspection or modification, live AI requests, dependency installation, full-suite run, commit or push was performed. Protected-evidence integrity hashing is deferred to the user-approved final validation workflow; this work does not claim a new historical integrity proof.

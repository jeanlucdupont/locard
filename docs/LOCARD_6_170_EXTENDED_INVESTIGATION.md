# Locard 6.170 — Controlled extended investigation

Implemented against committed 6.169 (`babde41`), 2026-11-24. Live acceptance is pending. This release adds an opt-in three-work-batch session; default investigations retain their existing grants and limits.

## Authorization and resource envelope

Use `investigation run <assessment-id> --follow-up --extended`. Omitting `--extended` retains smoke-test behavior. `--extended` without `--follow-up` is rejected before case/provider access. This profile does not combine with decomposition or synthesis.

The application service creates `investigation-context-extended-v1`; its exact `work_batches`, `limits` and `follow_up` values are validated by parent, controller, evidence worker and recorded-history services. An old grant cannot select `ExtendedBudget`. The same selected case identity, OpenAI provider/model, source IDs, artifact families, initial evidence IDs and UTC time window remain binding. Existing mandatory compatibility preflight remains in place.

| Resource | Each work batch | Whole session |
|---|---:|---:|
| Model attempts | 6 | 18 |
| Evidence operations | 6 | 18 |
| Temporal searches | 2 | 6 |
| Work batches | — | 3 |
| Input-content bytes | 24,576 per request | At most 442,368 |
| Output tokens | 1,024 per request | At most 18,432 |
| Provider retries | 0 | 0 |
| Analyst approvals | — | One initial grant |
| Elapsed envelope, from approval | Shared | 900 seconds |

Model work is admitted only before the 880-second boundary. The existing containment pattern reserves 15 seconds for finalization and 5 seconds for parent cleanup. No fresh deadline or authorization is created at a batch boundary. Earlier grant expiry clamps the deadline. Cancellation and uncertain-cleanup fail-closed behavior remain intact.

Each temporal search remains limited to three returned records, 1,000 candidates, five seconds and a five-minute radius clamped to the authorized window. Six searches can return at most 18 records; with at most 12 original seeds, the session admits at most 30 distinct records. Context inspection remains the existing bounded EVTX field operation, not a new search. Evidence-operation limits include seed retrieval, searches and context inspections.

The authorization display names these limits and the potential additional OpenAI billing. The byte maximum includes instructions and repeated evidence, not just newly disclosed evidence. Token usage/cost cannot be inferred exactly from that byte ceiling.

## Continuous state and work batches

`investigation_ai/extended.py` owns the reusable profile, receipt validation and concise progress summary. `autonomous.py` retains one controller state and one supervised read-only SQLite read transaction for the entire session. No batch reopens the database or resets the original-record store, exposure ledger, search deduplication, context-inspection keys, findings or pending seeds.

After six model requests or six operations, the controller persists and validates a work-batch checkpoint before starting another batch. Continuation requires pending, already authorized seed work, a valid grant, time and remaining total allocations. A batch does not consume unused requests merely to reach six. Each batch reserves its last available model response for grounded analysis; tools are not available in that response.

The model receives bounded current original evidence, retained supporting fields selected by the existing disclosure machinery, compact search/context-operation history, resource accounting and up to three accumulated unresolved questions explicitly classified as unverified. The complete transcript is not appended to prompts. Accepted historical findings influence scheduling and support selection, but new factual citations must resolve to original fields represented in the current request. Strict grounding, truncation metadata and interpretation distinctions are unchanged.

Duplicate searches stop rather than execute again. Repeated context proposals use the existing bounded continuation rule, whose counters are now relative to the current work batch while duplicate keys remain session-wide. Findings accepted before a provider failure, rejected citation, cancellation or scope/view failure remain available.

## Checkpoints, history and progress

`investigation-work-batch-v1` receipts record cumulative and per-batch request/operation/search counts, validated delta identities, a findings digest, unresolved questions, pending seed IDs, retrieved IDs and records represented in validated observations/interpretations. These are derived records, not evidence.

Every normal batch closure:

1. Durably appends its receipt using the existing hash-chained journal.
2. Loads and verifies the persisted manifest and chain.
3. Replays operation authority, current-request disclosures and accepted findings.
4. Recomputes the receipt and checks batch and overall allocations.
5. Allows the next batch only after those checks succeed.

Transition events bind the prior receipt digest. Final receipt lists are independently checked against history. Existing journal byte/event bounds and publication failure behavior are unchanged; resource pressure may stop an extended session early. An interrupted batch may lack a completed batch receipt, but previously durable analysis and completed checkpoints survive. This is not durable restart continuation.

The backend offers a `batch_progress` callback independent of command parsing. The parent relays completed summaries to the interactive adapter. Normal progress shows counts and pending/unresolved work; exact IDs, source details and journal bindings remain in structured history. The final display separates these work batches from individual validated analysis responses.

## Termination and limits of inference

- `NO_FURTHER_AUTHORIZED_LEADS`: the retained authorized work queue ended; this does not certify the objective answered or the case exhausted.
- `BATCH_RESOURCE_LIMIT`: a checkpoint boundary, not forensic completion.
- `OVERALL_RESOURCE_EXHAUSTED`: the extended envelope ended; partial findings remain partial.
- Provider, authorization, evidence, read-view and cancellation failures retain their existing specific termination behavior. Parent-enforced timeouts may report the existing `MAX_SECONDS`/startup timeout diagnostic.

The application does not assert that an objective is sufficiently answered based on model confidence, plan completion or valid citations. It reports grounded observations and explicit unresolved questions. No causal or successful-execution inference is added by extending execution time.

Continuation currently follows pending selected seeds and in-batch model-proposed existing tools. It does not turn arbitrary unresolved prose into new search authority. At most 30 records can be sampled; this is not exhaustive analysis of millions of records. Large fields, journal pressure or the unchanged request ceiling can still stop work early. No filename/path pivots, unrestricted queries, new parsers, provider parity or restart recovery are implemented.

## Validation

All fixtures are disposable and providers scripted. No live case or provider was accessed.

- Three-batch scenario: 15 requests/operations, three temporal searches, 12 accepted analyses; earlier findings and unresolved questions survive. The third batch explicitly retains uncertainty about causality and successful execution rather than inventing a cross-artifact conclusion.
- Exhaustion scenario: 18 operations/requests, 12 distinct contextual inspections and three checkpoints, with pending seeds still present; final status remains partial.
- Real Windows-compatible spawned supervisor and forensic SQLite worker: eight accepted analyses across a work-batch boundary, one initial read view, consistent read-view bindings, unchanged synthetic database bytes and deterministic replay.
- Early stop, batch-two provider failure/cancellation/citation rejection, unauthorized source/time results, changed read view, forged receipt accounting, exact grant limits, expiry, one approval, parent deadline/cancellation containment and CLI opt-in tests.
- Historical startup, disclosure, context inspection, temporal search, duplicate avoidance, authorization/preflight and command regression suites remain covered.

Recorded focused results (overlapping sets, not additive): **189 passed in 133.97 seconds** in the initial expanded relevant set; **37 passed in 36.54 seconds** across extended-session, packet-capacity and investigation-progress suites; **59 passed in 39.75 seconds** across extended-session and CLI consolidation tests. After the final parent-deadline refinement, **31 passed in 56.75 seconds** across extended-session, autonomous startup and B2 parent-timeout coverage. `git diff --check` passed and `pyproject.toml` reports **6.170**. No full suite was run.

## Manual acceptance

After installation in the separate test checkout:

```powershell
.\.venv\Scripts\python.exe locard.py --version
.\.venv\Scripts\python.exe locard.py
```

Expected version: `Locard 6.170`. Select the intended case and retain the existing neutral question:

```text
investigation run 3aa7e12d14d94720b172ad072c56f92d --follow-up --extended
```

Review the single grant before approval: correct case/provider/model/sources/families/window; three batches; 18 requests and operations; six temporal searches; 24,576 input bytes; 900 seconds. Observe batch summaries, preserved findings, actual retrieved/disclosed/examined counts and final unresolved questions. Check termination and cleanup separately. A session stopping before batch three is valid if its authorized work queue is exhausted or a safe limit/failure intervenes.

For comparison, the default remains:

```text
investigation run 3aa7e12d14d94720b172ad072c56f92d --follow-up
```

No live investigative outcome is claimed by these synthetic tests. The analyst's acceptance run must assess whether the additional evidence materially answers the original question. No commit or push was performed during implementation.

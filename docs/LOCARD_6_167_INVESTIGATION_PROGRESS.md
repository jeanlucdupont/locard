# Locard 6.167 — Investigation progress and redundant proposals

Date: 2026-11-24. Baseline `920d774` (6.166); working-tree implementation, pending manual acceptance.

## Confirmed mechanism

`autonomous.run` persisted tool proposals and retrieved results but only persisted findings after a validated final response. Four successive tool proposals could therefore produce no accepted observations. A repeated record/category request immediately terminated with `CONTEXT_DUPLICATE`. The next prompt contained temporal coverage but no explicit completed-context ledger.

The synthetic acceptance fixture was executed against the committed 6.166 controller without changing the checkout. It reproduced:

- Browser seed, two three-record EVTX searches, one contextual inspection.
- Seven unique records retrieved, four model attempts, zero accepted batches.
- A repeated context proposal, no second context lookup, `CONTEXT_DUPLICATE`.
- The selected actor field **was present** in the post-inspection model request.

Thus the reproduction confirms a controller/protocol gap, not a necessary disclosure-budget failure. A scripted model can repeat an operation even when its original fields were disclosed. The actual live model's motivations and precise omissions remain unknown: no real case or transcript was accessed.

`follow_up.render` also labeled `State.summary()['inspected_artifact_families']` as retrieved families. That set was populated through `show_evidence`, excluding temporal-search records. This was a confirmed accounting/presentation defect.

## Completed-operation ledger

`investigation_ai/progress.py:ledger` derives a versioned `bounded-investigation-progress-v1` ledger exclusively from completed, validated tool results. Every new contextual-workflow request includes it; the existing temporal coverage description remains.

Compact context rows contain exact evidence ID, category, original field count, count represented **in this request**, partial/truncation status, available projection-slot/original-ordinal pairs, and represented original ordinals. Global flags state that these inspections completed and repeating them is unavailable. A zero field count denotes empty bounded context, not an empty source event. Projection slots map to `/original_event_data/N/value`; original ordinals preserve identity across projection pages.

Representation requires the disclosed original field's record ID, original ordinal, name and unchanged value to match. A historical disclosure alone does not count as current representation. Values are never copied into the operation ledger. Only actual compact evidence can ground observations.

The ledger is bounded to six rows and 2,400 serialized bytes; empty history uses a short form. Packet construction reserves its worst-case representation encoding, selects mandatory current evidence, then writes the exact represented counts. Final instruction-adapted content still must fit 5,600 UTF-8 bytes. Optional context can be removed by the existing repack; mandatory evidence is never replaced with history or summaries. If mandatory disclosure still cannot fit, the existing explicit budget limitation applies.

The model is instructed not to repeat a completed record/category inspection, to record remaining limitations, and to consider another authorized lead or category. Omitted fields are not described as absent; co-occurrence does not establish attribution or causality.

## Duplicate handling and analysis opportunity

`autonomous.run` records a duplicate as `redundant_context`, increments rejected-proposal accounting, and never dispatches the duplicate lookup. The already-made model attempt remains charged.

When resources remain and there is a pending authorized seed, `progress.continuation` selects the lexicographically first pending exact evidence ID. The ordinary policy, expiry, source/time and read-view checks still apply. This is a new authorized seed lookup, not a provider retry over the failed proposal. There is no new search direction or scope expansion.

The model request following this continuation is **analysis-only**. Additionally, request six or a request after the sixth tool operation is analysis-only. The application advertises no tools and uses the existing strict final-response schema/parser. It makes no additional request and reserves no extra runtime. A tool response at that point is rejected rather than executed.

The latest inspected context record is eligible for re-disclosure alongside the new mandatory seed. Its ledger cannot substitute for supporting fields; a model can cite it only when the exact original support fits the current request. Earlier accepted batches remain unchanged.

If no pending seed or capacity remains after the duplicate, the run stops with `CONTEXT_DUPLICATE` and a PARTIAL result. There is no automatic repair call. Deadlines, provider failure or disclosure limits can still prevent the analysis opportunity from completing. The strategy creates an opportunity, not a guarantee of a positive conclusion or even an accepted observation.

## Recording and replay

New contextual transcripts carry `progress_profile=bounded-investigation-progress-v1`. Exposure events persist the exact operation ledger and analysis-only decision. `follow_up.validate_journal` reconstructs completed inspections and compares the ledger to the actual exposure. It validates duplicate origin, counters, exact permitted continuation seed, final-analysis allocation and family accounting. A fabricated duplicate receipt, altered ledger, wrong continuation or unauthorized repeated execution is rejected.

Historical transcripts without the profile use their existing rules. Existing autonomous replay continues to validate read-view bindings, original disclosure and accepted grounding. Hash-chain validity alone does not prove forensic correctness. No existing transcript is rewritten.

## Result presentation

Retrieved families derive from retained tool results; disclosed families from model-dispatch exposures; accepted-finding families from observation/interpretation support. The three are displayed separately. Context attempts, completed inspections and rejected redundant proposals have distinct counts.

No-observation output explains whether accepted analysis contained no observations, batch validation failed, or no grounded analysis batch was accepted. Tool execution alone is never presented as investigative success. The overall answer remains PARTIAL; historical hypotheses and unresolved questions are preserved.

## Synthetic validation

`tests/test_investigation_progress.py` reproduces the tool-only symptom and verifies deterministic continuation, actual re-disclosure of actor context, grounded analysis, honest empty answers, empty/partial context, no-seed termination without retry, forged replay rejection, bounded ledger size and inability to ground claims through ledger-only metadata.

The corrected matching sequence uses five model attempts and five tool operations: one context lookup, one rejected duplicate, a new authorized seed and one accepted grounded analysis. It retrieves eight records after the continuation; the baseline stopped at seven. The transcript reconstructs identically twice.

Focused context tests retain real disposable SQLite worker checks, source/time authorization, old/expired-grant rejection, multiple categories, six-call ceilings, provider/worker failures, cancellation, cleanup and unchanged synthetic database bytes. One existing scripted test now expects validation failure when its sixth response improperly requests a tool: the analysis-only contract intentionally prohibits that action; the six-call and prior-findings assertions remain unchanged.

Focused results:

| Check | Result |
|---|---|
| Progress, context, temporal follow-up, post-retrieval and Stage A regressions | 88 passed, 1 warning; 52.47 seconds |
| Final progress/context set including ledger bounds and ledger-only citation rejection | 21 passed, 1 warning; 16.36 seconds |
| Final presentation and URL-redaction checks | 2 passed, 1 warning; 3.20 seconds |
| Prior findings survive duplicate continuation (real disposable worker) | 1 passed, 1 warning; 2.21 seconds |
| Source version | 6.167 |
| `git diff --check` | Passed |

No full suite, live providers, real evidence, original transcripts, commits or pushes were used.

## Remaining limits and manual acceptance

There are still at most six model attempts, six tool operations, two temporal searches, five minutes and 5,600 bytes/request. No new retrieval types, parser changes, filename/Registry pivots, preflight changes or cross-session continuation were introduced. The ledger consumes some context capacity; particularly large original fields may still be omitted. The model may abstain, propose an invalid answer or ignore instructions; strict validation remains authoritative.

After installation in the separate test checkout:

```powershell
.\.venv\Scripts\python.exe locard.py --version
```

Expect `Locard 6.167`. In the intended case, reuse the assessment and neutral question:

```text
investigation run 3aa7e12d14d94720b172ad072c56f92d --follow-up
```

Review and approve the unchanged bounded scope. Verify that repeated context requests do not execute twice, that remaining authorized seeds can be inspected, and that output shows grounded partial findings or an explicit reason for none. A positive compromise finding is not required.

Provider-free review of the actual new run:

```text
investigation history show <actual-run-id> --json --explain
```

Inspect `operation_ledger`, `analysis_only`, `redundant_context`, authorized seed/result/exposure events and validated deltas. Confirm counts, read-view binding and final PARTIAL status without renewing the historical grant.

# Locard 6.169 — Supervised budget startup

## Diagnosis

Source baseline: 85b2802 (6.168). Diagnosis and focused validation: 2026-11-24.

Both failure points were reproduced with a synthetic v2 authorization before production edits:

1. `investigation_ai/autonomous.py:start()` supplied `Budget()` (5,600 bytes). After handoff validation, `run()` compared it against `recorded_budget()`'s `ContextBudget` (24,576 bytes), raising `ValueError: Stage A uses the approved fixed limits`. This precedes transcript initialization and evidence read-view establishment.
2. Correcting only the parent would still fail: `investigation_ai/supervision.py:_child()` reconstructed the serialized request as `Budget(**request['budget'])`, raising `ValueError: Invalid investigation budget: prompt_bytes` for 24,576 bytes.

The first failure matches the reported live phase and absence of a read view. No live transcript or case was accessed for this correction; the exact live exception is not independently recovered.

## Correction and contracts

`investigation_ai/state.py:execution_budget()` delegates contract selection to the existing `recorded_budget()` service. `autonomous.start()`, parent supervision and child reconstruction now use that selection. Supplied budgets must match the selected type and all values; serialized budgets must reconstruct to exactly the selected budget, with the complete field set. They cannot override grant limits. The existing controller equality check remains unchanged.

| Authorization | Prompt-content ceiling |
|---|---:|
| Temporal follow-up v1 | 5,600 UTF-8 bytes |
| Context follow-up v1 | 5,600 UTF-8 bytes |
| Context follow-up v2 | 24,576 UTF-8 bytes |

No change to requests, steps, tool operations, context inspection, selection, prompt construction, provider abstraction, compatibility preflight, or authorization scope. Historical replay continues using `recorded_budget()`; no recorded data is rewritten.

Child startup diagnostics now distinguish `BUDGET_CONTRACT_MISMATCH`, `HANDOFF_VALIDATION_FAILED`, `PROVIDER_START_FAILURE`, `WORKER_START_FAILURE`, and `READ_VIEW_START_FAILURE`, while preserving existing authorization/scope codes. Categories identify the failing boundary, not a speculative lower-level cause. Arbitrary exception messages are not transmitted. Cleanup and read-view status retain their existing independent reporting.

## Focused validation

`tests/test_supervised_context_budget.py` crosses the real Windows-compatible multiprocessing spawn boundary, with a synthetic provider and disposable SQLite evidence. It exercises parent serialization, child reconstruction, actual handoff validation, transcript initialization, real forensic worker/read transaction, validated analysis and provider-free reconstruction. The success test uses the ModelBackend descriptor restoration branch; only the provider is substituted. It also checks case bytes remain unchanged, budget tampering fails before provider entry, safe failure categories, historical ceilings and the budget passed by `autonomous.start()`.

Relevant suites: `test_autonomous_startup`, `test_packet_capacity`, `test_context_inspection`, `test_follow_up_discovery`, `test_investigation_progress`, `test_investigation_preflight`, `test_autonomous_stage_a`. The existing packet-capacity end-to-end test performs two temporal searches, two distinct contextual inspections and subsequent validated analysis, then deterministic replay. It uses mock tool results; the separate startup integration uses a real synthetic SQLite worker.

Startup timeout fixtures now shorten the supervisor deadline instead of supplying a budget inconsistent with the grant. Assertions about termination, descendant cleanup, partial checkpoint preservation and uncertain-cleanup fail-closed behavior remain intact.

Recorded results: the eight-file focused run produced **125 passed, 2 failed in 94.75 seconds**; both failures were older deadline fixtures supplying mismatched budgets. After correcting those fixtures, the six new startup tests, both failed tests and the existing B2 parent-timeout test produced **9 passed in 19.16 seconds**. All 128 distinct tests exercised have a passing result. `git diff --check` passed. The direct launcher reported `Locard 6.169`, alongside a session-audit coverage warning in the execution environment; audit configuration was not repaired or changed in this task.

No full suite, live provider calls, real evidence inspection, commit or push. Live acceptance remains required; successful startup is not forensic success.

## Manual acceptance

After installing this checkout in the test environment, verify:

```powershell
.\.venv\Scripts\python.exe locard.py --version
.\.venv\Scripts\python.exe locard.py
```

Expected version: `Locard 6.169`. Open the intended existing case and use the unchanged neutral question:

```text
investigation run 3aa7e12d14d94720b172ad072c56f92d --follow-up
```

Review the fresh grant: context follow-up v2, 24,576 input-content bytes, six model attempts, six tool operations, two temporal searches and five-minute execution limit. Approve only the intended provider, case, source and time scope. Confirm startup reaches the read view and authorized retrieval/analysis begins. Inspect termination, validated batch counts and cleanup independently; do not interpret startup success as proof of a supported conclusion.

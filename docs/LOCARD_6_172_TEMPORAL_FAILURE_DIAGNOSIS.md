# Locard 6.172 — Temporal failure diagnosis

Inspected November 25, 2026. Committed baseline: `5bc8507` (6.171), initially clean. This document describes the uncommitted 6.172 diagnostic changes. No real case or historical transcript was inspected; no provider requests were made.

## Conclusion and acceptance boundary

**The original live root cause remains unconfirmed.** The supplied 6.171 output identifies a non-deadline internal exception in the temporal-search phase, which includes search and handler restoration. It does not identify an exception class or failing internal operation. No further timeout, SQL-selection, batch-counter or evidence-projection correction is justified by that output.

This release implements acceptance path **B**: safe, precise localization. Synthetic irregular data reproduces several possible failures, but none establishes which occurred in the live case. Successful synthetic retrieval is not evidence of successful incident reconstruction.

## Source-confirmed path

| Step | Implementation and data-dependent boundary |
|---|---|
| Proposal validation | `investigation_ai/autonomous.py:run`, `follow_up.parse/arguments/proposed`: canonical tool shape and a currently disclosed original timestamp, not an invented anchor |
| Anchor window | `follow_up.record_window/window`: retained record field, timestamp normalization, approved time interval; invalid/missing timestamps can reject the operation |
| Worker authorization | `worker.py:serve`, `autonomous_policy.validate/operation`: current grant, case identity, sources, families, allowed tool, lifetime and ceilings |
| Deduplication | `worker.py:serve`: digest of authorized window, session-wide search keys, per-batch search count; these are retained/reset under the existing rules |
| SQL | `follow_up._search`: two indexed timestamp ranges with family filtering; at most 500 retained candidates per side plus overflow detection |
| Ordering | `_search`: parse each candidate timestamp and order by distance, timestamp, evidence ID and slot; lexically in-range malformed timestamps can fail here |
| Source validation | `autonomous_policy.record_scope`: metadata authorization before hydration; out-of-scope candidates are excluded, including conflicting source membership |
| Hydration | `retrieval/evidence.py:get_evidence`: original record, JSON fields, timestamps and provenance; malformed stored JSON or missing subtype structure can fail here |
| Projection | `investigation_ai/tools.py:compact`, `llm/context.py:compact_record`, `llm/artifact_fields.py:compact_artifact`: bounded original fields and limitations; assumptions include required subtype keys and timestamp structure |
| Result validation | `follow_up.validate_result/time_eligible`: matching identities, family, sources and a retained timestamp witnessing eligibility. An indexed timestamp alone cannot authorize a returned projection lacking that witness |
| Restoration | `follow_up.search` clears its handler; `worker.serve` restores `case.ReadView.deadline`. Successful restoration must not overwrite the originating failure location |
| Response | `worker.serve` serializes a bounded result; `runner.ForensicWorker._exchange` validates the response/diagnostic shape before controller acceptance |

The five-second search deadline and 6.171 coordination remain unchanged. `case.ReadView.check_identity` still checks transaction/identity, and the controller still attempts the final read-view check and independent cleanup. No accepted findings, read view or search history is reset on a batch transition.

## Diagnostic contract

`worker_diagnostics.py` adds `worker-failure-v2`. Historical `worker-failure-v1` remains valid without requiring new fields. The existing outer `investigation-failure-v1` and `WORKER_FAILURE` reporting remain compatible.

New bounded fields:

- `location`: fixed application identifier, including anchor resolution, worker authorization, search deduplication, timestamp query, candidate ordering, source-scope validation, hydration, projection, result validation, handler setup/restoration, response serialization and parent response validation. `SEARCH_EXECUTION`/`WORKER_OPERATION` provide honest fallback locations.
- `exception_class`: exact allowlist of common built-in/SQLite exception classes, plus `JSONDecodeError`; unrecognized classes become `Other`. Custom exception names and messages are not emitted.
- `counts`: candidates fetched/examined and source-excluded candidates (each 0–1,000), and successfully projected records (0–3). These are progress counters, **not accepted retrieval counts**. A malformed parent response has unknown internal progress, represented by zero counters.

Existing category, phase and deadline-exceeded Boolean remain. Recognized timestamp/result-validation errors and malformed stored JSON use `SEARCH_DATA_VALIDATION_FAILURE`; arbitrary `ValueError`, `KeyError`, `TypeError` and other programming exceptions remain internal failures. Source-policy rejections retain their separate category. Classification uses fixed types/sentinels, not arbitrary exception text in diagnostics.

`Trace.at` captures the originating location and bounded counter snapshot on the exception. A subsequent successful `finally` restoration does not relabel it. If restoration itself raises a new exception, that failure is reported at restoration. No secondary traceback or original exception prose is published.

Serialization exceptions now return a bounded protocol failure when the output channel remains usable, instead of escaping without a typed response. Oversized responses retain fail-closed rejection with a serialization location. Parent-side malformed response validation supplies its own location and does not claim knowledge of the remote exception class.

Normal output adds only safe location, exception class and counters. No evidence IDs/values, SQL parameters, raw messages, URLs, usernames, paths or credentials are added. Existing stopped/terminal events carry the typed diagnostic through the existing transcript hash chain and replay validation; no separate evidence store or audit channel was introduced.

## Synthetic reproduction

`tests/test_temporal_failure_diagnosis.py` extends `test_extended_search_reliability.py` using a real spawned supervisor/controller and persistent read-only SQLite worker. The provider is scripted. Disposable fixtures contain dense repeated timestamps; a later seed permits batch two. The expanded sequence completes six operations in batch one, five distinct context inspections across the run, and a third temporal search in batch two.

| Fixture/fault | Observed result |
|---|---|
| Missing process/command fields; duplicate-name/null/long/malformed EventData entries | Third search succeeds; existing bounded EventData limitations remain in effect |
| Lexically in-range invalid indexed timestamp | `ValueError`, `CANDIDATE_ORDERING`, recognized data-validation failure |
| Valid indexed timestamp but hydrated EVTX SystemTime outside the search window | `ValueError`, `SEARCH_RESULT_VALIDATION`; no ineligible projection accepted |
| Invalid locator JSON | `JSONDecodeError`, `EVIDENCE_HYDRATION`; no raw JSON exposed |
| Injected projection `KeyError` | `EVIDENCE_PROJECTION`, internal error |
| Injected handler-restoration `TypeError` | `PROGRESS_HANDLER_RESTORATION`, internal error |
| Injected unserializable result | `WORKER_RESPONSE_SERIALIZATION`, protocol error |
| Mixed EVTX/Browser candidates with multiple timestamps, missing optional referrer and separately sourced Browser contexts | Third search succeeds; only authorized Browser records returned |

The injected faults test instrumentation, not claims about production root cause. Deliberately malformed disposable storage tests fail-closed behavior rather than justifying silent data repair. No original evidence is discarded or rewritten. No change was made to timestamp selection, projection or source authorization to accommodate these fixtures.

Tests verify retained prior findings/checkpoints, two equal independent provider-free reconstructions, unchanged disposable database bytes, safe diagnostics and cleanup. Existing focused regressions cover SQL interruption, parent timeout, process exit, cancellation, duplicate refusals, source/time constraints and legacy grants. Failed retrievals are not counted as completed searches. Surviving-worker final read-view checks and supervisor cleanup are distinct assertions.

Focused validation results:

- Combined temporal-diagnostic, extended-search, extended-investigation, follow-up, context-inspection, worker and post-retrieval-packet suites: **121 passed in 118.76 seconds**.
- Final temporal-diagnostic suite, including added rendering, final read-view outcome and completed-search assertions: **24 passed in 30.24 seconds**. This overlaps the combined run; counts are not additive unique coverage.
- `git diff --check`: passed. Source version in `pyproject.toml`: **6.172**.

No full regression suite or live acceptance is part of this task.

## Remaining uncertainties and manual acceptance

The production exception, exact failing record shape, and whether restoration failed are unknown. Synthetic evidence does not establish an inherent third-search bug. Optional forensic fields and source conflicts do not all fail: many already have deliberate omission/limitation handling. The new identifiers let the next failure distinguish those boundaries without exposing sensitive parameters.

After installing 6.172 in the test checkout:

```powershell
.\.venv\Scripts\python.exe locard.py --version
.\.venv\Scripts\python.exe locard.py
```

Expect `Locard 6.172`. Select the intended case and repeat the approved workflow:

```text
investigation run <assessment-id> --follow-up --extended
```

Review and approve the fresh scope/grant. Historical transcripts do not authorize this execution. If the failure recurs, retain the category, phase, location, exception class, bounded counters and deadline Boolean, alongside completed-search/checkpoint and cleanup status. Do not share raw evidence or credentials merely to obtain these diagnostics.

No optional standalone real-case retrieval command was added: the specific failed parameters are unavailable and a new authority surface is unnecessary for this instrumentation release. A provider-free targeted retrieval procedure, if still needed, should be scoped separately to analyst-supplied parameters and fresh explicit authorization; never reuse an expired grant.

Unchanged limits: 18 AI requests, 18 evidence operations, six temporal searches, three batches, 900-second session, five-second search, 24,576-byte input. Mandatory AI preflight, forensic grounding, parsers and provider routing are untouched. No retries, grant renewal, commit or push.

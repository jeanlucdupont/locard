# Locard 6.165 — Post-retrieval disclosure failure

Date: 2026-11-24. Starting revision: `adb7896` (6.164). This document describes uncommitted 6.165 changes awaiting manual acceptance.

## Established cause and limits of the diagnosis

The allocator and its caller imposed incompatible requirements. `autonomous.packet()` selected the current record and only the first prior supporting record, but `disclosure.prompt()` ranked fields without reserving either the current record or the exact field cited by the previous batch. The caller then raised `PRIOR_SUPPORT_NOT_DISCLOSED` if none of those prior fields survived. An eligible record's presence did not guarantee that its required field was represented. Competition could also displace the current record. The outer handler recorded these as generic `OPERATION_FAILURE / ValueError`.

The targeted synthetic sequence reproduced `PRIOR_SUPPORT_NOT_DISCLOSED` after two successful three-record follow-ups, one validated batch and the next `show_evidence`, with eight retrieved records. This is a confirmed implementation defect matching the reported failure location. It does **not** establish the exact subtype in the referenced live run: its case and transcript were deliberately not accessed, and the supplied generic diagnostic cannot settle that question.

The relevant execution trace in `forensic_assistant/investigation_ai/autonomous.py:run` is:

`worker.call → validate result → append result → required activity completion → state.ingest → remove pending seed → packet → state.prompt → disclosure.prompt → append exposure → state.disclose → provider`

`State.ingest` copies validated projections into the retained store. No matching business-level failure was found there or in ordinary pending-seed removal. The reproduction fails in packet preparation, before exposure and before another provider call.

## Correction

- `autonomous.packet` / `_packet_once`: select current records and prior supporting record IDs; supply the exact previous observation pointers and values to the allocator. At most one deterministic repack removes optional unresolved prose and redundant search-result IDs. This is not a model retry or an evidence lookup.
- `disclosure.prompt`: reserve one eligible substantive original field from the required current record first, then try exact retained prior observations, then ordinary ranked fields and complete interpretation objects. Field IDs, values, semantic descriptors, provenance references and truncation metadata remain unchanged.
- Missing required current evidence and genuinely oversized mandatory disclosure have distinct failure codes. Previous support that cannot fit is counted as omitted rather than causing a generic failure. It remains in accumulated findings, but current-request grounding continues to reject a new citation to an absent field.
- `State.prompt` forwards the optional allocation requirements. Unrelated callers retain the existing default interface.
- Final serialized message content, including the follow-up OpenAI instruction envelope, is measured in UTF-8 bytes and remains limited to **5,600 bytes**. Temporary record filtering and budget reduction are restored on failure.

This is bounded scalar disclosure, not a promise to include an entire current record or every historical finding. At most 12 observations and four complete deterministic interpretations remain eligible per compact packet. No new artifact-specific ranking rules were introduced.

## Safe diagnostics and replay

`failure_diagnostics.py` defines `investigation-failure-v1`, a closed vocabulary for code, phase and operation, plus bounded retrieved-record, accepted-batch, model-attempt, tool-call and prompt-limit counts. It never serializes arbitrary exception text. Examples:

| Condition | Code |
|---|---|
| Required record has no eligible disclosure fields | `CURRENT_RECORD_NOT_DISCLOSED` |
| Required disclosure cannot fit | `PROMPT_BUDGET_EXHAUSTED` |
| Invalid original field/value or packet | `EVIDENCE_PACKET_VALIDATION_FAILED` |
| Normal allocation exhaustion | `RESOURCE_BUDGET_EXHAUSTED` |
| Worker / provider error | `WORKER_FAILURE` / `PROVIDER_FAILURE` |
| Unexpected exception | `INTERNAL_FAILURE` |
| Required audit/storage error | `AUDIT_OR_PERSISTENCE_FAILURE` |

The stopped event and terminal result retain the safe diagnostic. Human presentation shows its code, phase and operation. Exposure events include represented and omitted candidate counts, omitted prior-support fields and whether optional context was removed. Replay checks their shape and represented counts against the exposure. These are allocation diagnostics, not proof of exhaustive case coverage.

Existing disclosure and delta validation still govern replay. Historical events without these optional diagnostics remain supported. Previously accepted deltas survive later packet failure; the existing final read-view check and worker close still run. A persistence failure can itself prevent durable publication; this patch does not bypass mandatory auditing or claim cleanup beyond existing confirmation.

## Synthetic reproduction and validation

`tests/test_post_retrieval_packet.py` uses synthetic Browser and EVTX projections, long URL chains, large command/EventData values, multiple timestamp slots and substantial source metadata. A scripted OpenAI stand-in executes the requested seed → follow-up → follow-up → accepted analysis → show sequence. No external service is contacted.

Before correction, the matching test failed after one accepted batch with `PRIOR_SUPPORT_NOT_DISCLOSED`. After correction it reaches two accepted batches using exactly four model calls and the same authorized lookup sequence. Tests measure the actual instruction-adapted request size, independently reconstruct the journal twice, reject forged or omitted citations, preserve source projections, exercise typed partial failures and verify worker closure/final checking.

Focused results on the working tree:

| Check | Result |
|---|---|
| `test_post_retrieval_packet.py`, `test_follow_up_discovery.py`, `test_compact_disclosure.py`, `test_autonomous_stage_a.py`, `test_synthesis_consumer.py` | 133 passed, 1 warning; 68.80 seconds |
| Subsequently added `test_allocation_receipt_is_bound_to_disclosed_counts` | 1 passed, 1 warning; 0.72 seconds |
| `git diff --check` | Passed |
| Source version read from `pyproject.toml` | 6.165 |

The existing injected audit-failure test now expects the specific persistence code instead of generic `OPERATION_FAILURE`; its no-dispatch and prior-findings safeguards remain intact. No full regression suite, real ingestion, real-case inspection or provider requests were run.

## Safety and remaining limitations

Authorization, source/time restrictions, worker containment, provider abstraction, retrieval types, request/lookup limits, interpretation semantics and final grounding are unchanged. There are no filename/path pivots, new schema requirements or case-sidecar writes.

The allocator is deterministic and bounded, not an exhaustive optimizer. Large original values and required metadata may still prevent a useful field from fitting. Omitted candidates were not necessarily assessed for relevance. A bounded partial result is not a complete investigation or evidence of absence. Synthetic worker closure does not prove operating-system cleanup of the uninspected live run.

## Manual acceptance (analyst only)

After installing this development version in the test checkout:

```powershell
.\.venv\Scripts\python.exe locard.py --version
```

Expect `Locard 6.165`. Open the intended case through the normal workflow. If desired, perform the separately authorized provider readiness check, then reuse the saved assessment and the existing neutral question without adding known indicators:

```text
ai check --full
investigation run 3aa7e12d14d94720b172ad072c56f92d --follow-up
```

Review the authorization before approving. After completion, inspect the actual new run (do not reuse a historical run ID):

```text
investigation history show <actual-run-id> --json --explain
```

Confirm no more than the existing two bounded follow-ups, unchanged request/lookup ceilings, exposure after successful packet preparation, explicit omissions and retention of accepted findings. If a limitation prevents progress, expect its safe code and phase instead of generic `OPERATION_FAILURE`. Model choices are nondeterministic; this correction does not promise the same live lookup sequence or a supported final conclusion.

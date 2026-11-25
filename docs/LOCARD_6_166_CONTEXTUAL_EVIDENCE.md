# Locard 6.166 — Contextual evidence inspection

Date: 2026-11-24. Baseline: `1c267cf` (6.165). These working-tree changes await analyst acceptance; no live case or provider was accessed.

## Disclosure limitations found

These are distinct layers, not interchangeable promises of available evidence:

| Layer | Implementation and limitation |
|---|---|
| Acquired original | Ingestion may encounter unavailable, malformed or partial events. This feature does not reparse original files or recover missing acquisition data. |
| Persisted normalized evidence | `retrieval/evidence.py:get_evidence` can return retained `event_data_json`, provider/channel and normalized attributes. Absent persisted data cannot be invented. |
| Worker projection | `investigation_ai/tools.py:compact` uses `retrieval/event_data.py:projection`: ordinary EventData exposure is capped at 1,024 bytes, with entry/value truncation. Useful fields later in the original array may be absent. |
| Compact disclosure | `investigation_ai/disclosure.py:prompt` further selects individual fields under the 5,600-byte serialized request ceiling. Retrieval is not model disclosure. |
| Current-request grounding | `State.disclose` and `State.render` authorize citations only through the actual current disclosure. A retained historical field is not sufficient. |

Before this change, the follow-up model could request only temporal neighbors. It could not ask for an omitted actor or object in an already retrieved event. This explains a capability gap, not a claim that the uninspected live case actually contains any particular missing field.

## Operation and authorization

The existing `investigation run ... --follow-up` workflow now prepares a fresh `investigation-context-follow-up-v1` grant. Its tools are `show_evidence`, `follow_up`, and `inspect_context`. The approval display explicitly describes EVTX categories, repeated OpenAI disclosure and shared limits.

Synthetic model proposal:

```json
{"action":"tool","tool":"inspect_context","arguments":{"evidence_id":"EVTX:<original-hash>:Offset:<original-offset>","category":"actor"},"reason":"Inspect the recorded actor context"}
```

The placeholder ID above is illustrative, not a valid executable request. Real requests require an exact EVTX evidence ID in the current disclosure. Categories are `event`, `actor`, `object`, and `process`; arbitrary pointers, SQL, paths and search parameters are rejected. The reason remains bounded proposal text, not retrieval authority.

Historical `investigation-temporal-follow-up-v1` grants remain replayable and can execute their original tools while valid; they cannot authorize context inspection. No new CLI command is introduced. The exact new response schema is recognized by the OpenAI adapter; canonical validation remains strict.

## Deterministic selection

`investigation_ai/context_inspection.py` is a reusable backend service. The worker rechecks source/time membership before fetching the exact record in its existing pinned read view. It requires both prior retrieval and controller-supplied disclosure membership.

- `actor`: original field names containing subject, account, user, logon or SID.
- `object`: names containing object, access, permission, security descriptor or handle.
- `process`: names containing process, command, image, executable or parent.
- `event`: a bounded overview that prioritizes those named context categories before background fields.

Matching uses normalized field **names**, not event IDs, suspiciousness, known incident values or model-generated search terms. Categories guide selection only: they do not establish that a named person caused an action or that co-occurring values form a causal relationship. Ambiguous names may require a different category or ordinary evidence review.

Within a category, original ordinal order is deterministic. The existing original-payload reader remains capped at 32,768 UTF-8 bytes and 256 fields. A context result selects at most eight complete entries and 1,800 serialized bytes. Oversized entries are omitted atomically rather than shortened; original names, ordinals, values and explicit truncation flags are retained. Existing normalized-field truncation qualifications remain conservative. Missing or non-fitting context is explicitly unknown.

The ordinary compact selector now admits provider and channel. For contextual records, current EventData receives priority and up to four original fields are attempted before optional prior support. Every field still carries its pointer, semantic descriptor and provenance reference. Subsequent filling and exact byte measurement remain bounded. Optional prior support may be omitted and cannot then ground a new claim. A context result fitting its worker limit does not guarantee every selected field fits the final model request.

## Execution, accounting and replay

`autonomous.run` validates the typed proposal against the current exposure, persists `context_proposed` with the exposure digest, and schedules the operation through the existing authorization/activity/worker/result/exposure sequence. It does not remove a pending seed merely because another record was context-inspected. Accepted earlier batches remain intact.

The unchanged limits are six total tool operations, six model attempts, two temporal searches, eight investigation steps, 300 seconds and 5,600 serialized message-content bytes. Context inspection consumes a tool operation and its subsequent reasoning consumes an existing model attempt. It creates no new evidence IDs or refill allowance. Repeated requests for the same record/category stop explicitly; there are no automatic retries or hidden provider calls.

`follow_up.validate_journal` verifies proposal-to-current-exposure binding, grant eligibility, authorized operation/result identity, category/ordinal/count bounds, read scope, duplicate requests and terminal accounting. Existing autonomous replay validates the result read-view binding, compact fields and accepted observations. Reconstruction needs neither a provider nor the live case. As before, authenticated worker results are the recorded original-projection authority; a hash chain alone does not prove acquisition completeness.

The parent supervision, read transaction, deadlines, final integrity check and cleanup are unchanged. Invalid IDs or grants fail closed. Failed operations preserve accepted findings and a PARTIAL result, subject to existing mandatory persistence guarantees.

## Human presentation

Normal output separately shows contextual-inspection counts. Identical observation qualifications are grouped once. Questions differing only in word order or selected generic question words are consolidated for display; negations and distinct substantive terms remain distinct. The complete original question list remains in structured history. Observations, deterministic interpretations, hypotheses and coverage limitations remain separate. No summary is promoted to a forensic conclusion.

## Focused validation

Synthetic tests use disposable SQLite evidence, the real supervised read-only worker and a scripted OpenAI stand-in. They cover initial omission of actor fields, typed inspection, recovery of original ordinals, subsequent grounded use, independent replay, forged references, old/expired grants, strict schema adaptation, unknown oversized context, shared operation exhaustion, worker/provider failures, cancellation, retained prior findings, cleanup and unchanged database bytes.

Focused checks:

| Check | Result |
|---|---|
| Context, temporal follow-up, post-retrieval packet, compact disclosure and Stage A regressions during implementation | 98 passed; 1 warning; 44.04 seconds |
| Expanded context/failure tests plus follow-up and post-retrieval regressions | 56 passed; 1 warning; 32.19 seconds |
| Final context validation checks | 11 passed; 1 warning; 10.68 seconds |
| `git diff --check` | Passed |
| Source version | 6.166 |

One existing budget-exhaustion fixture now removes provider and channel as well as other small fields, so it still tests its original condition: the only usable original value is too large. No budget or grounding assertion was weakened. No full suite, live provider request, real-case access, commit or push was performed.

## Deferred capabilities and acceptance

Inspection is EVTX-only. There is no arbitrary pagination, filename/path pivot, raw-file recovery, cross-artifact context operation, new event interpretation or semantic guarantee about actor/object name classification. The original payload and request limits can still omit useful information. Live model decisions and investigative usefulness require manual acceptance.

After installing the development checkout in the test environment:

```powershell
.\.venv\Scripts\python.exe locard.py --version
```

Expect `Locard 6.166`. In the intended case, reuse the saved assessment and neutral question:

```text
investigation run 3aa7e12d14d94720b172ad072c56f92d --follow-up
```

Confirm that the new approval includes EVTX contextual inspection and unchanged shared budgets before authorizing. Look for a progression from partial disclosure to `inspect_context`, then an observation grounded in the newly disclosed original field. A successful run need not prove compromise. Missing context must remain unknown.

Use the actual newly generated run ID for provider-free recorded review:

```text
investigation history show <actual-run-id> --json --explain
```

Review `context_proposed`, authorized operation, result, exposure and validated delta; inspect original ordinals, omissions, request sizes and final PARTIAL accounting. No historical grant is renewed by replay.

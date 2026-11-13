# Locard 6.130 — Response contract reliability diagnostic

Date: 2026-11-13 (America/Chicago). Revision:
`46b9226fc8a04f9bbd40c7f945571f4dddc2814e`, `main`, version **6.130**.
The pre-existing uncommitted readiness report and its ignore exception were
preserved. This diagnostic adds this document and its exact ignore exception;
production source, tests, configuration and version are unchanged.

## 1. Finding and recommendation

**Yes: the current contract can reject an otherwise acceptable investigative
proposal solely because an inference includes a bounded root explanation.**
This was reproduced with the actual installed SDK, mocked HTTP, and production
parent validation. The provider-facing schema permits the response; local
outcome validation rejects it. The system instructions do not explicitly state
that inference requires `r = ""`.

This does **not** establish which branch occurred in the discarded live response.
An abstention with an empty reason produces the same diagnostic. Neither its
outcome nor its reasoning quality can be reconstructed from the reported error.

Recommend **6.131**, after authorization: a new versioned quality-response policy
that permits a bounded outcome explanation for inference, retains nonempty
abstention reasons, and preserves all explanation text as **unverified model
commentary**. Do not discard it, move it into evidence, or claim its consistency
has been semantically verified. Add bounded outcome/count/reason-state diagnostics.
Do not add another repair rule, retry, larger budget or provider fallback.

Do not recommend another paid test until this narrowly scoped correction has
passed provider-free acceptance. Nothing proposed here has been implemented.

## 2. Live evidence and what is unknown

User-reported live result: OpenAI `gpt-6.1-sol`, `d2-cross-artifact-request-v1`,
16,268/16,384 bytes, 1,024 output tokens, one attempt, zero lookups, no retries,
confirmed cleanup, original S3 `NOT_ASSESSABLE`. Usage was 4,025 prompt + 950
completion = 4,975 total tokens. Rejection was
`response_schema_validation`, specifically `outcome_validation / outcome_reason`.
No validated explanation was displayed. The raw response is unavailable.

Source inspection establishes that the normal path reached parsed JSON, typed
schema checks, and canonical outcome validation. Normal completion extraction
must have succeeded to reach this branch: refusal, `length` or an unexpected
finish reason fails earlier. **The exact recorded finish value was not supplied**;
the normal path accepts `stop`/`end_turn`. This inference from the code is not a
recovered live finish-reason log.

Unknown: outcome, account text, reason text, actual account count within its
allowed range, content quality, reasoning-token split, visible output token
count, and whether later grounding would have passed. A valid typed alias alone
does not prove premise closure or semantic entailment. No invented response is
used in this diagnosis.

## 3. Exact failure semantics

`investigation_ai/d2_quality.py:validate()` executes:

1. Canonical shape/string/count validation through `_nonempty()` and
   `contracts.validate()`.
2. Outcome/account-count consistency.
3. For one competing-explanations account, a nonempty alternative.
4. Outcome/root-reason consistency.

Only step 4 raises `D2_QUALITY_OUTCOME_REASON`.
`d2_diagnostics.failure()` maps that exact application-owned constant to
`outcome_validation / outcome_reason`. Parent-origin diagnostics wrap the stage
as `parent_canonical_revalidation` and retain the underlying failure stage.

| Outcome | Required account count | Required `r` | Exactly when outcome_reason occurs |
|---|---|---|---|
| `new_inference` | 1–2 | Exact empty string | Nonempty canonical-valid string |
| `competing_explanations` | 1–2; one requires alternative | Exact empty string | Nonempty canonical-valid string, after alternative check |
| `no_material_inference` | 0 | Nonblank string | Exact empty string |
| `insufficient_packet_support` | 0 | Nonblank string | Exact empty string |

Whitespace-only reasons, NUL, overlong reasons, wrong types, missing fields and
wrong account counts fail **before** this rule, with different diagnostics.
The branch is deterministic from response structure/text presence alone. It is
an application-level conditional contract failure, not evidence-grounding or
semantic evaluation of the reason's meaning. Helpful and contradictory nonempty
reasons are rejected identically for inference.

Twelve direct canonical probes (four outcomes × empty/nonempty/whitespace reason)
confirmed this table. No provider or case database was used.

## 4. Provider contract versus canonical contract

`d2_quality.SCHEMA` is a closed object with all four fields required:

```text
v: enum d2q1
o: enum new_inference | competing_explanations |
        no_material_inference | insufficient_packet_support
a: array, 0–2 ACCOUNT objects
r: string, maximum 240
ACCOUNT: s, e, c, i, a, u, d, n (all keys required)
s: nonempty string <=400
e: 1–6 current O references; c: 0–6 current O references
i: 0–4 current I references (zero allowed when packet has no interpretations)
a/u/d/n: strings <=240/320/400/400; exact empty string allowed
```

`d2_schema.from_packet()` replaces reference string schemas with packet-specific
enums. `ai/openai_schema.request_schema()` strips `uniqueItems` on the recognized
D2 schema. Duplicate valid references are then handled by the existing bounded,
set-preserving normalization; unknown references are not repaired.

The wire schema contains **no conditional relationship between o, a and r**.
It permits inference with a reason, abstention with no reason, and incompatible
outcome/account counts. Provider strict-schema compliance is therefore
insufficient for canonical acceptance. Provider maxLength is characters;
canonical validation also applies UTF-8 byte, blank and NUL restrictions.

Current `d2_quality.GUIDE` says: `Inference:1-2 accounts. Abstention:0 and r reason`.
It does not say `r` must be empty for inference. The cross-artifact guide adds
evidence qualifications and comparison guidance, not this missing condition.
Legacy guide wording about optional empty text is not a clear inference-specific
root rule either.

The root reason is not needed to encode an inference's evidence or alternative:
those have account fields. Making it a required empty string imposes a convention
with no additional forensic grounding benefit. But a reason that a model supplies
may express meaningful caution or conflict and cannot safely be deleted.

## 5. Provider-free first-failure matrix

Twenty cases used installed OpenAI SDK + LiteLLM, `httpx.MockTransport`, exact
production request-body equality, `cloud_worker.generate()`, and
`d2_execution.validate_model_response(parent=True)`. Socket connection functions
were blocked. Each case made exactly one **mock transport** call, zero network
calls. Original evidence was synthetic except the separate historical request
size measurement. No rejected live response was captured or persisted.

The table reports the underlying first failure; the diagnostic helper was invoked
at that boundary to avoid conflating the enclosing parent-stage label.

| Case | Result / first stage and code |
|---|---|
| 1. Inference, empty reason | Accepted |
| 2. Same inference, bounded reason | `outcome_validation / outcome_reason` |
| 3. Abstention, valid reason | Accepted |
| 4. Abstention, empty reason | `outcome_validation / outcome_reason` |
| 5. Competing account with alternative | Accepted |
| 6. Competing account, contradictory root reason | `outcome_validation / outcome_reason`; no semantic contradiction analysis occurred |
| 7. Qualified hypothesis | Accepted |
| 8. Empty original support list | `provider_schema / item_count`, `/a/0/e` |
| 9. Unknown O99 | `provider_schema / unknown_support`, `/a/0/e` |
| 10. Duplicate valid O1 | Accepted; one duplicate removed with normalization receipt |
| 11. Registered interpretation missing a premise | `interpretation_premises / incomplete_interpretation` |
| 12. Specific proposed examination | Accepted |
| 13. Empty optional account text | Accepted |
| 14. 401-character statement | `provider_schema / utf8_byte_limit`, `/a/0/s` |
| 15. Malformed JSON | `json_parsing / malformed_json` |
| 16. Finish reason length | `output_truncation / output_truncated` |
| 17. Explicit refusal | `provider_refusal / provider_refusal` |
| 18. Finish reason content_filter | `sdk_response_extraction / invalid_response_envelope` |
| 19. Valid response, mocked 1,000 completion tokens | Accepted; stop preserved |
| 20. Valid response, mocked 240 tokens under a simulated 256 allowance | Accepted; stop preserved |

Cases 19–20 test usage/envelope handling, **not real tokenization or generation**.
The actual serialized request remained at the required 1,024-token ceiling;
case 20 did not modify that policy. Mock usage is not evidence that a model can
produce this answer within 240 tokens. Refusal/truncation were distinct from
outcome validation. All normally completed cases preserved finish `stop`.

Three existing focused regressions also ran unchanged:

- `test_d2_cross.py::test_windows_supervisor_history_roundtrip`
- `test_d2_cross.py::test_windows_rejected_response_sanitized`
- `test_d2_cross.py::test_parent_does_not_trust_worker_acceptance`

**3 passed, 1 warning, 21.26 seconds**, pytest return code 0. Warning: pytest cache
path creation, not an assertion failure. The existing diagnostic launcher exits
after pytest returns to avoid the previously observed SDK host shutdown issue;
natural test-host shutdown is not established by this run. The subprocess
cleanup and independent parent-validation assertions themselves passed.

## 6. Output budget and investigative usefulness

The installed SDK's `openai/types/completion_usage.py` documents reasoning tokens
as part of total completion tokens for output limits. Locard's
`cloud_worker.complete()` and `d2_diagnostics.usage()` retain only prompt,
completion and total counts, not `completion_tokens_details.reasoning_tokens`.
Therefore **950 is not necessarily 950 visible JSON tokens**. No split is
recoverable from the supplied live summary.

`response_envelope.content()` rejects length, refusal and unexpected finish
reasons distinctly. `cloud_worker.complete()` returns the accepted OpenAI finish
reason, and D2 diagnostics can retain it even after local response validation
fails. The live failure is not evidence of truncation; 950/1,024 alone cannot
establish truncation or prove ample spare reasoning capacity.

The synthetic useful account was **514 UTF-8 bytes**; the abstention fixture was
**100 bytes**. The prior readiness assessment also validated a 688-byte account.
These are measured serialization sizes, not typical live-token distributions.
No model-specific tokenizer measurement was available offline; no tokenizer
download or provider request was attempted in this diagnostic. The finite byte
sizes demonstrate that concise prose need not be large, but do not establish
reliable generation within a reasoning-inclusive token budget. Two maximal
accounts could approach 3,520 bytes of allowed prose before JSON/references.

The synthetic account explicitly represented possible pathname correspondence,
an independent-copy alternative, unknown volume/clock identity, comparison of
recoverable hashes/volume mappings, and a separately authorized examination
whose evidence availability is unknown. These all fit the existing contract
without asserting causality or execution. Synthetic acceptance is not successful
live investigative reasoning.

The contract permits two long accounts plus overlapping alternative/assumption/
discriminator/examination fields, which can encourage repetition. Yet this failure
does not justify enlarging the output ceiling. First simplify the root convention,
preserve concise guidance, and measure actual completion/usage in a later approved
test. Do not conflate readable text length with hidden reasoning consumption.

## 7. Alternative designs and exact request costs

Measurement used the same copied history, question, OpenAI model and full evidence
envelope as the readiness report. Baseline complete-body digest is
`19b7020921b08d47885812c16a92778eb8bb3dd2c51859b93e6ae8035f48c4b5`.
Bodies were serialized with HTTPX's JSON serializer, as used by the existing SDK
gate. Variants are **design measurements only**; production's exact schema/policy
recognizers do not authorize execution of these alternative contracts.

| Design | Complete bytes | Schema bytes | Assessment |
|---|---:|---:|---|
| A. Current | 16,268 | 1,021 | Fits; avoidable conditional mismatch persists |
| B. Reason allowed for inference | 16,334 | 1,021 | Fits, 50 bytes spare; strongest narrow candidate |
| C. Nested inference/abstention variants | 17,351 | 2,063 | 967 over ceiling; does not yet encode competing-one-account alternative rule |
| C. Four branches including competing-one/two accounts | 19,236 | 3,948 | 2,852 over ceiling; much larger than necessary |
| D. Drop reason locally, unchanged wire | 16,268 | 1,021 | Fits but unsafe loss of meaningful text |
| E. Remove outcome discriminator | 16,235 | 891 | Fits in this illustrative measurement; broader outcome redesign |

B adds exactly this candidate instruction:
` Root r explains outcome choice; it is unverified, never evidence.`
Same-width version identifiers would not themselves grow this size; final
implementation must remeasure all changed wording/schema, not rely on this estimate.

C uses a root object with required `result`, containing nested `anyOf` branches;
it avoids a root-level union. Four branches distinguish inference, competing with
one nonempty alternative, competing with two accounts, and abstention. MinLength
still cannot enforce canonical nonblank/byte rules. Actual provider compatibility
of a new contract would require its explicit adapter and mock-schema tests; it
is not established merely by serialization. It also adds a response wrapper.

E removes `o` and its required entry and appends candidate account-count guidance.
Its measured envelope still contains old outcome wording and is **not a deployable
prompt**. Final wording would need replacement and remeasurement. This option
loses the explicit distinction between no new material inference and insufficient
support unless another field restores it. That is a larger semantic change than B.

| Design | Canonical rules, information and compatibility |
|---|---|
| A | No migration, but requires clearer instructions or a larger conditional schema. Stronger evidence safety is not gained from empty inference r. |
| B | Keep outcomes/account rules and all grounding checks; allow existing bounded r for inference. Preserve/display it as unverified rationale, never support. A contradictory rationale remains visible and invalidates analyst usefulness, not mechanically verified as consistent. Requires versioned parsing/rendering policy; retain legacy d2q1 semantics. |
| C | Provider-enforced outcome shape reduces one mismatch, but duplicates account schema, exceeds budget and adds adaptation complexity. Cannot enforce semantic entailment, whitespace or UTF-8 limits by itself. |
| D | Trimming whitespace, dropping nonempty r or moving it into another field is not proven semantics-preserving. It may erase caution/contradiction or change attribution. Reject as a general correction. Existing valid-alias set deduplication is materially different. |
| E | Could unify abstention/explanation, but removes meaningful outcome distinctions and requires broader UI/validator compatibility work. No evidence yet that this disruption is necessary. |

For all variants, references, hypotheses, alternatives, uncertainty and proposed
examinations must remain. B changes no reference namespace or evidence authority.
Neither B nor C makes schema compliance proof of forensic entailment. More
generous root text can marginally increase response size (up to the existing
240-byte canonical limit); no extra fields or output allocation are required.

## 8. Observability correction

Current `outcome_reason` is payload-safe but ambiguous. It does not record the
selected outcome, account count or reason state. Future versioned bounded
diagnostics should include only:

```text
outcome: one of four registered enums
account_count: 0..2
account_count_consistent: boolean
root_reason_state: empty | nonempty | invalid
rule: inference_reason_forbidden | abstention_reason_required
completion: existing closed enum
usage_availability: existing closed enum
```

Populate these before discarding a rejected response, using validated primitive
types and a closed vocabulary. The inference-forbidden branch would apply only
to the historical policy after B is implemented. Existing completion/usage
metadata should remain. No raw text, field values, arbitrary keys, credentials or
raw-response persistence is needed. Preserve the 2,048-byte diagnostic bound and
32-KiB terminal bound; do not append unbounded explanatory exceptions.

## 9. Focused architectural assessment

Source path:
`cloud_worker.generate/complete` → response envelope →
`d2_normalization.canonicalize` → typed wire structural validation → reference
membership/set deduplication → `d2_quality.expand_response/validate` →
`d2.validate_response` → `d2_quality.parse/validate` → evidence/premise checks →
parent repeats against frozen authority.

- Repeated canonical shape validation within expand/parse is a possible small
  consolidation opportunity, not the live cause. Do not remove boundary checks
  as part of this correction.
- Independent parent validation is necessary because the child is not evidence
  authority. Wire expansion, packet sealing, source/view binding and typed aliases
  protect different boundaries; they are not redundant format patches.
- d2c1, d2q1 and d2x1 coexist. d2x1 changes request selection/budget while reusing
  d2q1 response semantics. No evidence here establishes that legacy paths are safe
  to delete. Version new response semantics instead of silently reinterpreting
  old output.
- Exact schema recognition appears in `d2_schema`, `d2_wire.schema_for`,
  `ai/openai_schema` and the transport gate. This coupling is deliberate admission
  protection; every recognized-policy integration needs coordinated tests.
- `_nonempty()` accommodates permitted exact-empty optional strings within a
  generally nonblank canonical validator. The root rule then adds a second,
  inadequately communicated outcome condition. This is the demonstrated avoidable
  complexity; it does not justify a broad refactor.
- Existing duplicate-alias normalization preserves a bounded eligible reference
  set. Treating arbitrary prose as disposable would not preserve semantics.

## 10. Proposed next change and acceptance gate

Authorize a focused **6.131** implementation if B is accepted:

1. Introduce a new explicit response/validation policy (for example d2q2, final
   naming decided in implementation); preserve d2q1 behavior for old contracts.
2. Allow bounded inference r, retaining all text in canonical results and an
   explicitly unverified outcome-rationale presentation. Require abstention r.
3. Keep account counts, competing alternatives, current original O membership,
   I premise closure, contradictions/qualifications, source/view/request binding,
   parent revalidation and S3 separation unchanged.
4. Integrate exact schema recognition, normalization routing and frozen grant
   identity for the new policy. Do not normalize away prose or silently infer a
   different outcome.
5. Add the bounded diagnostic metadata above and preserve completion/usage.
6. Remeasure the exact historical body and unrelated synthetic cases within
   5,600/16,384 bytes. No required evidence or qualifiers may be removed to fund
   redundant schema variants. Retain 1,024 tokens, 60 seconds, 32/128-KiB IPC.
7. Re-run the matrix, including contradictory root rationale visibility and both
   old/new policy semantics, actual mock SDK serialization, Windows supervision,
   malicious references and parent rejection. No retry/fallback/continuation.

Only then consider one separately authorized paid usefulness test. Evaluate
pathname comparison, alternatives and examinations separately from structural
acceptance. A preserved contradictory rationale is a failed usefulness result,
not an authoritative conclusion. A safe abstention is legitimate but does not
demonstrate new investigative value.

## 11. Scope and verification record

No live forensic database, original transcript, provider or permissions changes.
Copied historical data was only read for existing preparation/size calculation.
Synthetic diagnostic runner resides under the ignored `.tmp-6130` workspace;
application source/tests/configuration and the prior reports are unchanged.
No new response persistence, full suite, commit or push. Final documentation
whitespace checks are performed separately. Findings establish a reproducible
contract mismatch and a bounded design recommendation, **not the contents or
quality of the discarded live answer**.

# Locard 6.126 — Bounded D2 validation diagnostics

Date: 2026-11-11, America/Chicago. Development branch main; starting HEAD `8615eca3c2dac769e02a601139a75a03af8c063c` (6.125). These are uncommitted implementation changes, with `pyproject.toml` as the only application-version authority, now 6.126. The pre-existing uncommitted 6.125 diagnostic document was preserved unchanged.

## Outcome and limits

D2 now distinguishes compact JSON/schema, outcome, reference membership, interpretation/relationship premises, provider envelope, and parent revalidation failures using bounded, sanitized metadata. Known numeric provider usage survives rejection. No rejected text is put in the diagnostic, no durable D2 state is added, and the original 6.125 live payload remains unavailable: this release does not retrospectively identify its cause.

Unchanged: one explicitly authorized attempt/round, 5,600-byte complete request, 1,024 output tokens, 60-second total supervised allocation (55 work + 5 cleanup), zero new lookups, no retries/fallback/continuation, 32-KiB terminal and 128-KiB receiver limits. Strict d2c1/d2q1 validators, packet/source/view binding, S1/S2/S3 semantics and historical reconstruction remain unchanged.

## Root cause and implementation

Previously `d2_execution._child` discarded exceptions, text and usage together on response validation failure; the parent likewise collapsed local revalidation errors and discarded usage. `response_schema_validation` alone could not distinguish several valid JSON but invalid response cases. The new diagnostic never weakens validation or repairs a response.

`d2_diagnostics.py` provides the reusable contract, exact constant/error-detail mapping, path normalization, numeric usage filter, strict IPC validation and concise rendering. It does not access files or providers. Existing validators still decide acceptance. Diagnostic fields have no evidence authority.

`d2_execution.py` preserves bounded usage immediately after backend receipt, adds child diagnostics, and separately reports parent revalidation with origin parent and underlying failure_stage. Parent validates the whole IPC binding, then independently expands and validates the raw successful response against parent-owned context. A child claiming success cannot override parent grounding. Only after controlled termination succeeds does the parent mark cleanup confirmed; existing CleanupError remains the failure signal when cleanup cannot be confirmed.

`d2_result.py` uses `d2-worker-result-v2` when the diagnostic is present. The v1 field set/decoder remains supported. v2 is a closed additive shape, with the existing fields plus diagnostic. The child cannot claim parent origin or confirmed cleanup; receipt/outcome and usage availability must agree with the envelope. No extra diagnostic IPC message is sent; the pre-existing attempt notification remains unchanged.

## Diagnostic contract

`d2-validation-diagnostic-v1`, maximum **2,048 serialized UTF-8 bytes** within the existing terminal budget:

| Field | Contract |
|---|---|
| stage / code | Closed allowlists, never exception prose |
| origin | child or parent |
| failure_stage | Optional underlying stage when parent revalidation fails |
| pointer | Optional normalized known-contract path; no arbitrary model keys |
| expected_type / observed_type | Closed type names |
| characters / utf8_bytes / maximum_bytes / response_bytes | Optional bounded integers, no values |
| provider_response_received | true / false / null (unknown) |
| json_extraction / json_parsing | passed, failed, not_attempted, unknown |
| completion | stop, end_turn, length, refusal, unknown |
| usage_availability | reported, absent, not_received, discarded_by_earlier_failure |
| worker_outcome | accepted, rejected, interrupted, unknown |
| cleanup | unknown from child; confirmed only after parent containment; unconfirmed reserved |

Example (synthetic):

```json
{"contract":"d2-validation-diagnostic-v1","stage":"compact_schema","code":"utf8_byte_limit","origin":"child","pointer":"/a/0/s","expected_type":"string","observed_type":"str","characters":134,"utf8_bytes":402,"maximum_bytes":400,"provider_response_received":true,"json_extraction":"passed","json_parsing":"passed","completion":"stop","usage_availability":"reported","worker_outcome":"rejected","cleanup":"confirmed"}
```

Cleanup confirmed in this example is the final parent-updated application result, not the wire value accepted from a child.

Stages: initialization, provider_dispatch, provider_response_receipt, sdk_response_extraction, provider_refusal, output_truncation, json_parsing, compact_schema, outcome_validation, alias_membership, interpretation_premises, relationship_premises, parent_canonical_revalidation, ipc, complete.

Codes: malformed_json, duplicate_key, missing_field, unknown_field, wrong_type, unsupported_enum, item_count, duplicate_item, blank_text, nul_text, utf8_byte_limit, outcome_accounts, outcome_reason, competing_account_required, unknown_support, incomplete_interpretation, incomplete_relationship, request_binding, provider_refusal, output_truncated, unknown_internal_validation_error; plus none, provider_failure, timeout, cancelled, invalid_response_envelope, ipc_failure and diagnostic_limit for operational states.

Unknown exception details become a generic safe code. Only exact known Locard constants and allowlisted validator fields are mapped. No general str(exception), missing-field list with arbitrary keys, provider body, evidence identifier/value, generated explanation, credential or refusal prose is serialized. Numeric array positions are bounded and paths normalized; malicious unknown keys never enter paths. No raw response capture was enabled.

## Usage, receipt and provider refusals

Only existing bounded integer prompt_tokens/completion_tokens/total_tokens are preserved. A rejected proposal may incur cost. Empty usage is not zero usage. Success or local rejection after an envelope with empty usage is absent; no established receipt is not_received; a known earlier response with unpreserved usage is discarded_by_earlier_failure. Earlier envelope failures can retain the numeric usage seen before extraction failed. Receipt and transmission are not inferred from the attempt counter or cleanup.

A mock test confirmed that installed LiteLLM conversion drops OpenAI's refusal field. `d2_transport.guarded_client` now observes the already-received OpenAI SDK response, including LegacyAPIResponse.parse(), before that conversion. This parse decodes/caches the existing response; it does not issue another HTTP request. Only safe failure category/stage/metadata are held, not exception tracebacks or raw SDK response objects. `cloud_worker.generate` preserves that failure through conversion. Normal response integrity checks still apply; null/empty text without explicit refusal is not classified as refusal. This observation is D2-only; normal cloud extraction retains its prior behavior.

HTTP errors can still have unknown model-response receipt even when an HTTP response existed: these are distinct facts. No future billing amount is inferred from token counters.

## Wire-budget gate: approved guide retained

The canonical response schema and the approved 546-byte d2q1 guide are unchanged. Comprehensive clear guidance for all diagnosed gaps measured 791 guide bytes and **5,797 complete request bytes** on the previously eligible large-value fixture: 197 bytes over the limit. Two smaller proposed reason-only additions measured 5,601 and 5,602 bytes. The actual OpenAI SDK serializer through MockTransport reproduced these measurements. Oversized candidates were diagnostic serialization fixtures only, never dispatched or admitted by production.

Rather than trim mandatory support/qualifications, expand budgets or silently change eligibility, this release implements diagnostics independently. Remaining communication gaps: reason emptiness/nonblank rules, single-account alternative, null versus empty optional text, uniqueness, UTF-8 byte ceilings, and full interpretation-premise citations. Local enforcement remains strict. Another separately measured wording revision could address them later; this release makes failures inspectable first.

Complete requests, unchanged from 6.125 (SDK MockTransport, gpt-6.1-sol):

| Fixture | Bytes | Headroom / disposition |
|---|---:|---|
| Historical packet | 5,395 | 205; previously measured, unchanged code/guide |
| Browser only | 3,470 | 2,130 |
| Registry persistence | 3,663 | 1,937 |
| Process/service | 4,589 | 1,011 |
| Filesystem without EVTX | 3,860 | 1,740 |
| Prefetch only | 3,594 | 2,006 |
| Mixed | 6,118 | Already oversized; rejected before transport |
| Smaller mixed | 4,507 | 1,093 |
| Shared path relationship | 4,629 | 971 |
| No supported relationships | 3,303 | 2,297 |
| Contradictory/incomplete | 4,741 | 859 |
| Large original value | 5,552 | 48 |
| Extensive qualifications | 7,167 | Already oversized |
| Oversized original value | 5,952 | Already oversized |

Each admitted complete request equals the actual SDK outgoing body. For the large-value fixture: serialized system string 548, user string 3,811, response_format 1,053, other JSON fields/punctuation 140 bytes. No diagnostics are added to the model request. No case/artifact-specific selection or schema rules were introduced.

## Terminal IPC measurements and failure behavior

Real Windows-spawn tests with synthetic history, actual SDK MockTransport and the normal D2 parent/child controller (nested cloud subprocess bridge mocked):

| Case | Terminal payload bytes | Final diagnostic bytes | Result |
|---|---:|---:|---|
| Abstention | 1,256 | 279 | Accepted |
| Competing accounts | 1,845 | 279 | Accepted |
| Unknown alias | 1,216 | 319 | Rejected / unknown_support |
| UTF-8 overflow | 1,335 | 438 | Rejected / utf8_byte_limit |
| Empty abstention reason | 1,216 | 319 | Rejected / outcome_reason |
| Explicit refusal | 1,194 | 309 | Rejected / provider_refusal |
| Truncated output | 1,224 | 330 | Rejected / output_truncated |
| HTTP 400 | 1,156 | 321 | Rejected / provider_failure |

Terminal measurements exclude the eight-byte allowance conservatively charged by existing admission; all remain below 32 KiB after adding it. Final diagnostic measurements include the parent's confirmed cleanup label. Usage 10/10/20 supplied by synthetic envelopes survives all corresponding local/extraction rejections; the HTTP error has unknown usage. All eight runs: one attempt, zero lookups, confirmed cleanup and no remaining controlled multiprocessing children.

IPC serialization validates diagnostics before sending and measures the complete terminal. Invalid/oversized diagnostics or result serialization failure become a small rejected terminal with no response, bounded retained usage and safe IPC classification. Accepted data is never truncated to fit or accepted without grounding. A broken pipe still reports through the existing parent failure path rather than attempting a second write. Legacy v1 decoding and historical d2c1 responses remain supported.

## Focused validation and historical compatibility

The 34-case matrix from the diagnostic was reproduced: valid abstention, insufficient support, inference, competing accounts, optional-empty text, contrary refs and complete interpretations; invalid aliases, missing premises, outcome rules, field/type/count/enum violations, Unicode overlength, duplicates, blank/NUL strings, null fields, malformed/incomplete JSON, wrong version/wrapper, missing content, explicit refusal, truncation and HTTP errors. Each rejection asserts a specific safe code. Added tests cover malicious diagnostics, path normalization, usage, parent-only rejection identity, byte limit, overflow fallback, legacy envelope, UI and five unrelated artifact families.

Development failures were investigated rather than weakening assertions: the first run had two refusal failures (61 passed), revealing LiteLLM's lost refusal field. An intermediate hook saw SDK LegacyAPIResponse wrappers before parsing and failed four focused cases. Parsing the existing wrapper before observing it fixed refusal while preserving valid extraction; wrong envelope types now receive the more precise extraction classification. Expected matrix outcomes were updated only for these improved diagnostic categories.

Recorded completed runs and final checks are appended below. No full-suite run or live model request.

All three copied 6.118 runs and the copied 6.111 run were reconstructed twice provider-free. Their previews were equal and matched the previously recorded digests. SHA-256 before/after comparisons of all eight manifest/events files were identical. This establishes task-time preservation, not integrity before the available baseline. No live case database was opened. The existing zero-analysis retrospective Cross-view explanation issue remains outside scope.

| Run | D2 preview digest |
|---|---|
| 6.118 ffdabecc9ded47e6acd5f4977fa3c2fa | 8717086a7e6cf2f18832dfb898c4c604e6001c16d9040e9fbaaffe456457ba2b |
| 6.118 08cfd054f85a4a36b8520832427201c3 | 18348f984e0c23df4e00d4e43c8d3930a550eef062951c1aa7c8d5b14b444cdd |
| 6.118 6ad0c85499564406aa4d949f3b0e72e5 | cb1308c5873137b2a6feddcfbdbdca0cf7ef72e19bdea358e51c6df5680ab500 |
| 6.111 ec81a1af5b1f471ca4f3a4c0bb917fa2 | f3a6fed1a18f11e9b2395ef5e4b5025befa7cb066d300842a7bc7fa7744a9fa4 |

## Changed files

- `pyproject.toml`: version 6.126 only.
- `forensic_assistant/investigation_ai/d2_diagnostics.py`: new bounded contract, safe mapping, usage filter and display helper.
- `forensic_assistant/investigation_ai/d2_result.py`: v2 diagnostic terminal, strict v1/v2 parsing and bounded fallback.
- `forensic_assistant/investigation_ai/d2_execution.py`: child/parent diagnostics, preserved usage and parent cleanup observation.
- `forensic_assistant/investigation_ai/d2_presentation.py`, `d2_reasoning.py`: concise failure identity and diagnostic/usage presentation.
- `forensic_assistant/ai/d2_transport.py`: sanitized observation of the existing SDK envelope before LiteLLM conversion.
- `forensic_assistant/ai/cloud_worker.py`: preserve that D2-only failure; normal extraction remains checked.
- `forensic_assistant/ai/response_envelope.py`: opt-in explicit refusal and bounded usage-availability metadata.
- `forensic_assistant/ai/provider_diagnostics.py`: registered refusal category.
- `tests/test_d2_diagnostics.py`: matrix, SDK, Windows spawn, safety and measurement tests.
- This document. The earlier 6.125 diagnostic document was already uncommitted and was not rewritten.

## Manual acceptance

After the analyst's Git workflow and installation in the test checkout:

```powershell
Set-Location C:\tmp\locard260927\locard
.\.venv\Scripts\python.exe -m pip install -e .
.\.venv\Scripts\python.exe -c "from importlib.metadata import version; print(version('locard-forensics'))"
# Expected installed version: 6.126
$root = 'C:\tmp\locard-diagnostics\6.118-live'
$run = '6ad0c85499564406aa4d949f3b0e72e5'
$issue = 'd81869143ab5f3a355285bd79802d93912491834bc4f602c0a5fda6fd28739e7'
# Provider-free issue/request preview:
.\.venv\Scripts\python.exe -B -m forensic_assistant.investigation_ai.d2_reasoning $root $run --exploratory --issue $issue --json
# Expected complete request remains 5,395 bytes.
# Provider-free synthetic tests, including Windows spawn/MockTransport:
.\.venv\Scripts\python.exe -B -m pytest -q tests/test_d2_diagnostics.py
```

Only if the analyst separately chooses to authorize a new live request:

```powershell
.\.venv\Scripts\python.exe -B -m forensic_assistant.investigation_ai.d2_reasoning $root $run --exploratory --issue $issue --execute
```

Review provider/model/source/budgets before answering y. A rejection should now show a specific stage/code and safe pointer/byte count when available. For exhaustive ephemeral output, use `--execute --json` instead for that same attempt; running again is a new authorization, not a way to retrieve the previous response. Retain the sanitized diagnostic/usage fields for diagnosis; the full JSON view also contains forensic context, so do not publish it indiscriminately. Do not enable raw response capture. No automatic retry is introduced.

Live reasoning quality and the original rejection cause remain unknown. The intended next acceptance can establish the failing rule if rejection recurs; a successful response does not prove forensic causality. No commit, push, new evidence access or permission changes were performed.

## Final recorded validation and remaining baseline failures

| Run | Result |
|---|---|
| Initial focused quality + result checks | 89 passed in 38.11 s |
| Completed actual SDK, new diagnostics, Windows spawn, legacy/quality transport suites | 98 passed in 89.67 s (two SDK warnings for ReadOnly annotation / deliberately invalid synthetic content) |
| Final additional safety, guide measurement, UI and five-family checks | 29 passed, 42 deselected in 15.58 s |
| Expanded relevant regressions | 343 passed, 13 failed in 146.81 s |
| Committed 6.125 envelope baseline reproduced in memory | Same 13 failures, 4 passed in 0.82 s |

Counts overlap and must not be added as unique coverage. The 13 expanded failures are pre-existing in `tests/test_response_envelope.py`: twelve `test_envelope_checks_and_briefing_output` cases fail at the old briefing-rendering assertion after their extraction/category/privacy checks pass; `test_uniqueness_instruction_and_budget_unchanged` expects an old briefing prompt sentence. Replacing the changed AI modules in memory with their exact committed HEAD versions reproduces the same set. No repository files were reverted, no unrelated test assertions were weakened, and no briefing production changes were made. The overall expanded selection is therefore not fully green; the D2-focused checks pass. Baseline briefing corrections remain outside this release.

The implementation report and test outcomes support manual D2 acceptance, not a claim that the whole repository test suite is green. No full-suite execution was performed. The final small IPC regression and Git checks are recorded below.

Final IPC safety regression: **10 passed, 94 deselected in 4.77 seconds**, including complete-result overflow versus diagnostic overflow, one-message fallback, known-usage preservation, JSON codes and parent rejection identity. `git diff --check` passed. No application version other than `pyproject.toml` was introduced; it reads 6.126. HEAD is unchanged, with implementation/test/document changes left for review; no commit or push. The new report is included despite docs ignore rules.

Final review also verified unexpected parent validator exceptions are reported as parent revalidation with a safe unknown-internal code, rather than misleading startup failures; timeout propagation remains unchanged. Focused parent failure/deadline regression: **3 passed, 102 deselected in 4.50 seconds**. Known usage remains present and exception text is excluded. Final diff check passed after this correction.

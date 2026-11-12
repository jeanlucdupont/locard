# Locard 6.125 — D2 response-validation diagnostic

Date: 2026-11-11 (America/Chicago). Branch: main. HEAD: `8615eca3c2dac769e02a601139a75a03af8c063c` (Full AI investigation 13). Starting tree clean. Compared with committed 6.124 `c898fa07a931316beb28823766fa5a1ee43bbbeb`. Application remains 6.125. Diagnosis only; this document is the only retained change.

## 1. Executive finding

**Classification G: the exact live-response cause is unresolved because the rejected ephemeral payload and validation detail were not retained.** The live error does not establish malformed JSON, schema incompatibility, or a model failure. It covers JSON parsing, compact validation, outcome rules, alias/interpretation grounding, and parent revalidation.

Confirmed contributing defects: diagnostic information and known usage are discarded on child validation rejection; several locally enforced response requirements are not explicitly communicated in the compact guide. Mocked valid responses for all four outcomes succeed. No universal failure of the new contract or SDK adapter was reproduced.

Three different synthetic responses reproduce the reported visible result with successful cleanup: unknown support alias, 402-byte/134-character explanation, and zero-account abstention with an empty reason. All have valid provider-facing JSON Schema shapes. This is **not** proof that the live model returned any of them.

The implementation calls its format `d2q1`, not the attachment's `d2c2`. `d2c2` is correctly rejected. Canonical response: `d2-quality-proposal-v1`; accepted validation result: `d2-quality-validation-v1`. Legacy `d2c1` remains separate.

## 2. Exact execution path and error boundaries

| Boundary | Repository source / function | Behavior |
|---|---|---|
| Read-only historical reconstruction | `forensic_assistant/investigation_ai/d2.py`: `open_history`, `_History.preview`, `_encode` | Reconstructs validated original support and canonical packet; no new case lookup |
| Request creation | `d2_execution.py`: `prepare`, `Prepared.__init__`, `check` | Uses quality profile; validates original authority; freezes packet/context/config/body identity |
| Compact evidence | `d2_quality.py`: `messages`, `expand_view`; `d2_wire.py`: `alias`, `tuples` | Original support preserved; version marker d2q1; opaque binding context retained locally |
| Authorization / supervision | `d2_execution.py`: `authorize`, `_Permit`, `execute` | One approval and consumed permit; spawn worker; 55 seconds work, remaining 5 cleanup within 60 total |
| Backend selection | `ai/backend.py`: `ModelBackend.complete_d2` | Exact schema selected by `d2_wire.schema_for`; directly calls `_cloud_request`, bypassing ordinary `_cloud` logging/translation |
| Cloud worker subprocess | `ModelBackend._cloud_request` | Supplies schema/messages/body hash, forces raw diagnostics false; accepts bounded text/usage/finish_reason envelope |
| Provider schema | `ai/capabilities.py`: `configure`; `ai/openai_schema.py`: `request_schema`, `_wire` | `response_format.type=json_schema`, name forensic_analysis, strict true; removes uniqueItems |
| SDK / HTTP admission | `ai/cloud_worker.py`: `request_kwargs`, `generate`; `ai/d2_transport.py`: `guarded_client` | LiteLLM completion with explicit OpenAI client; exact serialized body gate; one HTTP attempt, no redirects/retries |
| Response extraction | `cloud_worker.complete`; `ai/response_envelope.py`: `content` | Requires a choice/message, nonblank string content, stop/end_turn, no tool calls; rejects length before JSON parsing |
| Child compact validation | `d2_execution._child` lines 134–139; `d2_quality.expand_response`, `validate` | Strict JSON, closed shape, local byte/uniqueness/content checks, outcome-dependent checks |
| Expansion / grounding | `d2_quality.parse`; `d2._History.validate`, `validate_response` lines 301–363 | Binds request and packet locally; validates current aliases, interpretation premises and contradictory support; preserves unverified status |
| Terminal IPC | `d2_result.py`: `envelope`, `encode`, `send`, `parse` | Bounded original raw response only on success; rejection sends no response, usage defaults to empty |
| Parent validation | `d2_execution.execute` lines 219–235 | Validates IPC binding, independently expands response and validates against parent-owned context |
| Display | `d2_presentation.py`: `view`, `render`; `d2_reasoning.py` | Displays rejected reason; never displays rejected text as accepted reasoning |

Only two locations assign the specific `response_schema_validation` category:

1. `_child` catch block after stage becomes `response_validation`: any exception, including non-schema exceptions, is broadly mapped here (TimeoutError has its own category).
2. `execute` catch after a parsed terminal envelope: ValueError/TypeError/KeyError/UnicodeError/RecursionError from expansion or parent validation maps here. An invalid IPC envelope instead maps to ipc_invalid_message.

For the inspected implementation, this category implies the backend returned a text envelope or the parent received an accepted child envelope; it does **not** prove JSON parsed or grounding passed. The provided console result lacks the stage/receipt fields needed to distinguish child from parent rejection. Cleanup alone proves neither transport success nor validity. This inference assumes the live installed code matches the inspected commit.

The ordinary `openai_schema.response` investigation-wrapper translation is **not** in this D2 route. D2 does not request a top-level `proposal` wrapper. An apparent wrapper-translation issue in unrelated `_cloud` logic cannot be assigned as this incident's cause.

## 3. Exact provider schema and canonical requirements

The SDK request has `response_format={type:json_schema,json_schema:{name:forensic_analysis,strict:true,schema:<below>}}`. No tools, streaming false, max_completion_tokens 1024. The final HTTP request is admitted by exact bytes and digest. The supplied live size 5,395 is consistent with the prior measured fixture; no new live dispatch was made.

Actual adapted schema (compact JSON, generated from inspected code):

```json
{"type":"object","additionalProperties":false,"properties":{"v":{"type":"string","enum":["d2q1"]},"o":{"type":"string","enum":["new_inference","competing_explanations","no_material_inference","insufficient_packet_support"]},"a":{"type":"array","items":{"type":"object","additionalProperties":false,"properties":{"s":{"type":"string","minLength":1,"maxLength":400},"e":{"type":"array","items":{"type":"string","minLength":1,"maxLength":16},"maxItems":6,"minItems":1},"c":{"type":"array","items":{"type":"string","minLength":1,"maxLength":16},"maxItems":6,"minItems":0},"i":{"type":"array","items":{"type":"string","minLength":1,"maxLength":16},"maxItems":4,"minItems":0},"a":{"type":"string","maxLength":240},"u":{"type":"string","maxLength":320},"d":{"type":"string","maxLength":400},"n":{"type":"string","maxLength":400}},"required":["s","e","c","i","a","u","d","n"]},"maxItems":2,"minItems":0},"r":{"type":"string","maxLength":240}},"required":["v","o","a","r"]}
```

All root keys v/o/a/r and all account keys s/e/c/i/a/u/d/n are required. Both objects are closed. Null is never an optional-text representation. Optional text means a present string which may be exactly empty. Account text limits: s400, a240, u320, d400, n400; root r240. Support e has 1–6 strings, contrary c 0–6, interpretation i 0–4; aliases max16; accounts 0–2. Local limits count UTF-8 **bytes**, provider maxLength counts characters. Local validation additionally requires nonblank/non-NUL strings except exact empty permitted for optional text, and uniqueness of all arrays.

| Outcome | Accounts | Reason r | Additional rule |
|---|---|---|---|
| new_inference | 1 or 2 | Exactly empty | Required s and nonempty e per account |
| competing_explanations | 1 or 2 | Exactly empty | If one account, its alternative a must be nonempty |
| no_material_inference | 0 | Nonblank | No fabricated account required |
| insufficient_packet_support | 0 | Nonblank | No fabricated account required |

Every valid local outcome has a provider-schema representation. There is no impossible abstention shape. For example, synthetic `{v:"d2q1",o:"no_material_inference",a:[],r:"The packet adds no useful inference."}` passes both layers. Empty d/n is accepted when no meaningful discriminator/examination is available.

Provider-schema-valid but locally rejected cases include: inference with zero accounts; abstention with an empty reason; inference with a nonempty reason; one competing account without an alternative; duplicate aliases; whitespace-only/NUL strings; Unicode text exceeding the local byte limit; unknown aliases; incomplete interpretation premises. Removing uniqueItems is intentional OpenAI adaptation, not permission to accept duplicates. The local shape is more restrictive by design; reference membership is necessarily packet-dependent.

Instruction gaps in `d2_quality.GUIDE`: it says inference needs 1–2 accounts, abstention zero and optional text may be empty, but does not explicitly require r empty for inference/nonblank for abstention, or an alternative for a single competing account. It does not explain UTF-8 byte ceilings, uniqueness, or explicitly require all original premise aliases when citing an interpretation. "Current aliases only; preserve qualifiers" does not fully state the premise-closure rule. These gaps can plausibly cause rejection; no one gap is established as the live cause.

## 4. Differences from 6.124

| Surface | 6.124 | 6.125 |
|---|---|---|
| Wire response | d2c1 flat single hypothesis | d2q1 outcome plus 0–2 accounts |
| Optional text | Alternatives/assumptions/etc arrays, required next text | Present string, exactly empty allowed |
| Abstention | No explicit zero-account quality outcome | Two explicit zero-account outcomes |
| Guide | Single hypothesis, aliases and qualifications | Four outcome semantics with compressed quality guidance |
| Schema selection | Single exact schema | Exact legacy or quality schema |
| Expansion | Legacy hypothesis plus next examination | Quality canonical envelope; unverified accounts and optional examination |
| Canonical classification | d2-offline-validation-v1 | d2-quality-validation-v1; outcome and abstention reason |
| IPC | d2-worker-result-v1, 32 KiB /128 KiB | Unchanged |
| Provider response extraction | cloud_worker.complete / content | Unchanged |
| Error collapse | Broad response_schema_validation | Unchanged, now hides more possible quality rules |

Smallest new regression surface is quality shape/outcome validation and its communication, not an identified routing, IPC-limit or schema-transport failure. Byte/character and uniqueness differences also existed in the old path. The successful historical 6.124 response does not establish what the new response contained.

## 5. Provider-free diagnostic matrix

Execution: installed OpenAI/LiteLLM SDK via HTTPX MockTransport, socket connection functions blocked, synthetic key, exact production body admission. No responses were sent to a provider. Actual SDK extraction and production compact/canonical validators were exercised. `wire valid` is an independent local JSON Schema comparison, not a claim that OpenAI guarantees every mocked response.

Diagnostic code strings below are current exception codes or rule names; dot paths are the validator's current paths, convertible to JSON pointers. Generic shape errors currently have no separate stable enum; proposed stable enums are in section 8.

| Synthetic case | First failing stage / code | Wire valid |
|---|---|---|
| Abstention / insufficient support / single inference / two competing accounts | Accepted (4 cases) | Yes |
| Empty optional text, including no examination | Accepted | Yes |
| Valid contrary reference | Accepted | Yes |
| Interpretation plus all premises | Accepted | Yes |
| Interpretation missing premises | Canonical grounding / D2_INCOMPLETE_INTERPRETATION | Yes |
| Unknown alias | Canonical grounding / D2_UNKNOWN_SUPPORT | Yes |
| Missing account n | Compact / a[0]: missing parameter | No |
| Null n | Compact / a[0].n: wrong type | No |
| String accounts instead of array | Compact / a: wrong type | No |
| Unsupported outcome | Compact / o: unsupported value | No |
| Inference with empty accounts | Outcome / D2_QUALITY_OUTCOME_ACCOUNTS | Yes |
| Three accounts | Compact / a: invalid item count | No |
| 134 three-byte characters in s (402 bytes) | Compact / a[0].s: invalid string length/content | Yes |
| Repeated O1 alias | Compact / a[0].e: duplicate items | Yes |
| Whitespace-only d / NUL d | Compact / a[0].d: invalid string length/content (2 cases) | Yes |
| Abstention r empty / inference r nonempty | Outcome / D2_QUALITY_OUTCOME_REASON (2 cases) | Yes |
| One competing account, empty alternative | Outcome / D2_COMPETING_ACCOUNT_REQUIRED | Yes |
| Empty e | Compact / a[0].e: invalid item count | No |
| Empty s | Compact / a[0].s: invalid string length/content | No |
| Version d2c2 | Compact / v: unsupported value | No |
| proposal wrapper | Compact / root: missing parameter | No |
| Malformed / incomplete JSON | JSON / Malformed structured response (2 cases) | Not parsed |
| Missing content / explicit refusal with null content | SDK envelope / response_envelope_failed, invalid_content_type (2 cases) | Not parsed |
| finish_reason length | SDK envelope / output_truncated | Not parsed |
| Array content / Responses-API-shaped envelope | SDK conversion / InternalServerError (2 cases) | Not parsed |
| HTTP 400 provider error | SDK / BadRequestError | Not parsed |

34 cases: 7 accepted, 27 intentional negative outcomes. SDK warnings for intentionally invalid array content were synthetic only. No retry was observed; mock handler asserts exactly one transport call per case.

The current extractor does not separately recognize message.refusal; null content becomes invalid_content_type. This is a diagnostic limitation, not acceptance of a refusal. Wrong API-envelope shapes fail before canonical parsing.

Windows spawn tests use the real D2 parent/child controller and ModelBackend.complete_d2. The nested cloud subprocess bridge is replaced in memory by the actual cloud adapter/MockTransport; no real network subprocess runs. Synthetic history reconstruction is substituted, and SQLite connection is blocked. This validates controlled process lifecycle and production validators, not real-provider behavior. Separately, the actual `_cloud_request` subprocess-result decoder was tested with fake Popen results: valid text/usage/stop accepted; missing text and length finish rejected as response_parse_failed; explicit worker request_rejected preserved.

The first temporary harness incorrectly assigned a filesystem root to an in-memory history and failed before authorization with FileNotFoundError. That harness setup was corrected; production code was not changed. An initial redirected diagnostic command was interrupted after its incomplete output; only the completed unredirected matrix and subsequent spawn results are counted. No full suite or repository test-file changes.

## 6. Live-response observability and integrity limits

Inspected the available bounded provider.log read-only: 26 parseable entries (18 investigation, 8 handshake), plus one non-JSON boundary line. No D2-tagged operation or rejected D2 payload was recovered. Existing copied transcript directories stop at 6.118-live, consistent with ephemeral D2 producing no new journal.

Code establishes why: `complete_d2` calls `_cloud_request` directly, bypassing `_cloud`'s record() calls. `_cloud_request` forcibly disables raw diagnostics for D2. The child discards response text and exception.validation_detail on rejection, then calls ipc.envelope without usage. Parent-side revalidation failure likewise drops detailed cause and usage. No raw-log switch can recover a past discarded response.

Known synthetic usage 10/10/20 becomes `{}` on rejection: empty displayed usage is not proof that provider usage was absent, nor that no charge occurred. Exact live JSON, failing pointer, length, aliases, and token usage remain unavailable. Original historical transcripts cannot reconstruct a fresh ephemeral response. No transcript or live database was opened or modified in this diagnostic.

## 7. Cause classification and safety

- **G confirmed:** exact live cause cannot be determined from retained artifacts.
- **F confirmed diagnostic weakness:** broad category and usage/detail loss; no actual IPC corruption reproduced.
- **B/C/E demonstrated possibilities:** provider-schema-valid responses can fail local byte/uniqueness/outcome/grounding checks. Not proven live causes; retaining these stricter rules is correct.
- **A/D not established live:** synthetic malformed, truncated, refusal and wrapper cases are rejected; no systematic extraction failure for valid shapes.

Code and synthetic runs preserve one attempt, no provider fallback, zero new evidence lookups, no durable D2 state or transcript writes, no S3 mutation, and no invalid text accepted as evidence. Supplied live output independently reports one attempt, zero lookups and confirmed cleanup; historical execution cannot be re-audited from a nonexistent D2 journal. Do not overstate live OS cleanup or historical file integrity beyond that report. Limits remain 5,600 bytes, 1,024 tokens, 60 seconds total, 32-KiB terminal/128-KiB receive.

## 8. Smallest recommended correction (not implemented)

Recommend focused 6.126 diagnostic/contract-communication repair, not rollback or relaxed validation:

1. Preserve sanitized error detail at the first failure and known usage/receipt/completion information through child IPC and parent classification. Distinguish transport, extraction, JSON, compact structure, outcome, reference membership, premise closure, parent revalidation and IPC.
2. Version an optional bounded diagnostic object in the existing terminal/result contract; maintain strict legacy decoding and size enforcement. Limit e.g. 2 KiB within existing terminal allowance, not added to the cap. Never serialize str(exc), response, source values, credential, or unknown model keys. Map field paths through an allowlist; unknown keys become an unknown-field category.
3. Preserve canonical rules. Clarify the existing guide about exact empty reason for inference, nonblank reason for abstention, competing alternative, empty optional text versus null, unique aliases, UTF-8 bytes, and interpretation premise closure. Remeasure complete SDK wire bytes against all representative cases; maximum prior headroom is only 48 bytes for the large-value fixture. If it cannot fit, report a gate blocker, do not trim evidence.
4. Recognize explicit refusal as a safe classification where the SDK exposes it. Do not claim an unknown exception is a refusal.

Proposed sanitized structure (synthetic example, no raw content):

```json
{"contract":"d2-validation-diagnostic-v1","stage":"compact_schema","code":"utf8_byte_limit","pointer":"/a/0/s","expected_type":"string","observed_type":"string","characters":134,"utf8_bytes":402,"maximum_bytes":400,"provider_response_received":true,"json_extraction":"passed","json_parse":"passed","completion":"stop","usage_available":true,"worker_outcome":"rejected","cleanup":"confirmed"}
```

Stable allowlisted codes should cover malformed_json, duplicate_key, missing_field, unknown_field, wrong_type, unsupported_enum, item_count, duplicate_item, blank_text, nul_text, utf8_byte_limit, outcome_accounts, outcome_reason, competing_account_required, unknown_support, incomplete_interpretation, incomplete_relationship, request_binding, provider_refusal, output_truncated and unknown_internal_validation_error. Preserve yes/no/unknown receipt; do not infer from cleanup. Ref/field aliases can be omitted where not necessary; no original evidence IDs or text need enter default diagnostics.

## 9. Required regressions and sequencing

Add future tests for every matrix row, including SDK MockTransport through supervised child and parent; preserve known usage on rejection; bounded safe pointers for malicious unknown keys; same error identity at child/parent boundary; absent diagnostic compatibility; oversized diagnostic safe failure; exact raw-capture prohibition; no retries; complete SDK body budgets; stale/foreign aliases; complete interpretation premises; duplicate JSON keys; EOF/malformed IPC; successful cleanup. Test model-free preview remains unchanged. Canned outputs do not prove live reasoning quality.

Keep zero-analysis reconstruction repair separate as proposed 6.127. Do not combine narrative continuity, additional rounds, persistence, or budget changes with 6.126. D2 quality remains usable when responses satisfy the contract, but cannot be meaningfully tuned from this lost payload.

**Another paid test is not justified before bounded diagnostic propagation is implemented and mock-tested.** After separately approved 6.126 and renewed wire-budget checks, one analyst-authorized live attempt can establish whether any additional response-handling correction is needed. Do not automatically retry a rejection. No specific change to acceptance rules is justified by the current evidence.

## 10. Completed supervised results and final checks

| Windows spawn fixture | Result / category | Receipt | Usage retained | IPC bytes |
|---|---|---|---|---:|
| Valid abstention | accepted / none | true | 10/10/20 | 965 |
| Valid competing explanations | accepted / none | true | 10/10/20 | 1,554 |
| Unknown alias | rejected / response_schema_validation | true | empty (discarded) | 826 |
| Overlong UTF-8 text | rejected / response_schema_validation | true | empty (discarded) | 826 |
| Missing abstention reason | rejected / response_schema_validation | true | empty (discarded) | 826 |
| Refusal with null content | rejected / provider_response_invalid | true | empty | 823 |
| Truncated completion | rejected / provider_response_invalid | true | empty | 823 |
| HTTP 400 | rejected / provider_dispatch_failure | unknown | empty | 823 |

All eight executions: one attempt, zero lookups, confirmed controlled cleanup. `multiprocessing.active_children()` was empty at the end. Receipt for HTTP 400 remains unknown at this controller boundary despite the mock knowing it supplied an error; the classification discards more specific provider information. No live-provider or live OS process-history claim is implied.

Totals: 34 direct SDK/validator scenarios, eight real Windows-spawn scenarios and four subprocess-envelope decoder scenarios. Expected negative outcomes were observed, not failures weakened into success. Existing repository tests were not modified or rerun; no full suite. Temporary synthetic diagnostic harness/output files were removed. Production code, tests, configuration, version and original implementation report are unchanged. The only retained change is this document, made visible using intent-to-add despite docs ignore rules. Final `git diff --check` passed. No commit or push.

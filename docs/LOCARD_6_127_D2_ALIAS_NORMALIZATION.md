# Locard 6.127 — D2 duplicate alias normalization

Implementation reviewed 2026-11-12. Starting committed revision:
`608c474fda4a8aa0f9761b4026916b2e4b4f0a18` (6.126).
This document describes the uncommitted 6.127 change, pending manual acceptance.
`pyproject.toml` remains the application-version authority.

## Failure and semantic boundary

The analyst-reported 6.126 live result was `compact_schema / duplicate_item`
at `/a/0/e`, after one OpenAI attempt with known usage and confirmed cleanup.
This establishes repetition in a reference array, not the alias values or the
validity of the discarded reasoning. The response has not been reconstructed.

`d2_quality.py` defines compact `d2q1` accounts. Evidence and contrary references
resolve to original support; interpretation references require registered premise
closure. Repeating an identical reference adds neither an observation nor support
strength. Removing exact repetition within one array preserves its reference set.
It does not endorse the model's prose or promote a proposal into evidence.

| Eligible path | Meaning | Raw maximum per account |
|---|---|---:|
| `/a/*/e` | Supporting original fields | 6 |
| `/a/*/c` | Contrary original fields | 6 |
| `/a/*/i` | Registered interpretations | 4 |

Only these paths are registered. There are at most two accounts, hence at most
32 reference entries to examine. No normalization of whole accounts, prose,
duplicate JSON keys, distinct aliases, case, whitespace, unknown aliases, source
epochs, packet bindings, or forensic values is allowed. Different arrays and
accounts remain separate. No artifact-specific branch exists.

## Algorithm and authority

`d2_normalization.canonicalize` implements `d2-reference-normalization-v1`:

1. Strictly parse the original response under the existing 16-KiB response limit;
   reject duplicate JSON keys.
2. Validate the original object against the exact OpenAI provider-facing schema
   returned by `ai/openai_schema.request_schema`. Raw types, unknown fields,
   lengths and item counts must pass before mutation.
3. Check every reference against the frozen packet's support/interpretation
   aliases. Unknown references are rejected before any normalization.
4. Copy the parsed object; remove only exact string repetitions within each
   registered array, preserving first occurrence order.
5. Run the existing strict compact validator, expansion and canonical grounding
   validator, including original support, source/view, interpretation/relationship
   premises, outcome requirements and original S3 authority.

OpenAI's schema adapter removes unsupported `uniqueItems`. Local canonical
validation still enforces uniqueness. This change adds an explicit response
interpretation policy before that validation; it does not relax the canonical
schema. An oversized raw array cannot become admissible by deduplication.

`d2_execution.validate_model_response` applies the policy in the worker and
independently in the parent. The parent validates against its frozen response
context and compares the worker's receipt with its own recomputation before
exposing accepted proposals. The policy version is sealed into prepared-request
identity and authorization metadata. It is not added to the provider prompt.

Legacy `d2c1` bypasses this policy. Strict direct `d2q1` parsing continues to reject
duplicates; only the explicitly versioned execution policy canonicalizes them.

## Diagnostics, containment and compatibility

The optional bounded normalization receipt contains only:

```json
{"contract":"d2-reference-normalization-v1","occurred":true,
 "removed":{"support":1,"contrary":0,"interpretation":0},
 "duplicates_removed":1,"canonical_validation":"passed"}
```

This is a synthetic example. Outcomes are `not_attempted` for pre-canonical
rejection, `failed` for later canonical/grounding rejection, and `passed` only
after complete validation. The human view reports removal count and final
validation when normalization occurred. Structured diagnostics identify affected
categories without aliases, model text or original values. Existing sanitized
stage/code diagnostics and known provider usage survive rejection.

No raw response is logged or persisted. As before, successful worker responses
travel transiently through bounded IPC so the parent can independently validate
the original response. Rejected worker responses are not returned as raw text.
There is no durable D2 state or journal change.

Unchanged limits: 5,600-byte final SDK request, 1,024 output tokens, one attempt,
zero evidence lookups/retries/fallback, 60-second execution envelope, 32-KiB
terminal result and 128-KiB receive ceiling. No provider guide/schema/request
bytes were added. Source provenance, S1/S2/S3 authority and historical transcripts
are unchanged. The separate zero-analysis Cross-view explanation defect remains
outside this patch.

## Focused validation

`tests/test_d2_normalization.py` covers support/contrary/interpretation arrays,
multiple accounts, order, idempotence, unknown/case/space/foreign aliases, wrong
types, duplicate JSON keys, all raw array limits, response byte limits, missing
premises, wrong binding, Unicode, distinct fields, closed receipts and five
artifact families. Actual OpenAI SDK `httpx.MockTransport` fixtures exercise both
accepted normalization and rejected incomplete interpretation premises, including
Windows multiprocessing spawn, parent validation, usage, cleanup and no extra
attempts. These tests make no external provider requests.

The existing unexpected-parent-exception test now supplies a structurally valid
response to reach its deliberately injected exception. The separate forged-alias
test retains its rejection assertion; no security assertion was weakened.

Recorded focused results (2026-11-12):

| Invocation scope | Result |
|---|---|
| `test_d2_quality`, `test_d2_execution`, `test_d2_result`, `test_d2_preview` | 183 passed in 88.73 s |
| Normalization and diagnostics, excluding SDK/spawn/guide subsets | 62 passed, 47 deselected in 14.00 s |
| `test_d2_normalization`, `test_d2_diagnostics`, `test_d2_transport`, `test_d2_quality_transport`, with actual SDK and mock HTTP | 144 passed in 115.21 s |

The 62-test check overlaps the 144-test run; these are not 389 unique tests.
The SDK run emitted two dependency warnings: Pydantic's SDK `ReadOnly` qualifier
warning and an expected serialization warning from the list-content adversarial
fixture. There were no failures. Windows normalized terminal messages measured
1,714 bytes accepted and 1,421 bytes rejected for missing interpretation premises.

Final SDK request serialization remains unchanged. Measured generic fixture sizes:

| Fixture | Bytes | Admission |
|---|---:|---|
| Browser only | 3,470 | Eligible |
| Registry persistence | 3,663 | Eligible |
| Process/service | 4,589 | Eligible |
| Filesystem without EVTX | 3,860 | Eligible |
| Prefetch only | 3,594 | Eligible |
| Mixed / smaller mixed | 6,118 / 4,507 | Rejected / eligible |
| Shared-path relationship | 4,629 | Eligible |
| No relationships | 3,303 | Eligible |
| Contradictory/incomplete | 4,741 | Eligible |
| Large original value | 5,552 | Eligible |
| Extensive qualifications | 7,167 | Rejected |
| Oversized original value | 5,952 | Rejected |

Over-budget requests are still rejected before transport; no fields or mandatory
qualifications are shortened to admit them. `git diff --check` passes.

Historical read-only compatibility: independently rebuilt previews twice for
three copied 6.118 runs and one copied 6.111 run. Each pair was identical, and
SHA-256 hashes of all eight manifest/event files were unchanged before/after.
These checks establish compatibility and unchanged copies during this validation,
not historical integrity of unrelated evidence.

| Run | Deterministic preview digest |
|---|---|
| `ffdabecc9ded47e6acd5f4977fa3c2fa` | `8717086a7e6cf2f18832dfb898c4c604e6001c16d9040e9fbaaffe456457ba2b` |
| `08cfd054f85a4a36b8520832427201c3` | `18348f984e0c23df4e00d4e43c8d3930a550eef062951c1aa7c8d5b14b444cdd` |
| `6ad0c85499564406aa4d949f3b0e72e5` | `cb1308c5873137b2a6feddcfbdbdca0cf7ef72e19bdea358e51c6df5680ab500` |
| `ec81a1af5b1f471ca4f3a4c0bb917fa2` | `f3a6fed1a18f11e9b2395ef5e4b5025befa7cb066d300842a7bc7fa7744a9fa4` |

## Manual acceptance

After transferring the reviewed development changes to the test checkout:

```powershell
Set-Location C:\tmp\locard260927\locard
.\.venv\Scripts\python.exe -m pip install -e .
.\.venv\Scripts\python.exe -c "from importlib.metadata import version; print(version('locard-forensics'))"
# Expected: 6.127
.\.venv\Scripts\python.exe -B -m pytest -q -p no:cacheprovider tests/test_d2_normalization.py

$root = 'C:\tmp\locard-diagnostics\6.118-live'
$run = '6ad0c85499564406aa4d949f3b0e72e5'
$issue = 'd81869143ab5f3a355285bd79802d93912491834bc4f602c0a5fda6fd28739e7'
.\.venv\Scripts\python.exe -B -m forensic_assistant.investigation_ai.d2_reasoning $root $run --exploratory --issue $issue --json
```

The preview is provider-free and does not open the live case. Verify the selected
provider/model and exact request size. For an **optional separately authorized
live request**, run the same command with `--execute` added and approve the shown
request. It may incur provider charges. A successful normalized response remains
unverified reasoning; unrelated substantive validation failures must still reject.
The original live rejection cannot be proven acceptable without its discarded
response, and a fresh model response need not contain duplicates.

No full suite, live provider request, live case access, commit or push is part of
this implementation validation. Manual acceptance remains pending.

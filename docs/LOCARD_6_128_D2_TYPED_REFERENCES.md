# Locard 6.128 — Packet-specific typed D2 references

Implementation date: 2026-11-12. Starting revision:
`81c312bd0f6351dc5a0eee6e883e1658553b4a86` (6.127).
This is an uncommitted 6.128 change pending manual acceptance.
`pyproject.toml` remains the single application-version authority.
The preceding read-only reference-reliability diagnostic is unchanged.

## Problem and scope

The 6.127 live rejection `alias_membership / unknown_support` does not identify
the discarded alias or establish whether the reasoning was otherwise valid.
The confirmed contract weakness was that multiple namespaces were visible while
the provider-facing response arrays accepted arbitrary strings. This release
constrains those arrays to the exact packet's eligible aliases. It does not
recover the missing response or prove natural-language entailment.

Canonical `d2q1` shape, outcomes and authority remain unchanged. A separate
`d2-typed-reference-schema-v1` policy identifies the dynamic wire restriction.
There are no changes to S1/S2/S3, multi-packet reasoning, persistence or loops.

## Namespace mapping and dynamic schema

Implemented in `forensic_assistant/investigation_ai/d2_schema.py`.

| Response field | Allowed values | Canonical meaning |
|---|---|---|
| `e` | Current packet O aliases | Supporting original fields, 1–6 |
| `c` | Current packet O aliases | Contrary original fields, 0–6 |
| `i` | Current packet I aliases | Registered deterministic interpretations, 0–4; all original premises still required |

E record, C clause, P source, D lineage, R relationship and V epoch identifiers
are not legal citations in these fields. Nor are exact EIDs, interpretation
metadata IDs, arbitrary identifiers inside evidence text or aliases omitted from
the current packet. O/I aliases are packet-local, not globally interchangeable.

Synthetic wire excerpt for two supports and one interpretation:

```json
{"e":{"type":"array","minItems":1,"maxItems":6,
      "items":{"type":"string","enum":["O1","O2"]}},
 "c":{"type":"array","minItems":0,"maxItems":6,
      "items":{"type":"string","enum":["O1","O2"]}},
 "i":{"type":"array","minItems":0,"maxItems":4,
      "items":{"type":"string","enum":["I1"]}}}
```

With no disclosed interpretations, `i` has `maxItems:0`, `minItems:0`, and
`items:{"type":"string"}`. No empty enum or placeholder is emitted. The zero
capacity prevents arbitrary identifiers. Interpretations existing elsewhere do
not populate this namespace. A packet without original support is rejected.

The builder accepts only the current deterministic contiguous O/I sequences,
bounded by 12 supports and four interpretations. Exact enum members imply
their existing string-length bounds, so redundant per-item length keywords are
omitted from the wire policy without relaxing admissible values. Canonical
length and uniqueness validation still applies. OpenAI's existing adapter
removes `uniqueItems`; the approved 6.127 normalization remains responsible for
exact duplicate known references before canonical validation.

## Binding and independent enforcement

`d2_execution.Prepared` derives `schema` from its packet before authorization.
The prepared identity includes the full schema, policy, body, source packet,
model/configuration and frozen response context. `check()` rederives and compares
the expected schema and complete request bytes. Preview and grant include policy
and schema digest; the grant seals them alongside the existing body digest.

The worker reconstructs the prepared request from trusted recorded history and
checks its seal and IPC binding. `d2_wire.schema_for` derives the expected schema
from the exact recognized guide and compact view. `ModelBackend.complete_d2`,
`cloud_worker.generate` and `d2_transport.guarded_client` use this existing path:
the caller's schema must equal the derived schema and its full serialized body
must match the authorized digest. A recomputed digest alone does not authorize
a widened enum. The OpenAI adapter recognizes only an exact generated policy
shape; canonical static quality and legacy d2c1 schemas remain recognized.

The parent independently reruns typed structural validation, exact normalization
and canonical grounding against its frozen packet/context. It does not accept
the worker's claim that the response was valid. Mutation after authorization of
schema, digest, model, packet, source frontier, view or response context rejects
before dispatch. No schema is independently mutable beside an authorized body.

## Instructions and mandatory budget gate

Before production edits, the complete proposed request was serialized by the
installed OpenAI SDK using mock HTTP. All 14 representative requests were checked
byte-for-byte against HTTPX serialization. All 11 previously eligible fixtures
passed; the same three oversized fixtures remained rejected. No evidence or
mandatory qualification was removed or truncated.

The rewritten guide is 611 UTF-8 bytes. It names supporting/contrary O and
registered I categories, original-premise requirements, context-only IDs,
account fields and calibrated abstention. It preserves untrusted-data treatment,
qualifiers, unexecuted examination/unknown availability and prohibitions on
factual execution, causality, intent, attribution, prevention, whole-case absence,
tools, scope expansion and S3 changes. Instruction expansion is offset by
logically redundant schema-key removal, not by evidence removal or new limits.

`no_material_inference` means the packet adds no material inference;
`insufficient_packet_support` means required packet support is missing. Both
require zero accounts and a reason, and neither establishes whole-case absence.
Inference still requires 1–2 accounts and an empty abstention reason. Existing
canonical validation enforces these conditions even when the model ignores them.

Complete SDK request sizes (including all fields and adapted response format):

| Fixture | 6.127 bytes | 6.128 bytes | Headroom / 5,600 |
|---|---:|---:|---:|
| Browser only | 3,470 | 3,486 | 2,114 |
| Registry persistence | 3,663 | 3,689 | 1,911 |
| Process/service | 4,589 | 4,645 | 955 |
| Filesystem without EVTX | 3,860 | 3,876 | 1,724 |
| Prefetch only | 3,594 | 3,610 | 1,990 |
| Mixed | 6,118 | 6,204 | Rejected |
| Smaller mixed | 4,507 | 4,543 | 1,057 |
| Shared-path relationship | 4,629 | 4,645 | 955 |
| No relationships | 3,303 | 3,309 | 2,291 |
| Contradictory/incomplete | 4,741 | 4,777 | 823 |
| Large original value | 5,552 | 5,568 | 32 |
| Extensive qualifications | 7,167 | 7,183 | Rejected |
| Oversized original value | 5,952 | 5,968 | Rejected |
| Historical interpretation | 5,395 | 5,455 | 145 |

These are representative eligibility guarantees, not a claim that arbitrary
future packets fit. The exact final body remains the admission criterion.
`d2_issues.inspect` now uses the same dynamic schema when displaying feasibility.

## Validation and sanitized diagnostics

Order: strict JSON → actual adapted typed provider schema → exact known-alias
normalization → strict compact/canonical outcome rules → source-bound original
support and interpretation/relationship closure → parent-owned validation.
No nearest-match mapping, inferred reference, missing-premise repair, retry or
fallback is added. An accepted proposal remains mechanically accepted **unverified**
reasoning, with original S3 preserved.

Schema failures detected locally carry stage `provider_schema`; HTTP/SDK provider
failures remain `provider_dispatch`, compact/outcome failures retain their own
stages, and premise failures retain `interpretation_premises` or
`relationship_premises`. A parent rejection has `parent_canonical_revalidation`
with its underlying `failure_stage`. A local provider-schema failure does not
claim that OpenAI itself rejected the response.

Reference diagnostics add a registered array pointer, expected O/I namespace,
`wrong_namespace`, `not_in_current_packet`, or `malformed_reference`, and a
boolean indicating membership in another current namespace. No rejected alias,
original field value or model prose is included. Example (synthetic):

```text
provider_schema / unknown_support; expected O / wrong_namespace at /a/0/e
```

Closed field/type/path checks and the existing 2,048-byte diagnostic ceiling
apply. Known usage and the normalization receipt survive rejection. No rejected
response is persisted. Successful raw responses still travel transiently through
bounded IPC for independent parent validation, as before.

Unchanged: one separately authorized attempt/round; 1,024 output tokens; 60-second
supervised envelope; zero new lookups/retries/fallback/continuation; 32-KiB terminal
result; 128-KiB receive ceiling; no durable D2 state.

## Focused validation record

Recorded focused results, 2026-11-12:

| Scope | Result |
|---|---|
| Existing quality, execution, result and historical-preview regressions | **183 passed** in 116.60 s |
| Typed references, normalization, diagnostics and actual SDK transport/serialization | **201 passed** in 317.48 s |
| Final typed-policy checks excluding the already completed Windows matrix | **50 passed**, 12 deselected, in 18.52 s |
| Added empty-interpretation namespace Windows SDK-to-parent checks | **2 passed**, 62 deselected, in 27.93 s |
| Final closed-diagnostic and reference-category checks | **15 passed**, 50 deselected, in 5.28 s |

These subsets overlap and must not be added as a unique-test total. The SDK run
reported two dependency warnings: Pydantic's SDK ReadOnly qualifier warning and
serialization of the intentionally invalid list-content fixture. No final focused
failure remains. An earlier development run had one stale expected stage:
forged references now fail at `provider_schema` rather than `alias_membership`;
its unknown-support rejection assertion remains intact. Historical budget tests
were kept against the old guide, while new exact-size tests cover the typed policy.

`git diff --check` passes. New untracked source/test/document files were also
checked for trailing whitespace. No complete regression suite was run.

New `tests/test_d2_typed_references.py` covers packet enums, namespace exclusion,
empty/omitted interpretations, maximum 12-O/4-I schema, invalid or widened schemas,
recomputed-body-digest tampering, request/grant/context mutations, stability,
legacy recognition, sanitized categories and Windows SDK-to-parent outcomes.
The maximum-table test is schema/SDK admission coverage, not a claim that every
12-O/4-I evidence bundle fits the request budget or has valid premises.

Existing fixtures cover Browser, Registry persistence, process/service, MFT,
Prefetch, mixed artifacts, shared paths, unrelated hosts, incomplete/conflicting
contexts, large original values and qualifications. Original/contrary references,
complete/incomplete interpretation premises, abstention, duplicate normalization,
malformed JSON, refusal, truncation, usage, one-attempt accounting, no lookups,
unchanged S3 and cleanup are tested using synthetic inputs.

Actual installed SDK calls use only in-memory mock HTTP, with network blocked in
the supervised fixture. The Windows D2 worker, terminal IPC and parent validation
are real; the nested cloud bridge uses the established mock fixture. This does
not claim live OpenAI schema acceptance or reasoning quality. No real provider
request occurred. Earlier diagnostic guide-size tests retain `LEGACY_GUIDE` and
their historical measurements; current tests assert the new exact dynamic sizes.

Four copied histories were reconstructed twice, deterministically, with unchanged
SHA-256 of their eight manifest/event files:

| Version/run | Preview digest |
|---|---|
| 6.118 `ffdabecc9ded47e6acd5f4977fa3c2fa` | `8717086a7e6cf2f18832dfb898c4c604e6001c16d9040e9fbaaffe456457ba2b` |
| 6.118 `08cfd054f85a4a36b8520832427201c3` | `18348f984e0c23df4e00d4e43c8d3930a550eef062951c1aa7c8d5b14b444cdd` |
| 6.118 `6ad0c85499564406aa4d949f3b0e72e5` | `cb1308c5873137b2a6feddcfbdbdca0cf7ef72e19bdea358e51c6df5680ab500` |
| 6.111 `ec81a1af5b1f471ca4f3a4c0bb917fa2` | `f3a6fed1a18f11e9b2395ef5e4b5025befa7cb066d300842a7bc7fa7744a9fa4` |

This confirms unchanged copies during testing, not historical integrity of
unrelated evidence. The live case database was not opened. The separate
zero-analysis Cross-view explanation defect remains outside scope.

## Files changed

* `d2_schema.py` (new): versioned derivation, exact recognition, safe reference categories.
* `d2_quality.py`, `d2_wire.py`: clearer guide, legacy guide recognition and typed schema routing.
* `ai/openai_schema.py`: exact dynamic-schema adaptation.
* `d2_execution.py`: schema preparation, sealing, grant/preview metadata and independent validation.
* `d2_normalization.py`, `d2_diagnostics.py`: typed raw boundary, bounded diagnostic categories; existing normalization unchanged.
* `d2_issues.py`: accurate feasibility sizing.
* `pyproject.toml`: 6.128, after the gate passed.
* New typed-reference tests and updated diagnostic/quality/transport tests.
* This document and its exact `.gitignore` exception; prior diagnostic unchanged.

## Manual acceptance

After the analyst transfers the reviewed changes to the test checkout:

```powershell
Set-Location C:\tmp\locard260927\locard
.\.venv\Scripts\python.exe -m pip install -e .
.\.venv\Scripts\python.exe -c "from importlib.metadata import version; print(version('locard-forensics'))"
# Expected: 6.128
.\.venv\Scripts\python.exe -B -m pytest -q -p no:cacheprovider tests/test_d2_typed_references.py tests/test_d2_quality_transport.py tests/test_d2_normalization.py

$root = 'C:\tmp\locard-diagnostics\6.118-live'
$run = '6ad0c85499564406aa4d949f3b0e72e5'
$issue = 'd81869143ab5f3a355285bd79802d93912491834bc4f602c0a5fda6fd28739e7'
.\.venv\Scripts\python.exe -B -m forensic_assistant.investigation_ai.d2_reasoning $root $run --exploratory --issue $issue --json
```

This preview makes no provider request. Confirm `schema_policy`, schema/body
digests, OpenAI/model selection, limits and 5,455-byte body for the measured model
`gpt-6.1-sol`. A different model name can change the serialized byte count.

For an **optional separately authorized paid live test**, add `--execute` to the
last command and explicitly approve that exact request. No retry is automatic.
Review outcome, usage, cleanup and safe diagnostic categories; accepted prose is
still unverified, and abstention is a valid result. The discarded live response
cannot be reconstructed, and valid references alone do not prove causality or
successful execution.

No full suite, live provider call, commit or push was performed. Stop for manual
acceptance; further implementation is not authorized by this report.

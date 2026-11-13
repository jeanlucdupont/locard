# Locard 6.131 — D2 outcome rationale contract

Date: 2026-11-13, America/Chicago. Starting revision:
`46b9226fc8a04f9bbd40c7f945571f4dddc2814e` (`main`, 6.130).
These are uncommitted development changes. `pyproject.toml` is the sole application
version authority and now specifies **6.131**. Earlier uncommitted readiness and
diagnostic documents are preserved; the original diagnostic is unchanged.

## Problem and correction

The reported live 6.130 rejection was `outcome_validation / outcome_reason`.
The discarded response is unavailable. Diagnosis reproduced two possible causes:
legacy inference with a nonempty reason, or abstention with an empty reason.
This change does not claim that the lost response would have passed.

Newly prepared D2 quality requests use **d2q2**. Inference still requires one or
two accounts, but its bounded root `r` may be empty or nonempty. Abstention still
requires zero accounts and a nonblank reason. One competing-explanations account
still requires a nonempty alternative. All four outcome names are unchanged.
Whitespace-only, NUL, wrong-type and overlong strings remain invalid; the root
limit remains 240 UTF-8 bytes. No prose is stripped, rewritten or deduplicated.

An accepted nonempty root rationale is retained exactly in structured
`outcome_rationale` and displayed under **Unverified outcome rationale**.
`rationale_classification` is `unverified_model_commentary`. An inference and a
contradictory rationale remain visible together. Mechanical acceptance does not
claim their semantic agreement. Rationale cannot supply references, satisfy
premises, identify a source or become evidence. Abstention is not case-wide absence.

## Versioning and boundaries

| Layer | Representation |
|---|---|
| Provider-visible response version / outcome semantics | `v: d2q2`; historical `d2q1` unchanged |
| Canonical envelope | Existing `d2-quality-proposal-v1`, whose nested response includes the explicit version |
| Single-packet request wire marker | `d2q2` for new requests; `d2q1` still recognized |
| Cross-artifact request wire marker | Existing `d2x1`; exact version-specific instructions plus schema's response-version enum distinguish requests |
| Authorization policy | Existing single-packet/cross-artifact policies; fresh grant also binds `response_version`, schema digest and complete body |
| Reference normalization / typed schema policy | Existing versions unchanged; they receive the frozen expected response version |

The canonical envelope shape did not change, so a second envelope version or
execution framework is unnecessary. `d2_quality.parse()` selects explicit nested
response semantics; execution first checks the response against the version and
schema frozen by the parent. It never chooses execution semantics from untrusted
output alone. Old and new response versions cannot be substituted.

`Prepared.identity()` seals version, body, schema, configuration, evidence context
and limits. The child reconstructs the same version and seal; the parent validates
the returned raw response independently. An absent version in an internal legacy
worker request selects legacy rules, and a new-policy seal cannot match that
reconstruction. There is no downgrade retry. Ephemeral in-memory identities are
not historical dispatch grants or restart authorization.

Historical `d2c1` codecs remain unchanged. Explicit legacy quality preparation
retains its old body, old inference-reason rejection and old outcomes. Historical
cross-artifact `d2x1` reconstruction is selectable with `response_version='d2q1'`;
its exact 6.130 serialized body hash is regression-tested. Original S1/S2/S3 state
is never rewritten.

## Implementation and coupling

| File / functions | Change |
|---|---|
| `investigation_ai/d2_quality.py`: schema, guide, validate, parse | Two explicit semantic versions; bounded outcome diagnostics; preserve rationale |
| `d2_schema.py`: build/from_packet/from_view/recognized | Build and recognize exact packet-specific schemas for either response version |
| `d2_wire.py`: schema_for/request_limit | Recognize exact old/new instructions and markers without changing ceilings |
| `d2_cross.py`: History/prepare/preview | Seal response version; measure the corresponding final schema/instructions during selection |
| `d2_execution.py`: Prepared, prepare, _Permit, _child, validate_model_response | Bind version through approval, reconstruction and both validation boundaries |
| `d2_normalization.py` | Apply expected-version structural schema; retain existing eligible-reference-only deduplication |
| `d2.py`: validate_response | Carry accepted rationale and version in the structured result |
| `d2_diagnostics.py` | Closed outcome metadata and concise exact rule display |
| `d2_presentation.py` | Explicit unverified rationale; avoid repeating the new abstention reason twice |
| `d2_issues.py` | Size new single-packet previews using the current instructions |

No changes were needed to `d2_result.py`, provider transport, backend, or
`ai/openai_schema.py`: the existing exact typed-schema recognizer delegates to
`d2_schema.recognized()`. Canonical envelope, terminal contracts, journal contracts
and investigation workflows are unchanged. Existing profile names still select
the codec family; `response_version` selects semantics. This naming distinction
and the distributed exact-schema recognizers are documented coupling for a future
independent review, not a reason to refactor security boundaries here.

## Instructions and provider schema

The new guide states `Inference:1-2 accounts, r optional. Abstention:0, r required`
and `Root r is unverified rationale, never evidence`. It retains typed original
references, interpretation premises, uncertainty, qualifications, untrusted-data
handling, proposed examinations, no factual execution/causality/attribution, no
tools and no S3 changes. It is **609 bytes**, versus the previous 611.

The response schema changes only its same-width version enum. Provider and
canonical schemas now both allow a bounded inference reason. Account-count and
nonblank abstention requirements remain canonical conditional checks, explicitly
described by the instructions. No larger discriminated schema, parser repair or
inference-to-abstention coercion was introduced.

## Sanitized diagnostics

Existing diagnostics may now carry allowlisted `outcome`, `account_count` (0–2),
`account_count_consistent`, `root_reason_state` (empty/nonempty/invalid), and
`outcome_rule`. Rules distinguish `inference_reason_forbidden` (legacy),
`abstention_reason_required`, `account_count_mismatch`,
`competing_alternative_required`, and `structural_invalid`.

No rationale text or evidence values enter diagnostics. Existing completion,
usage, origin and normalization receipts remain. Unknown values, arbitrary keys
and oversized diagnostics are rejected by the existing 2,048-byte boundary.
Parent revalidation retains its own origin/stage. Refusal, truncation and
unexpected finish reasons remain distinct from outcome validation.

## Exact request-budget gate

No evidence or qualifications were removed. Measurements include actual messages,
schema, model and parameters serialized by HTTPX, with installed OpenAI SDK mock
transport checking the outgoing bytes. No network/provider calls occurred.

Historical copied source:
`C:\tmp\locard-diagnostics\6.118-live\6ad0c85499564406aa4d949f3b0e72e5`.
Question: "What evidence connects the recorded download and subsequent filesystem
observations? Which links remain hypotheses and what additional examination would
discriminate?"

| Request | Legacy bytes | New bytes | Ceiling |
|---|---:|---:|---:|
| Historical cross-artifact | 16,268 | **16,266** | 16,384 |
| Historical single-packet issue | 5,455 | **5,453** | 5,600 |
| Browser only | 3,486 | 3,484 | 5,600 |
| Registry persistence | 3,689 | 3,687 | 5,600 |
| Process/service | 4,645 | 4,643 | 5,600 |
| Filesystem without EVTX | 3,876 | 3,874 | 5,600 |
| Prefetch only | 3,610 | 3,608 | 5,600 |
| Mixed | 6,204 | 6,202 | 5,600; still ineligible |
| Mixed small | 4,543 | 4,541 | 5,600 |
| Shared-path relationship | 4,645 | 4,643 | 5,600 |
| No relationships | 3,309 | 3,307 | 5,600 |
| Contradictory/incomplete | 4,777 | 4,775 | 5,600 |
| Large value | 5,568 | 5,566 | 5,600 |
| Extensive qualifications | 7,183 | 7,181 | 5,600; still ineligible |
| Oversized original value | 5,968 | 5,966 | 5,600; still ineligible |

Every measured old eligible single packet remains eligible. The historical
canonical evidence packet is identical, including all twelve original supports
and mandatory qualifications. New historical identity:

```text
body_sha256  7387a19bda548f708a1a742030776e601e6609d689024c796cf090c02264cee6
packet_digest c7e164375606ee467d7e9787466c8c039677cfa9713fb91f3d095060cbb395f8
schema_sha256 a89141c1f166c6e3c8c3f6b65db743553b4a4846bd46776950a68bb037bcd0fd
```

The unchanged packet digest is intentional; new body/schema and prepared/grant
identities prevent confusing old authorization with new response semantics.

## Validation and integrity

Final focused validation: **325 passed, 1 warning, 147.62 seconds**, followed by
**3 additional unrelated cross-artifact cases passed in 2.10 seconds**: **328
distinct passing cases**, zero remaining failures in these final runs. The main
run covered `test_d2_rationale.py`, `test_d2_quality.py`, `test_d2_cross.py`,
`test_d2_execution.py`, `test_d2_transport.py`, `test_d2_result.py`,
`test_d2_normalization.py` and `test_d2_selection.py`. The warning is the installed
Pydantic `ReadOnly` qualifier warning, not a failed security assertion. The existing
SDK diagnostic launcher exits only after pytest returns; natural interpreter
shutdown is not demonstrated by that launcher. Actual worker cleanup assertions
ran and passed. No full suite was requested or run.

The new `tests/test_d2_rationale.py` exercises legacy/new outcome combinations,
competing alternatives, exact rationale preservation, contradictory commentary,
missing/unknown/wrong-namespace support, interpretation closure, duplicate aliases,
empty optional fields, byte/whitespace/NUL limits, malformed JSON, refusal,
truncation, unexpected finish reasons, usage preservation, allowlisted diagnostics,
version/schema/policy tampering, exact historical SDK bytes and generic fixtures.

Existing Windows tests cover old/new historical single-packet requests, new
cross-artifact rationale preservation, cleanup, rejected response sanitation and
parent rejection of forged worker acceptance. A new synthetic historical proposal
cites O1/O12 pathname fields and O9/O11 timestamp fields, preserves volume/host/clock
uncertainty, proposes independent-file alternatives and an authorized examination,
and retains its root rationale. It is not evidence of live AI usefulness.

Development failures were investigated rather than weakening assertions: old
fixtures assumed the legacy default/version/body size; worker fixtures lacked
the explicit response version; one fixture edit mistakenly referenced an undefined
variable. Legacy scenarios now explicitly select old semantics, and new-policy
mock replies use the requested version. The fixture mistake was corrected.
The initial compatibility run recorded 236 passed / 6 failed; a later focused
run recorded 59 passed / 1 failed from that fixture-edit mistake. These are
development results, not additional distinct passes or remaining failures.
The subsequent final runs above supersede those failures. `git diff --check`
and explicit whitespace checks of the new files passed.

Historical manifest/event hashes were checked before and after relevant Windows
and SDK tests and remain:

```text
manifest.json 23a6e2c496b2e34aa20810e08c152e37b8b51afacde0a3dba1a074e16e7e350f
events.jsonl  a943a1e2bf39d8f2aafca6f374804f1cefb20b080bc2cdf0a46d2c050625ac28
```

No current case database, original transcript, sidecar or permissions were modified.
These hashes prove no change to those copied files during this work, not historical
forensic integrity before their baseline existed.

## Manual acceptance

After the analyst's Git/install workflow in the separate test checkout:

```powershell
.\.venv\Scripts\python.exe -m pip install -e .
.\.venv\Scripts\locard.exe --version
$root = 'C:\tmp\locard-diagnostics\6.118-live'
$run = '6ad0c85499564406aa4d949f3b0e72e5'
$question = 'What evidence connects the recorded download and subsequent filesystem observations? Which links remain hypotheses and what additional examination would discriminate?'
.\.venv\Scripts\python.exe -m forensic_assistant.investigation_ai.d2_reasoning $root $run --cross-artifact --question $question --json
```

Verify version 6.131, OpenAI / `gpt-6.1-sol`, `response_version: d2q2`, the three
digests above and 16,266 bytes. The preview is provider-free, not authorization.
Stop for manual acceptance. Only after separate approval for one live usefulness
test, append `--execute` to that invocation and approve the exact displayed
request. `--json` may be retained for the single structured result; do not run it
twice to obtain both output formats. No live request is performed by this task.

All existing limits remain: one attempt/round, 1,024 completion tokens, 60 seconds
including cleanup, 32-KiB terminal IPC, 128-KiB receive, zero new lookups, no retries,
fallback, continuation or durable D2 response persistence. High completion usage
does not imply truncation. A simpler rationale rule does not prove that model prose
is entailed, internally consistent or useful; those remain explicit analyst
acceptance judgments. The unrelated zero-analysis reconstruction defect is untouched.

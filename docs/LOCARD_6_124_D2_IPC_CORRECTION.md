# Locard 6.124 — D2 IPC correction

Date: 2026-11-10. Starting revision: `ad794c17d8b4beebfe5b689dd83fccf6d21c54ed` (6.123). This document describes the uncommitted 6.124 working tree. No live provider requests were made.

## Defect and correction

The authorized 6.123 historical request fit its 5,600-byte HTTP-body budget, but a successful child response expanded into a 191,464-byte IPC message. Its embedded unchanged S3 assessment occupied 172,460 bytes. The parent called `recv_bytes(131072)`, closed the pipe with `bad message length`, and the child's second error-reporting send could raise another BrokenPipeError.

The isolated regression still constructs and measures the exact 191,464-byte legacy message. Corrected Windows-spawn execution sends **1,094 bytes**, retains the same validated proposals and original S3 `NOT_ASSESSABLE`, and confirms cleanup. The complete model request remains **5,324 bytes** for this fixture. The original live response and billing remain unknown.

## Contract and ownership

`forensic_assistant/investigation_ai/d2_result.py` defines `d2-worker-result-v1`:

| Field | Meaning |
|---|---|
| contract | Exact version; unknown versions rejected |
| binding | Request ID, canonical packet digest, complete request SHA-256, source run/manifest/frontier, issue, provider and model |
| status / validation | Accepted + passed, or rejected + not_accepted; child assertion alone grants no evidence authority |
| response | Original structured model response string on success; null on failure |
| attempted | Whether backend entry was attempted; not proof of transmission |
| provider_response_received | True only when observed; null if unknown; false before backend entry |
| stage / category | Allowlisted stage and diagnostic code, never arbitrary exception text |
| usage | Optional bounded integer token counters only; absent usage is unknown |

No S3 replacement, C1/D1b state, original packet, transcript, prompt or error body is accepted in the envelope. Unknown fields and forged bindings fail closed.

The child reconstructs and validates the recorded source as before, preserves provider/model authorization, calls the existing backend once, and applies the strict D2 validator. It sends the small structured response instead of its expanded validation return value.

The parent owns the authenticated packet and S3 context. `Prepared` freezes a validation context before approval and includes it in the preparation seal. It contains the original assessment, source anchor, eligible issue IDs and independently recomputed registered S2 relationships. The parent never constructs this context from child data.

`d2.validate_response` extracts the existing strict validation body without changing its checks. Historical `History.validate` still rebuilds the packet and verifies the source, then invokes that validator. After IPC, the parent invokes the same validator using frozen local context. Aliases resolve only through the authorized packet; interpretations require premises; registered relationships require original endpoints and semantics; model prose remains mechanically accepted **unverified** reasoning. S3 and coverage qualifications remain unchanged.

This is reusable backend logic, not terminal-only validation. The renderer still uses parent-owned evidence and qualifications. It additionally distinguishes received/not-observed/unknown provider-response status.

## Bounds and execution

- Terminal envelope budget: **32,768 bytes including an eight-byte conservative framing allowance**. Maximum JSON payload is therefore 32,760 bytes.
- Existing parent receive ceiling remains **131,072 bytes**.
- Existing raw structured-response cap remains **16,384 UTF-8 bytes**; canonical schema also bounds strings and cardinalities.
- Exact compact UTF-8 JSON serialization is measured before send. Control-character escaping can expand serialized bytes; tests exercise that expansion. Token count is never used to assume a byte bound.
- The measured successful message is 1,094 bytes. The 32 KiB budget allows the bounded response plus bindings/usage/status while leaving a large margin below transport capacity. An exceptional escaping-heavy or oversized envelope is rejected, not truncated.
- Serialization failure or oversize produces one small failure envelope before any terminal send. No splitting, field stripping or retry occurs.
- If the channel write fails, no second write is attempted. Child exits with controlled code 74; the parent reports IPC send failure when that exit is observed, otherwise channel closure/unknown exit as available.

One attempt, one round, 1,024 output tokens, 5,600 HTTP-body bytes, zero additional lookups/retries/fallback and the 60-second allocation are unchanged. Work uses the existing approval+55-second deadline; the final five seconds remain reserved for containment.

Parent validation performs no filesystem, replay, provider or database operations. It processes bounded packet/response data, checks cancellation/deadline before and between proposal validations, and checks again after construction before accepting the result. It does not start a new clock or move history replay outside supervision. As with other synchronous bounded Python operations, a single serialization/copy is not preemptible midway; no result is accepted after the deadline check fails.

## Error handling and accounting

| Observed condition | Result category |
|---|---|
| Initialization/provider identity/source checks fail | worker_initialization_failure |
| Backend fails without more specific observable state | provider_dispatch_failure |
| Provider timeout | provider_timeout |
| Recognized provider refusal | provider_refusal |
| Provider response envelope invalid/incomplete | provider_response_invalid |
| Structured response/citation validation fails | response_schema_validation |
| Result cannot serialize | result_serialization_failure |
| Exact result exceeds terminal budget | result_byte_limit |
| Parent cannot receive framed message | ipc_receive_failure |
| Malformed envelope or forged binding | ipc_invalid_message |
| EOF without terminal message | ipc_channel_closed, or worker_terminated_unexpectedly if abnormal exit observed |
| Controlled failed child send observed | ipc_send_failure |
| Work deadline / analyst cancellation | timeout / cancelled |
| Containment not confirmed | Existing CleanupError / CLEANUP_LIMITATION; never success |

The SDK's existing refusal/envelope metadata is not always specific enough to distinguish a refusal from invalid content; do not invent that distinction. Response receipt is marked only when backend return or existing positive envelope metadata supports it. The implementation does not infer non-billing from missing usage or failed IPC.

Attempt allocation is still consumed once before launch. The child attempt message precedes backend entry. A missing attempt message after gate release remains unknown, at most one. An accepted envelope cannot provide a new provider identity, scope, grant, source assessment or evidence payload. Raw exceptions are not printed by the controlled send-failure path.

## Validation

The focused tests cover:

- Exact 191,464-byte legacy regression and 1,094-byte corrected spawn result.
- Parent-owned strict validation with replay/database access prohibited.
- Forged request/body/packet/source/issue/provider/model bindings; unknown fields and evidence aliases.
- Invalid schema/JSON, proposed authoritative execution/causal fields, oversized responses and messages.
- Unicode byte accounting, control-character escaping, usage allowlist, serialization failures.
- One failed write only; normal Windows child exit; closed channel; unexpected exit; receive overflow; cancellation and timeout; confirmed cleanup.
- Existing authorization/no-retry/provider isolation and generic artifact fixtures.
- Existing actual OpenAI SDK path against MockTransport only.

Final results (overlapping sets, not summed):

| Focused run | Result |
|---|---|
| D2 result/execution/preview, synthesis packets/consumer, OpenAI schema, D1b replay/compaction | **267 passed in 121.91 seconds** |
| Final IPC set including normal-exit/closed-pipe spawn additions and renderer check | **32 passed in 23.68 seconds** |
| Actual installed SDK with mock HTTP transport | **22 passed in 10.34 seconds**, one upstream Pydantic ReadOnly warning |
| Exact historical overflow regression, separately measured | **1 passed in 5.84 seconds**, 191,464 -> 1,094 bytes |

`git diff --check` passes. New files, including this otherwise-ignored document, are marked intent-to-add for review; no file contents are staged and no commit is created. The initial development run had seven fixture failures because direct child tests lacked the newly required binding. Only those fixture inputs were updated; their rejection/no-retry/redaction assertions were preserved. A subsequent execution/result run passed 85 tests. No full suite ran.

Free-form model language is not deterministically proven true. Tests reject structural attempts to add authoritative execution/causal status; ordinary model hypotheses remain explicitly unverified. This correction does not introduce a new prose entailment validator.

## Historical compatibility

Provider-free reconstruction read only the three requested 6.118 copies and the existing readable 6.111 copy. D2 previews were compared with `git show HEAD`'s original D2 implementation. All matched. B2 and D1b reconstruct successfully; D1 pages retain their previous behavior. All eight manifest/events hashes stayed unchanged.

| Run | D2 preview digest |
|---|---|
| 6ad0c85499564406aa4d949f3b0e72e5 | cb1308c5873137b2a6feddcfbdbdca0cf7ef72e19bdea358e51c6df5680ab500 |
| ffdabecc9ded47e6acd5f4977fa3c2fa | 8717086a7e6cf2f18832dfb898c4c604e6001c16d9040e9fbaaffe456457ba2b |
| 08cfd054f85a4a36b8520832427201c3 | 18348f984e0c23df4e00d4e43c8d3930a550eef062951c1aa7c8d5b14b444cdd |
| 6.111 ec81a1af5b1f471ca4f3a4c0bb917fa2 | f3a6fed1a18f11e9b2395ef5e4b5025befa7cb066d300842a7bc7fa7744a9fa4 |

The 6.111 D1 page digest remains `36121cbc44ec2f3577ec9ecaae946f444a36abdeb4f33e607ae17b5b2d6399fc`.
The zero-analysis 6.118 D1 page builder still raises the pre-existing `Cross-view explanation`; D2/B2/D1b replay succeeds. No correction outside IPC scope was attempted. Current hashes prove diagnostic preservation of these copies, not historical integrity of the uninspected live database.

## Changed files

- `pyproject.toml`: 6.124, sole version authority.
- `forensic_assistant/investigation_ai/d2_result.py`: bounded versioned terminal envelope.
- `forensic_assistant/investigation_ai/d2_execution.py`: frozen local validation context, bounded child send, strict parent receipt/validation, sanitized IPC outcomes.
- `forensic_assistant/investigation_ai/d2.py`: reuse existing validation as an IO-free operation; historical API retained.
- `forensic_assistant/investigation_ai/d2_reasoning.py`: provider-response observation status.
- `tests/test_d2_result.py`: IPC and large-source regressions.
- `tests/test_d2_execution.py`: direct-child fixtures supply authenticated binding.
- This document.

## Manual acceptance

After your commit/push/pull and installation in the test checkout:

```powershell
Set-Location C:\tmp\locard260927\locard
.\.venv\Scripts\python.exe -m pip install -e .
.\.venv\Scripts\python.exe -c "from importlib.metadata import version; print(version('locard-forensics'))"
# Expected: 6.124
$root = 'C:\tmp\locard-diagnostics\6.118-live'
$run = '6ad0c85499564406aa4d949f3b0e72e5'
$issue = 'd81869143ab5f3a355285bd79802d93912491834bc4f602c0a5fda6fd28739e7'
# Provider-free, no grant or transmission:
.\.venv\Scripts\python.exe -B -m forensic_assistant.investigation_ai.d2_reasoning $root $run --exploratory --issue $issue --json
# Provider-free regression, if developer tests are installed:
.\.venv\Scripts\python.exe -B -m pytest -q tests/test_d2_result.py::test_exact_historical_overflow_fixed
```

Only if you choose to authorize a new paid request:

```powershell
.\.venv\Scripts\python.exe -B -m forensic_assistant.investigation_ai.d2_reasoning $root $run --exploratory --issue $issue --execute
```

Review the exact provider/model, source, issue and budget before answering y. Expected: recorded evidence separately rendered, AI explanation explicitly unverified, original S3 NOT_ASSESSABLE, one attempt, no new lookups, cleanup confirmed. This is a new authorization, not an automatic retry of the failed request. D2 remains ephemeral; no result sidecar is written.

## Remaining limitations

No live provider outcome is claimed. The previous request's response/usage/billing remain unknown. The terminal budget can still reject unusually large serialized results safely. Remote work cannot be retroactively cancelled or unbilled by local cleanup. No durable D2 state, multi-round reasoning, new provider parity or causal authority is added.

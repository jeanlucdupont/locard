# Locard 6.187 — token-aware local context management

2026-11-27. Implementation based on committed 6.186 (`f712e9d`). Real llama.cpp parity and improved investigative capability remain pending analyst acceptance. No model or dependency download is required.

## What the live result establishes

The analyst reports successful 6.186 native-tool, full-catalog and mock diagnostics. The full-catalog requests were 15,077 / 15,430 HTTP bytes but 4,609 / 4,662 prompt tokens. The actual synthetic investigator made two successful requests and two successful operations, then paused with `CONTEXT_CAPACITY`; no original inspection, verification, memory retrieval or final response occurred. Its case remained unchanged and worker cleanup was confirmed. These are user-reported results, not executions repeated during development.

This does **not** demonstrate exhaustion of 32,768 model tokens. The exact third candidate was not captured and cannot be reconstructed numerically from these aggregates.

## Source-confirmed failure path

`resources.request_capacity` in 6.186 subtracted output reservation, 2,048 framing units and wire overhead from configured tokens, then used the result as a byte ceiling. `Session.messages` assembled authorization, the ten-tool catalog, a bounded workspace projection, the initial analyst message and recent complete exchanges. Its reverse history selection stopped at the first oversized exchange. If the latest exchange was not retained, it raised before the successful-consolidation counter/event. Thus zero recorded consolidations did not mean reduction was unnecessary or that the model was full.

With unchanged instructions/catalog and the first two requests fitting, the latest-exchange guard explains how a growing tool result/workspace combination can fail on the next iteration. There is insufficient captured data to identify the exact field or byte contribution in the live third candidate. New diagnostics record component sizes and the limiting resource without recording another full prompt.

## Backend path and parity

The referenced [llama.cpp source at b2e5e9b28](https://github.com/ggml-org/llama.cpp/blob/b2e5e9b28/tools/server/server-context.cpp) uses `oaicompat_chat_params_parse` for both `/apply-template` and chat inference; inference tokenizes the rendered prompt with special-token insertion and parsing enabled. Locard supplies the same final body to template rendering: messages, native calls/results, transformed tools, tool choice, sampling/output settings and non-thinking template kwargs. It then sends the rendered prompt to `/tokenize` with `add_special=true`, `parse_special=true`, `with_pieces=false`. It never tokenizes raw HTTP JSON as a model prompt.

The [server endpoint documentation](https://github.com/ggml-org/llama.cpp/blob/b2e5e9b28/tools/server/README.md) describes template rendering without inference and the tokenizer flags. Source inspection supports the intended parity path; it does not establish the analyst's binary/configuration behavior. Live counts must still be compared.

`local_context.ContextMeter` is a session-local service. It checks `/props`, fingerprints returned server/template properties and performs one harmless template feature probe per stable server identity. The probe includes system/user content, native assistant/tool messages and the actual tool catalog. Missing message sentinels or tool names fail capability detection. This is a compatibility check, not proof of all template semantics.

Each actual candidate is rendered/tokenized. Initial and tool-bearing histories independently require **exact measured/reported prompt-token agreement** from an already-authorized normal completion before subsequent counts of that class govern capacity. Measurement itself never launches a completion. A new authorization starts with new parity state; the separate diagnostic cannot authorize or silently calibrate another session.

On observed parity, capacity is measured input tokens + reserved output + **32 tokens** of additional framing reserve. The small reserve is an operational cushion after exact observed parity, not a universal guarantee against arbitrary template changes. Before parity, use the explicitly labeled 6.186-style conservative byte fallback with its 2,048 reserve. A mismatch disables trusted counts for the session. Missing usage cannot establish parity. Changed server properties reset parity. The lower of configured capacity and a valid reported slot `n_ctx` is used; training context does not increase the approved allocation.

There is no persistent token-count cache. Only the selected, exact request digest has a single-dispatch measurement receipt, bound to local configuration, server identity and session. It is consumed on dispatch and cleared on session closure. Different candidate content is measured again. No rendered forensic prompt is written to a separate cache. Server mutation between the last measurement and inference cannot be locked by this client; the analyst must keep the trusted server configuration stable. Returned usage is checked again after each completion.

## Independent limits

| Dimension | Behavior |
|---|---|
| Model context | Configured tokens; bounded by reported slot allocation when available |
| Output reservation | Existing configured `output_tokens`, unchanged |
| Template reserve | 32 tokens after parity; explicit 2,048-unit conservative fallback before parity |
| HTTP request | Existing requested byte limit (default 256 KiB), maximum 512 KiB; final JSON body measured |
| Auxiliary body / rendered prompt | 512 KiB technical transport bound; no truncated tokenization input |
| Child IPC | Existing 600 KiB request and 1 MiB response bounds |
| HTTP response | Existing 1 MiB bound; bounded token list and strict types |
| Tool results | Existing `result_bytes`, unchanged |
| Automatic workspace projection | Existing bounded SQL selections and 6,000-byte target; optional projections may be omitted explicitly |
| Measurement deadline | At most 30 seconds per candidate, shared by its metadata/render/tokenizer steps, clamped to active investigation/provider time |
| Inference deadline | Existing provider deadline and optional active-work limit, unchanged |
| Analyst budgets | Inference attempts, operations, cumulative tokens, records and exposure remain distinct; no new investigative quota |

OpenAI capacity and routing are unchanged. All ten tools, 6.186 generation adaptation and canonical validators are preserved. No evidence/workspace schema or authorization identity migration is introduced.

## Consolidation and recovery

The local selector first measures the complete candidate. On failure it attempts to reduce optional notebook projections, then selects a fitting suffix of **whole exchanges** using bounded binary search. It preserves authorization, tools, initial/current objective and principal workspace state. Omitted note/verification/search projections remain queryable; their omission is explicit and does not erase the journal or SQL projection. Relevant original values can be rehydrated and verified through the existing tools.

An indivisible latest exchange is never silently split. If it still cannot fit, a separate mandatory-envelope measurement distinguishes instructions from workspace/latest-exchange pressure. The pause identifies token capacity, conservative unverified capacity or byte containment, plus the blocking component. Retrieved results remain persisted but are not newly counted as inference-disclosed or examined. The analyst can redirect with, for example, “Use memory actions/evidence to recover the last result and inspect smaller show_evidence pages.” The new analyst exchange permits omission of the old oversized exchange; the result stays available in the workspace/journal. This is recovery, not an automatic retry or additional authorization.

## Security, accounting and diagnostics

Auxiliary calls use the same checked numeric-loopback endpoint and contained child transport, with no DNS, proxies, redirects or cloud fallback. Cancellation closes the owned client child; the independently owned server's cancellation cannot be attested. Every auxiliary attempt has a durable intent before transport, a route/body digest and byte count. Template/tokenizer body bytes are charged against cumulative disclosure and counted separately as `auxiliary_bytes`; they do not consume an AI-completion attempt or fabricate billable usage. An audit/budget failure prevents the call. Auxiliary text exposure creates **no** verification authority, original-field exposure ledger entry or inference-disclosed record.

Candidate diagnostics include configured/server tokens, measured tokens, active method and capability, output/margin/remaining capacity, exact HTTP bytes and byte ceiling, rendered bytes, mandatory/catalog/workspace/latest-exchange sizes, retained/omitted history, consolidation attempts, and separate metadata/template/tokenizer/inference durations. They include hashes, sizes and statuses, not complete rendered prompts or original values. Normal model request/journal policies remain unchanged.

Unsupported endpoints, partial template/tokenizer support, malformed data, network failure, timeout, unknown parity and parity mismatch are explicit. Fallback is conservative and may still stop early. The implementation does not claim a universal characters-per-token ratio. Model reasoning quality remains independent of capacity management.

## Automated validation

Only synthetic fixtures/mock endpoints are used. Mock token counts are deliberately artificial and labeled as such. **195 distinct focused tests passed**, counting overlapping follow-up runs only once:

| Focused set | Distinct tests | Recorded result |
|---|---:|---|
| Conversational provider/AI, resource policy, investigative memory, behavioral population reuse | 127 | 127 passed in 218.51 s |
| Existing local conversation and grammar suites | 50 | 50 passed in 47.95 s |
| New token-aware context suite | 18 | Initial 16 passed in 7.27 s; single-use receipt passed in 0.86 s; cancellation case passed in a 3-test follow-up (0.64 s, two overlapping cases) |

Subsequent focused checks covered final status measurements, whole-exchange suffix selection, and the token-aware mock integration. The final mock/context run passed 17 tests in 79.14 s (overlap, not additional distinct tests). `git diff --check` passed. Source version resolves to **Locard 6.187**.

One existing test expectation changed: local `request_capacity` now reports the independent HTTP byte capacity, not `configured_tokens - output - 2048` expressed as bytes. The new tests separately enforce token limits and fallback. No forensic/security assertions were weakened. No full regression suite or live provider was run.

The new tests cover independent token/byte limits; candidates larger in bytes than configured token count; actual fixture token exhaustion; auxiliary accounting without authority; malformed/unsupported/partial endpoints; network and timeout fallback; child timeout cleanup; cancellation/audit propagation; parity mismatch and server-identity invalidation; exact receipt binding; complete native sequencing; oversized latest-exchange diagnostics; and disclosure budgets preventing auxiliary transport.

### Measured synthetic mock run

The standalone `--mock` run passed **12/12 checks**, exited zero, and took **65.00 seconds** including reconstruction. It completed 26 inference requests and 25 successful operations, with zero failures and analyst pauses; 23 consolidations and 51 automatic checkpoints occurred. Original-value recovery, verification history, incomplete-search recovery, case SHA-256 stability, deterministic reconstruction and worker cleanup passed.

There were **139 auxiliary attempts** (46 metadata GETs and 93 template/tokenizer POSTs), exposing 2,379,611 aggregate auxiliary body bytes to the mock. Measurement consumed **41.67 seconds**, including per-call contained client startup. Inference bodies ranged from **20,179 to 27,770 bytes**, below the existing diagnostic 28,000-byte ceiling. This pressure fixture retains its artificial 32,096-token configuration; production/manual acceptance remains 32,768.

This is meaningful overhead relative to instantaneous mock inference. It is not a measurement of llama.cpp CPU tokenization or Qwen inference. Each ordinary candidate uses a metadata check, rendering and tokenization; consolidation may measure multiple distinct candidates. No count cache crosses server/template identity or authorization. A future persistent transport could reduce child-startup overhead, but it was not introduced as an unreviewed lifecycle redesign. Actual latency and the fraction of time spent measuring must be reviewed in the acceptance JSON.

## Changed files

- `forensic_assistant/conversational_ai/local_context.py`: new session-bound measurement/parity service.
- `conversational_ai/local.py`: allowlisted auxiliary transport and one-use measured dispatch (under `forensic_assistant/`).
- `conversational_ai/resources.py`, `service.py`, `cli.py`: separated capacities, local consolidation, exposure accounting and presentation.
- `forensic_assistant/ai/backend.py`: forwards the session's measurement receipt on local dispatch only.
- `scripts/diagnose_local_provider.py`: tokenization/parity diagnostic, synthetic capacity output and mock tokenizer.
- `tests/test_local_context.py` and the single revised capacity expectation in `tests/test_local_conversation.py`.
- `pyproject.toml`, this document and its `.gitignore` inclusion.

## Windows acceptance — existing environment and server

After you update the test checkout to your committed 6.187 changes, use your existing Python executable. No dependency reinstall, model download or server restart is required by this release. Keep CPU inference, context **32768**, existing alias, loopback and Jinja settings. Do not use a real case in this batch.

`--tokenization` explicitly makes at most two harmless completions to compare usage: one initial request and one constructed synthetic tool-result history. It covers the full catalog, Unicode, Windows paths, a long EID, Registry text, escaped JSON and a mock memory result. This diagnostic is separate from production measurement, which makes no hidden completions. A mismatch fails the diagnostic; inspect it before proceeding.

The script archives results even on failure. Existing server logs may contain other sessions; review them before sharing.

```powershell
$ErrorActionPreference = 'Stop'
Set-Location 'C:\tmp\locard'
$python = Read-Host 'Path to the existing Python executable used for Locard (or python)'
if (-not $python) { $python = 'python' }
$endpoint = 'http://127.0.0.1:8080'
$model = 'locard-local'
if ((Read-Host 'Confirm existing trusted server: Qwen3-4B, CPU, 32768 context, single slot, Jinja, alias locard-local. Type YES') -cne 'YES') { throw 'Verify existing server configuration first.' }
$serverLogs = Read-Host 'Existing server log paths separated by semicolons (blank if unavailable)'
$out = Join-Path $env:TEMP ('locard-6187-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $out | Out-Null
'Locard 6.187 synthetic acceptance; no real-case commands.' | Set-Content -Encoding utf8 -LiteralPath (Join-Path $out 'run.txt')
function Invoke-LocalCheck([string]$name, [string[]]$diagnosticArgs) {
    $result = & $python scripts\diagnose_local_provider.py @diagnosticArgs 2> (Join-Path $out "$name.stderr.txt")
    $code = $LASTEXITCODE
    $result | Set-Content -Encoding utf8 -LiteralPath (Join-Path $out "$name.json")
    $result
    if ($code -ne 0) { throw "$name failed (exit $code). No real-case acceptance." }
}
try {
    $version = & $python locard.py --version
    $code = $LASTEXITCODE
    $version | Set-Content -Encoding utf8 -LiteralPath (Join-Path $out 'version.txt')
    $version
    if ($code -ne 0 -or "$version" -notmatch 'Locard 6\.187\b') { throw 'Update the test checkout to 6.187 before testing.' }
    git rev-parse HEAD | Set-Content -Encoding utf8 -LiteralPath (Join-Path $out 'revision.txt')
    $common = @('--endpoint', $endpoint, '--model', $model, '--context', '32768', '--timeout', '600')
    Invoke-LocalCheck '01-mock' @('--mock')
    Invoke-LocalCheck '02-native' ($common + @('--output-tokens', '512'))
    Invoke-LocalCheck '03-full-catalog' ($common + @('--full-catalog', '--output-tokens', '512'))
    Invoke-LocalCheck '04-tokenization-parity' ($common + @('--tokenization', '--output-tokens', '512'))
    Invoke-LocalCheck '05-synthetic-investigation' ($common + @('--synthetic-investigation', '--output-tokens', '2048'))
    Write-Host 'Review inspection, verification, memory recovery, final response and reasoning quality separately.'
}
finally {
    $n = 0
    foreach ($log in ($serverLogs -split ';')) {
        if ($log.Trim()) {
            $n++
            if (Test-Path -LiteralPath $log.Trim() -PathType Leaf) {
                Copy-Item -LiteralPath $log.Trim() -Destination (Join-Path $out "server-$n.log") -ErrorAction Continue
            }
        }
    }
    Compress-Archive -Path (Join-Path $out '*') -DestinationPath "$out.zip"
    Write-Host "Diagnostic archive: $out.zip"
}
```

## Remaining limitations and scope

Exact real-machine parity, tokenization latency and deeper synthetic forensic progress are unverified until this acceptance runs. Separate sessions deliberately re-establish parity from their own authorized responses. A large first/tool-history request that cannot fit the conservative bootstrap may pause before parity is established; no persisted diagnostic result silently bypasses this gate. A server without suitable properties/endpoints retains the conservative fallback. Large indivisible results, missing usage, a template change or a genuine token limit can still cause an explicit pause.

No tokenizer dependency, universal multiplier, model change, parallel agent, GPU optimization, dynamic tool routing or memory redesign was added. Version is **6.187** in `pyproject.toml`. No commit or push was performed.

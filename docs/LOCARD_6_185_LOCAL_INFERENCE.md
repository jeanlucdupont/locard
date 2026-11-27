# Locard 6.185 — Local conversational inference

Implementation date: November 27, 2026. Starting accepted revision: `ca55375` (6.184), clean working tree. Application version: **6.185**, from `pyproject.toml`. No dependency installation, model download, real-case access, paid inference, commit or push was performed during development.

## What changed

The conversational investigator now accepts an explicit, session-bound **loopback llama.cpp OpenAI-compatible endpoint** through the existing `ModelBackend`. The OpenAI/LiteLLM reference path is retained. No second investigation engine, evidence store or memory service was introduced.

The existing local infrastructure already provided llama.cpp process management, a numeric-loopback validator and structured-completion transport. Native conversation was blocked by the CLI, authorization and `ModelBackend.converse`. Its legacy JSON completion endpoint could not be reused unchanged: a conversation needs native assistant `tool_calls` and matching `tool_call_id` results, not arbitrary JSON prose.

The new conversation transport reuses the loopback validator and Windows worker-job containment, with a small standard-library HTTP adapter. It does not route local requests through LiteLLM or initialize a cloud SDK. The initial supported runtime is an **analyst-started llama-server** with a tool-capable chat template. Existing managed startup/preferences are unchanged; they are not silently reconfigured to add tool calling. An existing suitable server can be reused. No server/model is automatically started or downloaded by the new conversation path.

## Configuration and approval

| Setting | Interface | Meaning |
|---|---|---|
| Provider | `--local-endpoint http://127.0.0.1:8080` | Explicit local override for this conversation; saved OpenAI preferences unchanged |
| Model | `--local-model locard-local` | Exact server model ID/alias; not attestation of model weights |
| Context | `--local-context 32768` | Declared server context tokens, 4096–131072; match the server's per-slot allocation |
| Output | `--output-tokens 2048` | Existing output reservation; choose explicitly for local testing |
| Tool mode | Default sequential; `--local-parallel-tools` optional | Requests multiple calls only when enabled; Locard still executes calls sequentially |
| Sampling | `--local-temperature 0.2` | Explicit numeric sampling parameter, 0–2 |
| Provider deadline | `--provider-seconds 600` | Existing technical bound, 1–600 seconds; default remains 180 |
| Analyst budgets | Existing `--max-seconds`, `--max-requests`, etc. | Unchanged optional session budgets; no arbitrary successful-operation quota |
| Continuation | Existing checkpoint controls | Automatic default, explicit pause mode retained |

The new local grant is `conversational-authorization-v3`, containing the canonical endpoint, model, context and sampling/tool-mode binding. Existing v1/v2 OpenAI grants remain supported. The Session and worker validate the grant; the Session also compares the live backend binding before work. Model-provided arguments cannot change it. A saved grant or SQLite workspace never authorizes a new execution.

Only HTTP numeric loopback addresses (and `localhost`, canonicalized to `127.0.0.1`) are accepted. Remote/LAN addresses, arbitrary hostnames, credentials in URLs, query strings, redirects and proxy routing are rejected. This release **does not implement remote local-server authorization**; it refuses such endpoints rather than treating a LAN server as local. Supplying local options without an endpoint cannot silently select the saved cloud provider.

Approval displays the loopback endpoint and context/reservation information and explicitly authorizes repeated local model disclosure. Locard's client makes no external AI fallback. A loopback address does not attest the server's software or prevent an independently configured server from forwarding data: use a trusted local runtime and appropriate host/network controls.

## Native protocol and execution

`conversational_ai/local.py` sends `POST /v1/chat/completions` with model, messages, all ten tools, `tool_choice`, `max_tokens`, explicit sequential/parallel preference, temperature and `stream=false`. Non-thinking template mode is requested. Native calls must have unique IDs, function names and strict JSON object arguments. Tool results retain their IDs and complete exchange ordering. Multiple calls are accepted within existing response bounds and executed sequentially. Final text remains unverified model interpretation.

Existing canonical response/argument validation remains in force. Malformed JSON, duplicate call IDs, invalid usage, truncated output, legacy `function_call`, unsupported finish reasons and mismatched tool-call/finish structures fail closed. Prose resembling a tool call is never executed. A successful text reply alone does not prove tool compatibility; the diagnostic explicitly requests and validates a harmless native call and its continuation.

Each inference request runs in a fresh, bounded HTTP client subprocess, without provider credentials or proxy environment variables. Parent timeout/Ctrl+C closes the Windows job and kills/waits for the client where needed. A cleanup failure remains an error. HTTP response size and IPC size are bounded. No automatic retries, schema-repair requests, fallback models or hidden readiness inference are introduced.

The independently running llama-server is **not owned by that subprocess**. Disconnecting usually informs a server that a client has gone, but this implementation cannot confirm server-side cancellation or release of server-owned RAM/VRAM. Stop/restart your own server if it continues computing after cancellation. Locard does not terminate unrelated processes. Provider execution is nonstreaming: existing elapsed activity messages continue, but live generated-token progress is unavailable. Completion usage is provider-reported, duration/request bytes are measured, and missing usage/RAM/VRAM remains unavailable. A parent deadline is absolute, not refreshed by received bytes.

## Context and original evidence

Measured catalog: **10 tools, 13,311 UTF-8 bytes**, including **3,795 description bytes**. Shared system instructions: **2,184 bytes**, plus approval, local small-page guidance, current objective and bounded workspace projection. Most tool-catalog size is schema/argument structure. No tools or forensic constraints were removed. The memory description was clarified rather than introducing dynamic tool routing.

Local capacity uses the configured context, requested output reservation, a **2,048-unit template reserve**, and exact JSON transport overhead. The resulting message/tool byte ceiling is further clamped by the existing request-byte limit. The final HTTP JSON body is independently measured before dispatch. A byte proxy is **not a tokenizer guarantee**: tokenizer behavior, server templates and actual server context allocation can differ. The template reserve is an engineering estimate, not measured model tokens. This release does not depend on optional template/tokenizer APIs that differ across server builds. The diagnostic reports that limitation and returned usage rather than inventing exact token counts.

With 32,768 configured context tokens and 2,048 output tokens, the HTTP body proxy allowance is 28,672 bytes; message/tool allowance is slightly smaller by the exact envelope overhead. A 4,096-token context cannot hold the mandatory catalog and instructions. Locard records the mandatory/usable byte sizes and pauses before model dispatch instead of deleting authorization instructions. **32K is the initial test configuration, not a promise of reasoning quality or VRAM fit.**

The accepted SQLite workspace remains an indexed, selective projection of the authoritative JSONL journal. Local requests can retrieve prior EIDs, action coverage, note revisions and verification references; originals still require `show_evidence` and existing field verification under the pinned read view. Complete historical exchanges can be omitted; omitted evidence remains recoverable. No whole workspace is loaded into model context.

Small-page guidance recommends starting original inspection with `limit=3`, then following `next_offset`. Limits are guidance, not a capability restriction. Large results can still exceed available context and produce an explicit pause; redirect to smaller pages using memory references. Existing 1,024-byte scalar preview truncation and redaction remain explicit and do not confer verification authority. There is no new arbitrary substring reconstruction for an oversized original scalar; pagination advances fields, not chunks within a field. Use existing deterministic inspection outside the model when a complete scalar cannot be disclosed safely.

## Memory filter correction

- `evidence_id`: only `evidence`, `fields`, `verified`.
- `query`: only `notes` (literal text) or `actions` (exact tool name).
- `status`: only `notes`, `actions`.
- Other views use bounded `limit`/`offset` navigation; `state` is a summary.

The canonical argument layer rejects incompatible combinations before execution. Tool feedback now explains these combinations, rather than returning only a generic failure. Evidence/field lookup does not become an unrestricted narrative/content scan or a SQL tool. Exact-repeat information remains concise and recoverable; successful repeated operations are still permitted.

## Diagnostics and acceptance status

`scripts/diagnose_local_provider.py` has three modes:

1. `--mock`: disposable loopback HTTP server with scripted responses, **production ModelBackend/subprocess transport/Session/forensic worker**, synthetic case, memory pressure and independent reconstruction. No real model.
2. `--endpoint ... --model ...`: model availability from `/v1/models`, harmless text request, required native echo call and associated tool-result continuation. It reports usage and explicit unsupported-protocol outcomes. This makes real local model requests, but sends no forensic evidence.
3. `--synthetic-investigation`: actual configured local model with disposable synthetic forensic records and the production service. A clearly reported **12-request diagnostic budget** bounds this test only; production defaults remain unbounded unless the analyst selects budgets. It reports whether inspection, verification, memory, consolidation, checkpoints and final text actually occurred. Missing capabilities are not hidden by an exit code or a fabricated success assertion.

Automated tests also cover malformed responses, unknown usage, connection refusal, explicit deadlines, process interruption, no cloud fallback, endpoint/binding rejection, redirect rejection, exact wire capacity and unsupported memory filters. Both the GET metadata diagnostic and inference use parent-enforced total deadlines. Model-list output is bounded to 128 short identifiers.

No real model configuration was visible in the development execution environment. Real-model reasoning, CPU/GPU speed and resource residency remain **unvalidated**. The live 6.184 results supplied by the analyst are a comparison baseline, not results reproduced here.

### Recorded focused validation

**207 distinct tests passed**, without adding overlapping development runs:

- Local integration: **26 passed, 1 warning, 28.91 seconds**. Includes real loopback HTTP to a mock server, supervised client cleanup, both analyst diagnostic modes against mock responses, native call association, memory recovery and local grant/capacity checks.
- Memory, population reuse, execution discovery, 6.182 retrieval and retrieval resilience: **85 passed, 1 warning, 166.97 seconds**.
- Existing conversational provider/service/resource and legacy local-completion diagnostics: **95 passed** on the initial run; one obsolete expectation that every local provider must be unsupported failed. The corrected test (unbound local rejected, unsupported provider still rejected, immutable scope retained) then **passed in 1.09 seconds**, completing those **96 distinct tests**. The initial run took 115.72 seconds; it is not represented as a wholly green run.

The sandbox denied loopback connections with Windows error 10013. The HTTP tests were therefore run outside that restriction, with fresh workspace-local temporary directories. No ACLs, Windows settings or actual forensic data were changed. An initial external test attempt could not use the old shared pytest temporary directory; none of those setup errors count as passes. No full regression suite was run.

The final machine-readable mock diagnostic reported:

| Measurement | Result |
|---|---|
| Protocol/model substitute | Scripted loopback server; no real LLM |
| Configured artificial context / output reserve | 32,096 / 2,048 token settings; byte proxy, not measured tokens |
| HTTP body allowance / measured range | 28,000 / 18,857–27,732 UTF-8 bytes |
| Requests / successful operations | 26 / 25 (5 forensic, 18 notes, 2 memory) |
| Context consolidations / automatic checkpoints / analyst pauses | 18 / 51 / 0; accelerated diagnostic interval |
| Inspections / independent verifications | 2 inspection pages / 1 verification |
| Message/tool serialization / message-content bytes | 649,778 / 303,120 |
| Repeated original-result / memory-result bytes | 27,576 / 3,699 |
| Elapsed time | 16.72 seconds including reconstruction; not inference performance |
| Checks | All 11 true: omission/recovery, verification/coverage recovery, equal reconstruction, unchanged synthetic case, history omission, checkpoints, worker closure and both request/wire bounds |

Synthetic usage reports are fixtures, not billed or real model tokens. The standard acceptance server uses 32,768 context tokens, slightly more than this artificial pressure test. Existing accounting semantics remain unchanged; exact HTTP-body sizes are reported separately by the harness. `git diff --check` passed and an isolated application launch reported `Locard 6.185`.

## Model and hardware recommendation

Start with **Qwen3-4B Q4_K_M** in non-thinking mode as a functional tool-protocol trial, not a claim of OpenAI-equivalent investigative reasoning. The publisher provides an approximately **2.5 GB GGUF**, including a published SHA-256. [Official Qwen GGUF file](https://huggingface.co/Qwen/Qwen3-4B-GGUF/blob/main/Qwen3-4B-Q4_K_M.gguf).

Use a llama.cpp build with its tool-capable Jinja chat template. The server documents OpenAI-style tool calling and CPU/GPU options, including disabling GPU KV-cache offload. [llama.cpp function calling](https://github.com/ggml-org/llama.cpp/blob/master/docs/function-calling.md), [server options](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md).

Begin with CPU inference (`-ngl 0`). The 4 GB GPU need not hold the entire model. After functional acceptance, optionally try a small layer offload such as `-ngl 8`, leaving KV cache in RAM with `--no-kv-offload`, and measure actual use. Weights alone do not include KV cache, compute buffers, drivers or Windows display memory; no full-VRAM-fit or fixed throughput claim is made. Avoid changing context/server settings without changing the declared Locard context to match.

No new Python dependency is required. llama.cpp and the GGUF are separately installed by the analyst. Existing llama-server may be reused; an optional Windows package is `ggml.llamacpp`. [Official installation guide](https://github.com/ggml-org/llama.cpp/blob/master/docs/install.md), [Windows package manifest](https://github.com/microsoft/winget-pkgs/blob/master/manifests/g/ggml/llamacpp/b11193/ggml.llamacpp.installer.yaml).

## One Windows setup and acceptance block

Run after your normal development commit/push/test-checkout workflow. This block deliberately asks before downloading the model and before moving to real evidence. It does not alter the saved provider configuration. Use a free loopback port; do not attach to an unknown existing listener.

```powershell
Set-Location C:\tmp\locard
$py = if (Test-Path .\.venv\Scripts\python.exe) { '.\.venv\Scripts\python.exe' } else { 'python' }
& $py locard.py --version   # Expected: Locard 6.185
& $py scripts\diagnose_local_provider.py --mock
if ($LASTEXITCODE -ne 0) { throw 'Synthetic protocol diagnostic failed' }

# Stage A: use the existing llama-server.exe, or install separately if absent:
# winget install --id ggml.llamacpp --exact
$server = Read-Host 'Full path to the tool-capable llama-server.exe'
if (-not (Test-Path -LiteralPath $server -PathType Leaf)) { throw 'Server executable not found' }
& $server --version
$modelDir = Join-Path $env:LOCALAPPDATA 'Locard\models'
$model = Join-Path $modelDir 'Qwen3-4B-Q4_K_M.gguf'
if (-not (Test-Path -LiteralPath $model)) {
    if ((Read-Host 'Download the approximately 2.5 GB official Qwen GGUF now? [y/N]') -ne 'y') { throw 'Model download not authorized' }
    New-Item -ItemType Directory -Force -Path $modelDir | Out-Null
    Invoke-WebRequest -Uri 'https://huggingface.co/Qwen/Qwen3-4B-GGUF/resolve/main/Qwen3-4B-Q4_K_M.gguf' -OutFile $model
}
$expected = '7485fe6f11af29433bc51cab58009521f205840f5b4ae3a32fa7f92e8534fdf5'
if ((Get-FileHash -LiteralPath $model -Algorithm SHA256).Hash.ToLowerInvariant() -ne $expected) {
    throw 'Model differs from the documented publisher hash; review the publisher revision before proceeding'
}
# These files may become sensitive once real model requests begin. Protect them accordingly.
$stamp = [guid]::NewGuid().ToString('N')
$stdout = Join-Path $modelDir ("server-$stamp.out.log")
$stderr = Join-Path $modelDir ("server-$stamp.err.log")
$serverArgs = @('-m', ('"' + $model + '"'), '--alias', 'locard-local', '--host', '127.0.0.1', '--port', '8080', '--jinja', '-c', '32768', '-np', '1', '-ngl', '0', '--no-kv-offload')
$serverProcess = Start-Process -FilePath $server -ArgumentList $serverArgs -WindowStyle Hidden -PassThru -RedirectStandardOutput $stdout -RedirectStandardError $stderr
try {
Write-Host "Server PID $($serverProcess.Id). Startup log: $stderr"
Read-Host 'Wait for the server to report model readiness, then press Enter' | Out-Null
if ($serverProcess.HasExited) { throw 'The selected server exited; inspect its startup log before continuing' }

# Stage B: harmless REAL local inference, no case data.
& $py scripts\diagnose_local_provider.py --endpoint http://127.0.0.1:8080 --model locard-local --context 32768 --timeout 600 --output-tokens 512
if ($LASTEXITCODE -ne 0) { throw 'Native local tool protocol not demonstrated' }

# Stage C: real local inference against disposable SYNTHETIC evidence only.
& $py scripts\diagnose_local_provider.py --endpoint http://127.0.0.1:8080 --model locard-local --context 32768 --timeout 600 --output-tokens 2048 --synthetic-investigation
# Review observations as well as safety checks; missing verification/memory is not acceptance.
if ((Read-Host 'Synthetic capability reviewed and accepted; proceed to real-case scope? [y/N]') -ne 'y') { return }

# Stage D: analyst supplies and explicitly approves the real-case scope.
$db = Read-Host 'Approved existing case.db path'
$source = Read-Host 'Approved source ID'
$start = Read-Host 'Approved start timestamp with UTC/offset'
$end = Read-Host 'Approved exclusive end timestamp with UTC/offset'
$localArgs = @('--local-endpoint','http://127.0.0.1:8080','--local-model','locard-local','--local-context','32768','--output-tokens','2048','--provider-seconds','600')
& $py locard.py --db $db investigation chat @localArgs --source $source --start $start --end $end
# At the prompt request a narrow, neutral search, original inspection and verification.
# Inspect exact values/IDs/coverage, /status, then /exit.

# Stage E: a fresh blind session; enter the SAME neutral 6.184 reference question.
# Do not seed known incident indicators. A fresh approval is required.
& $py locard.py --db $db investigation chat @localArgs --source $source --start $start --end $end

# Stop only the server process started by this block when all testing is finished:
} finally {
    if (-not $serverProcess.HasExited) { Stop-Process -Id $serverProcess.Id }
}
```

The `main` model download URL can change upstream; a hash mismatch must be reviewed, not silently accepted. For an already running suitable server, skip startup/download and use its exact model ID. All automatic downloads and actual inference in the block are analyst actions; Codex performed none.

## Compatibility, limitations and files

No forensic database or workspace schema migration. Stable IDs, read-only views, original verification, JSONL authority, SQLite reconstruction, behavioral scoring/population cache, checkpoint continuation and optional budgets remain unchanged. Local grants add a provider binding; legacy OpenAI behavior remains available without local flags.

No tokenizer parity, streaming-token progress, remote endpoint support, managed-model startup changes, server-side cancellation attestation, model fine-tuning, new artifacts or general planning redesign. A small model may stop early, choose invalid tools, reason poorly or fail to handle the full catalog. Diagnostics expose these limitations; deterministic rules do not manufacture an incident or conclusion.

Changed/new files: `conversational_ai/local.py` (new), `ai/backend.py`, `ai/provider_diagnostics.py`, `conversational_ai/{cli,contracts,diagnostics,resources,service}.py`, `scripts/diagnose_local_provider.py` (new), the shared synthetic fixture in `scripts/diagnose_investigative_memory.py`, `tests/test_local_conversation.py` (new), one authorization regression in `tests/test_conversational_ai.py`, `.gitignore`, `pyproject.toml` and this document.

The former test requiring all local providers to be unsupported now rejects an unbound local provider and retains a separate unsupported-provider assertion. It still checks immutable scope and no fallback. No security assertion was weakened to accommodate malformed local responses.

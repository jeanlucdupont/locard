# Locard 6.186 — local tool grammar compatibility

Implementation: 2026-11-27. Based on accepted 6.185. Manual llama.cpp acceptance is pending. No model, dependency or case acquisition was performed during development.

## Diagnosis

The analyst's build 10549 / b2e5e9b28 of llama-server, Qwen3-4B Q4_K_M, CPU, 32768 context and Jinja passed the echo protocol but rejected the production tool grammar before investigative inference. The supplied stderr reports repetition complexity exceeding sane defaults and failure to initialize grammar/samplers. This establishes a grammar initialization problem, not demonstrated context exhaustion or model reasoning failure. The exact first failing generated rule is not known.

The 6.185 path was `contracts.catalog → Session.submit → ModelBackend.converse → local.dispatch/body_for → llama.cpp`. All ten canonical schemas, including arrays of long strings, reached grammar generation unchanged. Note alternatives permit ten 1000-byte strings; missing-information entries permit twenty 512-byte strings; evidence/supporting/contradictory lists permit forty 160-byte IDs. Large bounded repetitions can multiply during grammar construction.

## Correction and contracts

`conversational_ai/local_schema.py:generation_catalog` makes a deep, deterministic, idempotent copy. It removes `minLength`, `maxLength`, `minItems`, `maxItems`, `uniqueItems`, `minimum` and `maximum` from generation schemas. Concise descriptions retain application limits, including UTF-8 byte semantics. Names, types, required properties, enums, nested item shapes and closed objects remain. Optional-property structure is unchanged; there is no evidence requiring its redesign. No tools or parameters are removed, and no grammar safeguard is disabled.

`local.body_for` applies this transformation at the provider boundary, including direct diagnostic calls. `Session.catalog` selects the identical projection for local context sizing, consolidation and accounting; OpenAI still receives the original catalog. The canonical schema is never modified. Currently serialized catalogs are **13,311 canonical bytes / 14,633 generation bytes**: descriptions add bytes even though grammar complexity decreases. No byte/token capacity increase hides that overhead.

`contracts.arguments → investigation_ai.contracts.validate` independently checks exact types (including rejecting bool as integer), required/unknown keys, nonblank/NUL-free UTF-8 string bounds, array counts and uniqueness, enums and numeric ranges. It runs before execution. No missing canonical enforcement was found for removed generation keywords. Worker authorization, source/time restrictions, known-record eligibility, original-field verification and workspace reference checks remain separate and unchanged. Native response parsing still requires strict JSON, bounded structured tool IDs and arguments; prose is never executed.

Context accounting uses the transmitted schema and measures the complete serialized HTTP body. Output reservation, template allowance, native tool/result order, automatic continuation, memory and disclosure accounting are unchanged. UTF-8 byte capacity is a conservative proxy, not a tokenizer guarantee. A locally generated invalid argument remains a rejected operation, never a new permission.

## Diagnostics

`diagnose_local_provider.py --full-catalog` sends all ten transformed production tools with harmless instructions to call `memory(kind=state)`. It validates each returned call with the canonical validator, executes **no** investigative tool, supplies a clearly synthetic empty result and checks continuation. It reports canonical/generation sizes, removed constraints, exact HTTP body sizes, status, usage when supplied and elapsed durations. Wrong arguments are reported separately from transport/grammar errors. An HTTP/model response does not establish investigative competence.

`local_diagnostics.py` recognizes safe error fragments and emits fixed bounded summaries. `local_grammar_rejected` is distinct from context exhaustion, network/timeout, envelope parsing and argument selection. HTTP status, request bytes, timeout and confirmed client cleanup survive child IPC, backend diagnostics and session pause recording. Arbitrary server text, paths, credentials, prompts and generated grammar are not retained. Unknown server messages are withheld explicitly, not echoed. Classification depends on the HTTP error containing a recognized fragment; stderr-only details still require the analyst's server log. Server claims are untrusted diagnostics, not evidence.

Inference-start status is **unknown** on failures unless separately observed. Unknown usage remains unknown. Client-process cleanup does not attest cancellation of work inside the separately owned llama-server. Synthetic reports include endpoint/model identity, worker cleanup, failure category/stage and sanitized detail. A synthetic run ending `PROVIDER_FAILURE` exits nonzero even if case-integrity and cleanup checks pass. Capability success additionally requires original inspection, verification, memory retrieval and a final response. This is a diagnostic result, not a new production quota.

## Validation

Only synthetic fixtures and mock providers were used. **183 distinct focused tests passed** (overlapping follow-up checks are not added twice):

| Suites | Distinct passing tests | Recorded execution |
|---|---:|---|
| Conversational provider, conversational AI, conversation resources, investigative memory, execution population reuse | 127 | 226.50 seconds |
| Existing local conversation suite + initial grammar tests | 41 | 35.02 seconds |
| Additional catalog separation, failure exit and persisted diagnostic tests | 3 | 3.67 seconds |
| Additional safe error-category cases | 4 | 5 passed / 23 deselected in 1.13 seconds, including one previously counted test |
| Existing local diagnostic suite | 6 | 0.74 seconds |
| Full-catalog failure usage reporting | 1 | 0.80 seconds |
| Additional truncated-response usage test | 1 | 9 passed in 4.64 seconds, including eight previously counted tests |

The final full-catalog mock paths were rechecked (2 passed in 2.26 seconds). Initial sandbox loopback tests could not reach their synthetic server; these were rerun outside the sandbox with a fresh private test directory. An initial verbose description adaptation caused a genuine context-capacity regression; shorter descriptions fixed it without changing capacity or weakening assertions. `git diff --check` passed; source-version resolution reports `Locard 6.186`. No full suite was run. The loopback mock cannot compile llama.cpp grammar and does not prove real-model acceptance. No actual server/model was contacted.

Coverage includes immutable/deterministic schemas; OpenAI catalog separation; all ten tools; nested limits; oversized Unicode/scalars/arrays; duplicate entries; enums/types/required/unknown arguments; exact wire sizing; native parsing; full-catalog continuation; redacted grammar errors; failed-diagnostic exit status; preserved provider-failure detail; worker cleanup; authorization/source/time/verification rejection; memory revisions, reconstruction and continuation.

## Windows acceptance — existing trusted server and model

Run after committing/pushing development changes yourself. Use the existing test checkout and venv. This block does not start/stop servers or download models. Confirm the existing server is numeric-loopback, single-slot, Jinja/native tools, the intended Qwen model, and **32768** context. `/v1/models` can check the model alias; it cannot prove every launch setting. Review your original server command/log. Do not continue if configuration differs; restart manually only if necessary.

The archive contains synthetic diagnostics and the server log(s) you explicitly select. Logs may contain other sessions: review/redact before sharing. No real-case command is included. Each stage must succeed before the next; the archive is created even on failure. A passed mock is not real grammar acceptance. A passed grammar probe is not real forensic reasoning acceptance.

```powershell
$ErrorActionPreference = 'Stop'
Set-Location 'C:\tmp\locard'
if (git status --porcelain) { throw 'Test checkout is not clean; preserve/reconcile its changes first.' }
git pull --ff-only
if ($LASTEXITCODE -ne 0) { throw 'Git update failed.' }
$python = Join-Path $PWD '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $python)) { throw 'Existing test venv not found.' }
& $python -m pip install --no-deps -e .
if ($LASTEXITCODE -ne 0) { throw 'Install failed.' }
$version = & $python locard.py --version
$version
if ($LASTEXITCODE -ne 0 -or "$version" -notmatch 'Locard 6\.186\b') { throw 'Expected Locard 6.186.' }

$endpoint = 'http://127.0.0.1:8080'
$model = Read-Host 'Exact existing server model alias (for example locard-local)'
if ((Read-Host 'Confirmed trusted loopback server, intended model, Jinja, single slot and 32768 context? Type YES') -cne 'YES') { throw 'Verify server configuration first.' }
$serverLogs = Read-Host 'Existing server stdout/stderr log paths separated by semicolons (blank if unavailable)'
$out = Join-Path $env:TEMP ('locard-6186-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $out | Out-Null
function Invoke-LocalDiagnostic([string]$name, [string[]]$diagnosticArgs) {
    $result = & $python scripts\diagnose_local_provider.py @diagnosticArgs 2> (Join-Path $out "$name.stderr.txt")
    $code = $LASTEXITCODE
    $result | Set-Content -Encoding utf8 -LiteralPath (Join-Path $out "$name.json")
    $result
    if ($code -ne 0) { throw "$name failed (exit $code). Stop before real evidence." }
}
try {
    $version | Set-Content -Encoding utf8 -LiteralPath (Join-Path $out 'version.txt')
    git rev-parse HEAD | Set-Content -Encoding utf8 -LiteralPath (Join-Path $out 'revision.txt')
    Invoke-LocalDiagnostic '01-mock' @('--mock')
    $common = @('--endpoint', $endpoint, '--model', $model, '--context', '32768', '--timeout', '600')
    Invoke-LocalDiagnostic '02-native-protocol' ($common + @('--output-tokens', '512'))
    Invoke-LocalDiagnostic '03-full-catalog' ($common + @('--full-catalog', '--output-tokens', '512'))
    Invoke-LocalDiagnostic '04-synthetic-investigation' ($common + @('--synthetic-investigation', '--output-tokens', '2048'))
    Write-Host 'Review reasoning quality, coverage and verification before any real-case acceptance.'
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

## Changed files

- `pyproject.toml`: version only.
- `conversational_ai/local_schema.py`: new generation-only projection.
- `conversational_ai/local_diagnostics.py`: new closed diagnostic vocabulary.
- `conversational_ai/local.py`: wire adaptation, error classification and usage preservation.
- `conversational_ai/service.py`: provider-specific sizing and durable sanitized pause details.
- `ai/provider_diagnostics.py`: safe storage/rendering of local transport diagnostics.
- `scripts/diagnose_local_provider.py`: full-catalog probe and truthful failure/capability exit status.
- `scripts/diagnose_investigative_memory.py`: measure the actual selected provider catalog.
- `tests/test_local_grammar.py`: new focused regressions; existing tests unchanged.
- This document and its `.gitignore` inclusion.

Python paths above are under `forensic_assistant/` unless a repository directory is shown. No evidence schema, workspace schema, canonical tool schema or authorization contract changed.

## Remaining acceptance boundaries

The reported failure is addressed by removing bounded repetition constraints from local generation. Actual grammar compilation on the analyst's build remains unverified, including optional-property combinator complexity. If it still fails, retain the full-catalog JSON and server log, isolate the remaining rule, and review alternatives before changing architecture. Do not disable server safeguards, weaken canonical validation, remove tools or increase context merely to suppress failure.

After grammar success, evaluate actual synthetic inspection, independent verification, retrieval recovery and quality of qualified conclusions separately. Invalid model arguments or poor reasoning may persist even with successful grammar compilation. There is no provider fallback, automatic repair request or paid call in this change.

Version authority remains `pyproject.toml` at **6.186**. No commit or push was performed.

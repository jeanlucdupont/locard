# Locard 6.188 — Local investigative failure diagnostics

## Cause and preserved behavior

The supplied 6.187 live result established usable token parity and original-evidence retrieval, but not the cause of its three failed operations. That run's discarded temporary journal cannot be recovered by this patch. No real case, existing transcript or live model was accessed here.

`conversational_ai/service.py:Session.submit` counts **three consecutive failed operations within one submit**. A successful operation resets the counter. Identical arguments are not required. This differs from the separate nonadvancing-continuation check. Neither policy changed.

Previously, `diagnose_local_provider.py:synthetic_investigation` inspected the cause of `Paused`. `REPEATED_TOOL_FAILURE` is raised without an exception cause; consequently category/stage were null even though private failure events existed. Invalid arguments were rejected before `tool_attempt`, and worker-side exceptions lost their specific rule during IPC serialization.

## Diagnostic changes

- `operation_diagnostics.py` reconstructs chronological operation records from the integrity-validated journal. Each includes request sequence, call ID, original arguments, canonical validation status, execution result, safe rule/parameter/constraint, worker dispatch (unknown handling on communication loss), duration, returned identities, coverage, exact argument signature/repeat, feedback and subsequent response identity.
- `service.py` records these diagnostics privately, including successful operations. General logs do not receive attempted arguments or result payloads. Canonical validation details and explicitly allowlisted static application rules are retained. Unknown exceptions remain unspecified rather than exposing arbitrary text.
- `worker.py` and `supervision.py` carry safe diagnostic details across the existing IPC error path. Authorization, failure classification, recoverability and worker control remain unchanged.
- The repeated-failure report includes contributing operations and earlier successes. Remaining state is available in final usage and the reconstructed workspace summary.
- Feedback **prepared** for a native tool result and feedback **sent in a later request** are distinguished. The terminal third failure usually has no subsequent provider response. No additional corrective model request is made.
- Per-request provider timings, reported tokens, metadata/template/tokenizer timings, worker elapsed time and workspace projection time are available. Residual active time is an approximate orchestration measure, including uninstrumented checks; operation durations include validation/bookkeeping. Timing components can include small instrumentation overhead. No total-request-duration generation throughput is claimed.

All ten tools, validation, grammar, context management, continuation, optional analyst budgets and provider selection remain unchanged. The new diagnostic event kinds are ignored by the existing workspace reducer while remaining hash-chained journal events.

## Retained synthetic artifacts

`scripts/diagnose_local_provider.py --synthetic-investigation --output-dir <fresh-directory>` retains:

| File/location | Meaning |
|---|---|
| `SYNTHETIC_ONLY.txt` | Synthetic-data and sharing warning |
| `case.db` | Generated disposable evidence, hash checked after investigation |
| `case.db.conversations/<session>/events.jsonl` | Complete private activity journal |
| Same directory: `manifest.json`, `workspace.db` | Publication frontier and structured investigative projection |
| `reconstructed/` | Independent provider-free workspace reconstruction |
| `diagnostic.json` | Outcome, accounting, remaining state, trace and timings |
| `operation-trace.json` | Successful and failed operations |
| `provider-diagnostics.json` | Sanitized capacity, timing and pause diagnostics |

Output uses existing `local_path`, `DirectoryGuard` and `_private_mkdir` protections: fresh directory only, no overwrite, no symlink/reparse ancestry, protected Windows DACL at creation (current user and SYSTEM, inherited by children), mode 0700 on POSIX. The parent must exist. A completed controlled failure retains artifacts and remains a failing diagnostic exit. Unexpected errors retain available artifacts and a sanitized failure JSON; startup failures cannot manufacture a completed manifest or workspace. Without `--output-dir`, temporary-disposable behavior remains.

Full synthetic journals intentionally include model prose and synthetic fields. Sanitized provider files are not substitutes for those journals. Review archives before sharing. Exported ZIP files have the protection of their destination, not the private directory DACL.

`--diagnostic-requests N` changes only this synthetic authorization; default remains 12. This is not a production quota.

## Parity probe

Both initial and constructed native-tool-history requests use `tool_choice=none` for measurement **and** inference. Available prompt usage/parity is recorded before canonical argument checks. Native response validity, unexpected calls and canonical argument validity remain separate results. Reliable missing usage never becomes a parity claim. Production response validation is unchanged; a malformed native envelope can still prevent access to usable response usage. There are no hidden completions or fallback providers.

## Validation

Focused provider/context/grammar, conversation and resource regressions: **165 passed in 174.90 seconds**. The initial sandbox run had 46 passes and one mock-loopback network-access failure; the loopback-enabled run passed. Final changed-path validation after timing/dispatch refinements: **41 passed in 68.63 seconds** (overlaps the preceding set; not 206 distinct tests). `git diff --check` passed. `locard.py --version` reported 6.188 and also emitted a development-environment audit-storage warning; synthetic tests use isolated storage. Starting commit: `d22b954`; no commit was created. Tests use scripted responses, synthetic evidence and loopback fixtures, not real reasoning acceptance. No full suite, live provider, real evidence, commit or push.

## Windows manual acceptance

After the analyst has committed/pushed this patch, use the existing regular Python environment and already-running trusted llama-server (Qwen3-4B Q4_K_M, build 10549, CPU, 32768 context, single slot, Jinja, alias `locard-local`). No restart, download or reinstall is required. Change the checkout path if needed. The block continues to the synthetic investigation if parity fails so both diagnostics are retained. Model/server errors do not prevent ZIP creation.

```powershell
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false # Record native exit codes explicitly.
Set-Location 'C:\tmp\locard'
$python = Read-Host 'Existing Python executable (blank for python)'
if (-not $python) { $python = 'python' }
if (git status --porcelain) { throw 'Preserve local changes before updating this checkout.' }
git pull --ff-only
if ($LASTEXITCODE -ne 0) { throw 'Git update failed.' }
$version = & $python locard.py --version
if ($LASTEXITCODE -ne 0 -or "$version" -notmatch 'Locard 6\.188\b') { throw "Expected Locard 6.188; got $version" }
$version
$serverLogs = Read-Host 'Existing server log paths separated by semicolons (blank if unavailable)'
$out = Join-Path $env:TEMP ('locard-6188-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $out | Out-Null
$common = @('--endpoint','http://127.0.0.1:8080','--model','locard-local','--context','32768','--timeout','600')
try {
    $version | Set-Content -LiteralPath (Join-Path $out 'version.txt') -Encoding utf8
    git rev-parse HEAD | Set-Content -LiteralPath (Join-Path $out 'revision.txt') -Encoding utf8
    & $python scripts\diagnose_local_provider.py @common --tokenization --output-tokens 512 2> (Join-Path $out 'parity.stderr.txt') | Set-Content -LiteralPath (Join-Path $out 'parity.json') -Encoding utf8
    "Parity exit: $LASTEXITCODE" | Set-Content -LiteralPath (Join-Path $out 'exit-codes.txt')
    & $python scripts\diagnose_local_provider.py @common --synthetic-investigation --output-tokens 2048 --diagnostic-requests 12 --output-dir (Join-Path $out 'synthetic') 2> (Join-Path $out 'synthetic.stderr.txt') | Set-Content -LiteralPath (Join-Path $out 'synthetic.stdout.json') -Encoding utf8
    "Synthetic exit: $LASTEXITCODE" | Add-Content -LiteralPath (Join-Path $out 'exit-codes.txt')
}
finally {
    $n = 0
    foreach ($log in ($serverLogs -split ';')) {
        if ($log.Trim() -and (Test-Path -LiteralPath $log.Trim() -PathType Leaf)) {
            $n++
            Copy-Item -LiteralPath $log.Trim() -Destination (Join-Path $out "server-$n.log") -ErrorAction Continue
        }
    }
    Compress-Archive -Path (Join-Path $out '*') -DestinationPath "$out.zip"
    Write-Host "Review diagnostic archive before sharing: $out.zip"
}
```

Actual failed-call identities and argument-generation quality remain unknown until a retained real-local synthetic run is reviewed. Successful investigation completion is not required for diagnostic acceptance. Do not infer model limitations, change tool selection, repair arguments or increase failure thresholds from the old terminal reason alone.

Repository note: `/docs/*` is ignored by the existing `.gitignore`. This document is present locally; include it explicitly when preparing your commit if it should be distributed. The ignore rule was not changed.

# Locard 6.191 — Evidence examination and availability-aware investigation

Built on clean 6.190 revision `e176b7f`; inspected/validated November 27, 2026. Version authority remains `pyproject.toml` (6.191). Changes are uncommitted for manual acceptance.

## Diagnosis

The supplied 6.190 synthetic GPU acceptance report records COMPLETED but diagnostic exit 1: seven requests, six operations (five successful, one failed), one registered representative EID and no original fields, original inspections, verifications, notes or memory operations. It reports 53,174 input / 1,272 output tokens, 498.635 seconds active, 488.152 seconds inference, 6.363 seconds context measurement, 0.759 seconds workspace persistence, 0.033 seconds worker time and 0.001643 seconds progress assessment. These are analyst-reported results; no historical transcript was supplied or independently inspected here. Infrastructure success did not demonstrate substantive investigation.

Source-confirmed causes:

* `forensic_assistant/conversational_ai/progress.py::Progress.assess` counted new references without distinguishing an aggregate representative from original fields. `Progress.completion` required zero registered IDs and repeated searches, so one representative bypassed recovery.
* `conversational_ai/tools.py::Tools` delegates timestamps to `retrieval/queries.py::required_time` and `model.py::utc_timestamp`. The reported colon before fractional seconds is invalid. A dot, 1–9 fractional digits and Z or an explicit offset are accepted. The worker's safe diagnostic whitelist lacked this rule and parameter location. The parser itself was correct.
* Queries against known unavailable Browser/Prefetch/Defender families were technically successful; that did not establish new information or absence of suspicious activity.

## Changes and semantics

`Workspace.engagement` reuses the existing actions, evidence, fields, field exposures and verifications. No schema migration, duplicated original payload, evidence authority, model request, planner or tool was added.

| Projection | Meaning and limitation |
|---|---|
| Registered IDs | References, not examination |
| Representative IDs / aggregate operations | IDs associated with overview actions; group counts are not individually inspected records |
| Original records / fields | Distinct EIDs/pointers with non-preview, non-truncated, non-redacted fields |
| Fields possibly disclosed | Original fields linked to provider dispatch; not proof of reception or comprehension |
| Inspection operations | Successful/partial show_evidence calls; usable original fields counted separately |
| Verifications | Existing independent original-value checks, not semantic entailment |
| Relationships | No new relationship authority inferred from any counter |

Automatic context exposes at most three lexically ordered unexamined IDs, show_evidence as an available option, and the latest aggregate's first three group counts with exactness/coverage limitations. Other references remain available through selective memory queries. This is not a relevance ranking or forced sequence. Original source/time scope remains in the system message. Duplicate state counters and recent-frontier identifiers are removed from automatic context only. All ten tools, canonical schemas and system instructions remain intact.

`Progress.assess` separates new query coverage from new investigative information. Known unavailable-family queries retain their original successful result but receive operational guidance to consider available alternatives. Unknown availability remains unknown. Mixed-family execution discovery is not assumed to be EVTX-only. Exact exhausted repeats still use the existing post-feedback repetition guard; no unavailable-family quota was added.

`Session.submit` extends the existing one-shot challenge for explicit broad intent when references are registered but usable original fields remain unexamined, available alternatives exist and existing resource admission succeeds. Repetition is unnecessary in this case. One unsuccessful recovery ends INCONCLUSIVE_NO_PROGRESS; resource exhaustion retains its own reason. No verification or note quota is introduced. Narrow, unspecified and explicit inventory intent are not challenged. The shell does not infer broad intent from prose. No number of inspected records establishes objective completion.

`tools.time_argument` adds only a schema-owned start/end location to the unchanged parser rejection. `tool_feedback` provides a static accepted format and harmless example. Invalid input is not repaired; valid out-of-scope bounds still fail authorization separately. Raw exception text is not exposed.

Completion `records_retrieved` now counts original-field records; registered references remain separately counted. Unknown productivity has unknown new-information status. Rehydrating already recorded fields can aid context without claiming new forensic information.

Operation traces retain delivered guidance and subsequent model-selected actions. Completion assessments include engagement, recovery reason and examination state, separate from unverified model prose. The synthetic diagnostic reports engagement even if there was no final response. Existing timing, progress, retained artifacts, read-only evidence checks and worker closure checks remain.

## Context measurement

At the same aggregate-only synthetic frontier, using the local wire encoder with all ten tools, identical history and output allowance:

| Measurement | Former context shape | Updated | Delta |
|---|---:|---:|---:|
| Serialized UTF-8 request bytes | 23,277 | 23,868 | +591 |
| Existing synthetic template/tokenizer fixture units | 6,008 | 6,155 | +147 |

The fixture is byte-derived and is **not Qwen's tokenizer**. Actual tokenizer-derived input counts remain a manual acceptance measurement; no live tokenizer/model service was contacted. This is a modest increase for examination state, not a claimed net reduction or proof of improved reasoning. Real context diagnostics continue measuring tokenizer input and enforcing existing limits. Sizes vary with IDs/history.

## Validation

Final progress/examination subset after completion-counter clarification: **23 passed in 59.78 seconds** (earlier pass: 65.80 seconds). Initial progress/feedback regression: **34 passed in 42.36 seconds**. Wire measurement: **1 passed in 3.19 seconds**. Runs overlap and are not additive. Focused safety run: 182 passed in 350.18 seconds; two mock-loopback tests failed under sandbox networking, then both passed with loopback access in 2.42 seconds. Local context/provider run: 39 passed and five mock-loopback failures in 22.79 seconds; those five passed with loopback access in 91.94 seconds. No assertions were weakened for the network environment. These reruns use synthetic HTTP servers, not the running Qwen server or external providers.

`git diff --check` passed. PowerShell acceptance block parser validation passed; the block was not executed. `locard.py --version` returned Locard 6.191, with an audit-storage degraded warning in the sandbox environment. This change does not diagnose or alter that unrelated storage condition.

New tests cover aggregate-only vs original fields; challenge without repeats; recovery and inconclusive termination; narrow/inventory intent; unavailable coverage and changed approach; unknown availability; repeated unavailable accounting; real synthetic worker timestamp failure then correction and scope rejection; resource refusal; preview/truncation/redaction; original case hash preservation; deterministic replay; and bounded request encoding. Existing regressions cover authorization, field verification, resources, cancellation, provider routing, grammar and retained diagnostics. No full suite or live provider calls.

## Windows manual acceptance

Reuse the existing running Qwen GPU server and regular Python environment. Do not restart it or change model/GPU settings, dependencies or server arguments. This block retains visible progress and diagnostic artifacts and snapshots active logs into closed staging files before archiving. The established test checkout is C:\tmp\locard; adjust only if it has moved. Commit/push development changes yourself before updating it.

```powershell
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
Set-Location 'C:\tmp\locard'
$python = Read-Host 'Existing regular Python executable (blank for python)'
if (-not $python) { $python = 'python' }
if (git status --porcelain) { throw 'Preserve local changes before updating.' }
git pull --ff-only
if ($LASTEXITCODE -ne 0) { throw 'Update failed.' }
$version = & $python locard.py --version
if ($LASTEXITCODE -ne 0 -or "$version" -notmatch 'Locard 6\.191\b') { throw "Expected 6.191; got $version" }
$version
$serverLogs = Read-Host 'Existing server log paths, separated by semicolons (blank if unavailable)'
$root = Join-Path $env:TEMP ('locard-6191-' + [guid]::NewGuid().ToString('N'))
$run = Join-Path $root 'completed-run'
$stage = Join-Path $root 'archive-staging'
New-Item -ItemType Directory -Path $run,$stage | Out-Null
try {
    $version | Set-Content -LiteralPath (Join-Path $run 'version.txt') -Encoding utf8
    git rev-parse HEAD | Set-Content -LiteralPath (Join-Path $run 'revision.txt') -Encoding utf8
    # Progress remains visible on stderr and is also retained privately by Python.
    $ErrorActionPreference = 'Continue'
    & $python scripts\diagnose_local_provider.py --endpoint http://127.0.0.1:8080 --model locard-local --context 32768 --timeout 600 --synthetic-investigation --output-tokens 2048 --diagnostic-requests 12 --progress --output-dir (Join-Path $run 'synthetic') | Set-Content -LiteralPath (Join-Path $run 'stdout.json') -Encoding utf8
    $code = $LASTEXITCODE
    $ErrorActionPreference = 'Stop'
    "Synthetic exit: $code" | Set-Content -LiteralPath (Join-Path $run 'exit-code.txt') -Encoding utf8
}
finally {
    $ErrorActionPreference = 'Continue'
    Copy-Item -LiteralPath $run -Destination (Join-Path $stage 'diagnostics') -Recurse
    $snapshots = @(); $n = 0
    foreach ($entry in ($serverLogs -split ';')) {
        $log = $entry.Trim()
        if (-not $log) { continue }
        $n++; $inputStream = $null; $outputStream = $null
        try {
            # Snapshot only a fixed initial extent; never archive the active file.
            $share = [IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete
            $inputStream = [IO.File]::Open($log, [IO.FileMode]::Open, [IO.FileAccess]::Read, $share)
            $length = $inputStream.Length
            $start = [Math]::Max(0L, $length - 64MB)
            $null = $inputStream.Seek($start, [IO.SeekOrigin]::Begin)
            $target = Join-Path $stage "server-$n.snapshot.log"
            $outputStream = [IO.File]::Open($target, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write)
            $buffer = New-Object byte[] 65536
            $remaining = $length - $start; $copied = 0L
            while ($remaining -gt 0) {
                $read = $inputStream.Read($buffer, 0, [int][Math]::Min($buffer.Length, $remaining))
                if ($read -eq 0) { break }
                $outputStream.Write($buffer, 0, $read)
                $remaining -= $read; $copied += $read
            }
            $snapshots += [pscustomobject]@{ source=$log; start=$start; initial_length=$length; copied=$copied; status='snapshot'; limitation='Live log may change; at most last 64 MiB, not an atomic server snapshot' }
        }
        catch {
            $snapshots += [pscustomobject]@{ source=$log; status='unavailable'; reason=$_.Exception.Message }
            Write-Warning "Could not snapshot server log; server left running: $log"
        }
        finally {
            if ($outputStream) { $outputStream.Dispose() }
            if ($inputStream) { $inputStream.Dispose() }
        }
    }
    ConvertTo-Json -InputObject @($snapshots) -Depth 4 | Set-Content -LiteralPath (Join-Path $stage 'server-snapshot-status.json') -Encoding utf8
    $zip = "$root.zip"
    try {
        Compress-Archive -Path (Join-Path $stage '*') -DestinationPath $zip -ErrorAction Stop
        if (-not (Test-Path -LiteralPath $zip -PathType Leaf) -or (Get-Item -LiteralPath $zip).Length -eq 0) { throw 'ZIP missing or empty.' }
        Write-Host "Archive created; review before sharing: $zip"
    }
    catch { Write-Warning "Archive failed. Completed artifacts remain at $run; staging remains at $stage. $($_.Exception.Message)" }
}
```

Review diagnostic exit separately from conversational termination. Compare original fields/inspections, appropriate verification, availability feedback and subsequent choices, timestamp recovery, completion challenge outcome, final limitations, tokens and durations. The synthetic harness still tests memory and verification capabilities; ordinary completion does not require performing those just to pass a quota. The server remains running. If shared-read log snapshotting fails, that limitation is recorded. Staging inherits TEMP permissions; review artifacts before sharing.

## Limits and preserved safeguards

No live Qwen acceptance was performed. A small model may ignore guidance; final prose remains unverified, with no automatic semantic validator. Disclosure/inspection counts do not establish comprehension, relevance, causality or investigative sufficiency. Availability may be unknown after bounded probing. Automatic context is bounded; memory retains additional references and coverage. Historical journals lacking new events retain unknown/missing summaries instead of fabricated history. Original evidence, authority, pinned read views, verification rules, journal/reconciliation, grammar, provider routing, timeouts and budgets are unchanged. No forced workflow, argument repair, new planner or model/GPU change.

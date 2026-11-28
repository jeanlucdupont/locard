# Locard 6.190 — Investigative progress awareness

## Scope and diagnosis

Starting revision: `fb739c4`, clean Locard 6.189. Source version is now **6.190** in `pyproject.toml`. No commit/push, full suite, model request or real-case access.

The analyst-reported 6.189 GPU run made three identical, successful recorded-signal queries, retrieved no records and produced a final response. The reported parity/capacity results exclude context exhaustion as the explanation. The CPU/GPU elapsed totals are not controlled performance comparisons because the work differed.

Source inspection confirms:

- `service.py:Session.submit` already recorded `operation_repeat`; `workspace.py:Workspace.context` exposed `previous_repeated_action`. Therefore this was **not** an absence of every repeat notice.
- Original native results already contained query coverage, no matches and the qualified Defender signal availability state. Error feedback was correctly absent for successful queries. New synthetic tests inspect those native messages unchanged; the historical GPU transcript itself was not supplied/read in this task.
- Existing failure stopping counts three consecutive failed operations. Successful empty queries reset that counter. Existing `NONADVANCING_CONTINUATION` separately stops repeated nonadvancing offset pages. Neither mechanism covers repeated exhausted successful searches.
- Previously, no-tool provider responses immediately ended the turn. This established conversational termination, not adequate investigative coverage.

## Operational assessment

`conversational_ai/progress.py:Progress` is provider/UI independent. It reuses workspace signatures, action/field/note history, authorization and pinned read-view identity. It never validates model prose or gives evidence authority.

| Classification | Deterministic basis |
|---|---|
| productive | New original IDs/eligible field references; first qualified query/page coverage; original rehydration; first independent verification; distinct structured note; recovered memory information |
| nonproductive_repeat | Identical stable completed/exhausted search under the same binding; identical structured note arguments; identical memory result without context consolidation |
| failed | Existing canonical/worker failure; original error and safeguards remain authoritative |
| unknown | Insufficient coverage metadata, repeated verification with an unknown new purpose, context-recovery ambiguity, or productivity not demonstrable |

A first empty completed query establishes new coverage. An exhausted tail page is not proof that every earlier page was examined. Arbitrary prose is not compared for semantic equivalence. Calling a differently worded note “new structured data” is not a claim of a novel hypothesis.

Comparison keys include authorization, pinned view, tool, validated effective arguments (including source/time/filter/pagination choices) and population identity when supplied. Exact explicit arguments are compared conservatively; omitted defaults are not assumed equivalent to explicit defaults. Stable result digests must also agree before an exhausted search is called nonproductive. Unrecognized variable result metadata can therefore cause conservative false negatives, not false claims of exhaustion.

Analyst turns reset stopping eligibility. The first cross-turn revisit is classified as unknown-purpose analyst reconsideration, while its previously established coverage and earlier operation remain available; it is not mislabeled new coverage. Historical actions remain recorded. Rehydration executes normally, including after context consolidation. Reverification remains allowed and is not subject to the new stopping rule. All repeated forensic calls still execute; no broad result cache or query suppression was added. Existing behavioral population caching is unchanged.

## Scoped availability and feedback

`progress.py:availability`, invoked once in `worker.py:serve` during read-view setup, uses existing `EvidenceQueries.search` source/time membership predicates with limit-one presence probes. It does not hydrate, disclose or register those records. Ambiguous memberships remain excluded by the existing query layer. Results are available/unavailable/unknown for authorized families only; these are eligibility facts within approval, not case-wide counts.

The optional metadata probe has a two-second total SQL-interrupt budget inside the existing startup deadline and cancellation boundary. Timeout means unknown, not absent. No repeated source-wide inventory or new model tool is introduced. This startup metadata work is separate from model-selected operation counts.

A Defender signal-unavailable result is retained as a **query signal state**; it does not declare the EVTX family unavailable. Alternatives come only from known available authorized families and registered tool capabilities. Unknown families are not advertised as containing evidence.

The original native tool-result content remains byte-for-byte the same. `Session.submit` adds a separate bounded user-role operational-metadata message after all native tool results in the exchange. It includes the earlier operation reference, query completion/exhaustion, new coverage/evidence indicators and authorized alternatives. This preserves original result digests and workspace field-exposure matching. There is no additional provider call just to deliver progress feedback.

The concise system addition distinguishes completed queries from investigations, unavailable artifacts from absence of activity, and executed work from suggestions. It reinforces existing single-approval autonomy without mandating a tool sequence.

## Nonprogress safeguard

The new `NONPRODUCTIVE_REPETITION` pause is deliberately narrow:

1. A query executes and establishes coverage.
2. An identical exhausted query returns the same result; guidance is prepared.
3. The guidance appears in an actually journaled provider request.
4. The same comparable exhausted query persists in **two subsequent distinct provider decisions** after that feedback, with no intervening changed/productive/unknown/failed operation.
5. Pause, retaining all work and original successful-operation counts.

Normally this permits the first query, its first repeat, and two further repeats before stopping. Multiple calls in one provider response cannot count as multiple post-feedback decisions. A changed comparison key or any other classification resets the streak. A new analyst turn resets the guard. Failure stopping remains three consecutive failures. Nonadvancing-offset stopping remains separate; incomplete nonadvancing pages do not qualify as exhausted-search repeats.

This is not a total operation quota or limit on investigative avenues. Identical memory/note results receive guidance but are not stopped by this search-specific guard. Alternating already-exhausted query keys may evade this initial narrow guard; the journal exposes them. No broader semantic stopping policy is claimed.

## Completion assessment and recovery

`Progress.completion` records `investigative-completion-v1` before accepting a provider final response. It reports records/inspections/verifications, available-family query status, latest continuation frontiers, unresolved recorded questions, repetition, and limitations. Query-level coverage never means a family was exhaustively investigated. Objective completion is explicitly **not deterministically established**.

`Session.submit(..., intent='broad')` allows one completion challenge when there are no retrieved records, demonstrated repeats and known authorized alternatives. The synthetic diagnostic declares its objective broad. Narrow and unspecified callers receive assessments without a forced challenge; no heuristic pretends to understand arbitrary analyst prose. The existing shell does not infer broad intent or gain a new flag in this release. The explicit backend intent is available to other callers/future UI integration.

A challenge preserves the provisional response in the journal, checks request and operation admission, and returns through the same provider loop, context measurement, disclosure accounting, cancellation and budgets. The model chooses the next action. There is no predetermined tool execution. Only one challenge is allowed per analyst turn. If it returns another final answer with the same strong no-progress condition, pause as `INCONCLUSIVE_NO_PROGRESS`. Budget/authorization/integrity failures keep their existing reasons and prevent extra dispatch.

Normal conversational outcome remains `COMPLETED` for compatibility. The CLI emits a concise final-response coverage notice, and `/status` exposes the latest completion assessment independently of the termination label. Diagnostics now separately expose normal termination, whether a provider final response occurred, completion/coverage assessment and the existing synthetic capability checks. An empty authorized scope may finish normally. Verification, notes and explicit memory are not mandatory for ordinary investigations; the synthetic capability diagnostic still evaluates them separately.

## Journal, memory and diagnostics

Journal-first events include `artifact_availability`, `operation_progress`, `progress_feedback_sent`, `completion_assessment` and `completion_challenge`. Existing private storage, hash chaining, append order and workspace transaction/idempotency rules apply.

SQLite schema remains **version 1**, with no new table or evidence copy. Versioned progress metadata uses the existing indexed `meta` table, while existing actions, original-field references, populations and notes remain the underlying history. Comparison/frontier hashes and compact summaries contain no original field values. Last-two query coverage summaries and availability supplement the bounded context; explicit memory retrieval remains available. Historical journals lacking these events still reconstruct normally. No stored progress authorizes resume or retrieval in another session/view.

Operation traces expose classification, reason, earlier comparable action, original new-reference/coverage indicators, prepared versus sent feedback, next response identity, and subsequent operation outcomes. Provider diagnostics retain completion challenges, assessments and terminal pauses. Neither a later successful operation nor a transcript hash proves model comprehension or forensic correctness.

`--progress` on the synthetic diagnostic routes liveness, elapsed time, request number, phase, last completed registered tool, counts and checkpoints to stderr and retained `synthetic/progress.txt`. `progress_display.py:ProgressDisplay` consumes reusable structured service events and never prints model prose or original evidence values. Stdout remains final JSON. Inference liveness is not token-generation or forensic computational progress.

## Validation

Final focused validation (2026-11-27):

| Run | Result |
|---|---|
| Progress, feedback, retained diagnostics, conversation/resource/provider, workspace, local context/grammar regressions | 218 passed in 290.29 seconds |
| Final retained progress/reconstruction checks | 24 passed in 44.90 seconds |
| Cross-turn reconsideration and resource regressions | 55 passed in 95.22 seconds |
| Final empty-scope CLI/status assessment | 1 passed in 2.48 seconds |
| Final compact-context mock-local wire/continuation checks | 3 passed in 72.45 seconds |
| `git diff --check` | Passed |
| PowerShell acceptance block | Parser syntax check passed; not executed |

Runs overlap and must not be added as distinct test counts. Earlier development checks also passed. Tests use scripted providers, synthetic evidence and loopback protocol fixtures only; these are not live Qwen acceptance. No full suite was run.

Tests cover completed empty searches, exact exhausted repeats, model-selected recovery, valid/tail pagination, rehydration, changed memory, changed view/authorization/analyst turn, bounded persistent-repeat pause, one-shot final-response challenge, resource refusal, narrow and empty-scope conclusions, no evidence mutation, deterministic reconstruction, private diagnostics and progress output separation. Existing local grammar, OpenAI, token-aware context, independent authority, cancellation and long-session resource tests remain regression controls.

## Windows manual acceptance

Use the existing checkout, regular Python and running Qwen3-4B Q4_K_M Vulkan server: `-ngl 99`, `--no-kv-offload`, 32768 context, one slot, Jinja, alias locard-local. Do not restart or tune the server. This block starts no benchmark-monitoring process and stops no process. It runs only the retained synthetic investigation, not redundant standalone parity/grammar checks.

After committing/pushing the reviewed development changes:

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
if ($LASTEXITCODE -ne 0 -or "$version" -notmatch 'Locard 6\.190\b') { throw "Expected 6.190; got $version" }
$version
$serverLogs = Read-Host 'Existing server log paths, separated by semicolons (blank if unavailable)'
$root = Join-Path $env:TEMP ('locard-6190-' + [guid]::NewGuid().ToString('N'))
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

If an active log denies shared read, its failure is recorded; the server remains untouched and available diagnostic artifacts still archive. Only staged, closed snapshots enter the ZIP. File sharing does not guarantee atomic log contents. The fresh synthetic directory retains application protections; archive/staging files inherit the user's TEMP-directory permissions. Review before sharing.

## Acceptance and limitations

Application behavior and actual model reasoning are separate acceptance dimensions. Review whether Qwen changes approach, retrieves and inspects relevant originals, verifies appropriately, avoids unsupported claims and describes incomplete work accurately. Compare requests/tokens/inference duration/progress overhead, not operation count alone. Case-hash equality and confirmed worker closure remain safety checks.

Known limits: conservative comparison can miss equivalent differently encoded calls; availability probes may time out to unknown; non-search repetition is advisory; final prose is not semantically validated; automatic completion recovery requires explicit broad intent from the caller; the existing shell does not infer it. There is no arbitrary investigation quota, model replacement, GPU change, automatic argument repair, full-results cache, broad workspace redesign or multi-agent workflow.

This document has a narrow `.gitignore` exception and appears in Git status without force-add.

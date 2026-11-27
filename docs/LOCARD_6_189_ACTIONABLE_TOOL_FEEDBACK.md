# Locard 6.189 — Actionable tool feedback

## Confirmed problem and scope

The analyst's retained 6.188 synthetic run established exact tokenizer parity and sufficient context. Three operations succeeded, then verification rejected a field descriptor instead of a scalar, and two different note texts failed the same empty `supersedes` constraint. The three-consecutive-failure stop was correct. The model received generic feedback instead of the safe rejection detail already recorded privately.

These historical results are analyst-supplied; no real case or retained live transcript was opened for this patch. The source-confirmed deficiency was in `conversational_ai/service.py:Session.submit`: it constructed the same generic error for these different failures. The worker's original scalar, disclosure and timestamp checks in `tools.py:Tools._execute` are unchanged.

Version is **6.189**, solely from `pyproject.toml`. Starting revision: `194326d` (clean 6.188 checkout). No commit or push.

## Model-facing contract

`conversational_ai/tool_feedback.py:tool_feedback` builds bounded explanations from registered schemas, allowlisted constraints and static safe application rules. Feedback is an ordinary native tool-result message, subject to the same disclosure accounting, token-aware sizing and authorization as other results. There is no extra request, repair call or retry.

Where known, the result includes:

| Field | Meaning |
|---|---|
| `error`, `stage`, `tool` | Existing failure code, safe processing stage and registered tool |
| `parameter`, `expected_type` / `expected_representation` | Schema-owned path and expected JSON type or scalar encoding |
| `constraint`, `validation_rule` | Recognized validation rule; not arbitrary exception prose |
| Schema bounds / enum / required or allowed parameters | Static application constraints, never model-invented keys |
| `worker_reached` | Confirmed handling, false before dispatch, or unknown after uncertain transport |
| `result_accepted` | False; feedback cannot establish verification authority |
| `correction` | Concise action for a subsequent model-generated operation |
| `read_view_available`, `limitation` | Existing availability and forensic uncertainty |

Unknown failures retain generic feedback. Authorization/integrity/containment failures instruct the model to stop and defer resolution to the analyst, never bypass the boundary. Arbitrary exception messages, SQL, stack traces, raw rejected values, unrecognized parameter names and credentials are not copied into feedback.

Examples (synthetic; not captured model responses):

- Object-valued verification: `request.value_json` must encode exactly one original scalar, not its descriptor. Harmless examples illustrate encoded strings, numbers and booleans. Inspection, complete unredacted disclosure and matching timestamp semantics still apply.
- Empty `request.supersedes`: omit it for a new note; use an existing valid note ID for a revision. The original empty argument remains rejected and recorded.
- Missing/unknown parameters, types, enums and size/range violations: consult the registered schema constraints returned with the error.
- Incompatible memory filters: use evidence_id for evidence/fields/verified, query for notes/actions, status for notes/actions.
- Missing original-field authority: inspect the eligible original field, without treating error feedback as disclosure.
- Scope errors: stay within existing approval. Optional schema parameters are not automatically optional under source, timestamp or paired-window constraints.

`operation_diagnostics.py` also recognizes the existing static strict-JSON parser errors so malformed JSON receives scalar guidance instead of losing its reason at the worker boundary. JSON parsing and validation themselves did not change.

## Tool descriptions and diagnostics

Only descriptions of show_evidence, verify_observation, note and memory changed. They clarify descriptors versus scalar values, exact IDs/pointers, timestamp meanings, omission of unused fields, supersession and pagination. No parameter schema changed; all ten tools remain. Both providers use the descriptions; local schema adaptation remains deterministic and does not mutate the canonical catalog.

Total description UTF-8 bytes: **3,795 → 4,202** (+407); canonical serialized catalog: **13,724 bytes**. Request measurements still use the transmitted catalog and messages, not a fixed estimate.

Existing operation traces retain the exact model-facing feedback. Added fields identify the validation rule, recurrence of the same known validation error, and subsequent operations with outcomes. Exact argument repetition remains separate from constraint recurrence. Prepared versus actually sent feedback and subsequent provider-response identity remain distinct. The third failure can stop before its feedback is sent. A later successful scripted operation is not evidence of model comprehension.

## Validation and preserved authority

The synthetic recovery scenario uses the actual diagnostic EVTX factory. It searches, inspects a complete non-redacted `/command_line`, submits the descriptor with an inappropriate timestamp meaning, receives rejection feedback, then submits the unchanged original scalar without timestamp meaning. Independent verification succeeds through the real read-only worker. The test does not assume the historical `document3.txt` value or grant authority from the example.

It then creates an invalid note with empty supersedes, receives omission guidance, creates a new note, and retrieves memory. Separate tests preserve the three-failure stop despite changing note text, with recurrence distinguished from exact duplicates. Unknown evidence feedback reveals no unreturned content. Arbitrary exception text is withheld.

Focused authority checks also preserve rejection for truncated, redacted, undisclosed, malformed-JSON and incorrectly qualified timestamp fields. No error feedback changes disclosure state or transforms arguments. Existing scope, original-value, cancellation, provider, local grammar, context and persistent-memory regressions are included in validation.

Results (2026-11-27): **155 focused regressions passed in 208.12 seconds** across feedback, retained diagnostics, conversation/provider, local context/grammar and investigative memory. After adding continuation and authority cases, the final feedback suite passed **22 tests in 11.78 seconds**; this overlaps the preceding run. `git diff --check` passed. `pyproject.toml` confirms 6.189. No full suite, real evidence, live provider, model download or dependency installation.

## Windows manual acceptance

After the analyst commits/pushes the development changes, run this block in the separate test checkout. Use the existing regular Python interpreter and already-running Qwen3-4B Q4_K_M server: CPU, 32768 context, one slot, Jinja, endpoint 127.0.0.1:8080, alias locard-local. No model/server change is requested. Previously accepted standalone parity and protocol diagnostics need not be repeated; the actual synthetic session measures its own context/parity.

```powershell
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
Set-Location 'C:\tmp\locard' # Adjust to your existing test checkout if different.
$python = Read-Host 'Existing regular Python executable (blank for python)'
if (-not $python) { $python = 'python' }
if (git status --porcelain) { throw 'Preserve local changes before updating.' }
git pull --ff-only
if ($LASTEXITCODE -ne 0) { throw 'Update failed.' }
$version = & $python locard.py --version
if ($LASTEXITCODE -ne 0 -or "$version" -notmatch 'Locard 6\.189\b') { throw "Expected Locard 6.189; got $version" }
$version
$serverLogs = Read-Host 'Existing server log paths, separated by semicolons (blank if unavailable)'
$out = Join-Path $env:TEMP ('locard-6189-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $out | Out-Null
try {
    $version | Set-Content -LiteralPath (Join-Path $out 'version.txt') -Encoding utf8
    git rev-parse HEAD | Set-Content -LiteralPath (Join-Path $out 'revision.txt') -Encoding utf8
    & $python scripts\diagnose_local_provider.py --endpoint http://127.0.0.1:8080 --model locard-local --context 32768 --timeout 600 --synthetic-investigation --output-tokens 2048 --diagnostic-requests 12 --output-dir (Join-Path $out 'synthetic') 2> (Join-Path $out 'synthetic.stderr.txt') | Set-Content -LiteralPath (Join-Path $out 'synthetic.stdout.json') -Encoding utf8
    "Synthetic exit: $LASTEXITCODE" | Set-Content -LiteralPath (Join-Path $out 'exit-code.txt') -Encoding utf8
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
    Write-Host "Review before sharing: $out.zip"
}
```

The fresh synthetic subdirectory retains its existing private protections, complete journal, manifest, workspace, synthetic DB, operation trace and diagnostic JSON. The ZIP has its destination's permissions; review before sharing. Controlled investigation failure still produces a nonzero diagnostic exit and retained artifacts. The finally block archives available artifacts even on failure.

Review actual verification/note/memory success, repeated constraints, completion and final prose quality separately from safety. Compare inference duration, tokens, case-hash equality and confirmed worker closure. Qwen's ability to correct its own arguments remains **pending manual acceptance**. No local reasoning-quality success is claimed from scripted recovery.

A narrow `.gitignore` exception includes this release document in ordinary Git status/add operations. Other ignored documentation is unaffected.

# Locard 6.142 — CLI consolidation

## Scope and inventory

This is an intentionally breaking command-surface migration, not a change to forensic storage or investigation contracts. The previous inventory supplied for this task contained 49 command/subcommand nodes and 524 option entries. The new parser inventory contains 88 nodes and 652 option entries (including group nodes, global options and repeated definitions). The top-level surface is reduced to eight families. Additional leaf nodes replace multiplexed briefing flags and expose existing findings services; these counts do not mean 88 independent forensic capabilities.

The complete generated inventory, usage, defaults and choices are in [LOCARD_SHELL_COMMAND_REFERENCE.md](LOCARD_SHELL_COMMAND_REFERENCE.md). `help all` is generated from the same parser tree.

## Migration map and responsibilities

| Previous entry | Canonical entry | Backend / distinction |
|---|---|---|
| shell case PATH | case open PATH | Existing read-only case validation and shell activation |
| new-case / case new | case new | Empty managed case creation; ingest separately |
| status | case status | Existing complete status calculation |
| ingest / ingest-KIND | evidence ingest KIND | v2_cli.ingest_sources and existing supervised artifact workers |
| add-evidence / ingest-wizard | evidence ingest wizard | interactive.setup.add_evidence; existing selection and confirmations |
| source | evidence source | source_cli and database.sources; mutations retain preview/confirmation |
| search/show/timeline/around | evidence search/show/timeline/around | Existing bounded retrieval services, original IDs and coverage |
| semantic | evidence semantic | Existing semantic index/search lifecycle; similarity is not evidence |
| dump | evidence export | Existing protected CSV output service |
| logons/session/process-tree/detections | analyze NAME | v1_cli deterministic analysis |
| investigate EID | analyze correlate EID | Same deterministic correlation, no model |
| briefing --show/edit/interview/analyze | investigation briefing show/edit/interview/analyze | Existing saved analyst briefing services |
| briefing --file/--text | investigation briefing inspect --file/--text | Transient unverified input; explicit optional AI/discovery |
| briefing --save --file/--text | investigation briefing import --file/--text | Explicit confirmed narrative import |
| briefing --import-json/--export-json | investigation briefing import-json/export PATH | Existing canonical exchange and overwrite protections |
| briefing assessment flags | investigation assess/list/show/reauthorize | Existing assessment plan, approval, store and fresh-view semantics |
| briefing --investigate with stage flags | investigation run [ASSESSMENT] | Sequential choices, then existing exact autonomous grant |
| per-tool assessment handoff | investigation advanced assessment [ASSESSMENT] | Separate historical-handoff contract; per-tool approval |
| investigate-ai | investigation advanced current-case | Existing supervised current-case investigation; also used by ! |
| analyze-timeline | investigation advanced timeline | Unique bounded local-model timeline interface |
| noninteractive ask | investigation advanced local-query | Unique legacy local retrieval capability; interactive ask alias removed |
| ai-history show | investigation history show | Provider-free recorded review; no implicit live-case fingerprint |
| ai-history replay | investigation history replay | Explicit current-case replay, not continuation |
| standalone findings module | investigation findings | Existing Workspace services and append-only decisions |
| standalone d2_reasoning module | investigation reason | Existing recorded D2 preparation, exact permits and separate capture |
| report generate/recorded | report from-case/from-history | Separate current-case and recorded-disclosure report backends |
| report validate/inspect-recorded | report verify/verify-history | Separate validation contracts retained |
| report show | report show | Existing case-report bundle inspection |
| activity / activity --verify | audit activity / audit verify | Full chain inspection; verification itself writes no activity entry |
| color/version | settings color/version | Session preference and source-authoritative version |
| expert, interactive ask, exit | removed | No-function mode notice, redundant AI alias and duplicate exit; use ! and quit |

`ai provider/configure/status/check/start/stop/logs` retain their existing interfaces and Quick/Connectivity/Full distinctions. Status and Quick do not call providers.

## Implementation boundaries

`command_surface.Operations` places existing operation parsers at canonical paths. Internal operation identifiers remain stable service/audit labels; they are not accepted command aliases. It does not translate obsolete argv. `interactive.help.paths` walks the parser; completion follows nested parser metadata. `cli_parser.configure_ingest_namespace` and its alias registration are removed. Shell interception for expert, ask, new-case, add-evidence, ingest-wizard, flat color/version and exit is removed.

The standalone `findings.main` and `d2_reasoning.main` adapters are removed. Findings services remain unchanged; D2 now exposes configure/run for the canonical adapter. Assessment orchestration is extracted into `assessment_cli.assess` and `assessment_handoff_cli.execute`; guided orchestration in `investigation_workflow` calls these functions directly, without artificial argparse namespaces or subprocess dispatch. No second engine or database is introduced.

`interactive.workspace.create_empty` uses the existing exclusive workspace initialization and audit facilities. `case new` never starts evidence discovery. The existing ingestion wizard remains available independently.

Only MFT and all-artifact ingestion accept `--record-size`. Other parsers receive no user-settable record-size option. Existing artifact limits, timeout semantics and publication remain unchanged.

## Guided workflow and approvals

1. `investigation start` reviews an existing saved briefing or uses the editor/adaptive interview. Saving retains the existing revision/digest checks. Interview startup asks separately before sending analyst text.
2. Review recorded source labels, an explicit time window and deterministic assessment plan. Evidence examination requires the existing plan approval. Source identity remains analyst supplied.
3. Enter the question. `investigation run` can instead select an existing assessment directly. It shows limitations and collects separate cloud-disclosure, question-decomposition and synthesis decisions.
4. The existing engine presents its exact grant, EID/source/time constraints, provider/model and request budgets. Earlier choices do not replace that approval. No scope is silently inferred or expanded.
5. Existing supervised execution, cleanup and partial-result rendering run unchanged. Declining synthesis does not erase analysis. Completion of the authorized plan does not establish forensic completeness.
6. Navigation points to recorded review, findings and reporting; nothing is automatically captured, accepted or published.

The guided autonomous path supports OpenAI as before. `!` retains configured-provider routing and per-tool approvals. The advanced assessment path preserves the non-autonomous handoff. There is no restart continuation.

## Findings and recorded outputs

Every findings invocation explicitly supplies `--workspace`. Mutations also require `--workspace-id`, `--revision` and `--actor`; review/supersession require rationale. The adapter compares the reviewed UUID and then uses the same pinned Workspace instance, whose transaction checks retain UUID/binding/revision protection. No implicit workspace switch is retained between commands. Identity is locally asserted.

`investigation reason --execute --findings-workspace ... --findings-actor ...` uses the existing real prepared/result capture flow. Execution approval and capture approval remain separate; capture leaves proposals unaccepted. Displayed prose is never imported as evidence.

Recorded show, D2, findings and version operations bypass active-case audit attachment. Recorded show uses stdout JSON; use report from-history for guarded file publication. Its generic file-output flags were removed rather than silently ignoring them or opening the live case for destination checks. Explicit current-case replay retains generic output controls. Recorded review verifies saved data and reconstructs supported incremental histories using `recorded.open_history`; it does not perform a new live fingerprint. `history replay` remains explicitly current-case. Case-report imports, historical replay validators and recorded report source checks remain separate. No schema/digest changes are made.

## Manual acceptance

Use a disposable test case. Replace uppercase placeholders with reviewed paths/IDs; do not paste them literally.

```powershell
.\.venv\Scripts\python.exe locard.py --version
.\.venv\Scripts\python.exe locard.py --version-details
.\.venv\Scripts\python.exe -m forensic_assistant.cli --help
.\.venv\Scripts\locard.exe --help
.\locard.ps1
```

Inside the shell:

```text
help
help all
help evidence ingest mft
case new
evidence ingest wizard
case status
evidence source list
evidence search --artifact mft --limit 3 --ids
investigation start
investigation list
investigation show latest
investigation run latest --question "What can the available evidence establish?"
investigation history show RUN_ID --transcripts TRANSCRIPT_ROOT
investigation findings create --workspace NEW.findings --transcripts TRANSCRIPT_ROOT --run RUN_ID --actor "Analyst"
investigation findings select --workspace NEW.findings
investigation findings list --workspace NEW.findings --json
report from-history --transcript-root TRANSCRIPT_ROOT --run RUN_ID --output NEW_REPORT_DIRECTORY
report verify-history NEW_REPORT_DIRECTORY --transcript-root TRANSCRIPT_ROOT --run RUN_ID
audit verify
settings color off
settings version
quit
```

Check refusal independently at each approval, cancellation, partial outcomes, exact IDs/limitations and source bindings. Findings registration requires a reviewed original support ID; `help investigation findings register` documents its UUID/revision arguments. Never interpret analyst acceptance as forensic verification. For recorded D2, preview with `investigation reason ROOT RUN_ID --cross-artifact --question "QUESTION"`; add `--execute` only when explicitly intending a provider request. Development tests make no paid provider requests.

## Validation and limitations

Focused, provider-free executions during this change (separate invocations, with overlapping coverage):

| Focused selection | Result | Time |
|---|---|---|
| Canonical navigation, completion, shell and ingestion namespace | 173 passed | 30.35 s |
| CLI session/presentation/consistency and historical replay | 113 passed | 57.80 s |
| Recorded reporting/presentation, canonical findings mutations, AI readiness | 97 passed | 139.23 s |
| Briefing browser/Registry/Prefetch queries, interview and guided workflow | 71 passed | 27.28 s |
| Final help/completion/CLI consistency/source workflow checks | 134 passed; 7 sandbox-denied output-publication tests | 76.17 s |
| Those seven output-publication cases outside the sandbox | 7 passed | 23.05 s |
| Final canonical parser, replay and workflow checks | 70 passed | 31.82 s |
| Guided ingestion / timeout / findings capture selection | 90 passed, 7 failures (resolved separately below) | 452.98 s |
| Synthetic junction containment and migrated MFT ingestion, host execution | 2 passed | 15.08 s |
| Supervised SDK capture with installed SDK and MockTransport | 1 passed, 1 dependency deprecation warning | 33.02 s |
| Final assessment and reauthorization checks | 32 passed | 59.52 s |
| Migrated standalone findings/D2 capture entry points | 3 passed | 28.22 s |
| Updated guided case/ingestion navigation | 3 passed, then remaining corrected presentation assertion: 1 passed | 6.62 s / 1.39 s |

The seven ingestion/capture failures comprised four stale navigation expectations (corrected and retested), one retired MFT argv fixture (corrected and retested), sandbox denial of junction creation (passed on the host), and SDK availability in the project venv (checked separately with the installed SDK and mocked HTTP). Earlier runs exposed stale argv/presentation expectations and synthetic fixture entry points; these were migrated without changing forensic assertions. A legacy read-view replay test now asserts its existing fail-closed fingerprint requirement rather than claiming unsupported exact replay. Synthetic decoder injection is explicitly in-process only in a CLI framing test; worker containment tests remain separate.

The complete suite was not run, and these overlapping selections do not prove full-suite success. No test selection above deselected tests; none called live providers or opened real evidence. An earlier broad service selection skipped four optional/environment cases; this is not claimed as SDK-provider parity. Windows hard-link output and junction tests can be denied by the sandbox, so affected synthetic checks use normal host execution without changing ACLs. PowerShell 5.1 and the shared launch/terminal tests passed in the earlier host run; no interactive Windows Terminal/Console Host manual acceptance is claimed.

Detailed help now separates common and advanced controls without changing parsing, mutual exclusion or defaults. No persisted data, transcript, findings or report digest schemas were changed.

The guided workflow is synchronous and terminal-adapted. Its explicit orchestration functions are reusable, while prompt rendering remains a UI responsibility. Current-case replay is not durable recovery. Historical technical design documents retain historical syntax as implementation history; the active guide/reference describe the new interface.

Final checks: source and direct-launch version are 6.142; `git diff --check` passed. Changes remain uncommitted. No provider requests, live evidence inspection, permissions changes, commit or push were performed. Manual acceptance and the later complete regression suite remain outstanding.

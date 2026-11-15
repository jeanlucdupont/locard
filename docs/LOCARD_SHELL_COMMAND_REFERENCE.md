# Locard shell command reference

Generated from the canonical interactive parser for 6.149. Documentation wraps at 100 columns; live help uses terminal width.

Use `help <path>`, `? <path>`, or `<path> ?` without executing the operation. `help all` lists nested commands.

Analyst absolute-time CLI filters accept ISO shorthand and default omitted time/timezone to midnight/UTC. A date-only end is midnight, not end-of-day. Explicit offsets are normalized before existing authorization and time-window checks. Stored timestamps and JSON evidence are unchanged.

`case status --details` exposes ingestion/source diagnostics. `case list --details` shows locations. Omit the source ID in interactive `evidence source show` to select a numbered source; scripts/JSON require exact IDs. Timeline `--details` keeps verbose timestamp/provenance views; use `--text` in scripts for human output.

`! <question>` asks AI under existing disclosure and approval rules. `quit` ends the session. `settings color off` disables styling. JSON output is always uncolored.

## Command families

```text
  case           Open, create and inspect a case
  evidence       Ingest, find, inspect and export evidence
  analyze        Correlate evidence and review detections
  investigation  Investigate a case and review findings
  report         Create and verify investigation reports
  ai             Configure AI and review diagnostics
  audit          Review activity and verify audit integrity
  settings       Set terminal preferences and view the version
  help           Show command help
  ?              Show command help
  quit           End the session
  !              Ask AI
```

## investigation

```text
usage: investigation
       {briefing, advanced, history, start, assess, list, show, reauthorize, run, findings,
       reason} ...

Investigate a case and review findings

positional arguments:
  briefing     Saved analyst briefing and explicit lead discovery; not forensic findings
  advanced     Advanced
  history      Review or replay saved AI investigations
  start        Start a guided investigation
  assess       Plan and approve a new deterministic assessment
  list         List saved assessments
  show         Review a saved assessment
  reauthorize  Reauthorize an assessment in a NEW read view; not continuation
  run          Authorize an investigation from a saved assessment
  findings     Findings
  reason       Preview or authorize AI reasoning over recorded evidence
```

## investigation briefing

```text
usage: investigation briefing {show, edit, interview, import, export, import-json, analyze,
       inspect} ... [--force] [--page | --output FILE | --append FILE]

Saved analyst briefing and explicit lead discovery; not forensic findings

positional arguments:
  show         Show the saved briefing
  edit         Edit the saved briefing
  interview    Build a briefing through an AI interview
  import       Import an analyst narrative
  export       Export the saved briefing
  import-json  Import a briefing for explicit review
  analyze      Analyze the saved briefing
  inspect      Inspect a narrative without saving it

Options:
  --force        Overwrite an existing output file
  --page         View output page by page
  --output FILE  Save output to a file
  --append FILE  Append output to a file

Analyst-supplied derived information, not evidence. Interview/AI interpretation may contact the
configured provider; writes require confirmation.
```

## investigation briefing show

```text
usage: investigation briefing show [--details] [--json] [--force]
       [--page | --output FILE | --append FILE]

Show the saved briefing

Options:
  --details      Show provenance, search coverage and diagnostics
  --json         Include original narrative, spans, leads, packet and plan; sensitive derived
                 output
  --force        Overwrite an existing output file
  --page         View output page by page
  --output FILE  Save output to a file
  --append FILE  Append output to a file
```

## investigation briefing edit

```text
usage: investigation briefing edit [--details] [--json] [--force]
       [--page | --output FILE | --append FILE]

Edit the saved briefing

Options:
  --details      Show provenance, search coverage and diagnostics
  --json         Include original narrative, spans, leads, packet and plan; sensitive derived
                 output
  --force        Overwrite an existing output file
  --page         View output page by page
  --output FILE  Save output to a file
  --append FILE  Append output to a file
```

## investigation briefing interview

```text
usage: investigation briefing interview [--details] [--json] [--force]
       [--page | --output FILE | --append FILE]

Build a briefing through an AI interview

Options:
  --details      Show provenance, search coverage and diagnostics
  --json         Include original narrative, spans, leads, packet and plan; sensitive derived
                 output
  --force        Overwrite an existing output file
  --page         View output page by page
  --output FILE  Save output to a file
  --append FILE  Append output to a file
```

## investigation briefing import

```text
usage: investigation briefing import (--file BRIEFING_FILE | --text BRIEFING_TEXT) [--details]
       [--json] [--force] [--page | --output FILE | --append FILE]

Import an analyst narrative

Options:
  --file BRIEFING_FILE  UTF-8 analyst narrative, at most 32 KiB
  --text BRIEFING_TEXT  Inline analyst narrative
  --details             Show provenance, search coverage and diagnostics
  --json                Include original narrative, spans, leads, packet and plan; sensitive
                        derived output
  --force               Overwrite an existing output file
  --page                View output page by page
  --output FILE         Save output to a file
  --append FILE         Append output to a file
```

## investigation briefing export

```text
usage: investigation briefing export export_json [--details] [--json] [--force]
       [--page | --output FILE | --append FILE]

Export the saved briefing

positional arguments:
  export_json  New JSON file; overwriting is forbidden

Options:
  --details      Show provenance, search coverage and diagnostics
  --json         Include original narrative, spans, leads, packet and plan; sensitive derived
                 output
  --force        Overwrite an existing output file
  --page         View output page by page
  --output FILE  Save output to a file
  --append FILE  Append output to a file
```

## investigation briefing import-json

```text
usage: investigation briefing import-json import_json [--details] [--json] [--force]
       [--page | --output FILE | --append FILE]

Import a briefing for explicit review

positional arguments:
  import_json  Canonical JSON file; confirmation required

Options:
  --details      Show provenance, search coverage and diagnostics
  --json         Include original narrative, spans, leads, packet and plan; sensitive derived
                 output
  --force        Overwrite an existing output file
  --page         View output page by page
  --output FILE  Save output to a file
  --append FILE  Append output to a file
```

## investigation briefing analyze

```text
usage: investigation briefing analyze [--deterministic] [--revision REVISION] [--discover]
       [--approve LEAD_ID] [--artifact {evtx, mft, prefetch, registry, browser, all}]
       [--discovery-after DISCOVERY_AFTER] [--start START] [--end END] [--details] [--json]
       [--force] [--page | --output FILE | --append FILE]

Analyze the saved briefing

Common options:
  --deterministic                   Analyze saved briefing without AI
  --revision REVISION               Required current briefing revision for saved-briefing
                                    discovery approval
  --discover                        Execute approved lead lookups; requires --approve, --artifact,
                                    --start and --end
  --approve LEAD_ID                 Approve exactly this reviewed lead; repeat for at most six
                                    leads
  --artifact {evtx,mft,prefetch,registry,browser,all}
                                    Search one family or all available families (six queries
                                    total; review unsearched coverage)
  --discovery-after DISCOVERY_AFTER
                                    Resume one explicitly approved lead/family using its discovery
                                    continuation token
  --start START                     Authorized start; ISO shorthand defaults to UTC, never
                                    inferred from narrative
  --end END                         Authorized end; ISO shorthand defaults to UTC, maximum 24-hour
                                    window
  --json                            Include original narrative, spans, leads, packet and plan;
                                    sensitive derived output
  --page                            View output page by page
  --output FILE                     Save output to a file

Advanced options:
  --details      Show provenance, search coverage and diagnostics
  --force        Overwrite an existing output file
  --append FILE  Append output to a file
```

## investigation briefing inspect

```text
usage: investigation briefing inspect (--file BRIEFING_FILE | --text BRIEFING_TEXT)
       [--correction BRIEFING_CORRECTION] [--ai] [--discover] [--approve LEAD_ID]
       [--artifact {evtx, mft, prefetch, registry, browser, all}]
       [--discovery-after DISCOVERY_AFTER] [--start START] [--end END] [--details] [--json]
       [--force] [--page | --output FILE | --append FILE]

Inspect a narrative without saving it

Common options:
  --file BRIEFING_FILE              UTF-8 analyst narrative, at most 32 KiB
  --text BRIEFING_TEXT              Inline analyst narrative
  --correction BRIEFING_CORRECTION  Separate analyst correction; original wording remains intact
  --ai                              One bounded narrative interpretation using the configured
                                    provider; no tools
  --discover                        Execute approved lead lookups; requires --approve, --artifact,
                                    --start and --end
  --approve LEAD_ID                 Approve exactly this reviewed lead; repeat for at most six
                                    leads
  --artifact {evtx,mft,prefetch,registry,browser,all}
                                    Search one family or all available families (six queries
                                    total; review unsearched coverage)
  --discovery-after DISCOVERY_AFTER
                                    Resume one explicitly approved lead/family using its discovery
                                    continuation token
  --start START                     Authorized start; ISO shorthand defaults to UTC, never
                                    inferred from narrative
  --end END                         Authorized end; ISO shorthand defaults to UTC, maximum 24-hour
                                    window
  --json                            Include original narrative, spans, leads, packet and plan;
                                    sensitive derived output
  --page                            View output page by page
  --output FILE                     Save output to a file

Advanced options:
  --details      Show provenance, search coverage and diagnostics
  --force        Overwrite an existing output file
  --append FILE  Append output to a file
```

## investigation advanced

```text
usage: investigation advanced {timeline, local-query, current-case, assessment} ...

Advanced

positional arguments:
  timeline      Analyze a bounded timeline bundle using the local AI model
  local-query   Ask the local AI questions about case evidence
  current-case  Analyze case evidence using the local AI model
  assessment    Investigate a saved assessment with per-tool approval
```

## investigation advanced timeline

```text
usage: investigation advanced timeline --start START --end END [--hostname HOSTNAME] [--user USER]
       [--candidate-limit CANDIDATE_LIMIT] [--endpoint ENDPOINT] [--timeout TIMEOUT] [--dry-run]
       [--json | --text] [--raw] [--force] [--page | --output FILE | --append FILE]

Specialized workflow: deterministic retrieval and correlation in an explicit time range, followed
by local AI analysis. --dry-run builds the bounded evidence bundle without calling the model.
Model analysis is not evidence; citation checks do not establish factual correctness.

Common options:
  --start START                     Start time; ISO shorthand defaults to UTC
  --end END                         End time; ISO shorthand defaults to UTC
  --hostname HOSTNAME               Hostname filter
  --user USER                       Username filter
  --candidate-limit CANDIDATE_LIMIT
                                    Maximum candidate records examined
  --endpoint ENDPOINT               Local model endpoint
  --timeout TIMEOUT                 Request timeout in seconds
  --dry-run                         Preview without contacting AI
  --json                            Output as JSON
  --text                            Show readable text
  --page                            View output page by page
  --output FILE                     Save output to a file

Advanced options:
  --raw          Show the full diagnostic result as JSON
  --force        Overwrite an existing output file
  --append FILE  Append output to a file

Advanced model-consuming operation; existing provider disclosure and operation-specific approval
controls apply.
```

## investigation advanced local-query

```text
usage: investigation advanced local-query [--json | --text] question [--endpoint ENDPOINT]
       [--date DATE] [--limit LIMIT] [--timeout TIMEOUT] [--dry-run]
       [--semantic-index SEMANTIC_INDEX] [--embedding-model EMBEDDING_MODEL] [--force]
       [--page | --output FILE | --append FILE]

Advanced bounded local query with deterministic planning and optional semantic retrieval.
Deterministic search retrieves evidence by exact/filter-based criteria. Semantic retrieval
discovers meaning-based candidate leads, not evidence for the queried concept. The local LLM
analyzes only the bounded supplied bundle. Model analysis is not evidence.

positional arguments:
  question  Question to investigate

Common options:
  --json                            Output as JSON
  --text                            Show readable text
  --endpoint ENDPOINT               Local model endpoint
  --date DATE                       UTC date for time-only questions
  --limit LIMIT                     Maximum number of results
  --timeout TIMEOUT                 Request timeout in seconds
  --dry-run                         Show plan and evidence without contacting the model
  --semantic-index SEMANTIC_INDEX   Case-specific semantic index directory
  --embedding-model EMBEDDING_MODEL
                                    Local embedding model directory
  --page                            View output page by page
  --output FILE                     Save output to a file

Advanced options:
  --force        Overwrite an existing output file
  --append FILE  Append output to a file

Advanced model-consuming operation; existing provider disclosure and operation-specific approval
controls apply.
```

## investigation advanced current-case

```text
usage: investigation advanced current-case question [--details] [--endpoint ENDPOINT]
       [--date DATE] [--max-steps MAX_STEPS] [--max-tool-calls MAX_TOOL_CALLS]
       [--max-seconds MAX_SECONDS] [--dry-run] [--approve-tools] [--transcripts TRANSCRIPTS]
       [--json] [--explain] [--no-semantic] [--semantic-index SEMANTIC_INDEX]
       [--embedding-model EMBEDDING_MODEL] [--force] [--page | --output FILE | --append FILE]

Advanced / Diagnostic interface. Use ! <question> for normal interactive AI requests.

positional arguments:
  question  Question to investigate

Common options:
  --endpoint ENDPOINT               Advanced existing loopback endpoint; overrides configured
                                    provider for this invocation
  --date DATE                       Date for time-only questions
  --max-steps MAX_STEPS             Maximum investigation steps
  --max-tool-calls MAX_TOOL_CALLS   Maximum approved tool calls
  --max-seconds MAX_SECONDS         Maximum investigation duration in seconds
  --dry-run                         Retrieve evidence and request one AI proposal; no tools
  --approve-tools                   Require interactive approval for each proposed operation
  --transcripts TRANSCRIPTS         Sensitive local derived records, not evidence; default:
                                    DATABASE.investigations. Analyst controls retention/deletion.
  --json                            Output as JSON
  --explain                         Include step-by-step transcript data
  --no-semantic                     Disable semantic retrieval
  --semantic-index SEMANTIC_INDEX   Case-specific semantic index directory
  --embedding-model EMBEDDING_MODEL
                                    Local embedding model directory
  --page                            View output page by page
  --output FILE                     Save output to a file

Advanced options:
  --details      Show technical observations, full evidence IDs and provenance
  --force        Overwrite an existing output file
  --append FILE  Append output to a file

Advanced model-consuming operation; existing provider disclosure and operation-specific approval
controls apply.
```

## investigation advanced assessment

```text
usage: investigation advanced assessment [assessment] [--question QUESTION] [--start START]
       [--end END] [--details] [--json]

Investigate a saved assessment with per-tool approval

positional arguments:
  [assessment]  Saved assessment ID or latest

Options:
  --question QUESTION  Investigation question
  --start START        Start time; ISO shorthand defaults to UTC
  --end END            End time; ISO shorthand defaults to UTC
  --details            Show technical details
  --json               Output as JSON
```

## investigation history

```text
usage: investigation history {show, replay} ...

Review or replay saved derived AI investigation records for audit and review. These records are
not source evidence.

positional arguments:
  show    Review a saved AI investigation
  replay  Replay saved lookups against the current case

Saved records are derived data; replay does not establish forensic conclusions.
```

## investigation history show

```text
usage: investigation history show investigation_id [--transcripts TRANSCRIPTS] [--json]
       [--explain]

Review a saved AI investigation

positional arguments:
  investigation_id  Saved investigation ID

Options:
  --transcripts TRANSCRIPTS  Sensitive local derived records, not evidence; default:
                             DATABASE.investigations. Analyst controls retention/deletion.
  --json                     Output as JSON
  --explain                  Include step-by-step transcript data
```

## investigation history replay

```text
usage: investigation history replay investigation_id [--transcripts TRANSCRIPTS] [--json]
       [--explain] [--no-semantic] [--semantic-index SEMANTIC_INDEX]
       [--embedding-model EMBEDDING_MODEL] [--force] [--page | --output FILE | --append FILE]

Replay saved lookups against the current case

positional arguments:
  investigation_id  Saved investigation ID

Common options:
  --transcripts TRANSCRIPTS         Sensitive local derived records, not evidence; default:
                                    DATABASE.investigations. Analyst controls retention/deletion.
  --json                            Output as JSON
  --explain                         Include step-by-step transcript data
  --no-semantic                     Disable semantic retrieval
  --semantic-index SEMANTIC_INDEX   Case-specific semantic index directory
  --embedding-model EMBEDDING_MODEL
                                    Local embedding model directory
  --page                            View output page by page
  --output FILE                     Save output to a file

Advanced options:
  --force        Overwrite an existing output file
  --append FILE  Append output to a file
```

## investigation start

```text
usage: investigation start [--json]

Start a guided investigation

Options:
  --json  Structured result; prompts remain explicit
```

## investigation assess

```text
usage: investigation assess [--json] [--start START] [--end END]

Plan and approve a new deterministic assessment

Options:
  --json         Structured result; prompts remain explicit
  --start START  Start time; ISO shorthand defaults to UTC
  --end END      End time; ISO shorthand defaults to UTC
```

## investigation list

```text
usage: investigation list [--json]

List saved assessments

Options:
  --json  Structured result; prompts remain explicit
```

## investigation show

```text
usage: investigation show [--json] [assessment]

Review a saved assessment

positional arguments:
  [assessment]  Saved assessment ID or latest

Options:
  --json  Structured result; prompts remain explicit
```

## investigation reauthorize

```text
usage: investigation reauthorize [--json] [assessment]

Reauthorize an assessment in a NEW read view; not continuation

positional arguments:
  [assessment]  Saved assessment ID or latest

Options:
  --json  Structured result; prompts remain explicit
```

## investigation run

```text
usage: investigation run [--json] [assessment] [--question QUESTION]

Authorize an investigation from a saved assessment

positional arguments:
  [assessment]  Saved assessment ID or latest

Options:
  --json               Structured result; prompts remain explicit
  --question QUESTION  Investigation question; otherwise prompted
```

## investigation findings

```text
usage: investigation findings
       {create, select, list, show, register, accept, reject, supersede, history} ...

Findings

positional arguments:
  create     Create a findings workspace
  select     Review a findings workspace
  list       List findings
  show       Show a finding
  register   Register a proposed finding
  accept     Accept a finding as an analyst decision
  reject     Reject a proposed finding
  supersede  Replace a finding with an auditable decision
  history    Review finding decisions
```

## investigation findings create

```text
usage: investigation findings create --workspace WORKSPACE [--json] --transcripts TRANSCRIPTS
       --run RUN --actor ACTOR

Create a findings workspace

Options:
  --workspace WORKSPACE      Explicit .findings directory; never silently selected
  --json                     Output as JSON
  --transcripts TRANSCRIPTS  Recorded investigation directory
  --run RUN                  Saved investigation ID
  --actor ACTOR              Locally asserted analyst identity
```

## investigation findings select

```text
usage: investigation findings select --workspace WORKSPACE [--json]

Review a findings workspace

Options:
  --workspace WORKSPACE  Explicit .findings directory; never silently selected
  --json                 Output as JSON
```

## investigation findings list

```text
usage: investigation findings list --workspace WORKSPACE [--json]

List findings

Options:
  --workspace WORKSPACE  Explicit .findings directory; never silently selected
  --json                 Output as JSON
```

## investigation findings show

```text
usage: investigation findings show --workspace WORKSPACE [--json] finding_id

Show a finding

positional arguments:
  finding_id  Finding ID

Options:
  --workspace WORKSPACE  Explicit .findings directory; never silently selected
  --json                 Output as JSON
```

## investigation findings register

```text
usage: investigation findings register --workspace WORKSPACE [--json] --actor ACTOR
       --workspace-id WORKSPACE_ID --revision REVISION --statement STATEMENT --support SUPPORT
       [--contrary CONTRARY]
       [--kind {original_observation, deterministic_interpretation, deterministic_relationship,
       analyst_hypothesis}]

Register a proposed finding

Common options:
  --workspace WORKSPACE             Explicit .findings directory; never silently selected
  --json                            Output as JSON
  --actor ACTOR                     Locally asserted analyst identity
  --workspace-id WORKSPACE_ID       UUID from explicit workspace review
  --revision REVISION               Expected current workspace revision
  --statement STATEMENT             Proposed finding statement
  --support SUPPORT                 Supporting reference; repeat for additional support
  --contrary CONTRARY               Contrary evidence reference; repeat as needed
  --kind {original_observation,deterministic_interpretation,deterministic_relationship,analyst_hypothesis}
                                    Finding classification
```

## investigation findings accept

```text
usage: investigation findings accept --workspace WORKSPACE [--json] --actor ACTOR
       --workspace-id WORKSPACE_ID --revision REVISION finding_id --rationale RATIONALE

Accept a finding as an analyst decision

positional arguments:
  finding_id  Finding ID

Options:
  --workspace WORKSPACE        Explicit .findings directory; never silently selected
  --json                       Output as JSON
  --actor ACTOR                Locally asserted analyst identity
  --workspace-id WORKSPACE_ID  UUID from explicit workspace review
  --revision REVISION          Expected current workspace revision
  --rationale RATIONALE        Reason for this analyst decision
```

## investigation findings reject

```text
usage: investigation findings reject --workspace WORKSPACE [--json] --actor ACTOR
       --workspace-id WORKSPACE_ID --revision REVISION finding_id --rationale RATIONALE

Reject a proposed finding

positional arguments:
  finding_id  Finding ID

Options:
  --workspace WORKSPACE        Explicit .findings directory; never silently selected
  --json                       Output as JSON
  --actor ACTOR                Locally asserted analyst identity
  --workspace-id WORKSPACE_ID  UUID from explicit workspace review
  --revision REVISION          Expected current workspace revision
  --rationale RATIONALE        Reason for this analyst decision
```

## investigation findings supersede

```text
usage: investigation findings supersede --workspace WORKSPACE [--json] --actor ACTOR
       --workspace-id WORKSPACE_ID --revision REVISION finding_id --rationale RATIONALE
       --statement STATEMENT --support SUPPORT [--contrary CONTRARY]

Replace a finding with an auditable decision

positional arguments:
  finding_id  Finding ID

Common options:
  --workspace WORKSPACE        Explicit .findings directory; never silently selected
  --json                       Output as JSON
  --actor ACTOR                Locally asserted analyst identity
  --workspace-id WORKSPACE_ID  UUID from explicit workspace review
  --revision REVISION          Expected current workspace revision
  --rationale RATIONALE        Reason for this analyst decision
  --statement STATEMENT        Proposed finding statement
  --support SUPPORT            Supporting reference; repeat for additional support
  --contrary CONTRARY          Contrary evidence reference; repeat as needed
```

## investigation findings history

```text
usage: investigation findings history --workspace WORKSPACE [--json]

Review finding decisions

Options:
  --workspace WORKSPACE  Explicit .findings directory; never silently selected
  --json                 Output as JSON
```

## investigation reason

```text
usage: investigation reason root run_id [--issue ISSUE] [--exploratory] [--cross-artifact]
       [--question QUESTION] [--execute] [--json] [--findings-workspace FINDINGS_WORKSPACE]
       [--findings-actor FINDINGS_ACTOR]

Preview or authorize AI reasoning over recorded evidence

positional arguments:
  root    Recorded investigation directory
  run_id  Saved investigation ID

Options:
  --issue ISSUE                     Registered issue or question identifier
  --exploratory                     Preview organization without an objective-specific binding
  --cross-artifact                  Use the separate 16384-byte policy over saved authorized
                                    evidence
  --question QUESTION               Analyst question for --cross-artifact
  --execute                         Ask to authorize one cloud request; no automatic approval
  --json                            Output as JSON
  --findings-workspace FINDINGS_WORKSPACE
                                    Existing source-bound findings directory; saving requires a
                                    separate choice after execution
  --findings-actor FINDINGS_ACTOR   Locally asserted actor for optional capture; not authenticated
                                    identity
```

## evidence

```text
usage: evidence {export, search, timeline, around, show, ingest, semantic, source} ...

Ingest, find, inspect and export evidence

positional arguments:
  export    Export retained evidence to case-local CSV files
  search    Search case evidence
  timeline  Browse evidence chronologically
  around    Show evidence near a specific event or timestamp
  show      Show details about an evidence record
  ingest    Ingest
  semantic  Search case evidence by meaning
  source    Manage evidence sources
```

## evidence export

```text
usage: evidence export [{browser, evtx, mft, prefetch, registry, all}] [--force]

Usage:
  evidence export <type> [--force]

Types: browser, evtx, mft, prefetch, registry, all

Examples: evidence export browser; evidence export evtx; evidence export mft; evidence export
prefetch; evidence export registry; evidence export all
Fixed destination: <case database directory>/dump/<type>.csv
Existing files require --force. Empty categories are skipped.
CSV files are derived analyst output, not evidence.

positional arguments:
  [{browser,evtx,mft,prefetch,registry,all}]
                                    Artifact family to export

Options:
  --force  Replace requested derived CSV files
```

## evidence search

```text
usage: evidence search [--user USER] [--ip IP] [--hostname HOSTNAME] [--start START] [--end END]
       [--process PROCESS | --process-contains PROCESS] [--ids] [--evtx-text EVTX_TEXT]
       [--evtx-match {exact, contains}] [--evtx-after EVTX_AFTER] [--event-id EVENT_ID]
       [--kind {logons, failed-logons, processes, powershell, scheduled-tasks, services,
       account-changes}] [--limit LIMIT] [--offset OFFSET] [--raw]
       [--artifact {evtx, mft, prefetch, registry, browser}] [--path PATH]
       [--url URL | --url-contains URL_CONTAINS] [--title TITLE | --title-contains TITLE_CONTAINS]
       [--download-path DOWNLOAD_PATH | --download-path-contains DOWNLOAD_PATH_CONTAINS]
       [--browser {chrome, edge}] [--profile PROFILE] [--browser-kind {visit, download}] [--json]
       [--key KEY | --key-contains KEY_CONTAINS]
       [--value-name VALUE_NAME | --value-name-contains VALUE_NAME_CONTAINS] [--source SOURCE]
       [--force] [--page | --output FILE | --append FILE]

Search case evidence

Common options:
  --user USER                       Username filter
  --ip IP                           IP address filter
  --hostname HOSTNAME               Hostname filter
  --start START                     Start time; ISO shorthand defaults to UTC
  --end END                         End time; ISO shorthand defaults to UTC
  --process PROCESS                 Exact executable name, case-insensitive; .exe may be omitted
                                    for a bare name. Explicit paths remain exact.
  --process-contains PROCESS        Case-insensitive literal substring of the executable basename;
                                    no wildcards
  --ids                             Show complete, copyable evidence IDs
  --evtx-text EVTX_TEXT             Explicit literal, case-sensitive EVTX field search; requires
                                    --artifact evtx and a paired time window <=24 hours; bounded
                                    coverage, no raw/offset
  --evtx-match {exact,contains}     Whole-value exact or literal substring match; default contains
  --event-id EVENT_ID               Windows event identifier
  --kind {logons,failed-logons,processes,powershell,scheduled-tasks,services,account-changes}
                                    Normalized record kind
  --limit LIMIT                     Maximum results (default: 20)
  --artifact {evtx,mft,prefetch,registry,browser}
                                    Artifact family filter
  --path PATH                       Path filter
  --url URL                         Exact browser field match
  --url-contains URL_CONTAINS       Literal browser field substring; no wildcards
  --title TITLE                     Exact browser field match
  --title-contains TITLE_CONTAINS   Literal browser field substring; no wildcards
  --download-path DOWNLOAD_PATH     Exact browser field match
  --download-path-contains DOWNLOAD_PATH_CONTAINS
                                    Literal browser field substring; no wildcards
  --browser {chrome,edge}           Browser product filter
  --profile PROFILE                 Browser profile filter
  --browser-kind {visit,download}   Select browser visits or downloads
  --json                            Output as JSON
  --key KEY                         Registry key path: exact literal match (SQLite NOCASE);
                                    includes its values; no filesystem normalization
  --key-contains KEY_CONTAINS       Registry key path: literal substring (SQLite NOCASE); no
                                    wildcards; includes matching keys and their values
  --value-name VALUE_NAME           Registry value name: exact raw or decoded UserAssist name
                                    (SQLite NOCASE)
  --value-name-contains VALUE_NAME_CONTAINS
                                    Registry value name: literal substring of raw or decoded
                                    UserAssist name (SQLite NOCASE); no wildcards
  --source SOURCE                   Filter Locard source membership, not hostname identity
  --page                            View output page by page
  --output FILE                     Save output to a file

Advanced options:
  --evtx-after EVTX_AFTER  Copy the continuation cursor; retain the same filters and unchanged
                           case contents
  --offset OFFSET          Skip this many results
  --raw                    Include original record details where available
  --force                  Overwrite an existing output file
  --append FILE            Append output to a file
```

## evidence timeline

```text
usage: evidence timeline [--details] [timestamp] [--around AROUND] [--start START] [--end END]
       [--user USER] [--process PROCESS] [--ip IP] [--hostname HOSTNAME]
       [--artifact-type ARTIFACT_TYPE] [--event-id EVENT_ID] [--minutes MINUTES] [--limit LIMIT]
       [--offset OFFSET] [--raw] [--json | --text]
       [--artifact {evtx, mft, prefetch, registry, browser}] [--path PATH] [--force]
       [--page | --output FILE | --append FILE]

Browse evidence chronologically

positional arguments:
  [timestamp]  Anchor time; ISO shorthand defaults to UTC

Common options:
  --around AROUND                   Anchor time; ISO shorthand defaults to UTC
  --start START                     Start time; ISO shorthand defaults to UTC
  --end END                         End time; ISO shorthand defaults to UTC
  --user USER                       Username filter
  --process PROCESS                 Process name filter
  --ip IP                           IP address filter
  --hostname HOSTNAME               Hostname filter
  --artifact-type ARTIFACT_TYPE     Normalized artifact type filter
  --event-id EVENT_ID               Windows event identifier
  --minutes MINUTES                 Minutes on either side of the anchor
  --limit LIMIT                     Maximum results (default: 100)
  --json                            Output as JSON (default)
  --text                            Show a compact readable result
  --artifact {evtx,mft,prefetch,registry,browser}
                                    Artifact family filter
  --path PATH                       Path filter
  --page                            View output page by page
  --output FILE                     Save output to a file

Advanced options:
  --details        Show timestamp semantics and provenance
  --offset OFFSET  Skip this many results
  --raw            Include original record details where available
  --force          Overwrite an existing output file
  --append FILE    Append output to a file
```

## evidence around

```text
usage: evidence around evidence_id [--seconds SECONDS] [--direction {before, after, around}]
       [--limit LIMIT] [--offset OFFSET] [--raw] [--ids] [--json | --text]
       [--timestamp-slot TIMESTAMP_SLOT] [--force] [--page | --output FILE | --append FILE]

Compact text rounds timestamps and exact deltas to milliseconds (nearest, ties away from zero).
JSON/raw and --ids retain full precision. Temporal proximity is not causation; timestamp meanings
differ by artifact.

positional arguments:
  evidence_id  Evidence record identifier

Common options:
  --seconds SECONDS                 Seconds around the anchor
  --direction {before,after,around}
                                    Select evidence before, after or around the anchor
  --limit LIMIT                     Maximum number of results
  --ids                             Show exact IDs, timestamp types and full precision
  --json                            Output as JSON (default)
  --text                            Show a compact readable result
  --timestamp-slot TIMESTAMP_SLOT   Anchor timestamp type
  --page                            View output page by page
  --output FILE                     Save output to a file

Advanced options:
  --offset OFFSET  Skip this many results
  --raw            Include original record details where available
  --force          Overwrite an existing output file
  --append FILE    Append output to a file
```

## evidence show

```text
usage: evidence show evidence_id [--raw] [--json] [--force]
       [--page | --output FILE | --append FILE]

Human summary with populated timestamps and bounded references. --json preserves the structured
projection; --raw includes available XML/artifact bytes. Both retain existing
100-object/reference/value-ID bounds and truncation flags.

positional arguments:
  evidence_id  Evidence record identifier

Options:
  --raw          Include original record details where available
  --json         Output as JSON
  --force        Overwrite an existing output file
  --page         View output page by page
  --output FILE  Save output to a file
  --append FILE  Append output to a file
```

## evidence ingest

```text
usage: evidence ingest {mft, prefetch, registry, all, evtx, browser, wizard} ...

Ingest

positional arguments:
  mft       Import NTFS Master File Table (MFT) evidence
  prefetch  Import Windows Prefetch evidence
  registry  Import Windows Registry evidence
  all       Import all supported forensic artifacts
  evtx      Import Windows Event Logs (EVTX)
  browser   Ingest Chrome or Edge browsing history and downloads
  wizard    Guided evidence selection; confirmation required
```

## evidence ingest mft

```text
usage: evidence ingest mft path [--hostname HOSTNAME] [--user USER] [--volume-root VOLUME_ROOT]
       [--parser-timeout PARSER_TIMEOUT] [--record-size RECORD_SIZE] [--json] [--source SOURCE]
       [--force] [--page | --output FILE | --append FILE]

Import NTFS Master File Table (MFT) evidence

positional arguments:
  path  File or directory path

Common options:
  --hostname HOSTNAME        Analyst-supplied source hostname
  --user USER                Analyst-supplied source username
  --volume-root VOLUME_ROOT  Original volume root asserted by the analyst
  --json                     Output as JSON
  --source SOURCE            Reuse this source ID; omitted in scripts creates a NEW automatic
                             source for this invocation, never inferred or reused
  --page                     View output page by page
  --output FILE              Save output to a file

Advanced options:
  --parser-timeout PARSER_TIMEOUT  EVTX: seconds without parser advancement; other artifacts:
                                   wall-clock limit
  --record-size RECORD_SIZE        MFT record size in bytes
  --force                          Overwrite an existing output file
  --append FILE                    Append output to a file

Mutates the selected case through the existing ingestion service; source evidence is read-only.
Review partial outcomes.
```

## evidence ingest prefetch

```text
usage: evidence ingest prefetch path [--hostname HOSTNAME] [--user USER]
       [--volume-root VOLUME_ROOT] [--parser-timeout PARSER_TIMEOUT] [--json] [--source SOURCE]
       [--force] [--page | --output FILE | --append FILE]

Import Windows Prefetch evidence

positional arguments:
  path  File or directory path

Common options:
  --hostname HOSTNAME        Analyst-supplied source hostname
  --user USER                Analyst-supplied source username
  --volume-root VOLUME_ROOT  Original volume root asserted by the analyst
  --json                     Output as JSON
  --source SOURCE            Reuse this source ID; omitted in scripts creates a NEW automatic
                             source for this invocation, never inferred or reused
  --page                     View output page by page
  --output FILE              Save output to a file

Advanced options:
  --parser-timeout PARSER_TIMEOUT  EVTX: seconds without parser advancement; other artifacts:
                                   wall-clock limit
  --force                          Overwrite an existing output file
  --append FILE                    Append output to a file

Mutates the selected case through the existing ingestion service; source evidence is read-only.
Review partial outcomes.
```

## evidence ingest registry

```text
usage: evidence ingest registry path [--hostname HOSTNAME] [--user USER]
       [--volume-root VOLUME_ROOT] [--parser-timeout PARSER_TIMEOUT] [--json] [--source SOURCE]
       [--force] [--page | --output FILE | --append FILE]

Import Windows Registry evidence

positional arguments:
  path  File or directory path

Common options:
  --hostname HOSTNAME        Analyst-supplied source hostname
  --user USER                Analyst-supplied source username
  --volume-root VOLUME_ROOT  Original volume root asserted by the analyst
  --json                     Output as JSON
  --source SOURCE            Reuse this source ID; omitted in scripts creates a NEW automatic
                             source for this invocation, never inferred or reused
  --page                     View output page by page
  --output FILE              Save output to a file

Advanced options:
  --parser-timeout PARSER_TIMEOUT  EVTX: seconds without parser advancement; other artifacts:
                                   wall-clock limit
  --force                          Overwrite an existing output file
  --append FILE                    Append output to a file

Mutates the selected case through the existing ingestion service; source evidence is read-only.
Review partial outcomes.
```

## evidence ingest all

```text
usage: evidence ingest all path [--hostname HOSTNAME] [--user USER] [--volume-root VOLUME_ROOT]
       [--parser-timeout PARSER_TIMEOUT] [--evtx-hard-timeout EVTX_HARD_TIMEOUT]
       [--record-size RECORD_SIZE] [--json] [--source SOURCE] [--force]
       [--page | --output FILE | --append FILE]

Import all supported forensic artifacts

positional arguments:
  path  File or directory path

Common options:
  --hostname HOSTNAME               Analyst-supplied source hostname
  --user USER                       Analyst-supplied source username
  --volume-root VOLUME_ROOT         Original volume root asserted by the analyst
  --evtx-hard-timeout EVTX_HARD_TIMEOUT
                                    EVTX emergency absolute ceiling in seconds (default: 21600)
  --json                            Output as JSON
  --source SOURCE                   Reuse this source ID; omitted in scripts creates a NEW
                                    automatic source for this invocation, never inferred or reused
  --page                            View output page by page
  --output FILE                     Save output to a file

Advanced options:
  --parser-timeout PARSER_TIMEOUT  EVTX: seconds without parser advancement; other artifacts:
                                   wall-clock limit
  --record-size RECORD_SIZE        MFT record size in bytes
  --force                          Overwrite an existing output file
  --append FILE                    Append output to a file

Mutates the selected case through the existing ingestion service; source evidence is read-only.
Review partial outcomes.
```

## evidence ingest evtx

```text
usage: evidence ingest evtx path [--hostname HOSTNAME] [--user USER] [--volume-root VOLUME_ROOT]
       [--parser-timeout PARSER_TIMEOUT] [--evtx-hard-timeout EVTX_HARD_TIMEOUT] [--json]
       [--source SOURCE] [--force] [--page | --output FILE | --append FILE]

Import Windows Event Logs (EVTX)

positional arguments:
  path  File or directory path

Common options:
  --hostname HOSTNAME               Analyst-supplied source hostname
  --user USER                       Analyst-supplied source username
  --volume-root VOLUME_ROOT         Original volume root asserted by the analyst
  --evtx-hard-timeout EVTX_HARD_TIMEOUT
                                    EVTX emergency absolute ceiling in seconds (default: 21600)
  --json                            Output as JSON
  --source SOURCE                   Reuse this source ID; omitted in scripts creates a NEW
                                    automatic source for this invocation, never inferred or reused
  --page                            View output page by page
  --output FILE                     Save output to a file

Advanced options:
  --parser-timeout PARSER_TIMEOUT  EVTX: seconds without parser advancement; other artifacts:
                                   wall-clock limit
  --force                          Overwrite an existing output file
  --append FILE                    Append output to a file

Mutates the selected case through the existing ingestion service; source evidence is read-only.
Review partial outcomes.
```

## evidence ingest browser

```text
usage: evidence ingest browser path --browser {chrome, edge} --profile PROFILE
       [--hostname HOSTNAME] [--user USER] [--volume-root VOLUME_ROOT]
       [--parser-timeout PARSER_TIMEOUT] [--json] [--source SOURCE] [--force]
       [--page | --output FILE | --append FILE]

Ingest Chrome or Edge browsing history and downloads

positional arguments:
  path  File or directory path

Common options:
  --browser {chrome,edge}    Browser product; never inferred
  --profile PROFILE          Browser profile, not the Windows username
  --hostname HOSTNAME        Analyst-supplied source hostname
  --user USER                Analyst-supplied source username
  --volume-root VOLUME_ROOT  Original volume root asserted by the analyst
  --json                     Output as JSON
  --source SOURCE            Reuse this source ID; omitted in scripts creates a NEW automatic
                             source for this invocation, never inferred or reused
  --page                     View output page by page
  --output FILE              Save output to a file

Advanced options:
  --parser-timeout PARSER_TIMEOUT  EVTX: seconds without parser advancement; other artifacts:
                                   wall-clock limit
  --force                          Overwrite an existing output file
  --append FILE                    Append output to a file

Mutates the selected case through the existing ingestion service; source evidence is read-only.
Review partial outcomes.
```

## evidence ingest wizard

```text
usage: evidence ingest wizard

Guided evidence selection; confirmation required
```

## evidence semantic

```text
usage: evidence semantic {search, status} ... [--force] [--page | --output FILE | --append FILE]

Search case evidence by meaning

positional arguments:
  search  Search current case evidence by semantic similarity
  status  Show semantic search and index status

Options:
  --force        Overwrite an existing output file
  --page         View output page by page
  --output FILE  Save output to a file
  --append FILE  Append output to a file
```

## evidence semantic search

```text
usage: evidence semantic search [--json | --text] [--model-path MODEL_PATH] [--index INDEX]
       question [--limit LIMIT] [--show-weak] [--artifact ARTIFACT] [--start START] [--end END]
       [--hostname HOSTNAME] [--user USER] [--path PATH] [--force]
       [--page | --output FILE | --append FILE]

Search current case evidence by semantic similarity

positional arguments:
  question  Question to investigate

Common options:
  --json                   Output complete metadata as JSON
  --text                   Show a concise readable result
  --model-path MODEL_PATH  Override the local model for this command
  --index INDEX            Use a different case-specific semantic index
  --limit LIMIT            Maximum number of results
  --show-weak              Show candidates below the human display cutoff; JSON always retains all
                           results
  --artifact ARTIFACT      Artifact family filter
  --start START            Start time with timezone
  --end END                End time with timezone
  --hostname HOSTNAME      Hostname filter
  --user USER              Username filter
  --path PATH              Literal evidence path filter
  --page                   View output page by page
  --output FILE            Save output to a file

Advanced options:
  --force        Overwrite an existing output file
  --append FILE  Append output to a file
```

## evidence semantic status

```text
usage: evidence semantic status [--json | --text] [--model-path MODEL_PATH] [--index INDEX]
       [--force] [--page | --output FILE | --append FILE]

Show semantic search and index status

Options:
  --json                   Output complete metadata as JSON
  --text                   Show a concise readable result
  --model-path MODEL_PATH  Override the local model for this command
  --index INDEX            Use a different case-specific semantic index
  --force                  Overwrite an existing output file
  --page                   View output page by page
  --output FILE            Save output to a file
  --append FILE            Append output to a file
```

## evidence source

```text
usage: evidence source {list, show, create, update, assign} ... [--force]
       [--page | --output FILE | --append FILE]

Manage evidence sources

positional arguments:
  list    List evidence sources
  show    Show a source and its provenance
  create  Create analyst-supplied source metadata
  update  Update source metadata after confirmation
  assign  Assign retained files to a source after confirmation

Options:
  --force        Overwrite an existing output file
  --page         View output page by page
  --output FILE  Save output to a file
  --append FILE  Append output to a file

Read-only list/show; create/update/assign mutate analyst source metadata and retain existing
confirmations.
```

## evidence source list

```text
usage: evidence source list [--json] [--limit LIMIT] [--offset OFFSET] [--ids] [--force]
       [--page | --output FILE | --append FILE]

List retained sources; use show for selection or --ids for canonical identifiers.

Options:
  --json           Output as JSON
  --limit LIMIT    Maximum number of results
  --offset OFFSET  Skip this many results
  --ids            Show complete, copyable source IDs
  --force          Overwrite an existing output file
  --page           View output page by page
  --output FILE    Save output to a file
  --append FILE    Append output to a file
```

## evidence source show

```text
usage: evidence source show [--json] [source_id] [--limit LIMIT] [--offset OFFSET] [--details]
       [--force] [--page | --output FILE | --append FILE]

Show a source and its provenance

positional arguments:
  [source_id]  Exact source ID; omit show ID for interactive selection

Options:
  --json           Output as JSON
  --limit LIMIT    Maximum number of results
  --offset OFFSET  Skip this many results
  --details        Show source identifiers and paginated provenance
  --force          Overwrite an existing output file
  --page           View output page by page
  --output FILE    Save output to a file
  --append FILE    Append output to a file
```

## evidence source create

```text
usage: evidence source create [--json] [--name NAME] [--hostname HOSTNAME] [--user USER]
       [--volume-root VOLUME_ROOT] [--force] [--page | --output FILE | --append FILE]

Create analyst-supplied source metadata

Common options:
  --json                     Output as JSON
  --name NAME                Source display name
  --hostname HOSTNAME        Analyst-supplied source hostname
  --user USER                Analyst-supplied source username
  --volume-root VOLUME_ROOT  Analyst-supplied original volume root
  --page                     View output page by page
  --output FILE              Save output to a file

Advanced options:
  --force        Overwrite an existing output file
  --append FILE  Append output to a file
```

## evidence source update

```text
usage: evidence source update [--json] source_id [--name NAME] [--hostname HOSTNAME] [--user USER]
       [--volume-root VOLUME_ROOT] [--yes] [--force] [--page | --output FILE | --append FILE]

Update source metadata after confirmation

positional arguments:
  source_id  Exact source ID; omit show ID for interactive selection

Common options:
  --json                     Output as JSON
  --name NAME                Source display name
  --hostname HOSTNAME        Analyst-supplied source hostname
  --user USER                Analyst-supplied source username
  --volume-root VOLUME_ROOT  Analyst-supplied original volume root
  --yes                      Apply without interactive confirmation; otherwise confirm in the
                             shell or preview in scripts
  --page                     View output page by page
  --output FILE              Save output to a file

Advanced options:
  --force        Overwrite an existing output file
  --append FILE  Append output to a file
```

## evidence source assign

```text
usage: evidence source assign [--json] source_id [--yes] [--file-hash FILE_HASH] [--path PATH]
       [--confirmation-fingerprint CONFIRMATION_FINGERPRINT] --reason REASON [--force]
       [--page | --output FILE | --append FILE]

Assign retained files to a source after confirmation

positional arguments:
  source_id  Exact source ID; omit show ID for interactive selection

Common options:
  --json                            Output as JSON
  --yes                             Apply without interactive confirmation; otherwise confirm in
                                    the shell or preview in scripts
  --file-hash FILE_HASH             Explicit existing file SHA-256; repeat or combine with --path
                                    (deduplicated union)
  --path PATH                       Recorded absolute Windows file/directory path; repeatable, no
                                    filesystem scan or wildcards. Requires --path or --file-hash.
  --confirmation-fingerprint CONFIRMATION_FINGERPRINT
                                    Require the case fingerprint returned by a reviewed preview
                                    before applying
  --reason REASON                   Reason for retrospective assignment (does not reconstruct
                                    ingestion)
  --page                            View output page by page
  --output FILE                     Save output to a file

Advanced options:
  --force        Overwrite an existing output file
  --append FILE  Append output to a file
```

## analyze

```text
usage: analyze {process-tree, logons, session, detections, correlate} ...

Correlate evidence and review detections

positional arguments:
  process-tree  Reconstruct process parent-child relationships
  logons        Review recorded Windows logon activity
  session       Reconstruct activity within a Windows logon session
  detections    Show evidence matching Locard detection rules
  correlate     Gather and correlate evidence around a specific evidence record
```

## analyze process-tree

```text
usage: analyze process-tree (--evidence EVIDENCE | --process PROCESS) [--around AROUND]
       [--hostname HOSTNAME] [--seconds SECONDS] [--pid-window PID_WINDOW] [--max-nodes MAX_NODES]
       [--max-depth MAX_DEPTH] [--json | --text] [--raw] [--force]
       [--page | --output FILE | --append FILE]

Reconstruct process parent-child relationships

Common options:
  --evidence EVIDENCE      Process-creation evidence ID
  --process PROCESS        Process name filter
  --around AROUND          Anchor time with timezone
  --hostname HOSTNAME      Hostname filter
  --seconds SECONDS        Child-process window in seconds
  --pid-window PID_WINDOW  PID reuse lookback window in seconds
  --max-nodes MAX_NODES    Maximum process nodes
  --max-depth MAX_DEPTH    Maximum process relationship depth
  --json                   Output as JSON
  --text                   Show readable text
  --page                   View output page by page
  --output FILE            Save output to a file

Advanced options:
  --raw          Show the full diagnostic result as JSON
  --force        Overwrite an existing output file
  --append FILE  Append output to a file

Interactive shell defaults to human text; direct CLI defaults to JSON. --raw retains diagnostic
output, defaulting to JSON. Use --text for human paging; JSON paging is not supported.
```

## analyze logons

```text
usage: analyze logons [--user USER] [--ip IP] [--hostname HOSTNAME] [--start START] [--end END]
       [--limit LIMIT] [--offset OFFSET] [--json | --text] [--raw] [--force]
       [--page | --output FILE | --append FILE]

Review recorded Windows logon activity

Common options:
  --user USER          Username filter
  --ip IP              IP address filter
  --hostname HOSTNAME  Hostname filter
  --start START        Start time; ISO shorthand defaults to UTC
  --end END            End time; ISO shorthand defaults to UTC
  --limit LIMIT        Maximum number of results
  --json               Output as JSON
  --text               Show readable text
  --page               View output page by page
  --output FILE        Save output to a file

Advanced options:
  --offset OFFSET  Skip this many results
  --raw            Show the full diagnostic result as JSON
  --force          Overwrite an existing output file
  --append FILE    Append output to a file

Interactive shell defaults to human text; direct CLI defaults to JSON. --raw retains diagnostic
output, defaulting to JSON. Use --text for human paging; JSON paging is not supported.
```

## analyze session

```text
usage: analyze session --logon-id LOGON_ID [--hostname HOSTNAME] [--around AROUND]
       [--evidence EVIDENCE] [--max-hours MAX_HOURS] [--limit LIMIT] [--json | --text] [--raw]
       [--force] [--page | --output FILE | --append FILE]

Reconstruct activity within a Windows logon session

Common options:
  --logon-id LOGON_ID    Windows authentication Logon ID, decimal or hexadecimal (for example
                         0x1cd8f6); not a Locard evidence ID
  --hostname HOSTNAME    Hostname filter
  --around AROUND        Anchor time with timezone
  --evidence EVIDENCE    Successful-logon evidence ID for disambiguation
  --max-hours MAX_HOURS  Maximum session duration in hours
  --limit LIMIT          Maximum number of results
  --json                 Output as JSON
  --text                 Show readable text
  --page                 View output page by page
  --output FILE          Save output to a file

Advanced options:
  --raw          Show the full diagnostic result as JSON
  --force        Overwrite an existing output file
  --append FILE  Append output to a file

Interactive shell defaults to human text; direct CLI defaults to JSON. --raw retains diagnostic
output, defaulting to JSON. Use --text for human paging; JSON paging is not supported.
```

## analyze detections

```text
usage: analyze detections [--start START] [--end END] [--user USER] [--hostname HOSTNAME]
       [--rule RULE] [--severity {low, medium, high}] [--limit LIMIT]
       [--candidate-limit CANDIDATE_LIMIT] [--failure-threshold FAILURE_THRESHOLD]
       [--failure-window FAILURE_WINDOW] [--json | --text] [--raw] [--force]
       [--page | --output FILE | --append FILE]

Show evidence matching Locard detection rules

Common options:
  --start START                     Start time; ISO shorthand defaults to UTC
  --end END                         End time; ISO shorthand defaults to UTC
  --user USER                       Username filter
  --hostname HOSTNAME               Hostname filter
  --rule RULE                       Detection rule
  --severity {low,medium,high}      Recorded severity filter
  --limit LIMIT                     Maximum number of results
  --candidate-limit CANDIDATE_LIMIT
                                    Maximum candidate records examined
  --failure-threshold FAILURE_THRESHOLD
                                    Minimum failed logons for a detection
  --failure-window FAILURE_WINDOW   Failed-logon window in seconds
  --json                            Output as JSON
  --text                            Show readable text
  --page                            View output page by page
  --output FILE                     Save output to a file

Advanced options:
  --raw          Show the full diagnostic result as JSON
  --force        Overwrite an existing output file
  --append FILE  Append output to a file

Interactive shell defaults to human text; direct CLI defaults to JSON. --raw retains diagnostic
output, defaulting to JSON. Use --text for human paging; JSON paging is not supported.
```

## analyze correlate

```text
usage: analyze correlate evidence_id [--seconds SECONDS] [--candidate-limit CANDIDATE_LIMIT]
       [--json | --text] [--raw] [--timestamp-slot TIMESTAMP_SLOT] [--force]
       [--page | --output FILE | --append FILE]

Deterministic correlation around a specific evidence record identified by its canonical
evidence_id. Gathers nearby and related evidence within bounded criteria; no AI required.

positional arguments:
  evidence_id  Anchor evidence ID

Common options:
  --seconds SECONDS                 Time window around the anchor, in seconds (default: 120)
  --candidate-limit CANDIDATE_LIMIT
                                    Maximum candidate volume (default: 500)
  --json                            Output as JSON
  --text                            Show readable text
  --timestamp-slot TIMESTAMP_SLOT   Select the anchor timestamp slot when multiple slots exist
  --page                            View output page by page
  --output FILE                     Save output to a file

Advanced options:
  --raw          Show the full diagnostic result as JSON
  --force        Overwrite an existing output file
  --append FILE  Append output to a file

Interactive shell defaults to human text; direct CLI defaults to JSON. --raw retains diagnostic
output, defaulting to JSON. Use --text for human paging; JSON paging is not supported.
```

## case

```text
usage: case {status, open, new, list, root, register, unregister, clone} ...

Open, create and inspect a case

positional arguments:
  status      Show case ingestion and evidence status
  open        Open a case
  new         Create a case
  list        List available cases
  root        View or change the case directory
  register    Register an existing case
  unregister  Remove a case registration
  clone       Create an independent case copy
```

## case status

```text
usage: case status [--details] [--json] [--force] [--page | --output FILE | --append FILE]

Show case ingestion and evidence status

Options:
  --details      Show source and ingestion diagnostics
  --json         Output as JSON
  --force        Overwrite an existing output file
  --page         View output page by page
  --output FILE  Save output to a file
  --append FILE  Append output to a file
```

## case open

```text
usage: case open [path]

Open a case

positional arguments:
  [path]  Existing case path
```

## case new

```text
usage: case new [name]

Create a case

positional arguments:
  [name]  New case name
```

## case list

```text
usage: case list [--json] [--details]

List available cases

Options:
  --json     Output as JSON
  --details  Show case paths and discovery metadata
```

## case root

```text
usage: case root [--json] [{set}] [path] [--yes]

View or change the case directory

positional arguments:
  [{set}]  Select set to change the root
  [path]   File or directory path

Options:
  --json  Output as JSON
  --yes   Explicitly confirm the described local change; no evidence/provider authorization
```

## case register

```text
usage: case register [--json] name path [--yes]

Register an existing case

positional arguments:
  name  Case name
  path  File or directory path

Options:
  --json  Output as JSON
  --yes   Explicitly confirm the described local change; no evidence/provider authorization
```

## case unregister

```text
usage: case unregister [--json] name [--yes]

Remove a case registration

positional arguments:
  name  Case name

Options:
  --json  Output as JSON
  --yes   Explicitly confirm the described local change; no evidence/provider authorization
```

## case clone

```text
usage: case clone [--json] source name [--yes]

Create an independent case copy

positional arguments:
  source  Source case path
  name    Case name

Options:
  --json  Output as JSON
  --yes   Explicitly confirm the described local change; no evidence/provider authorization
```

## report

```text
usage: report {from-history, verify-history, from-case, show, verify} ... [--force]
       [--page | --output FILE | --append FILE]

Generate a forensic investigation report

positional arguments:
  from-history    Create a report from validated investigation history
  verify-history  Verify a report; optionally check recorded sources
  from-case       Create a report from selected case evidence
  show            Show a report bundle
  verify          Verify a report bundle and optional evidence grounding

Options:
  --force        Overwrite an existing output file
  --page         View output page by page
  --output FILE  Save output to a file
  --append FILE  Append output to a file

Derived output publication. Case and recorded-history reports retain separate grounding contracts.
```

## report from-history

```text
usage: report from-history --transcript-root TRANSCRIPT_ROOT --run RUN [--workspace WORKSPACE]
       [--profile {executive, technical, handover}] --output OUTPUT [--protect-root PROTECT_ROOT]
       [--json] [--text]

Create a report from validated investigation history

Options:
  --transcript-root TRANSCRIPT_ROOT
                                    Original investigation transcript directory
  --run RUN                         Saved investigation ID
  --workspace WORKSPACE             Optional matching .findings directory
  --profile {executive,technical,handover}
                                    Report detail level
  --output OUTPUT                   New local report directory
  --protect-root PROTECT_ROOT       Additional evidence directory to exclude from destinations
                                    (repeatable)
  --json                            Output as JSON
  --text                            Human-readable report result
```

## report verify-history

```text
usage: report verify-history directory [--transcript-root TRANSCRIPT_ROOT] [--run RUN]
       [--workspace WORKSPACE] [--json] [--text]

Verify a report; optionally check recorded sources

positional arguments:
  directory  Report directory

Options:
  --transcript-root TRANSCRIPT_ROOT
                                    Original investigation transcript directory
  --run RUN                         Saved investigation ID
  --workspace WORKSPACE             Matching findings workspace directory
  --json                            Output as JSON
  --text                            Human-readable report result
```

## report from-case

```text
usage: report from-case [--json | --text]
       (--evidence EVIDENCE_IDS | --investigation INVESTIGATION_IDS)
       [--transcript-root TRANSCRIPT_ROOT] --output OUTPUT [--profile {technical, executive}]
       [--redact {none, identifiers}] [--include-source-locations] [--case-name CASE_NAME]
       [--case-identifier CASE_IDENTIFIER] [--analyst-name ANALYST_NAME]
       [--organization ORGANIZATION] [--title TITLE] [--scope-note SCOPE_NOTE]
       [--max-claims MAX_CLAIMS] [--max-timeline MAX_TIMELINE] [--seconds SECONDS]
       [--llm-narrative] [--endpoint ENDPOINT] [--force] [--page | --append FILE]

Create a report from selected case evidence

Common options:
  --json                            Output as JSON
  --text                            Show a readable result
  --evidence EVIDENCE_IDS           Explicit evidence ID (repeatable); not a complete
                                    investigation
  --investigation INVESTIGATION_IDS
                                    Same-state V4 investigation ID (repeatable)
  --transcript-root TRANSCRIPT_ROOT
                                    Original investigation transcript directory
  --output OUTPUT                   New report directory under an existing directory
  --profile {technical,executive}   Report detail level
  --redact {none,identifiers}       Redact identifying information in the derived report
  --include-source-locations        Include original source locations in the report
  --case-name CASE_NAME             Case name shown in report
  --case-identifier CASE_IDENTIFIER
                                    Case identifier shown in report
  --analyst-name ANALYST_NAME       Analyst name shown in report
  --organization ORGANIZATION       Organization shown in report
  --title TITLE                     Report title
  --scope-note SCOPE_NOTE           Report scope qualification
  --max-claims MAX_CLAIMS           Maximum report claims
  --max-timeline MAX_TIMELINE       Maximum timeline observations in the report
  --seconds SECONDS                 Seconds around the anchor
  --llm-narrative                   Optional grounded narrative composition through local MiniCPM;
                                    rejected output falls back safely
  --endpoint ENDPOINT               Local model endpoint
  --page                            View output page by page

Advanced options:
  --force        Overwrite an existing output file
  --append FILE  Append output to a file
```

## report show

```text
usage: report show directory [--force] [--page | --output FILE | --append FILE]

Show a report bundle

positional arguments:
  directory  Report bundle directory, not a report ID

Options:
  --force        Overwrite an existing output file
  --page         View output page by page
  --output FILE  Save output to a file
  --append FILE  Append output to a file
```

## report verify

```text
usage: report verify directory [--case CASE] [--transcript-root TRANSCRIPT_ROOT] [--force]
       [--page | --output FILE | --append FILE]

Verify a report bundle and optional evidence grounding

positional arguments:
  directory  Report directory

Options:
  --case CASE                       Optional existing schema-3 case for fingerprint and grounding
                                    checks
  --transcript-root TRANSCRIPT_ROOT
                                    Original transcripts for investigation-report grounding
  --force                           Overwrite an existing output file
  --page                            View output page by page
  --output FILE                     Save output to a file
  --append FILE                     Append output to a file
```

## audit

```text
usage: audit {activity, verify, sessions, session, diagnostics} ...

Review activity and verify audit integrity

positional arguments:
  activity     Review and verify analyst activity
  verify       Verify activity and session integrity
  sessions     Review Locard's internal diagnostic logs
  session      Session
  diagnostics  Review Locard's internal diagnostic logs
```

## audit activity

```text
usage: audit activity [--limit LIMIT] [--json] [--force] [--page | --output FILE | --append FILE]

Review and verify analyst activity

Options:
  --limit LIMIT  Maximum number of results
  --json         Output as JSON
  --force        Overwrite an existing output file
  --page         View output page by page
  --output FILE  Save output to a file
  --append FILE  Append output to a file
```

## audit verify

```text
usage: audit verify [--json] [--application]

Verify activity and session integrity

Options:
  --json         Output as JSON
  --application  Review application logs instead of case logs
```

## audit sessions

```text
usage: audit sessions [--json] [--application]

Review Locard's internal diagnostic logs

Options:
  --json         Output as JSON
  --application  Review application logs instead of case logs
```

## audit session

```text
usage: audit session {show} ...

Session

positional arguments:
  show  Review Locard's internal diagnostic logs
```

## audit session show

```text
usage: audit session show [--json] [--application] [session] [--limit LIMIT] [--since SINCE]
       [--operation-id OPERATION_ID]

Review Locard's internal diagnostic logs

positional arguments:
  [session]  Session ID or latest session

Options:
  --json                       Output as JSON
  --application                Review application logs instead of case logs
  --limit LIMIT                Maximum recent records, 1..1000
  --since SINCE                Include records since a time with timezone
  --operation-id OPERATION_ID  Filter by operation ID
```

## audit diagnostics

```text
usage: audit diagnostics [--json] [--application] [session] [--limit LIMIT] [--since SINCE]
       [--operation-id OPERATION_ID] [--severity {DEBUG, INFO, WARNING, ERROR, CRITICAL}]

Review Locard's internal diagnostic logs

positional arguments:
  [session]  Session ID or latest session

Options:
  --json                            Output as JSON
  --application                     Review application logs instead of case logs
  --limit LIMIT                     Maximum recent records, 1..1000
  --since SINCE                     Include records since a time with timezone
  --operation-id OPERATION_ID       Filter by operation ID
  --severity {DEBUG,INFO,WARNING,ERROR,CRITICAL}
                                    Recorded severity filter
```

## ai

```text
usage: ai {provider, status, check, configure, start, stop, logs} ...

Local uses llama.cpp / llama-server with a compatible user-selected GGUF model. Status
distinguishes configuration readiness from runtime state. Cloud use sends bounded model context to
the selected provider.

positional arguments:
  provider   View or select provider
  status     Show provider configuration and readiness
  check      Check configuration or run an authorized provider diagnostic
  configure  Configure the provider, model or local paths
  start      Start the owned local runtime
  stop       Stop only the Locard-owned runtime
  logs       Review AI diagnostics

Status and Quick are provider-free; connectivity/full checks and runtime start are explicit
operations.
```

## ai provider

```text
usage: ai provider [--json] [{local, openai, anthropic, gemini, deepseek, xai}] [--model MODEL]
       [--acknowledge-cloud]

View or select provider

positional arguments:
  [{local,openai,anthropic,gemini,deepseek,xai}]
                                    AI provider

Options:
  --json               Output as JSON
  --model MODEL        Cloud model name without provider prefix
  --acknowledge-cloud  Explicitly acknowledge transmission to the selected cloud provider
```

## ai status

```text
usage: ai status [--json]

Show provider configuration and readiness

Options:
  --json  Output as JSON
```

## ai check

```text
usage: ai check [--json] [--connectivity | --full] [--authorize-diagnostic]

Check configuration or run an authorized provider diagnostic

Options:
  --json                  Output as JSON
  --connectivity          Non-generative authentication/reachability check
  --full                  Potentially billable synthetic compatibility diagnostic
  --authorize-diagnostic  Authorize synthetic model requests for this diagnostic only
```

## ai configure

```text
usage: ai configure [--json] [{local, openai, anthropic, gemini, deepseek, xai}] [--model MODEL]
       [--acknowledge-cloud] [--executable EXECUTABLE] [--model-path MODEL_PATH]
       [--context CONTEXT] [--gpu-layers GPU_LAYERS] [--port PORT] [--extra-options EXTRA_OPTIONS]

Configure the provider, model or local paths

positional arguments:
  [{local,openai,anthropic,gemini,deepseek,xai}]
                                    AI provider

Common options:
  --json                         Output as JSON
  --model MODEL                  Cloud model name without provider prefix
  --acknowledge-cloud            Explicitly acknowledge transmission to the selected cloud
                                 provider
  --executable EXECUTABLE        Local llama-server executable
  --model-path MODEL_PATH        Local GGUF model file
  --context CONTEXT              Local model context size
  --gpu-layers GPU_LAYERS        Number of model layers assigned to GPU
  --port PORT                    Loopback port; 0 selects an available port
  --extra-options EXTRA_OPTIONS  Validated performance options; -ngl/-c update dedicated settings,
                                 never duplicate defaults
```

## ai start

```text
usage: ai start [--json]

Start the owned local runtime

Options:
  --json  Output as JSON
```

## ai stop

```text
usage: ai stop [--json]

Stop only the Locard-owned runtime

Options:
  --json  Output as JSON
```

## ai logs

```text
usage: ai logs [--json] [--raw]

Review AI diagnostics

Options:
  --json  Output as JSON
  --raw   Enable session capture and display buffered cloud output; may contain case data
```

## settings

```text
usage: settings {color, version} ...

Set terminal preferences and view the version

positional arguments:
  color    View or change terminal colors
  version  Show the version and optional installation details
```

## settings color

```text
usage: settings color [{on, off}]

View or change terminal colors

positional arguments:
  [{on,off}]  Enable or disable terminal colors
```

## settings version

```text
usage: settings version [--details]

Show the version and optional installation details

Options:
  --details  Show technical details
```

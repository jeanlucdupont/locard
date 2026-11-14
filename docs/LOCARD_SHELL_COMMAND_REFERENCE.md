# Locard shell command reference

Generated from the working-tree parser for Locard 6.142.

Inventory: **88 canonical parser nodes**, **652 argument/option entries** including global options and repetition.
Type commands at `[case]>` without a `locard` prefix. For scripts, use `python locard.py --db CASE <command>`; global options precede the command. `case open`, `case new`, `settings color` and `evidence ingest wizard` are interactive shell operations.

`help` shows eight command families; `help all` lists the complete tree; `help <family> <operation>` shows syntax. `?` means help; `quit` ends the shell. `! <question>` preserves advisory/investigation routing and per-tool approvals. Retired flat command names are not aliases.

Human output is normally the interactive default. Use an explicit `--json` where available for structured output. Parent options must precede child commands. Standard `-h` / `--help` remain accepted even where hidden in usage.

Counts include group nodes and repeated option definitions, not independent forensic capabilities. Detailed terminal help separates common and advanced controls. Options are operation-specific; a shared spelling does not authorize an otherwise prohibited action.


## Command tree

```text
investigation
  investigation briefing
    investigation briefing show
    investigation briefing edit
    investigation briefing interview
    investigation briefing import
    investigation briefing export
    investigation briefing import-json
    investigation briefing analyze
    investigation briefing inspect
  investigation advanced
    investigation advanced timeline
    investigation advanced local-query
    investigation advanced current-case
    investigation advanced assessment
  investigation history
    investigation history show
    investigation history replay
  investigation start
  investigation assess
  investigation list
  investigation show
  investigation reauthorize
  investigation run
  investigation findings
    investigation findings create
    investigation findings select
    investigation findings list
    investigation findings show
    investigation findings register
    investigation findings accept
    investigation findings reject
    investigation findings supersede
    investigation findings history
  investigation reason
evidence
  evidence export
  evidence search
  evidence timeline
  evidence around
  evidence show
  evidence ingest
    evidence ingest mft
    evidence ingest prefetch
    evidence ingest registry
    evidence ingest all
    evidence ingest evtx
    evidence ingest browser
    evidence ingest wizard
  evidence semantic
    evidence semantic search
    evidence semantic status
  evidence source
    evidence source list
    evidence source show
    evidence source create
    evidence source update
    evidence source assign
analyze
  analyze process-tree
  analyze logons
  analyze session
  analyze detections
  analyze correlate
case
  case status
  case open
  case new
report
  report from-history
  report verify-history
  report from-case
  report show
  report verify
audit
  audit activity
  audit verify
ai
  ai provider
  ai status
  ai check
  ai configure
  ai start
  ai stop
  ai logs
settings
  settings color
  settings version
```

## Shell navigation

`help`, `help all`, `help <path>` and `?` show help; `quit` ends the session. `! <question>` uses the existing advisory/investigation approval flow.

Recorded-history review is provider-free. Use `report from-history` for a protected derived export; history show does not expose generic file-write options that could require inspecting the live case.

## Detailed parsers

### Global options

```text
usage: Locard shell [--version] [--version-details] [--db DB]
                    {investigation,evidence,analyze,case,report,audit,ai,settings}
                    ...
```

Locard — local evidence-first Windows forensics

| Argument / option | Meaning | Constraints / default |
|---|---|---|
| `--version` | show program's version number and exit | arity: 0 |
| `--version-details` | Show effective source and installed metadata versions (JSON) | arity: 0; default: None |
| `--db` | Db. | default: 'data/forensic.db' |
| `--no-color` | No color. | arity: 0; default: False |



### investigation

```text
usage: investigation
                     {briefing,advanced,history,start,assess,list,show,reauthorize,run,findings,reason}
                     ...
```

Guided investigation, recorded review and findings

| Argument / option | Meaning | Constraints / default |
|---|---|---|



### investigation briefing

```text
usage: investigation briefing [--force]
                              [--page | --output FILE | --append FILE]
                              {show,edit,interview,import,export,import-json,analyze,inspect}
                              ...
```



| Argument / option | Meaning | Constraints / default |
|---|---|---|
| `--no-color` | No color. | arity: 0 |
| `--force` | Permit replacing an existing derived output file without confirmation | arity: 0 |
| `--page` | Review output with the internal pager (Up/Down, PgUp/PgDn, Home/End, Q) | arity: 0 |
| `--output` | Write a derived UTF-8 file; existing files require confirmation or --force |  |
| `--append` | Append rendered output to a derived UTF-8 file |  |

Analyst-supplied derived information, not evidence. Interview/AI interpretation may contact the configured provider; writes require confirmation.

### investigation briefing show

```text
usage: investigation briefing show [--details] [--json] [--force]
                                   [--page | --output FILE | --append FILE]
```



| Argument / option | Meaning | Constraints / default |
|---|---|---|
| `--details` | Show full provenance, search packets and validation diagnostics | arity: 0; default: False |
| `--json` | Include original narrative, spans, leads, packet and plan; sensitive derived output | arity: 0; default: False |
| `--no-color` | No color. | arity: 0 |
| `--force` | Permit replacing an existing derived output file without confirmation | arity: 0 |
| `--page` | Review output with the internal pager (Up/Down, PgUp/PgDn, Home/End, Q) | arity: 0 |
| `--output` | Write a derived UTF-8 file; existing files require confirmation or --force |  |
| `--append` | Append rendered output to a derived UTF-8 file |  |



### investigation briefing edit

```text
usage: investigation briefing edit [--details] [--json] [--force]
                                   [--page | --output FILE | --append FILE]
```



| Argument / option | Meaning | Constraints / default |
|---|---|---|
| `--details` | Show full provenance, search packets and validation diagnostics | arity: 0; default: False |
| `--json` | Include original narrative, spans, leads, packet and plan; sensitive derived output | arity: 0; default: False |
| `--no-color` | No color. | arity: 0 |
| `--force` | Permit replacing an existing derived output file without confirmation | arity: 0 |
| `--page` | Review output with the internal pager (Up/Down, PgUp/PgDn, Home/End, Q) | arity: 0 |
| `--output` | Write a derived UTF-8 file; existing files require confirmation or --force |  |
| `--append` | Append rendered output to a derived UTF-8 file |  |



### investigation briefing interview

```text
usage: investigation briefing interview [--details] [--json] [--force]
                                        [--page | --output FILE | --append FILE]
```



| Argument / option | Meaning | Constraints / default |
|---|---|---|
| `--details` | Show full provenance, search packets and validation diagnostics | arity: 0; default: False |
| `--json` | Include original narrative, spans, leads, packet and plan; sensitive derived output | arity: 0; default: False |
| `--no-color` | No color. | arity: 0 |
| `--force` | Permit replacing an existing derived output file without confirmation | arity: 0 |
| `--page` | Review output with the internal pager (Up/Down, PgUp/PgDn, Home/End, Q) | arity: 0 |
| `--output` | Write a derived UTF-8 file; existing files require confirmation or --force |  |
| `--append` | Append rendered output to a derived UTF-8 file |  |



### investigation briefing import

```text
usage: investigation briefing import
                                     (--file BRIEFING_FILE | --text BRIEFING_TEXT)
                                     [--details] [--json] [--force]
                                     [--page | --output FILE | --append FILE]
```



| Argument / option | Meaning | Constraints / default |
|---|---|---|
| `--file` | UTF-8 analyst narrative, at most 32 KiB | default: None |
| `--text` | Inline analyst narrative | default: None |
| `--details` | Show full provenance, search packets and validation diagnostics | arity: 0; default: False |
| `--json` | Include original narrative, spans, leads, packet and plan; sensitive derived output | arity: 0; default: False |
| `--no-color` | No color. | arity: 0 |
| `--force` | Permit replacing an existing derived output file without confirmation | arity: 0 |
| `--page` | Review output with the internal pager (Up/Down, PgUp/PgDn, Home/End, Q) | arity: 0 |
| `--output` | Write a derived UTF-8 file; existing files require confirmation or --force |  |
| `--append` | Append rendered output to a derived UTF-8 file |  |



### investigation briefing export

```text
usage: investigation briefing export [--details] [--json] [--force]
                                     [--page | --output FILE | --append FILE]
                                     export_json
```



| Argument / option | Meaning | Constraints / default |
|---|---|---|
| `export_json` | Fresh JSON destination; no overwrite | required; default: None |
| `--details` | Show full provenance, search packets and validation diagnostics | arity: 0; default: False |
| `--json` | Include original narrative, spans, leads, packet and plan; sensitive derived output | arity: 0; default: False |
| `--no-color` | No color. | arity: 0 |
| `--force` | Permit replacing an existing derived output file without confirmation | arity: 0 |
| `--page` | Review output with the internal pager (Up/Down, PgUp/PgDn, Home/End, Q) | arity: 0 |
| `--output` | Write a derived UTF-8 file; existing files require confirmation or --force |  |
| `--append` | Append rendered output to a derived UTF-8 file |  |



### investigation briefing import-json

```text
usage: investigation briefing import-json [--details] [--json] [--force]
                                          [--page | --output FILE | --append FILE]
                                          import_json
```



| Argument / option | Meaning | Constraints / default |
|---|---|---|
| `import_json` | Canonical JSON file; confirmation required | required; default: None |
| `--details` | Show full provenance, search packets and validation diagnostics | arity: 0; default: False |
| `--json` | Include original narrative, spans, leads, packet and plan; sensitive derived output | arity: 0; default: False |
| `--no-color` | No color. | arity: 0 |
| `--force` | Permit replacing an existing derived output file without confirmation | arity: 0 |
| `--page` | Review output with the internal pager (Up/Down, PgUp/PgDn, Home/End, Q) | arity: 0 |
| `--output` | Write a derived UTF-8 file; existing files require confirmation or --force |  |
| `--append` | Append rendered output to a derived UTF-8 file |  |



### investigation briefing analyze

```text
usage: investigation briefing analyze [--deterministic] [--revision REVISION]
                                      [--discover] [--approve LEAD_ID]
                                      [--artifact {evtx,mft,prefetch,registry,browser,all}]
                                      [--discovery-after DISCOVERY_AFTER]
                                      [--start START] [--end END] [--details]
                                      [--json] [--force]
                                      [--page | --output FILE | --append FILE]
```



| Argument / option | Meaning | Constraints / default |
|---|---|---|
| `--deterministic` | Analyze saved briefing without AI | arity: 0; default: False |
| `--revision` | Required current briefing revision for saved-briefing discovery approval | default: None; type: int |
| `--discover` | Execute approved lead lookups; requires --approve, --artifact, --start and --end | arity: 0; default: False |
| `--approve` | Approve exactly this reviewed lead; repeat for at most six leads | default: []; repeatable |
| `--artifact` | Search one family or all available families (six queries total; review unsearched coverage) | choices: evtx, mft, prefetch, registry, browser, all; default: None |
| `--discovery-after` | Resume one explicitly approved lead/family using its discovery continuation token | default: None |
| `--start` | Authorized search start with UTC/offset; never inferred from narrative | default: None |
| `--end` | Authorized search end with UTC/offset; maximum 24-hour window | default: None |
| `--details` | Show full provenance, search packets and validation diagnostics | arity: 0; default: False |
| `--json` | Include original narrative, spans, leads, packet and plan; sensitive derived output | arity: 0; default: False |
| `--no-color` | No color. | arity: 0 |
| `--force` | Permit replacing an existing derived output file without confirmation | arity: 0 |
| `--page` | Review output with the internal pager (Up/Down, PgUp/PgDn, Home/End, Q) | arity: 0 |
| `--output` | Write a derived UTF-8 file; existing files require confirmation or --force |  |
| `--append` | Append rendered output to a derived UTF-8 file |  |



### investigation briefing inspect

```text
usage: investigation briefing inspect
                                      (--file BRIEFING_FILE | --text BRIEFING_TEXT)
                                      [--correction BRIEFING_CORRECTION]
                                      [--ai] [--discover] [--approve LEAD_ID]
                                      [--artifact {evtx,mft,prefetch,registry,browser,all}]
                                      [--discovery-after DISCOVERY_AFTER]
                                      [--start START] [--end END] [--details]
                                      [--json] [--force]
                                      [--page | --output FILE | --append FILE]
```



| Argument / option | Meaning | Constraints / default |
|---|---|---|
| `--file` | UTF-8 analyst narrative, at most 32 KiB | default: None |
| `--text` | Inline analyst narrative | default: None |
| `--correction` | Separate analyst correction; original wording remains intact | default: []; repeatable |
| `--ai` | One bounded narrative interpretation using the configured provider; no tools | arity: 0; default: False |
| `--discover` | Execute approved lead lookups; requires --approve, --artifact, --start and --end | arity: 0; default: False |
| `--approve` | Approve exactly this reviewed lead; repeat for at most six leads | default: []; repeatable |
| `--artifact` | Search one family or all available families (six queries total; review unsearched coverage) | choices: evtx, mft, prefetch, registry, browser, all; default: None |
| `--discovery-after` | Resume one explicitly approved lead/family using its discovery continuation token | default: None |
| `--start` | Authorized search start with UTC/offset; never inferred from narrative | default: None |
| `--end` | Authorized search end with UTC/offset; maximum 24-hour window | default: None |
| `--details` | Show full provenance, search packets and validation diagnostics | arity: 0; default: False |
| `--json` | Include original narrative, spans, leads, packet and plan; sensitive derived output | arity: 0; default: False |
| `--no-color` | No color. | arity: 0 |
| `--force` | Permit replacing an existing derived output file without confirmation | arity: 0 |
| `--page` | Review output with the internal pager (Up/Down, PgUp/PgDn, Home/End, Q) | arity: 0 |
| `--output` | Write a derived UTF-8 file; existing files require confirmation or --force |  |
| `--append` | Append rendered output to a derived UTF-8 file |  |



### investigation advanced

```text
usage: investigation advanced {timeline,local-query,current-case,assessment}
                              ...
```

Advanced

| Argument / option | Meaning | Constraints / default |
|---|---|---|



### investigation advanced timeline

```text
usage: investigation advanced timeline --start START --end END
                                       [--hostname HOSTNAME] [--user USER]
                                       [--candidate-limit CANDIDATE_LIMIT]
                                       [--endpoint ENDPOINT]
                                       [--timeout TIMEOUT] [--dry-run]
                                       [--json | --text] [--raw] [--force]
                                       [--page | --output FILE | --append FILE]
```

Specialized workflow: deterministic retrieval and correlation in an explicit time range, followed by local AI analysis. --dry-run builds the bounded evidence bundle without calling the model. Model analysis is not evidence; citation checks do not establish factual correctness.

| Argument / option | Meaning | Constraints / default |
|---|---|---|
| `--start` | Start. | required; default: None |
| `--end` | End. | required; default: None |
| `--hostname` | Hostname. | default: None |
| `--user` | User. | default: None |
| `--candidate-limit` | Candidate limit. | default: 500; type: int |
| `--endpoint` | Endpoint. | default: None |
| `--timeout` | Timeout. | default: 120; type: float |
| `--dry-run` | Dry run. | arity: 0; default: False |
| `--json` | Structured JSON output | arity: 0; default: False |
| `--text` | Human-readable text output | arity: 0; default: False |
| `--raw` | Raw. | arity: 0; default: False |
| `--no-color` | No color. | arity: 0 |
| `--force` | Permit replacing an existing derived output file without confirmation | arity: 0 |
| `--page` | Review output with the internal pager (Up/Down, PgUp/PgDn, Home/End, Q) | arity: 0 |
| `--output` | Write a derived UTF-8 file; existing files require confirmation or --force |  |
| `--append` | Append rendered output to a derived UTF-8 file |  |

Advanced model-consuming operation; existing provider disclosure and operation-specific approval controls apply.

### investigation advanced local-query

```text
usage: investigation advanced local-query [--json | --text]
                                          [--endpoint ENDPOINT] [--date DATE]
                                          [--limit LIMIT] [--timeout TIMEOUT]
                                          [--dry-run]
                                          [--semantic-index SEMANTIC_INDEX]
                                          [--embedding-model EMBEDDING_MODEL]
                                          [--force]
                                          [--page | --output FILE | --append FILE]
                                          question
```

Advanced bounded local query with deterministic planning and optional semantic retrieval. Deterministic search retrieves evidence by exact/filter-based criteria. Semantic retrieval discovers meaning-based candidate leads, not evidence for the queried concept. The local LLM analyzes only the bounded supplied bundle. Model analysis is not evidence.

| Argument / option | Meaning | Constraints / default |
|---|---|---|
| `--json` | Structured output | arity: 0; default: False |
| `--text` | Human-readable output | arity: 0; default: False |
| `question` | Question. | required; default: None |
| `--endpoint` | Endpoint. | default: None |
| `--date` | UTC date for time-only questions | default: None |
| `--limit` | Limit. | default: 30; type: int |
| `--timeout` | Timeout. | default: 120.0; type: float |
| `--dry-run` | Show plan and evidence without contacting the model | arity: 0; default: False |
| `--semantic-index` | Semantic index. | default: None |
| `--embedding-model` | Embedding model. | default: None |
| `--no-color` | No color. | arity: 0 |
| `--force` | Permit replacing an existing derived output file without confirmation | arity: 0 |
| `--page` | Review output with the internal pager (Up/Down, PgUp/PgDn, Home/End, Q) | arity: 0 |
| `--output` | Write a derived UTF-8 file; existing files require confirmation or --force |  |
| `--append` | Append rendered output to a derived UTF-8 file |  |

Advanced model-consuming operation; existing provider disclosure and operation-specific approval controls apply.

### investigation advanced current-case

```text
usage: investigation advanced current-case [--details] [--endpoint ENDPOINT]
                                           [--date DATE]
                                           [--max-steps MAX_STEPS]
                                           [--max-tool-calls MAX_TOOL_CALLS]
                                           [--max-seconds MAX_SECONDS]
                                           [--dry-run] [--approve-tools]
                                           [--transcripts TRANSCRIPTS]
                                           [--json] [--explain]
                                           [--no-semantic]
                                           [--semantic-index SEMANTIC_INDEX]
                                           [--embedding-model EMBEDDING_MODEL]
                                           [--force]
                                           [--page | --output FILE | --append FILE]
                                           question
```

Advanced / Diagnostic interface. Use ! <question> for normal interactive AI requests.

| Argument / option | Meaning | Constraints / default |
|---|---|---|
| `question` | Question. | required; default: None |
| `--details` | Show technical observations, full evidence IDs and provenance | arity: 0; default: False |
| `--endpoint` | Advanced existing loopback endpoint; overrides configured provider for this invocation | default: None |
| `--date` | Date. | default: None |
| `--max-steps` | Max steps. | default: 8; type: int |
| `--max-tool-calls` | Max tool calls. | default: 6; type: int |
| `--max-seconds` | Max seconds. | default: 300; type: int |
| `--dry-run` | Initial retrieval plus one model proposal; no iterative tool execution | arity: 0; default: False |
| `--approve-tools` | Require interactive approval for each proposed operation | arity: 0; default: False |
| `--transcripts` | Sensitive local derived records, not evidence; default: DATABASE.investigations. Analyst controls retention/deletion. | default: None |
| `--json` | Json. | arity: 0; default: False |
| `--explain` | Include step-by-step transcript data | arity: 0; default: False |
| `--no-semantic` | No semantic. | arity: 0; default: False |
| `--semantic-index` | Semantic index. | default: None |
| `--embedding-model` | Embedding model. | default: None |
| `--no-color` | No color. | arity: 0 |
| `--force` | Permit replacing an existing derived output file without confirmation | arity: 0 |
| `--page` | Review output with the internal pager (Up/Down, PgUp/PgDn, Home/End, Q) | arity: 0 |
| `--output` | Write a derived UTF-8 file; existing files require confirmation or --force |  |
| `--append` | Append rendered output to a derived UTF-8 file |  |

Advanced model-consuming operation; existing provider disclosure and operation-specific approval controls apply.

### investigation advanced assessment

```text
usage: investigation advanced assessment [--question QUESTION] [--start START]
                                         [--end END] [--details] [--json]
                                         [assessment]
```

Historical assessment handoff with per-tool approval; distinct from autonomous run

| Argument / option | Meaning | Constraints / default |
|---|---|---|
| `assessment` | Assessment. | arity: ?; default: 'latest' |
| `--question` | Question. | default: None |
| `--start` | Start. | default: None |
| `--end` | End. | default: None |
| `--details` | Details. | arity: 0; default: False |
| `--json` | Json. | arity: 0; default: False |



### investigation history

```text
usage: investigation history {show,replay} ...
```

Review or replay saved derived AI investigation records for audit and review. These records are not source evidence.

| Argument / option | Meaning | Constraints / default |
|---|---|---|

Saved records are derived data; replay does not establish forensic conclusions. Read-only examination by default; derived output files and activity records may be written. Coverage limitations remain significant.

### investigation history show

```text
usage: investigation history show [--transcripts TRANSCRIPTS] [--json]
                                  [--explain]
                                  investigation_id
```



| Argument / option | Meaning | Constraints / default |
|---|---|---|
| `investigation_id` | Investigation id. | required; default: None |
| `--transcripts` | Sensitive local derived records, not evidence; default: DATABASE.investigations. Analyst controls retention/deletion. | default: None |
| `--json` | Json. | arity: 0; default: False |
| `--explain` | Include step-by-step transcript data | arity: 0; default: False |



### investigation history replay

```text
usage: investigation history replay [--transcripts TRANSCRIPTS] [--json]
                                    [--explain] [--no-semantic]
                                    [--semantic-index SEMANTIC_INDEX]
                                    [--embedding-model EMBEDDING_MODEL]
                                    [--force]
                                    [--page | --output FILE | --append FILE]
                                    investigation_id
```



| Argument / option | Meaning | Constraints / default |
|---|---|---|
| `investigation_id` | Investigation id. | required; default: None |
| `--transcripts` | Sensitive local derived records, not evidence; default: DATABASE.investigations. Analyst controls retention/deletion. | default: None |
| `--json` | Json. | arity: 0; default: False |
| `--explain` | Include step-by-step transcript data | arity: 0; default: False |
| `--no-semantic` | No semantic. | arity: 0; default: False |
| `--semantic-index` | Semantic index. | default: None |
| `--embedding-model` | Embedding model. | default: None |
| `--no-color` | No color. | arity: 0 |
| `--force` | Permit replacing an existing derived output file without confirmation | arity: 0 |
| `--page` | Review output with the internal pager (Up/Down, PgUp/PgDn, Home/End, Q) | arity: 0 |
| `--output` | Write a derived UTF-8 file; existing files require confirmation or --force |  |
| `--append` | Append rendered output to a derived UTF-8 file |  |



### investigation start

```text
usage: investigation start [--json]
```

Guided briefing, assessment and separately authorized AI investigation

| Argument / option | Meaning | Constraints / default |
|---|---|---|
| `--json` | Structured result; prompts remain explicit | arity: 0; default: False |



### investigation assess

```text
usage: investigation assess [--json] [--start START] [--end END]
```

Plan and approve a new deterministic assessment

| Argument / option | Meaning | Constraints / default |
|---|---|---|
| `--json` | Structured result; prompts remain explicit | arity: 0; default: False |
| `--start` | Start. | default: None |
| `--end` | End. | default: None |



### investigation list

```text
usage: investigation list [--json]
```

List saved assessments

| Argument / option | Meaning | Constraints / default |
|---|---|---|
| `--json` | Structured result; prompts remain explicit | arity: 0; default: False |



### investigation show

```text
usage: investigation show [--json] [assessment]
```

Review a saved assessment

| Argument / option | Meaning | Constraints / default |
|---|---|---|
| `--json` | Structured result; prompts remain explicit | arity: 0; default: False |
| `assessment` | Assessment. | arity: ?; default: 'latest' |



### investigation reauthorize

```text
usage: investigation reauthorize [--json] [assessment]
```

Reauthorize an assessment in a NEW read view; not continuation

| Argument / option | Meaning | Constraints / default |
|---|---|---|
| `--json` | Structured result; prompts remain explicit | arity: 0; default: False |
| `assessment` | Assessment. | arity: ?; default: 'latest' |



### investigation run

```text
usage: investigation run [--json] [--question QUESTION] [assessment]
```

Review a saved assessment scope and authorize investigation stages

| Argument / option | Meaning | Constraints / default |
|---|---|---|
| `--json` | Structured result; prompts remain explicit | arity: 0; default: False |
| `assessment` | Assessment. | arity: ?; default: 'latest' |
| `--question` | Investigation question; otherwise prompted | default: None |



### investigation findings

```text
usage: investigation findings
                              {create,select,list,show,register,accept,reject,supersede,history}
                              ...
```

Findings

| Argument / option | Meaning | Constraints / default |
|---|---|---|



### investigation findings create

```text
usage: investigation findings create --workspace WORKSPACE [--json]
                                     --transcripts TRANSCRIPTS --run RUN
                                     --actor ACTOR
```



| Argument / option | Meaning | Constraints / default |
|---|---|---|
| `--workspace` | Explicit .findings directory; never silently selected | required; default: None |
| `--json` | Json. | arity: 0; default: False |
| `--transcripts` | Transcripts. | required; default: None |
| `--run` | Run. | required; default: None |
| `--actor` | Locally asserted analyst identity | required; default: None |



### investigation findings select

```text
usage: investigation findings select --workspace WORKSPACE [--json]
```



| Argument / option | Meaning | Constraints / default |
|---|---|---|
| `--workspace` | Explicit .findings directory; never silently selected | required; default: None |
| `--json` | Json. | arity: 0; default: False |



### investigation findings list

```text
usage: investigation findings list --workspace WORKSPACE [--json]
```



| Argument / option | Meaning | Constraints / default |
|---|---|---|
| `--workspace` | Explicit .findings directory; never silently selected | required; default: None |
| `--json` | Json. | arity: 0; default: False |



### investigation findings show

```text
usage: investigation findings show --workspace WORKSPACE [--json] finding_id
```



| Argument / option | Meaning | Constraints / default |
|---|---|---|
| `--workspace` | Explicit .findings directory; never silently selected | required; default: None |
| `--json` | Json. | arity: 0; default: False |
| `finding_id` | Finding id. | required; default: None |



### investigation findings register

```text
usage: investigation findings register --workspace WORKSPACE [--json] --actor
                                       ACTOR --workspace-id WORKSPACE_ID
                                       --revision REVISION --statement
                                       STATEMENT --support SUPPORT
                                       [--contrary CONTRARY]
                                       [--kind {original_observation,deterministic_interpretation,deterministic_relationship,analyst_hypothesis}]
```



| Argument / option | Meaning | Constraints / default |
|---|---|---|
| `--workspace` | Explicit .findings directory; never silently selected | required; default: None |
| `--json` | Json. | arity: 0; default: False |
| `--actor` | Locally asserted analyst identity | required; default: None |
| `--workspace-id` | UUID from explicit workspace review | required; default: None |
| `--revision` | Expected current workspace revision | required; default: None; type: int |
| `--statement` | Statement. | required; default: None |
| `--support` | Support. | required; default: None; repeatable |
| `--contrary` | Contrary. | default: []; repeatable |
| `--kind` | Kind. | choices: original_observation, deterministic_interpretation, deterministic_relationship, analyst_hypothesis; default: 'analyst_hypothesis' |



### investigation findings accept

```text
usage: investigation findings accept --workspace WORKSPACE [--json] --actor
                                     ACTOR --workspace-id WORKSPACE_ID
                                     --revision REVISION --rationale RATIONALE
                                     finding_id
```



| Argument / option | Meaning | Constraints / default |
|---|---|---|
| `--workspace` | Explicit .findings directory; never silently selected | required; default: None |
| `--json` | Json. | arity: 0; default: False |
| `--actor` | Locally asserted analyst identity | required; default: None |
| `--workspace-id` | UUID from explicit workspace review | required; default: None |
| `--revision` | Expected current workspace revision | required; default: None; type: int |
| `finding_id` | Finding id. | required; default: None |
| `--rationale` | Rationale. | required; default: None |



### investigation findings reject

```text
usage: investigation findings reject --workspace WORKSPACE [--json] --actor
                                     ACTOR --workspace-id WORKSPACE_ID
                                     --revision REVISION --rationale RATIONALE
                                     finding_id
```



| Argument / option | Meaning | Constraints / default |
|---|---|---|
| `--workspace` | Explicit .findings directory; never silently selected | required; default: None |
| `--json` | Json. | arity: 0; default: False |
| `--actor` | Locally asserted analyst identity | required; default: None |
| `--workspace-id` | UUID from explicit workspace review | required; default: None |
| `--revision` | Expected current workspace revision | required; default: None; type: int |
| `finding_id` | Finding id. | required; default: None |
| `--rationale` | Rationale. | required; default: None |



### investigation findings supersede

```text
usage: investigation findings supersede --workspace WORKSPACE [--json] --actor
                                        ACTOR --workspace-id WORKSPACE_ID
                                        --revision REVISION --rationale
                                        RATIONALE --statement STATEMENT
                                        --support SUPPORT
                                        [--contrary CONTRARY]
                                        finding_id
```



| Argument / option | Meaning | Constraints / default |
|---|---|---|
| `--workspace` | Explicit .findings directory; never silently selected | required; default: None |
| `--json` | Json. | arity: 0; default: False |
| `--actor` | Locally asserted analyst identity | required; default: None |
| `--workspace-id` | UUID from explicit workspace review | required; default: None |
| `--revision` | Expected current workspace revision | required; default: None; type: int |
| `finding_id` | Finding id. | required; default: None |
| `--rationale` | Rationale. | required; default: None |
| `--statement` | Statement. | required; default: None |
| `--support` | Support. | required; default: None; repeatable |
| `--contrary` | Contrary. | default: []; repeatable |



### investigation findings history

```text
usage: investigation findings history --workspace WORKSPACE [--json]
```



| Argument / option | Meaning | Constraints / default |
|---|---|---|
| `--workspace` | Explicit .findings directory; never silently selected | required; default: None |
| `--json` | Json. | arity: 0; default: False |



### investigation reason

```text
usage: investigation reason [--issue ISSUE] [--exploratory] [--cross-artifact]
                            [--question QUESTION] [--execute] [--json]
                            [--findings-workspace FINDINGS_WORKSPACE]
                            [--findings-actor FINDINGS_ACTOR]
                            root run_id
```

Advanced recorded D2 preview / explicitly authorized execution and optional capture

| Argument / option | Meaning | Constraints / default |
|---|---|---|
| `root` | Root. | required; default: None |
| `run_id` | Run id. | required; default: None |
| `--issue` | Issue. | default: None |
| `--exploratory` | Exploratory. | arity: 0; default: False |
| `--cross-artifact` | Use the separate 16384-byte policy over saved authorized evidence | arity: 0; default: False |
| `--question` | Analyst question for --cross-artifact | default: None |
| `--execute` | Ask to authorize one cloud request; no automatic approval | arity: 0; default: False |
| `--json` | Json. | arity: 0; default: False |
| `--findings-workspace` | Existing source-bound findings directory; saving requires a separate choice after execution | default: None |
| `--findings-actor` | Locally asserted actor for optional capture; not authenticated identity | default: None |



### evidence

```text
usage: evidence {export,search,timeline,around,show,ingest,semantic,source}
                ...
```

Ingest, find, inspect and export evidence

| Argument / option | Meaning | Constraints / default |
|---|---|---|



### evidence export

```text
usage: evidence export [--force] [{browser,evtx,mft,prefetch,registry,all}]
```

Usage:
  evidence export <type> [--force]

Types: browser, evtx, mft, prefetch, registry, all

Examples: evidence export browser; evidence export evtx; evidence export mft; evidence export prefetch; evidence export registry; evidence export all
Fixed destination: <case database directory>/dump/<type>.csv
Existing files require --force. Empty categories are skipped.
CSV files are derived analyst output, not evidence.

| Argument / option | Meaning | Constraints / default |
|---|---|---|
| `dump_type` | Dump type. | choices: browser, evtx, mft, prefetch, registry, all; arity: ?; default: None |
| `--force` | Replace requested derived CSV files | arity: 0; default: False |
| `--no-color` | No color. | arity: 0; default: False |

Read-only examination by default; derived output files and activity records may be written. Coverage limitations remain significant.

### evidence search

```text
usage: evidence search [--user USER] [--ip IP] [--hostname HOSTNAME]
                       [--start START] [--end END]
                       [--process PROCESS | --process-contains PROCESS]
                       [--ids] [--evtx-text EVTX_TEXT]
                       [--evtx-match {exact,contains}]
                       [--evtx-after EVTX_AFTER] [--event-id EVENT_ID]
                       [--kind {logons,failed-logons,processes,powershell,scheduled-tasks,services,account-changes}]
                       [--limit LIMIT] [--offset OFFSET] [--raw]
                       [--artifact {evtx,mft,prefetch,registry,browser}]
                       [--path PATH] [--url URL | --url-contains URL_CONTAINS]
                       [--title TITLE | --title-contains TITLE_CONTAINS]
                       [--download-path DOWNLOAD_PATH | --download-path-contains DOWNLOAD_PATH_CONTAINS]
                       [--browser {chrome,edge}] [--profile PROFILE]
                       [--browser-kind {visit,download}] [--json]
                       [--key KEY | --key-contains KEY_CONTAINS]
                       [--value-name VALUE_NAME | --value-name-contains VALUE_NAME_CONTAINS]
                       [--source SOURCE] [--force]
                       [--page | --output FILE | --append FILE]
```



| Argument / option | Meaning | Constraints / default |
|---|---|---|
| `--user` | User. | default: None |
| `--ip` | Ip. | default: None |
| `--hostname` | Hostname. | default: None |
| `--start` | Start. | default: None |
| `--end` | End. | default: None |
| `--process` | Exact executable name, case-insensitive; .exe may be omitted for a bare name. Explicit paths remain exact. | default: None |
| `--process-contains` | Case-insensitive literal substring of the executable basename; no wildcards | default: None |
| `--ids` | Include full copyable evidence IDs, numbered to match table rows; display paths may be shortened. Use evidence show for details, --json for the existing structured projection, --raw for available raw payloads. | arity: 0; default: False |
| `--evtx-text` | Explicit literal, case-sensitive EVTX field search; requires --artifact evtx and a paired time window <=24 hours; bounded coverage, no raw/offset | default: None |
| `--evtx-match` | Whole-value exact or literal substring match; default contains | choices: exact, contains; default: None |
| `--evtx-after` | Copy the continuation cursor; retain the same filters and unchanged case contents | default: None |
| `--event-id` | Event id. | default: None; type: int |
| `--kind` | Kind. | choices: logons, failed-logons, processes, powershell, scheduled-tasks, services, account-changes; default: None |
| `--limit` | Maximum results (default: 20) | default: 20; type: int |
| `--offset` | Offset. | default: 0; type: int |
| `--raw` | Include original XML or available artifact bytes/details | arity: 0; default: False |
| `--artifact` | Artifact. | choices: evtx, mft, prefetch, registry, browser; default: None |
| `--path` | Path. | default: None |
| `--url` | Exact browser field match | default: None |
| `--url-contains` | Literal browser field substring; no wildcards | default: None |
| `--title` | Exact browser field match | default: None |
| `--title-contains` | Literal browser field substring; no wildcards | default: None |
| `--download-path` | Exact browser field match | default: None |
| `--download-path-contains` | Literal browser field substring; no wildcards | default: None |
| `--browser` | Browser. | choices: chrome, edge; default: None |
| `--profile` | Profile. | default: None |
| `--browser-kind` | Browser evidence subtype (one record per visit or download) | choices: visit, download; default: None |
| `--json` | Json. | arity: 0; default: False |
| `--key` | Registry key path: exact literal match (SQLite NOCASE); includes its values; no filesystem normalization | default: None |
| `--key-contains` | Registry key path: literal substring (SQLite NOCASE); no wildcards; includes matching keys and their values | default: None |
| `--value-name` | Registry value name: exact raw or decoded UserAssist name (SQLite NOCASE) | default: None |
| `--value-name-contains` | Registry value name: literal substring of raw or decoded UserAssist name (SQLite NOCASE); no wildcards | default: None |
| `--source` | Filter Locard source membership, not hostname identity | default: None |
| `--no-color` | No color. | arity: 0 |
| `--force` | Permit replacing an existing derived output file without confirmation | arity: 0 |
| `--page` | Review output with the internal pager (Up/Down, PgUp/PgDn, Home/End, Q) | arity: 0 |
| `--output` | Write a derived UTF-8 file; existing files require confirmation or --force |  |
| `--append` | Append rendered output to a derived UTF-8 file |  |

Read-only examination by default; derived output files and activity records may be written. Coverage limitations remain significant.

### evidence timeline

```text
usage: evidence timeline [--around AROUND] [--start START] [--end END]
                         [--user USER] [--process PROCESS] [--ip IP]
                         [--hostname HOSTNAME] [--artifact-type ARTIFACT_TYPE]
                         [--event-id EVENT_ID] [--minutes MINUTES]
                         [--limit LIMIT] [--offset OFFSET] [--raw]
                         [--json | --text]
                         [--artifact {evtx,mft,prefetch,registry,browser}]
                         [--path PATH] [--force]
                         [--page | --output FILE | --append FILE]
                         [timestamp]
```



| Argument / option | Meaning | Constraints / default |
|---|---|---|
| `timestamp` | Anchor time as ISO 8601 with Z or an explicit UTC offset, e.g. 2026-06-29T19:08:00Z | arity: ?; default: None |
| `--around` | Anchor time as ISO 8601 with Z or an explicit UTC offset, e.g. 2026-06-29T19:08:00Z | default: None |
| `--start` | Start time as ISO 8601 with Z or an explicit UTC offset, e.g. 2026-06-29T19:07:30Z | default: None |
| `--end` | End time as ISO 8601 with Z or an explicit UTC offset, e.g. 2026-06-29T19:08:30Z | default: None |
| `--user` | User. | default: None |
| `--process` | Process. | default: None |
| `--ip` | Ip. | default: None |
| `--hostname` | Hostname. | default: None |
| `--artifact-type` | Artifact type. | default: None |
| `--event-id` | Event id. | default: None; type: int |
| `--minutes` | Minutes. | default: 5; type: int |
| `--limit` | Maximum results (default: 100) | default: 100; type: int |
| `--offset` | Offset. | default: 0; type: int |
| `--raw` | Include original XML or available artifact bytes/details | arity: 0; default: False |
| `--json` | JSON output (default) | arity: 0; default: False |
| `--text` | Compact readable output | arity: 0; default: False |
| `--artifact` | Artifact. | choices: evtx, mft, prefetch, registry, browser; default: None |
| `--path` | Path. | default: None |
| `--no-color` | No color. | arity: 0 |
| `--force` | Permit replacing an existing derived output file without confirmation | arity: 0 |
| `--page` | Review output with the internal pager (Up/Down, PgUp/PgDn, Home/End, Q) | arity: 0 |
| `--output` | Write a derived UTF-8 file; existing files require confirmation or --force |  |
| `--append` | Append rendered output to a derived UTF-8 file |  |

Read-only examination by default; derived output files and activity records may be written. Coverage limitations remain significant.

### evidence around

```text
usage: evidence around [--seconds SECONDS] [--direction {before,after,around}]
                       [--limit LIMIT] [--offset OFFSET] [--raw] [--ids]
                       [--json | --text] [--timestamp-slot TIMESTAMP_SLOT]
                       [--force] [--page | --output FILE | --append FILE]
                       evidence_id
```

Compact text rounds timestamps and exact deltas to milliseconds (nearest, ties away from zero). JSON/raw and --ids retain full precision. Temporal proximity is not causation; timestamp meanings differ by artifact.

| Argument / option | Meaning | Constraints / default |
|---|---|---|
| `evidence_id` | Evidence id. | required; default: None |
| `--seconds` | Seconds. | default: 120; type: int |
| `--direction` | Direction. | choices: before, after, around; default: 'around' |
| `--limit` | Limit. | default: 100; type: int |
| `--offset` | Offset. | default: 0; type: int |
| `--raw` | Raw. | arity: 0; default: False |
| `--ids` | Include full evidence/source IDs, timestamp slots and original timestamp precision in --text output | arity: 0; default: False |
| `--json` | JSON output (default) | arity: 0; default: False |
| `--text` | Compact readable output | arity: 0; default: False |
| `--timestamp-slot` | Timestamp slot. | default: None |
| `--no-color` | No color. | arity: 0 |
| `--force` | Permit replacing an existing derived output file without confirmation | arity: 0 |
| `--page` | Review output with the internal pager (Up/Down, PgUp/PgDn, Home/End, Q) | arity: 0 |
| `--output` | Write a derived UTF-8 file; existing files require confirmation or --force |  |
| `--append` | Append rendered output to a derived UTF-8 file |  |

Read-only examination by default; derived output files and activity records may be written. Coverage limitations remain significant.

### evidence show

```text
usage: evidence show [--raw] [--json] [--force]
                     [--page | --output FILE | --append FILE]
                     evidence_id
```

Human summary with populated timestamps and bounded references. --json preserves the structured projection; --raw includes available XML/artifact bytes. Both retain existing 100-object/reference/value-ID bounds and truncation flags.

| Argument / option | Meaning | Constraints / default |
|---|---|---|
| `evidence_id` | Evidence id. | required; default: None |
| `--raw` | Raw. | arity: 0; default: False |
| `--json` | Json. | arity: 0; default: False |
| `--no-color` | No color. | arity: 0 |
| `--force` | Permit replacing an existing derived output file without confirmation | arity: 0 |
| `--page` | Review output with the internal pager (Up/Down, PgUp/PgDn, Home/End, Q) | arity: 0 |
| `--output` | Write a derived UTF-8 file; existing files require confirmation or --force |  |
| `--append` | Append rendered output to a derived UTF-8 file |  |

Read-only examination by default; derived output files and activity records may be written. Coverage limitations remain significant.

### evidence ingest

```text
usage: evidence ingest {mft,prefetch,registry,all,evtx,browser,wizard} ...
```

Ingest

| Argument / option | Meaning | Constraints / default |
|---|---|---|



### evidence ingest mft

```text
usage: evidence ingest mft [--hostname HOSTNAME] [--user USER]
                           [--volume-root VOLUME_ROOT]
                           [--parser-timeout PARSER_TIMEOUT]
                           [--record-size RECORD_SIZE] [--json]
                           [--source SOURCE] [--force]
                           [--page | --output FILE | --append FILE]
                           path
```



| Argument / option | Meaning | Constraints / default |
|---|---|---|
| `path` | Path. | required; default: None |
| `--hostname` | Hostname. | default: None |
| `--user` | User. | default: None |
| `--volume-root` | Volume root. | default: None |
| `--parser-timeout` | EVTX: seconds without parser advancement; other artifacts: wall-clock limit | default: 300; type: int |
| `--record-size` | Record size. | default: None; type: int |
| `--json` | Json. | arity: 0; default: False |
| `--source` | Reuse this source ID; omitted in scripts creates a NEW automatic source for this invocation, never inferred or reused | default: None |
| `--no-color` | No color. | arity: 0 |
| `--force` | Permit replacing an existing derived output file without confirmation | arity: 0 |
| `--page` | Review output with the internal pager (Up/Down, PgUp/PgDn, Home/End, Q) | arity: 0 |
| `--output` | Write a derived UTF-8 file; existing files require confirmation or --force |  |
| `--append` | Append rendered output to a derived UTF-8 file |  |

Mutates the selected case through the existing ingestion service; source evidence is read-only. Review partial outcomes.

### evidence ingest prefetch

```text
usage: evidence ingest prefetch [--hostname HOSTNAME] [--user USER]
                                [--volume-root VOLUME_ROOT]
                                [--parser-timeout PARSER_TIMEOUT] [--json]
                                [--source SOURCE] [--force]
                                [--page | --output FILE | --append FILE]
                                path
```



| Argument / option | Meaning | Constraints / default |
|---|---|---|
| `path` | Path. | required; default: None |
| `--hostname` | Hostname. | default: None |
| `--user` | User. | default: None |
| `--volume-root` | Volume root. | default: None |
| `--parser-timeout` | EVTX: seconds without parser advancement; other artifacts: wall-clock limit | default: 300; type: int |
| `--json` | Json. | arity: 0; default: False |
| `--source` | Reuse this source ID; omitted in scripts creates a NEW automatic source for this invocation, never inferred or reused | default: None |
| `--no-color` | No color. | arity: 0 |
| `--force` | Permit replacing an existing derived output file without confirmation | arity: 0 |
| `--page` | Review output with the internal pager (Up/Down, PgUp/PgDn, Home/End, Q) | arity: 0 |
| `--output` | Write a derived UTF-8 file; existing files require confirmation or --force |  |
| `--append` | Append rendered output to a derived UTF-8 file |  |

Mutates the selected case through the existing ingestion service; source evidence is read-only. Review partial outcomes.

### evidence ingest registry

```text
usage: evidence ingest registry [--hostname HOSTNAME] [--user USER]
                                [--volume-root VOLUME_ROOT]
                                [--parser-timeout PARSER_TIMEOUT] [--json]
                                [--source SOURCE] [--force]
                                [--page | --output FILE | --append FILE]
                                path
```



| Argument / option | Meaning | Constraints / default |
|---|---|---|
| `path` | Path. | required; default: None |
| `--hostname` | Hostname. | default: None |
| `--user` | User. | default: None |
| `--volume-root` | Volume root. | default: None |
| `--parser-timeout` | EVTX: seconds without parser advancement; other artifacts: wall-clock limit | default: 300; type: int |
| `--json` | Json. | arity: 0; default: False |
| `--source` | Reuse this source ID; omitted in scripts creates a NEW automatic source for this invocation, never inferred or reused | default: None |
| `--no-color` | No color. | arity: 0 |
| `--force` | Permit replacing an existing derived output file without confirmation | arity: 0 |
| `--page` | Review output with the internal pager (Up/Down, PgUp/PgDn, Home/End, Q) | arity: 0 |
| `--output` | Write a derived UTF-8 file; existing files require confirmation or --force |  |
| `--append` | Append rendered output to a derived UTF-8 file |  |

Mutates the selected case through the existing ingestion service; source evidence is read-only. Review partial outcomes.

### evidence ingest all

```text
usage: evidence ingest all [--hostname HOSTNAME] [--user USER]
                           [--volume-root VOLUME_ROOT]
                           [--parser-timeout PARSER_TIMEOUT]
                           [--evtx-hard-timeout EVTX_HARD_TIMEOUT]
                           [--record-size RECORD_SIZE] [--json]
                           [--source SOURCE] [--force]
                           [--page | --output FILE | --append FILE]
                           path
```



| Argument / option | Meaning | Constraints / default |
|---|---|---|
| `path` | Path. | required; default: None |
| `--hostname` | Hostname. | default: None |
| `--user` | User. | default: None |
| `--volume-root` | Volume root. | default: None |
| `--parser-timeout` | EVTX: seconds without parser advancement; other artifacts: wall-clock limit | default: 300; type: int |
| `--evtx-hard-timeout` | EVTX emergency absolute ceiling in seconds (default: 21600) | default: 21600; type: int |
| `--record-size` | Record size. | default: None; type: int |
| `--json` | Json. | arity: 0; default: False |
| `--source` | Reuse this source ID; omitted in scripts creates a NEW automatic source for this invocation, never inferred or reused | default: None |
| `--no-color` | No color. | arity: 0 |
| `--force` | Permit replacing an existing derived output file without confirmation | arity: 0 |
| `--page` | Review output with the internal pager (Up/Down, PgUp/PgDn, Home/End, Q) | arity: 0 |
| `--output` | Write a derived UTF-8 file; existing files require confirmation or --force |  |
| `--append` | Append rendered output to a derived UTF-8 file |  |

Mutates the selected case through the existing ingestion service; source evidence is read-only. Review partial outcomes.

### evidence ingest evtx

```text
usage: evidence ingest evtx [--hostname HOSTNAME] [--user USER]
                            [--volume-root VOLUME_ROOT]
                            [--parser-timeout PARSER_TIMEOUT]
                            [--evtx-hard-timeout EVTX_HARD_TIMEOUT] [--json]
                            [--source SOURCE] [--force]
                            [--page | --output FILE | --append FILE]
                            path
```



| Argument / option | Meaning | Constraints / default |
|---|---|---|
| `path` | Path. | required; default: None |
| `--hostname` | Hostname. | default: None |
| `--user` | User. | default: None |
| `--volume-root` | Volume root. | default: None |
| `--parser-timeout` | EVTX: seconds without parser advancement; other artifacts: wall-clock limit | default: 300; type: int |
| `--evtx-hard-timeout` | EVTX emergency absolute ceiling in seconds (default: 21600) | default: 21600; type: int |
| `--json` | Json. | arity: 0; default: False |
| `--source` | Reuse this source ID; omitted in scripts creates a NEW automatic source for this invocation, never inferred or reused | default: None |
| `--no-color` | No color. | arity: 0 |
| `--force` | Permit replacing an existing derived output file without confirmation | arity: 0 |
| `--page` | Review output with the internal pager (Up/Down, PgUp/PgDn, Home/End, Q) | arity: 0 |
| `--output` | Write a derived UTF-8 file; existing files require confirmation or --force |  |
| `--append` | Append rendered output to a derived UTF-8 file |  |

Mutates the selected case through the existing ingestion service; source evidence is read-only. Review partial outcomes.

### evidence ingest browser

```text
usage: evidence ingest browser --browser {chrome,edge} --profile PROFILE
                               [--hostname HOSTNAME] [--user USER]
                               [--volume-root VOLUME_ROOT]
                               [--parser-timeout PARSER_TIMEOUT] [--json]
                               [--source SOURCE] [--force]
                               [--page | --output FILE | --append FILE]
                               path
```



| Argument / option | Meaning | Constraints / default |
|---|---|---|
| `path` | Path. | required; default: None |
| `--browser` | Explicit browser product; never inferred | required; choices: chrome, edge; default: None |
| `--profile` | Explicit browser profile; separate from Windows user | required; default: None |
| `--hostname` | Hostname. | default: None |
| `--user` | User. | default: None |
| `--volume-root` | Volume root. | default: None |
| `--parser-timeout` | EVTX: seconds without parser advancement; other artifacts: wall-clock limit | default: 300; type: int |
| `--json` | Json. | arity: 0; default: False |
| `--source` | Reuse this source ID; omitted in scripts creates a NEW automatic source for this invocation, never inferred or reused | default: None |
| `--no-color` | No color. | arity: 0 |
| `--force` | Permit replacing an existing derived output file without confirmation | arity: 0 |
| `--page` | Review output with the internal pager (Up/Down, PgUp/PgDn, Home/End, Q) | arity: 0 |
| `--output` | Write a derived UTF-8 file; existing files require confirmation or --force |  |
| `--append` | Append rendered output to a derived UTF-8 file |  |

Mutates the selected case through the existing ingestion service; source evidence is read-only. Review partial outcomes.

### evidence ingest wizard

```text
usage: evidence ingest wizard
```

Guided evidence selection; confirmation required

| Argument / option | Meaning | Constraints / default |
|---|---|---|



### evidence semantic

```text
usage: evidence semantic [--force] [--page | --output FILE | --append FILE]
                         {search,status} ...
```



| Argument / option | Meaning | Constraints / default |
|---|---|---|
| `--no-color` | No color. | arity: 0 |
| `--force` | Permit replacing an existing derived output file without confirmation | arity: 0 |
| `--page` | Review output with the internal pager (Up/Down, PgUp/PgDn, Home/End, Q) | arity: 0 |
| `--output` | Write a derived UTF-8 file; existing files require confirmation or --force |  |
| `--append` | Append rendered output to a derived UTF-8 file |  |

Read-only examination by default; derived output files and activity records may be written. Coverage limitations remain significant.

### evidence semantic search

```text
usage: evidence semantic search [--json | --text] [--model-path MODEL_PATH]
                                [--index INDEX] [--limit LIMIT] [--show-weak]
                                [--artifact ARTIFACT] [--start START]
                                [--end END] [--hostname HOSTNAME]
                                [--user USER] [--path PATH] [--force]
                                [--page | --output FILE | --append FILE]
                                question
```

Search current case evidence by semantic similarity

| Argument / option | Meaning | Constraints / default |
|---|---|---|
| `--json` | Full structured metadata, without terminal styling | arity: 0; default: False |
| `--text` | Concise human-readable output | arity: 0; default: False |
| `--model-path` | Advanced local model-directory override; does not change other commands | default: None |
| `--index` | Advanced case-specific derived index directory override | default: None |
| `question` | Question. | required; default: None |
| `--limit` | Limit. | default: None; type: int |
| `--show-weak` | Show candidates below the human display cutoff; JSON always retains all results | arity: 0; default: False |
| `--artifact` | Artifact. | default: None |
| `--start` | Start. | default: None |
| `--end` | End. | default: None |
| `--hostname` | Hostname. | default: None |
| `--user` | User. | default: None |
| `--path` | Path. | default: None |
| `--no-color` | No color. | arity: 0 |
| `--force` | Permit replacing an existing derived output file without confirmation | arity: 0 |
| `--page` | Review output with the internal pager (Up/Down, PgUp/PgDn, Home/End, Q) | arity: 0 |
| `--output` | Write a derived UTF-8 file; existing files require confirmation or --force |  |
| `--append` | Append rendered output to a derived UTF-8 file |  |



### evidence semantic status

```text
usage: evidence semantic status [--json | --text] [--model-path MODEL_PATH]
                                [--index INDEX] [--force]
                                [--page | --output FILE | --append FILE]
```

Show semantic runtime, model, and current-case index status

| Argument / option | Meaning | Constraints / default |
|---|---|---|
| `--json` | Full structured metadata, without terminal styling | arity: 0; default: False |
| `--text` | Concise human-readable output | arity: 0; default: False |
| `--model-path` | Advanced local model-directory override; does not change other commands | default: None |
| `--index` | Advanced case-specific derived index directory override | default: None |
| `--no-color` | No color. | arity: 0 |
| `--force` | Permit replacing an existing derived output file without confirmation | arity: 0 |
| `--page` | Review output with the internal pager (Up/Down, PgUp/PgDn, Home/End, Q) | arity: 0 |
| `--output` | Write a derived UTF-8 file; existing files require confirmation or --force |  |
| `--append` | Append rendered output to a derived UTF-8 file |  |



### evidence source

```text
usage: evidence source [--force] [--page | --output FILE | --append FILE]
                       {list,show,create,update,assign} ...
```



| Argument / option | Meaning | Constraints / default |
|---|---|---|
| `--no-color` | No color. | arity: 0 |
| `--force` | Permit replacing an existing derived output file without confirmation | arity: 0 |
| `--page` | Review output with the internal pager (Up/Down, PgUp/PgDn, Home/End, Q) | arity: 0 |
| `--output` | Write a derived UTF-8 file; existing files require confirmation or --force |  |
| `--append` | Append rendered output to a derived UTF-8 file |  |

Read-only list/show; create/update/assign mutate analyst source metadata and retain existing confirmations.

### evidence source list

```text
usage: evidence source list [--json] [--limit LIMIT] [--offset OFFSET] [--ids]
                            [--force] [--page | --output FILE | --append FILE]
```

Display abbreviations (...) are not command IDs; use --ids for full copyable IDs or --json for complete values.

| Argument / option | Meaning | Constraints / default |
|---|---|---|
| `--json` | Json. | arity: 0; default: False |
| `--limit` | Limit. | default: 100; type: int |
| `--offset` | Offset. | default: 0; type: int |
| `--ids` | Show full copyable source IDs below the compact table; --json also retains complete values | arity: 0; default: False |
| `--no-color` | No color. | arity: 0 |
| `--force` | Permit replacing an existing derived output file without confirmation | arity: 0 |
| `--page` | Review output with the internal pager (Up/Down, PgUp/PgDn, Home/End, Q) | arity: 0 |
| `--output` | Write a derived UTF-8 file; existing files require confirmation or --force |  |
| `--append` | Append rendered output to a derived UTF-8 file |  |



### evidence source show

```text
usage: evidence source show [--json] [--limit LIMIT] [--offset OFFSET]
                            [--details] [--force]
                            [--page | --output FILE | --append FILE]
                            source_id
```



| Argument / option | Meaning | Constraints / default |
|---|---|---|
| `--json` | Json. | arity: 0; default: False |
| `source_id` | Source id. | required; default: None |
| `--limit` | Limit. | default: 100; type: int |
| `--offset` | Offset. | default: 0; type: int |
| `--details` | Existing structured provenance detail, paginated with --limit/--offset; --json is equivalent | arity: 0; default: False |
| `--no-color` | No color. | arity: 0 |
| `--force` | Permit replacing an existing derived output file without confirmation | arity: 0 |
| `--page` | Review output with the internal pager (Up/Down, PgUp/PgDn, Home/End, Q) | arity: 0 |
| `--output` | Write a derived UTF-8 file; existing files require confirmation or --force |  |
| `--append` | Append rendered output to a derived UTF-8 file |  |



### evidence source create

```text
usage: evidence source create [--json] [--name NAME] [--hostname HOSTNAME]
                              [--user USER] [--volume-root VOLUME_ROOT]
                              [--force]
                              [--page | --output FILE | --append FILE]
```



| Argument / option | Meaning | Constraints / default |
|---|---|---|
| `--json` | Json. | arity: 0; default: False |
| `--name` | Name. | default: None |
| `--hostname` | Hostname. | default: None |
| `--user` | User. | default: None |
| `--volume-root` | Volume root. | default: None |
| `--no-color` | No color. | arity: 0 |
| `--force` | Permit replacing an existing derived output file without confirmation | arity: 0 |
| `--page` | Review output with the internal pager (Up/Down, PgUp/PgDn, Home/End, Q) | arity: 0 |
| `--output` | Write a derived UTF-8 file; existing files require confirmation or --force |  |
| `--append` | Append rendered output to a derived UTF-8 file |  |



### evidence source update

```text
usage: evidence source update [--json] [--name NAME] [--hostname HOSTNAME]
                              [--user USER] [--volume-root VOLUME_ROOT]
                              [--yes] [--force]
                              [--page | --output FILE | --append FILE]
                              source_id
```



| Argument / option | Meaning | Constraints / default |
|---|---|---|
| `--json` | Json. | arity: 0; default: False |
| `source_id` | Source id. | required; default: None |
| `--name` | Name. | default: None |
| `--hostname` | Hostname. | default: None |
| `--user` | User. | default: None |
| `--volume-root` | Volume root. | default: None |
| `--yes` | Apply without interactive confirmation; otherwise confirm in the shell or preview in scripts | arity: 0; default: False |
| `--no-color` | No color. | arity: 0 |
| `--force` | Permit replacing an existing derived output file without confirmation | arity: 0 |
| `--page` | Review output with the internal pager (Up/Down, PgUp/PgDn, Home/End, Q) | arity: 0 |
| `--output` | Write a derived UTF-8 file; existing files require confirmation or --force |  |
| `--append` | Append rendered output to a derived UTF-8 file |  |



### evidence source assign

```text
usage: evidence source assign [--json] [--yes] [--file-hash FILE_HASH]
                              [--path PATH]
                              [--confirmation-fingerprint CONFIRMATION_FINGERPRINT]
                              --reason REASON [--force]
                              [--page | --output FILE | --append FILE]
                              source_id
```



| Argument / option | Meaning | Constraints / default |
|---|---|---|
| `--json` | Json. | arity: 0; default: False |
| `source_id` | Source id. | required; default: None |
| `--yes` | Apply without interactive confirmation; otherwise confirm in the shell or preview in scripts | arity: 0; default: False |
| `--file-hash` | Explicit existing file SHA-256; repeat or combine with --path (deduplicated union) | default: None; repeatable |
| `--path` | Recorded absolute Windows file/directory path; repeatable, no filesystem scan or wildcards. Requires --path or --file-hash. | default: None; repeatable |
| `--confirmation-fingerprint` | Require the case fingerprint returned by a reviewed preview before applying | default: None |
| `--reason` | Reason for retrospective assignment (does not reconstruct ingestion) | required; default: None |
| `--no-color` | No color. | arity: 0 |
| `--force` | Permit replacing an existing derived output file without confirmation | arity: 0 |
| `--page` | Review output with the internal pager (Up/Down, PgUp/PgDn, Home/End, Q) | arity: 0 |
| `--output` | Write a derived UTF-8 file; existing files require confirmation or --force |  |
| `--append` | Append rendered output to a derived UTF-8 file |  |



### analyze

```text
usage: analyze {process-tree,logons,session,detections,correlate} ...
```

Model-free forensic correlation and detections

| Argument / option | Meaning | Constraints / default |
|---|---|---|



### analyze process-tree

```text
usage: analyze process-tree (--evidence EVIDENCE | --process PROCESS)
                            [--around AROUND] [--hostname HOSTNAME]
                            [--seconds SECONDS] [--pid-window PID_WINDOW]
                            [--max-nodes MAX_NODES] [--max-depth MAX_DEPTH]
                            [--json | --text] [--raw] [--force]
                            [--page | --output FILE | --append FILE]
```



| Argument / option | Meaning | Constraints / default |
|---|---|---|
| `--evidence` | Evidence. | default: None |
| `--process` | Process. | default: None |
| `--around` | Around. | default: None |
| `--hostname` | Hostname. | default: None |
| `--seconds` | Seconds. | default: 300; type: int |
| `--pid-window` | Pid window. | default: 300; type: int |
| `--max-nodes` | Max nodes. | default: 100; type: int |
| `--max-depth` | Max depth. | default: 8; type: int |
| `--json` | Structured JSON output | arity: 0; default: False |
| `--text` | Human-readable text output | arity: 0; default: False |
| `--raw` | Raw. | arity: 0; default: False |
| `--no-color` | No color. | arity: 0 |
| `--force` | Permit replacing an existing derived output file without confirmation | arity: 0 |
| `--page` | Review output with the internal pager (Up/Down, PgUp/PgDn, Home/End, Q) | arity: 0 |
| `--output` | Write a derived UTF-8 file; existing files require confirmation or --force |  |
| `--append` | Append rendered output to a derived UTF-8 file |  |

Interactive shell defaults to human text; direct CLI defaults to JSON. --raw retains diagnostic output, defaulting to JSON. Use --text for human paging; JSON paging is not supported.

### analyze logons

```text
usage: analyze logons [--user USER] [--ip IP] [--hostname HOSTNAME]
                      [--start START] [--end END] [--limit LIMIT]
                      [--offset OFFSET] [--json | --text] [--raw] [--force]
                      [--page | --output FILE | --append FILE]
```

Review Windows logon-related activity from normalized Windows Event Log evidence

| Argument / option | Meaning | Constraints / default |
|---|---|---|
| `--user` | User. | default: None |
| `--ip` | Ip. | default: None |
| `--hostname` | Hostname. | default: None |
| `--start` | Start. | default: None |
| `--end` | End. | default: None |
| `--limit` | Limit. | default: 100; type: int |
| `--offset` | Offset. | default: 0; type: int |
| `--json` | Structured JSON output | arity: 0; default: False |
| `--text` | Human-readable text output | arity: 0; default: False |
| `--raw` | Raw. | arity: 0; default: False |
| `--no-color` | No color. | arity: 0 |
| `--force` | Permit replacing an existing derived output file without confirmation | arity: 0 |
| `--page` | Review output with the internal pager (Up/Down, PgUp/PgDn, Home/End, Q) | arity: 0 |
| `--output` | Write a derived UTF-8 file; existing files require confirmation or --force |  |
| `--append` | Append rendered output to a derived UTF-8 file |  |

Interactive shell defaults to human text; direct CLI defaults to JSON. --raw retains diagnostic output, defaulting to JSON. Use --text for human paging; JSON paging is not supported.

### analyze session

```text
usage: analyze session --logon-id LOGON_ID [--hostname HOSTNAME]
                       [--around AROUND] [--evidence EVIDENCE]
                       [--max-hours MAX_HOURS] [--limit LIMIT]
                       [--json | --text] [--raw] [--force]
                       [--page | --output FILE | --append FILE]
```



| Argument / option | Meaning | Constraints / default |
|---|---|---|
| `--logon-id` | Windows authentication Logon ID, decimal or hexadecimal (for example 0x1cd8f6); not a Locard evidence ID | required; default: None |
| `--hostname` | Hostname. | default: None |
| `--around` | Around. | default: None |
| `--evidence` | Successful-logon evidence ID to disambiguate | default: None |
| `--max-hours` | Max hours. | default: 24; type: int |
| `--limit` | Limit. | default: 500; type: int |
| `--json` | Structured JSON output | arity: 0; default: False |
| `--text` | Human-readable text output | arity: 0; default: False |
| `--raw` | Raw. | arity: 0; default: False |
| `--no-color` | No color. | arity: 0 |
| `--force` | Permit replacing an existing derived output file without confirmation | arity: 0 |
| `--page` | Review output with the internal pager (Up/Down, PgUp/PgDn, Home/End, Q) | arity: 0 |
| `--output` | Write a derived UTF-8 file; existing files require confirmation or --force |  |
| `--append` | Append rendered output to a derived UTF-8 file |  |

Interactive shell defaults to human text; direct CLI defaults to JSON. --raw retains diagnostic output, defaulting to JSON. Use --text for human paging; JSON paging is not supported.

### analyze detections

```text
usage: analyze detections [--start START] [--end END] [--user USER]
                          [--hostname HOSTNAME] [--rule RULE]
                          [--severity {low,medium,high}] [--limit LIMIT]
                          [--candidate-limit CANDIDATE_LIMIT]
                          [--failure-threshold FAILURE_THRESHOLD]
                          [--failure-window FAILURE_WINDOW] [--json | --text]
                          [--raw] [--force]
                          [--page | --output FILE | --append FILE]
```



| Argument / option | Meaning | Constraints / default |
|---|---|---|
| `--start` | Start. | default: None |
| `--end` | End. | default: None |
| `--user` | User. | default: None |
| `--hostname` | Hostname. | default: None |
| `--rule` | Rule. | default: None |
| `--severity` | Severity. | choices: low, medium, high; default: None |
| `--limit` | Limit. | default: 100; type: int |
| `--candidate-limit` | Candidate limit. | default: 1000; type: int |
| `--failure-threshold` | Failure threshold. | default: 5; type: int |
| `--failure-window` | Failure window. | default: 300; type: int |
| `--json` | Structured JSON output | arity: 0; default: False |
| `--text` | Human-readable text output | arity: 0; default: False |
| `--raw` | Raw. | arity: 0; default: False |
| `--no-color` | No color. | arity: 0 |
| `--force` | Permit replacing an existing derived output file without confirmation | arity: 0 |
| `--page` | Review output with the internal pager (Up/Down, PgUp/PgDn, Home/End, Q) | arity: 0 |
| `--output` | Write a derived UTF-8 file; existing files require confirmation or --force |  |
| `--append` | Append rendered output to a derived UTF-8 file |  |

Interactive shell defaults to human text; direct CLI defaults to JSON. --raw retains diagnostic output, defaulting to JSON. Use --text for human paging; JSON paging is not supported.

### analyze correlate

```text
usage: analyze correlate [--seconds SECONDS]
                         [--candidate-limit CANDIDATE_LIMIT] [--json | --text]
                         [--raw] [--timestamp-slot TIMESTAMP_SLOT] [--force]
                         [--page | --output FILE | --append FILE]
                         evidence_id
```

Deterministic correlation around a specific evidence record identified by its canonical evidence_id. Gathers nearby and related evidence within bounded criteria; no AI required.

| Argument / option | Meaning | Constraints / default |
|---|---|---|
| `evidence_id` | Canonical evidence ID of the anchor record | required; default: None |
| `--seconds` | Time window around the anchor, in seconds (default: 120) | default: 120; type: int |
| `--candidate-limit` | Maximum candidate volume (default: 500) | default: 500; type: int |
| `--json` | Structured JSON output | arity: 0; default: False |
| `--text` | Human-readable text output | arity: 0; default: False |
| `--raw` | Raw. | arity: 0; default: False |
| `--timestamp-slot` | Select the anchor timestamp slot when multiple slots exist | default: None |
| `--no-color` | No color. | arity: 0 |
| `--force` | Permit replacing an existing derived output file without confirmation | arity: 0 |
| `--page` | Review output with the internal pager (Up/Down, PgUp/PgDn, Home/End, Q) | arity: 0 |
| `--output` | Write a derived UTF-8 file; existing files require confirmation or --force |  |
| `--append` | Append rendered output to a derived UTF-8 file |  |

Interactive shell defaults to human text; direct CLI defaults to JSON. --raw retains diagnostic output, defaulting to JSON. Use --text for human paging; JSON paging is not supported.

### case

```text
usage: case {status,open,new} ...
```

Open, create and inspect a case

| Argument / option | Meaning | Constraints / default |
|---|---|---|



### case status

```text
usage: case status [--json] [--force] [--page | --output FILE | --append FILE]
```



| Argument / option | Meaning | Constraints / default |
|---|---|---|
| `--json` | Json. | arity: 0; default: False |
| `--no-color` | No color. | arity: 0 |
| `--force` | Permit replacing an existing derived output file without confirmation | arity: 0 |
| `--page` | Review output with the internal pager (Up/Down, PgUp/PgDn, Home/End, Q) | arity: 0 |
| `--output` | Write a derived UTF-8 file; existing files require confirmation or --force |  |
| `--append` | Append rendered output to a derived UTF-8 file |  |

Read-only examination by default; derived output files and activity records may be written. Coverage limitations remain significant.

### case open

```text
usage: case open [path]
```

Interactive case open; no evidence ingestion is implied

| Argument / option | Meaning | Constraints / default |
|---|---|---|
| `path` | Path. | arity: ?; default: None |



### case new

```text
usage: case new
```

Interactive case new; no evidence ingestion is implied

| Argument / option | Meaning | Constraints / default |
|---|---|---|



### report

```text
usage: report [--force] [--page | --output FILE | --append FILE]
              {from-history,verify-history,from-case,show,verify} ...
```



| Argument / option | Meaning | Constraints / default |
|---|---|---|
| `--no-color` | No color. | arity: 0 |
| `--force` | Permit replacing an existing derived output file without confirmation | arity: 0 |
| `--page` | Review output with the internal pager (Up/Down, PgUp/PgDn, Home/End, Q) | arity: 0 |
| `--output` | Write a derived UTF-8 file; existing files require confirmation or --force |  |
| `--append` | Append rendered output to a derived UTF-8 file |  |

Derived output publication. Case and recorded-history reports retain separate grounding contracts.

### report from-history

```text
usage: report from-history --transcript-root TRANSCRIPT_ROOT --run RUN
                           [--workspace WORKSPACE]
                           [--profile {executive,technical,handover}] --output
                           OUTPUT [--protect-root PROTECT_ROOT]
```



| Argument / option | Meaning | Constraints / default |
|---|---|---|
| `--transcript-root` | Transcript root. | required; default: None |
| `--run` | Run. | required; default: None |
| `--workspace` | Optional matching .findings directory | default: None |
| `--profile` | Profile. | choices: executive, technical, handover; default: 'technical' |
| `--output` | Fresh local bundle directory | required; default: None |
| `--protect-root` | Additional evidence directory to exclude from destinations (repeatable) | default: []; repeatable |



### report verify-history

```text
usage: report verify-history [--transcript-root TRANSCRIPT_ROOT] [--run RUN]
                             [--workspace WORKSPACE]
                             directory
```



| Argument / option | Meaning | Constraints / default |
|---|---|---|
| `directory` | Directory. | required; default: None |
| `--transcript-root` | Transcript root. | default: None |
| `--run` | Run. | default: None |
| `--workspace` | Workspace. | default: None |



### report from-case

```text
usage: report from-case [--json | --text]
                        (--evidence EVIDENCE_IDS | --investigation INVESTIGATION_IDS)
                        [--transcript-root TRANSCRIPT_ROOT] --output OUTPUT
                        [--profile {technical,executive}]
                        [--redact {none,identifiers}]
                        [--include-source-locations] [--case-name CASE_NAME]
                        [--case-identifier CASE_IDENTIFIER]
                        [--analyst-name ANALYST_NAME]
                        [--organization ORGANIZATION] [--title TITLE]
                        [--scope-note SCOPE_NOTE] [--max-claims MAX_CLAIMS]
                        [--max-timeline MAX_TIMELINE] [--seconds SECONDS]
                        [--llm-narrative] [--endpoint ENDPOINT] [--force]
                        [--page | --append FILE]
```



| Argument / option | Meaning | Constraints / default |
|---|---|---|
| `--json` | Structured generation result | arity: 0; default: False |
| `--text` | Human generation result | arity: 0; default: False |
| `--evidence` | Explicit evidence ID (repeatable); not a complete investigation | default: None; repeatable |
| `--investigation` | Same-state V4 investigation ID (repeatable) | default: None; repeatable |
| `--transcript-root` | Transcript root. | default: None |
| `--output` | New report directory under an existing parent | required; default: None |
| `--profile` | Profile. | choices: technical, executive; default: 'technical' |
| `--redact` | Redact. | choices: none, identifiers; default: 'none' |
| `--include-source-locations` | Include source locations. | arity: 0; default: False |
| `--case-name` | Case name. | default: None |
| `--case-identifier` | Case identifier. | default: None |
| `--analyst-name` | Analyst name. | default: None |
| `--organization` | Organization. | default: None |
| `--title` | Title. | default: None |
| `--scope-note` | Scope note. | default: None |
| `--max-claims` | Max claims. | default: 100; type: int |
| `--max-timeline` | Max timeline. | default: 500; type: int |
| `--seconds` | Seconds. | default: 300; type: int |
| `--llm-narrative` | Optional grounded narrative composition through local MiniCPM; rejected output falls back safely | arity: 0; default: False |
| `--endpoint` | Endpoint. | default: None |
| `--no-color` | No color. | arity: 0 |
| `--force` | Permit replacing an existing derived output file without confirmation | arity: 0 |
| `--page` | Review output with the internal pager (Up/Down, PgUp/PgDn, Home/End, Q) | arity: 0 |
| `--append` | Append rendered output to a derived UTF-8 file |  |



### report show

```text
usage: report show [--force] [--page | --output FILE | --append FILE]
                   directory
```



| Argument / option | Meaning | Constraints / default |
|---|---|---|
| `directory` | Report bundle directory, not a report ID | required; default: None |
| `--no-color` | No color. | arity: 0 |
| `--force` | Permit replacing an existing derived output file without confirmation | arity: 0 |
| `--page` | Review output with the internal pager (Up/Down, PgUp/PgDn, Home/End, Q) | arity: 0 |
| `--output` | Write a derived UTF-8 file; existing files require confirmation or --force |  |
| `--append` | Append rendered output to a derived UTF-8 file |  |



### report verify

```text
usage: report verify [--case CASE] [--transcript-root TRANSCRIPT_ROOT]
                     [--force] [--page | --output FILE | --append FILE]
                     directory
```



| Argument / option | Meaning | Constraints / default |
|---|---|---|
| `directory` | Directory. | required; default: None |
| `--case` | Optional existing schema-3 case for fingerprint and grounding checks | default: None |
| `--transcript-root` | Original transcripts for investigation-report grounding | default: None |
| `--no-color` | No color. | arity: 0 |
| `--force` | Permit replacing an existing derived output file without confirmation | arity: 0 |
| `--page` | Review output with the internal pager (Up/Down, PgUp/PgDn, Home/End, Q) | arity: 0 |
| `--output` | Write a derived UTF-8 file; existing files require confirmation or --force |  |
| `--append` | Append rendered output to a derived UTF-8 file |  |



### audit

```text
usage: audit {activity,verify} ...
```

Analyst activity and integrity verification

| Argument / option | Meaning | Constraints / default |
|---|---|---|



### audit activity

```text
usage: audit activity [--limit LIMIT] [--json] [--force]
                      [--page | --output FILE | --append FILE]
```



| Argument / option | Meaning | Constraints / default |
|---|---|---|
| `--limit` | Limit. | default: 20; type: int |
| `--json` | Json. | arity: 0; default: False |
| `--no-color` | No color. | arity: 0 |
| `--force` | Permit replacing an existing derived output file without confirmation | arity: 0 |
| `--page` | Review output with the internal pager (Up/Down, PgUp/PgDn, Home/End, Q) | arity: 0 |
| `--output` | Write a derived UTF-8 file; existing files require confirmation or --force |  |
| `--append` | Append rendered output to a derived UTF-8 file |  |

Read-only examination by default; derived output files and activity records may be written. Coverage limitations remain significant.

### audit verify

```text
usage: audit verify [--json]
```

Verify the existing analyst activity chain; read-only

| Argument / option | Meaning | Constraints / default |
|---|---|---|
| `--json` | Json. | arity: 0; default: False |



### ai

```text
usage: ai {provider,status,check,configure,start,stop,logs} ...
```

Local uses llama.cpp / llama-server with a compatible user-selected GGUF model. Status distinguishes configuration readiness from runtime state. Cloud use sends bounded model context to the selected provider.

| Argument / option | Meaning | Constraints / default |
|---|---|---|

Status and Quick are provider-free; connectivity/full checks and runtime start are explicit operations.

### ai provider

```text
usage: ai provider [--json] [--model MODEL] [--acknowledge-cloud]
                   [{local,openai,anthropic,gemini,deepseek,xai}]
```



| Argument / option | Meaning | Constraints / default |
|---|---|---|
| `--json` | Json. | arity: 0; default: False |
| `provider` | Provider. | choices: local, openai, anthropic, gemini, deepseek, xai; arity: ?; default: None |
| `--model` | Explicit cloud model name, without provider prefix | default: None |
| `--acknowledge-cloud` | Explicitly acknowledge transmission to the selected cloud provider | arity: 0; default: False |



### ai status

```text
usage: ai status [--json]
```



| Argument / option | Meaning | Constraints / default |
|---|---|---|
| `--json` | Json. | arity: 0; default: False |



### ai check

```text
usage: ai check [--json] [--connectivity | --full] [--authorize-diagnostic]
```



| Argument / option | Meaning | Constraints / default |
|---|---|---|
| `--json` | Json. | arity: 0; default: False |
| `--connectivity` | Non-generative authentication/reachability check | arity: 0; default: False |
| `--full` | Potentially billable synthetic compatibility diagnostic | arity: 0; default: False |
| `--authorize-diagnostic` | Authorize synthetic model requests for this diagnostic only | arity: 0; default: False |



### ai configure

```text
usage: ai configure [--json] [--model MODEL] [--acknowledge-cloud]
                    [--executable EXECUTABLE] [--model-path MODEL_PATH]
                    [--context CONTEXT] [--gpu-layers GPU_LAYERS]
                    [--port PORT] [--extra-options EXTRA_OPTIONS]
                    [{local,openai,anthropic,gemini,deepseek,xai}]
```



| Argument / option | Meaning | Constraints / default |
|---|---|---|
| `--json` | Json. | arity: 0; default: False |
| `provider` | Provider. | choices: local, openai, anthropic, gemini, deepseek, xai; arity: ?; default: None |
| `--model` | Explicit cloud model name, without provider prefix | default: None |
| `--acknowledge-cloud` | Explicitly acknowledge transmission to the selected cloud provider | arity: 0; default: False |
| `--executable` | Executable. | default: None |
| `--model-path` | Model path. | default: None |
| `--context` | Context. | default: None; type: int |
| `--gpu-layers` | Gpu layers. | default: None; type: int |
| `--port` | Preferred loopback port; 0 selects a free port | default: None; type: int |
| `--extra-options` | Validated performance options; -ngl/-c update dedicated settings, never duplicate defaults | default: None |



### ai start

```text
usage: ai start [--json]
```



| Argument / option | Meaning | Constraints / default |
|---|---|---|
| `--json` | Json. | arity: 0; default: False |



### ai stop

```text
usage: ai stop [--json]
```



| Argument / option | Meaning | Constraints / default |
|---|---|---|
| `--json` | Json. | arity: 0; default: False |



### ai logs

```text
usage: ai logs [--json] [--raw]
```



| Argument / option | Meaning | Constraints / default |
|---|---|---|
| `--json` | Json. | arity: 0; default: False |
| `--raw` | Enable session capture and display buffered cloud output; may contain case data | arity: 0; default: False |



### settings

```text
usage: settings {color,version} ...
```

Terminal preferences and application version

| Argument / option | Meaning | Constraints / default |
|---|---|---|



### settings color

```text
usage: settings color [{on,off}]
```

Inspect or set terminal styling

| Argument / option | Meaning | Constraints / default |
|---|---|---|
| `setting` | Setting. | choices: on, off; arity: ?; default: None |



### settings version

```text
usage: settings version [--details]
```

Show effective version; optional source/installed diagnostics

| Argument / option | Meaning | Constraints / default |
|---|---|---|
| `--details` | Details. | arity: 0; default: False |

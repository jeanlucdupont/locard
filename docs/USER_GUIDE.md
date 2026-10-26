# Locard user guide and command reference

This guide describes the current development checkout. Command syntax, choices,
defaults and argument constraints below were checked against the actual parsers.
The application version is defined in `pyproject.toml`; run `locard --version`
or `version` inside the shell to identify your installed build. Reinstall after
changing a non-editable checkout so the launcher uses the updated code.

## Contents

- [How Locard works](#how-locard-works)
- [Installation and startup](#installation-and-startup)
- [A practical investigation](#a-practical-investigation)
- [Sources, completeness and interpretation](#sources-completeness-and-interpretation)
- [AI and semantic retrieval](#ai-and-semantic-retrieval)
- [Outputs, privacy and troubleshooting](#outputs-privacy-and-troubleshooting)
- [Interactive-shell commands](#interactive-shell-commands)
- [Complete command reference](#complete-command-reference)

## How Locard works

Locard is a Windows-oriented forensic analysis application with a deterministic
evidence engine and optional AI assistance. It is named after Edmond Locard and
the principle that every contact leaves a trace.

1. **Select a case and evidence source.** Guided setup creates a case workspace;
   an existing case can receive additional ingestion batches.
2. **Discover and ingest supported artifacts.** Locard hashes source files,
   invokes artifact parsers, retains provenance and errors, and stores normalized
   records in SQLite. Discovery identifies candidates; it does not prove validity.
3. **Inspect evidence deterministically.** Search, show, timeline, process/session
   reconstruction and deterministic detections work without an LLM.
4. **Optionally ask AI for guidance or bounded investigation.** Model requests
   receive bounded context. The model does not receive arbitrary SQL or shell
   execution authority. Locard validates proposed actions and supported findings.
5. **Export derived results.** CSV dumps, rendered output, AI transcripts and
   reports are analyst outputs, not new source evidence.

| Artifact family | Input and principal use | Important interpretation limit |
|---|---|---|
| EVTX | Windows event-log files; normalized security, Sysmon and other supported event data | Coverage depends on supplied logs, audit configuration, supported normalization and recovery limitations. |
| MFT | Extracted NTFS `$MFT`, or supported native acquisition from a mounted NTFS volume | File-system metadata and reconstructed paths alone do not prove program execution. SI and FN timestamps have different meanings. |
| Prefetch | Windows `.pf` files | Execution-related metadata and referenced paths need contextual interpretation; a referenced file is not necessarily the executed program. |
| Registry | Supported binary hive files, including system and user hives | Dirty-hive limitations remain visible; companion transaction logs are not automatically replayed as hives. |
| Browser | Supported Chromium `History` SQLite evidence for Chrome and Edge | Explicit browser/profile contexts and snapshot occurrences matter, even when file bytes are identical. Missing history is not proof of no browsing. |

Disk images must be mounted or extracted using appropriate acquisition tools.
Locard is not a general disk-image parser. Keep case/output storage off the source
evidence volume. Native MFT acquisition is read-only, but reading a live volume
does not freeze its state; preserve and review the reported acquisition limitations.

Evidence IDs, source IDs and investigation IDs are different identifiers. Copy
full IDs from output; abbreviated display labels are not valid substitutes.

## Installation and startup

The primary Windows installation path is:

```powershell
git clone https://github.com/jeanlucdupont/locard.git
cd locard
.\install.ps1
.\locard.ps1
```

Python 3.11 or later is required by the package; the bootstrapper checks available
Python and dependency compatibility. It installs core Locard into `.venv` using a
normal installation, reuses a healthy environment, and does not silently replace
a corrupt environment or install Python. Core installation does not install a
GGUF model or llama.cpp. No PATH change is needed when using `locard.ps1`.

If PowerShell blocks the scripts, review the script and your organization's
execution policy. A process-scoped policy change, when permitted, affects only
that PowerShell session:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

Manual installation into an existing virtual environment:

```powershell
.\.venv\Scripts\python.exe -m pip install .
```

Developer installation, which runs code directly from this checkout:

```powershell
.\.venv\Scripts\python.exe -m pip install -e '.[test]'
```

Optional extras are `semantic` and `cloud`. Install only those you intend to use,
for example `.\.venv\Scripts\python.exe -m pip install '.[semantic]'`.
Dependency installation/model setup may require network access; ordinary local
deterministic analysis does not need a cloud service. Keep manual/developer
installation choices consistent when reinstalling with extras.

Launching with no arguments requires an interactive terminal. The shell offers
the remembered database, or creation/opening of another case. It enters the main
prompt only with an active valid case. Existing case selection never creates a
database implicitly. Guided new-case creation requires confirmation.

For scripts, pass an explicit case and command. Root options precede the command:

```powershell
.\locard.ps1 --db 'C:\Cases\Example\case.db' status --json
.\locard.ps1 --db 'C:\Cases\Example\case.db' search --artifact mft --limit 20 --ids
```

`locard` can be used instead of `.\locard.ps1` when its installed entry point is
available. Inside the Locard prompt, omit both the executable and `--db`; use
`case` to switch cases. Quote paths containing spaces. In PowerShell, single-quote
literal `$MFT` paths so `$MFT` is not expanded as a variable.

## A practical investigation

The following examples run **inside Locard**, not PowerShell. Replace bracketed
placeholder IDs with full IDs returned by your own case.

### 1. Create a case or add evidence

```text
new-case
ingest wizard
```

`new-case` guides case creation; `ingest wizard` adds evidence to the current case.
Review discovered categories and browser profiles, supply source metadata only
when known, then confirm. Use `cancel` at a setup prompt to return. Previously
committed evidence is retained if a later file fails or ingestion is interrupted.

Direct ingestion into the active case is useful when you already know the input:

```text
ingest evtx "C:\Evidence\Logs" --hostname lab-host
ingest mft "C:\Evidence\$MFT" --parser-timeout 3600
ingest prefetch "C:\Evidence\Prefetch"
ingest registry "C:\Evidence\SYSTEM"
ingest browser "C:\Evidence\Chrome\History" --browser chrome --profile Default
```

`--parser-timeout 3600` is an explicit invocation setting, not a new default.
For EVTX, `--parser-timeout` is a no-progress threshold and `--evtx-hard-timeout`
is the separate absolute ceiling. Other artifact parsers use a wall-clock limit.
An extended timeout does not remove containment, staging-size or memory controls.

For the current temporary guided-MFT acceptance path, set the following in
PowerShell before launching Locard:

```powershell
$env:LOCARD_GUIDED_MFT_PARSER_TIMEOUT = '3600'
.\locard.ps1
```

The guided ingestion executor consumes this one-shot override. Only `3600` or
unset is accepted; it affects MFT only and does not change the normal 300-second
default or other artifact families. This is an explicit temporary acceptance
mechanism, not a progress-aware timeout redesign.

### 2. Review ingestion outcomes and source context

```text
status
source list --ids
source show <source-id> --details
activity --verify
```

Read partial/error outcomes before interpreting results. Inspect source assertions
and unknown/conflicting context. In scripts, omitted `--source` creates a new
automatic source for each ingestion invocation; it never guesses an existing
source from a path or hostname. To group commands explicitly:

```text
source create --name "Workstation image" --hostname lab-host
ingest evtx "C:\Evidence\Logs" --source <source-id>
ingest prefetch "C:\Evidence\Prefetch" --source <source-id>
```

### 3. Locate and inspect records

```text
search --artifact mft --path example.exe --ids
search --process example.exe --ids
show <evidence-id>
show <evidence-id> --raw
around <evidence-id> --seconds 300
timeline --around 2026-01-01T12:00:00Z --minutes 5 --text
```

Search takes named filters, not a bare natural-language question. Use the process
filter for the supported process identity search and path filters for filenames.
`--process-contains` provides substring matching where listed below. Inspect each
record's artifact type and timestamp slot before claiming an event happened.

### 4. Build deterministic context

```text
process-tree --evidence <process-creation-evidence-id>
logons --hostname lab-host
session --logon-id 0x123 --hostname lab-host
detections --hostname lab-host
investigate <evidence-id> --seconds 300
```

Use ISO 8601 times with `Z` or an explicit UTC offset. A Windows Logon ID is not a
Locard evidence ID. Host identity, process reuse and missing context can prevent
a deterministic relationship; temporal proximity is not itself causation.

### 5. Export and report

```text
dump mft
dump all
report generate --evidence <evidence-id> --output "C:\Reports\Example"
report show "C:\Reports\Example"
report validate "C:\Reports\Example" --case "C:\Cases\Example\case.db"
```

Create the report's parent directory first; choose a new report directory. Repeat
`--evidence` for an explicit set, or use repeatable `--investigation` with compatible
saved investigations instead. An evidence-list report covers only that supplied
set; it does not establish a complete investigation or negative findings outside
the set. Report validation distinguishes file integrity, structure, compatible
case state and grounding. Successful validation does not prove forensic conclusions.

## Sources, completeness and interpretation

- The evidence database stores normalized records, source-file hashes/locations,
  artifact-specific records, timestamps, objects and provenance.
- Sources have generated identities; ingestion batches and runs record operations.
  Hostname/user/volume-root assertions are analyst metadata, not automatically
  established historical facts. `source update` changes assertions; it does not
  rewrite original source bytes or artifact observations.
- `source assign` retrospectively associates explicitly selected existing files.
  It does not reconstruct an unknown original ingestion session. Review its
  preview and confirmation fingerprint before applying.
- Browser contexts distinguish browser/profile/snapshot identity; occurrences
  connect normalized browser evidence to contexts and specific ingestion runs.
- Partial ingestion can retain usable evidence and errors together. Zero records,
  parser failures, unreplayed Registry logs and EVTX recovery limitations must be
  considered when interpreting absence. Do not rerun automatically without
  reviewing whether a previous operation retained records.
- `COMPLETE` report status means the requested bounded report completed, not that
  the forensic examination is complete. `COMPLETE_WITH_LIMITATIONS` and `FAILED`
  require review of the corresponding limitations or failures.

## AI and semantic retrieval

The normal shell interface is:

```text
! What evidence categories are present?
! Did the identified executable run after the download?
```

Inventory can be answered deterministically without a model. Advisory responses
and bounded investigation are distinct: a record-level question may propose
forensic tools, each requiring approval in the normal `!` workflow. Rejecting a
tool may leave the investigation incomplete. Unsupported model conclusions can
be rejected; an empty answer is not an investigative negative result.

For local AI, configure your own compatible llama-server executable and GGUF:

```text
ai configure local
ai status
ai start
ai logs
ai stop
```

The configuration wizard collects paths. Locard does not install the executable
or model. `ai stop` targets the Locard-owned runtime, not arbitrary external
servers. Configuration readiness and successful structured-response compatibility
are separate; a running server does not guarantee a model can satisfy the contract.

Cloud providers are optional. **Cloud use sends supplied bounded context to the
selected service** and is not an offline workflow. Credentials are provided in
the environment, not stored in the provider preferences:

| Provider value | Credential environment variable |
|---|---|
| `local` | None |
| `openai` | `OPENAI_API_KEY` |
| `anthropic` | `ANTHROPIC_API_KEY` |
| `gemini` | `GEMINI_API_KEY` |
| `deepseek` | `DEEPSEEK_API_KEY` |
| `xai` | `XAI_API_KEY` |

Use `ai provider <provider> --model <model-name>` and review the cloud warning.
`--acknowledge-cloud` supplies explicit noninteractive acknowledgment. Select an
available model appropriate to the provider; this guide does not prescribe a
permanent model catalog. `ai logs --raw` can expose sensitive model content.

Semantic retrieval is a separate optional capability:

```text
semantic status
semantic search "downloaded executable"
```

Semantic search uses a local embedding model and derived per-case index. The
interactive workflow can offer required setup/rebuild; scripts need prepared
assets. Similarity is a retrieval aid, never a forensic correlation or confidence
score. Inspect the returned evidence IDs using deterministic commands.

`investigate-ai` is an advanced/diagnostic interface with explicit budgets; normal
users should start with `!`. Its `--dry-run` may still make one model request.
This differs from the model-free dry runs of `ask` and `analyze-timeline`.

## Outputs, privacy and troubleshooting

- Human-readable versus JSON defaults vary by command and execution mode. Use
  explicit `--json` or `--text` where supported for predictable scripts.
- `--ids` exposes full identifiers in supported human displays; JSON retains IDs.
  `--raw` is command-specific diagnostic output, not an export of an entire disk.
- `--page` uses the internal pager on supported commands. `--output FILE` and
  `--append FILE` produce derived UTF-8 output; `--force` allows replacement.
  Do not assume these switches exist on `dump` or `ai`; consult the exact tables.
- CSV dumps go to `<case-directory>/dump/<type>.csv`. Existing files require
  `--force`; empty categories are skipped. Collections remain structured JSON
  cells. Spreadsheet-formula protection can prefix a cell with an apostrophe.
- Reports include standalone offline HTML, structured JSON and manifests/checksums.
  Redaction is output-only and does not alter the evidence database.
- UI state is separate from evidence under `%LOCALAPPDATA%\Locard`; the shell
  remembers recent cases. Command-line editing history is session-local, but the
  analyst activity log can retain command activity. Do not mistake the absence of
  persistent editor history for the absence of audit records.
- Investigation transcripts default to `DATABASE.investigations`; activity records
  and other sidecars may also contain sensitive paths, questions and metadata.
  Restrict sharing of the case and its derived outputs accordingly.
- If ingestion times out, review retained records/errors before retrying. Changing
  a timeout does not repair malformed evidence or remove resource caps.
- If AI fails, check `ai status` and `ai logs`; deterministic commands remain usable.
- If an old database is rejected, preserve it and use a compatible build or an
  approved recovery workflow. This checkout has no `case-upgrade` or `migrate`
  command. Do not edit SQLite version markers to bypass validation.
- After updating source code, rerun the installer for a normal installation or
  refresh the editable installation as appropriate. Use `version` to verify it.

## Interactive-shell commands

Tab completion assists command entry. Use Up/Down for session command history.
Ctrl+C cancels current input or requests operation cancellation; wait for cleanup
before continuing. It does not imply already committed ingestion was rolled back.

| Syntax | Use |
|---|---|
| `help [command [subcommand]]` or `? [command [subcommand]]` | Discover commands and exact options; for example `help ingest mft`. |
| `case` | Display/select a case through the case menu. |
| `case "path"` | Open an existing valid database and switch the active case. |
| `case new` or `new-case` | Guided creation of a new case. |
| `ingest wizard` | Guided ingestion into the active case; accepts no arguments. |
| `color [on\|off]` | Query or change session coloring; `NO_COLOR` and terminal capability still apply. |
| `version` | Display the installed application version. |
| `! question` | AI advisory/bounded investigation interface described above. |
| `exit` or `quit` | Leave the session and clean up owned resources; no arguments. |

Compatibility commands remain callable: `add-evidence` and `ingest-wizard` refer
to `ingest wizard`; `expert` displays a compatibility notice rather than switching
modes; interactive `ask question` redirects to `!`. Noninteractive `ask` retains
its retrieval-oriented compatibility behavior and is documented below.

The former hyphenated names `ingest-all`, `ingest-browser`, `ingest-evtx`,
`ingest-mft`, `ingest-prefetch`, and `ingest-registry` remain aliases of the
corresponding `ingest` subcommands, with the same arguments and options.

## Complete command reference

The following sections include every current argparse command/subcommand, including
advanced and hidden compatibility commands. Canonical ingestion paths are shown
once; the aliases above share those parsers. Shell-only commands are listed above.

`-h` and `--help` remain accepted on every parser even where ordinary help hides
them. “Unset” means no value is provided at the parser layer; runtime validation
or the selected provider may resolve it. Boolean defaults describe flag state,
not a promise that the operation is permitted. Parent/root options remain
available in their proper position before the relevant subcommand.

The tables state direct-CLI defaults. Interactive differences and dynamic defaults
are called out below. A usage line's brackets denote optional syntax; do not type
the brackets. Mutually exclusive options must not be combined.

Some existing help strings retain older "local" or "MiniCPM" terminology. For
provider-backed AI workflows, inspect `ai status` and any explicit endpoint
override to establish the actual destination before supplying sensitive context.

Reference index: [Global options](#global-options) · [dump](#dump) · [process-tree](#process-tree) · [logons](#logons) · [session](#session) · [detections](#detections) · [investigate](#investigate) · [analyze-timeline](#analyze-timeline) · [search](#search) · [timeline](#timeline) · [around](#around) · [show](#show) · [status](#status) · [ask](#ask) · [semantic](#semantic) · [semantic search](#semantic-search) · [semantic status](#semantic-status) · [investigate-ai](#investigate-ai) · [ai-history](#ai-history) · [ai-history show](#ai-history-show) · [ai-history replay](#ai-history-replay) · [report](#report) · [report generate](#report-generate) · [report show](#report-show) · [report validate](#report-validate) · [source](#source) · [source list](#source-list) · [source show](#source-show) · [source create](#source-create) · [source update](#source-update) · [source assign](#source-assign) · [activity](#activity) · [ai](#ai) · [ai provider](#ai-provider) · [ai status](#ai-status) · [ai configure](#ai-configure) · [ai start](#ai-start) · [ai stop](#ai-stop) · [ai logs](#ai-logs) · [ingest](#ingest) · [ingest all](#ingest-all) · [ingest browser](#ingest-browser) · [ingest evtx](#ingest-evtx) · [ingest mft](#ingest-mft) · [ingest prefetch](#ingest-prefetch) · [ingest registry](#ingest-registry) · [ingest wizard](#ingest-wizard)

### Global options

Locard — local evidence-first Windows forensics

```text
usage: locard [--version] [--db DB] [--no-color]
              {dump,process-tree,logons,session,detections,investigate,analyze-timeline,search,timeline,around,show,status,semantic,ai-history,report,source,activity,ai,ingest}
              ...
```

| Argument / option | Meaning | Accepted value / default |
|---|---|---|
| `-h, --help` | Display help and exit (accepted even when omitted from ordinary help). |  |
| `--version` | show program's version number and exit |  |
| `--db` | Case database path. In the shell, switch with case instead. | Default: data/forensic.db |
| `--no-color` | Disable terminal styling (also respects NO_COLOR) | Default: False |

Required subcommand: `dump`, `process-tree`, `logons`, `session`, `detections`, `investigate`, `analyze-timeline`, `search`, `timeline`, `around`, `show`, `status`, `ask`, `semantic`, `investigate-ai`, `ai-history`, `report`, `source`, `activity`, `ai`, `ingest`.

### `dump`

Export retained evidence to case-local CSV files

Usage:
  dump <type> [--force]

Types: browser, evtx, mft, prefetch, registry, all

Examples: dump browser; dump evtx; dump mft; dump prefetch; dump registry; dump all
Fixed destination: <case database directory>/dump/<type>.csv
Existing files require --force. Empty categories are skipped.
CSV files are derived analyst output, not evidence.

```text
usage: locard dump [--force] [--no-color]
                   [{browser,evtx,mft,prefetch,registry,all}]
```

No generic --output/--append/--page options. Files use fixed case-local destinations. This command does not use --json.

| Argument / option | Meaning | Accepted value / default |
|---|---|---|
| `-h, --help` | Display help and exit (accepted even when omitted from ordinary help). |  |
| `dump_type` | Artifact category to export; omitted displays dump help. | Choices: browser, evtx, mft, prefetch, registry, all; Arity: ?; Default: unset |
| `--force` | Replace requested derived CSV files | Default: False |
| `--no-color` | Disable terminal styling | Default: False |

### `process-tree`

Reconstruct process parent-child relationships

```text
usage: locard process-tree (--evidence EVIDENCE | --process PROCESS)
                           [--around AROUND] [--hostname HOSTNAME]
                           [--seconds SECONDS] [--pid-window PID_WINDOW]
                           [--max-nodes MAX_NODES] [--max-depth MAX_DEPTH]
                           [--json | --text] [--raw] [--no-color] [--force]
                           [--page | --output FILE | --append FILE]
```

--process also requires --around at runtime. Interactive output defaults to text; CLI output defaults to JSON unless explicitly selected.

| Argument / option | Meaning | Accepted value / default |
|---|---|---|
| `-h, --help` | Display help and exit (accepted even when omitted from ordinary help). |  |
| `--evidence` | Anchor evidence ID (process-creation evidence for process-tree). | Default: unset |
| `--process` | Process identity/name selector; process-tree also requires --around. | Default: unset |
| `--around` | Anchor ISO 8601 time with timezone. | Default: unset |
| `--hostname` | Hostname filter; on source/ingest commands, analyst-supplied hostname assertion. | Default: unset |
| `--seconds` | Time window or operation budget in seconds, according to this command. | Type: int; Default: 300 |
| `--pid-window` | Maximum PID-based relationship window in seconds. | Type: int; Default: 300 |
| `--max-nodes` | Maximum process-tree nodes. | Type: int; Default: 100 |
| `--max-depth` | Maximum process-tree traversal depth. | Type: int; Default: 8 |
| `--json` | Structured JSON output | Default: False |
| `--text` | Human-readable text output | Default: False |
| `--raw` | Include command-specific raw/diagnostic detail. | Default: False |
| `--no-color` | Disable terminal styling (also respects NO_COLOR) | Default: unset |
| `--force` | Permit replacing an existing derived output file without confirmation | Default: unset |
| `--page` | Review output with the internal pager (Up/Down, PgUp/PgDn, Home/End, Q) | Default: unset |
| `--output` | Write a derived UTF-8 file; existing files require confirmation or --force | Default: unset |
| `--append` | Append rendered output to a derived UTF-8 file | Default: unset |

Choose exactly one: `--evidence`, `--process`.

Choose at most one: `--json`, `--text`.

Choose at most one: `--page`, `--output`, `--append`.

Interactive shell defaults to human text; direct CLI defaults to JSON. --raw retains diagnostic output, defaulting to JSON. Use --text for human paging; JSON paging is not supported.

### `logons`

Review Windows logon-related activity from normalized Windows Event Log evidence

```text
usage: locard logons [--user USER] [--ip IP] [--hostname HOSTNAME]
                     [--start START] [--end END] [--limit LIMIT]
                     [--offset OFFSET] [--json | --text] [--raw] [--no-color]
                     [--force] [--page | --output FILE | --append FILE]
```

Interactive output defaults to text; CLI output defaults to JSON.

| Argument / option | Meaning | Accepted value / default |
|---|---|---|
| `-h, --help` | Display help and exit (accepted even when omitted from ordinary help). |  |
| `--user` | User filter; on source/ingest commands, analyst-supplied user assertion. | Default: unset |
| `--ip` | IP-address filter. | Default: unset |
| `--hostname` | Hostname filter; on source/ingest commands, analyst-supplied hostname assertion. | Default: unset |
| `--start` | Inclusive query start time; provide an ISO 8601 timezone. | Default: unset |
| `--end` | Query end time; provide an ISO 8601 timezone. | Default: unset |
| `--limit` | Maximum returned rows/candidates. | Type: int; Default: 100 |
| `--offset` | Number of results to skip for pagination. | Type: int; Default: 0 |
| `--json` | Structured JSON output | Default: False |
| `--text` | Human-readable text output | Default: False |
| `--raw` | Include command-specific raw/diagnostic detail. | Default: False |
| `--no-color` | Disable terminal styling (also respects NO_COLOR) | Default: unset |
| `--force` | Permit replacing an existing derived output file without confirmation | Default: unset |
| `--page` | Review output with the internal pager (Up/Down, PgUp/PgDn, Home/End, Q) | Default: unset |
| `--output` | Write a derived UTF-8 file; existing files require confirmation or --force | Default: unset |
| `--append` | Append rendered output to a derived UTF-8 file | Default: unset |

Choose at most one: `--json`, `--text`.

Choose at most one: `--page`, `--output`, `--append`.

Interactive shell defaults to human text; direct CLI defaults to JSON. --raw retains diagnostic output, defaulting to JSON. Use --text for human paging; JSON paging is not supported.

### `session`

Reconstruct activity within a Windows logon session

```text
usage: locard session --logon-id LOGON_ID [--hostname HOSTNAME]
                      [--around AROUND] [--evidence EVIDENCE]
                      [--max-hours MAX_HOURS] [--limit LIMIT]
                      [--json | --text] [--raw] [--no-color] [--force]
                      [--page | --output FILE | --append FILE]
```

Use --evidence or host/time context when a Logon ID is ambiguous. Interactive output defaults to text; CLI defaults to JSON.

| Argument / option | Meaning | Accepted value / default |
|---|---|---|
| `-h, --help` | Display help and exit (accepted even when omitted from ordinary help). |  |
| `--logon-id` | Windows authentication Logon ID, decimal or hexadecimal (for example 0x1cd8f6); not a Locard evidence ID | Required; Default: unset |
| `--hostname` | Hostname filter; on source/ingest commands, analyst-supplied hostname assertion. | Default: unset |
| `--around` | Anchor ISO 8601 time with timezone. | Default: unset |
| `--evidence` | Successful-logon evidence ID to disambiguate | Default: unset |
| `--max-hours` | Maximum session span in hours. | Type: int; Default: 24 |
| `--limit` | Maximum returned rows/candidates. | Type: int; Default: 500 |
| `--json` | Structured JSON output | Default: False |
| `--text` | Human-readable text output | Default: False |
| `--raw` | Include command-specific raw/diagnostic detail. | Default: False |
| `--no-color` | Disable terminal styling (also respects NO_COLOR) | Default: unset |
| `--force` | Permit replacing an existing derived output file without confirmation | Default: unset |
| `--page` | Review output with the internal pager (Up/Down, PgUp/PgDn, Home/End, Q) | Default: unset |
| `--output` | Write a derived UTF-8 file; existing files require confirmation or --force | Default: unset |
| `--append` | Append rendered output to a derived UTF-8 file | Default: unset |

Choose at most one: `--json`, `--text`.

Choose at most one: `--page`, `--output`, `--append`.

Interactive shell defaults to human text; direct CLI defaults to JSON. --raw retains diagnostic output, defaulting to JSON. Use --text for human paging; JSON paging is not supported.

### `detections`

Show evidence matching Locard detection rules

```text
usage: locard detections [--start START] [--end END] [--user USER]
                         [--hostname HOSTNAME] [--rule RULE]
                         [--severity {low,medium,high}] [--limit LIMIT]
                         [--candidate-limit CANDIDATE_LIMIT]
                         [--failure-threshold FAILURE_THRESHOLD]
                         [--failure-window FAILURE_WINDOW] [--json | --text]
                         [--raw] [--no-color] [--force]
                         [--page | --output FILE | --append FILE]
```

Deterministic matches are leads, not proof of compromise. Interactive output defaults to text; CLI defaults to JSON.

| Argument / option | Meaning | Accepted value / default |
|---|---|---|
| `-h, --help` | Display help and exit (accepted even when omitted from ordinary help). |  |
| `--start` | Inclusive query start time; provide an ISO 8601 timezone. | Default: unset |
| `--end` | Query end time; provide an ISO 8601 timezone. | Default: unset |
| `--user` | User filter; on source/ingest commands, analyst-supplied user assertion. | Default: unset |
| `--hostname` | Hostname filter; on source/ingest commands, analyst-supplied hostname assertion. | Default: unset |
| `--rule` | Detection rule identifier filter. | Default: unset |
| `--severity` | Detection severity filter. | Choices: low, medium, high; Default: unset |
| `--limit` | Maximum returned rows/candidates. | Type: int; Default: 100 |
| `--candidate-limit` | Bound on candidates considered before returning results. | Type: int; Default: 1000 |
| `--failure-threshold` | Minimum failure count for the applicable authentication detection. | Type: int; Default: 5 |
| `--failure-window` | Failure aggregation window in seconds. | Type: int; Default: 300 |
| `--json` | Structured JSON output | Default: False |
| `--text` | Human-readable text output | Default: False |
| `--raw` | Include command-specific raw/diagnostic detail. | Default: False |
| `--no-color` | Disable terminal styling (also respects NO_COLOR) | Default: unset |
| `--force` | Permit replacing an existing derived output file without confirmation | Default: unset |
| `--page` | Review output with the internal pager (Up/Down, PgUp/PgDn, Home/End, Q) | Default: unset |
| `--output` | Write a derived UTF-8 file; existing files require confirmation or --force | Default: unset |
| `--append` | Append rendered output to a derived UTF-8 file | Default: unset |

Choose at most one: `--json`, `--text`.

Choose at most one: `--page`, `--output`, `--append`.

Interactive shell defaults to human text; direct CLI defaults to JSON. --raw retains diagnostic output, defaulting to JSON. Use --text for human paging; JSON paging is not supported.

### `investigate`

Gather and correlate evidence around a specific evidence record

Deterministic correlation around a specific evidence record identified by its canonical evidence_id. Gathers nearby and related evidence within bounded criteria; no AI required.

```text
usage: locard investigate [--seconds SECONDS]
                          [--candidate-limit CANDIDATE_LIMIT]
                          [--json | --text] [--raw]
                          [--timestamp-slot TIMESTAMP_SLOT] [--no-color]
                          [--force] [--page | --output FILE | --append FILE]
                          evidence_id
```

Deterministic correlation; no model required. Interactive output defaults to text; CLI defaults to JSON.

| Argument / option | Meaning | Accepted value / default |
|---|---|---|
| `-h, --help` | Display help and exit (accepted even when omitted from ordinary help). |  |
| `evidence_id` | Canonical evidence ID of the anchor record | Required; Default: unset |
| `--seconds` | Time window around the anchor, in seconds (default: 120) | Type: int; Default: 120 |
| `--candidate-limit` | Maximum candidate volume (default: 500) | Type: int; Default: 500 |
| `--json` | Structured JSON output | Default: False |
| `--text` | Human-readable text output | Default: False |
| `--raw` | Include command-specific raw/diagnostic detail. | Default: False |
| `--timestamp-slot` | Select the anchor timestamp slot when multiple slots exist | Default: unset |
| `--no-color` | Disable terminal styling (also respects NO_COLOR) | Default: unset |
| `--force` | Permit replacing an existing derived output file without confirmation | Default: unset |
| `--page` | Review output with the internal pager (Up/Down, PgUp/PgDn, Home/End, Q) | Default: unset |
| `--output` | Write a derived UTF-8 file; existing files require confirmation or --force | Default: unset |
| `--append` | Append rendered output to a derived UTF-8 file | Default: unset |

Choose at most one: `--json`, `--text`.

Choose at most one: `--page`, `--output`, `--append`.

Interactive shell defaults to human text; direct CLI defaults to JSON. --raw retains diagnostic output, defaulting to JSON. Use --text for human paging; JSON paging is not supported.

### `analyze-timeline`

Analyze a bounded timeline bundle using the local AI model

Specialized workflow: deterministic retrieval and correlation in an explicit time range, followed by local AI analysis. --dry-run builds the bounded evidence bundle without calling the model. Model analysis is not evidence; citation checks do not establish factual correctness.

```text
usage: locard analyze-timeline --start START --end END [--hostname HOSTNAME]
                               [--user USER]
                               [--candidate-limit CANDIDATE_LIMIT]
                               [--endpoint ENDPOINT] [--timeout TIMEOUT]
                               [--dry-run] [--json | --text] [--raw]
                               [--no-color] [--force]
                               [--page | --output FILE | --append FILE]
```

| Argument / option | Meaning | Accepted value / default |
|---|---|---|
| `-h, --help` | Display help and exit (accepted even when omitted from ordinary help). |  |
| `--start` | Inclusive query start time; provide an ISO 8601 timezone. | Required; Default: unset |
| `--end` | Query end time; provide an ISO 8601 timezone. | Required; Default: unset |
| `--hostname` | Hostname filter; on source/ingest commands, analyst-supplied hostname assertion. | Default: unset |
| `--user` | User filter; on source/ingest commands, analyst-supplied user assertion. | Default: unset |
| `--candidate-limit` | Bound on candidates considered before returning results. | Type: int; Default: 500 |
| `--endpoint` | Invocation-specific local model endpoint override; not a persistent provider change. | Default: unset |
| `--timeout` | Model-request timeout in seconds. | Type: float; Default: 120 |
| `--dry-run` | Build the bounded analysis input without a model request for this command. | Default: False |
| `--json` | Structured JSON output | Default: False |
| `--text` | Human-readable text output | Default: False |
| `--raw` | Include command-specific raw/diagnostic detail. | Default: False |
| `--no-color` | Disable terminal styling (also respects NO_COLOR) | Default: unset |
| `--force` | Permit replacing an existing derived output file without confirmation | Default: unset |
| `--page` | Review output with the internal pager (Up/Down, PgUp/PgDn, Home/End, Q) | Default: unset |
| `--output` | Write a derived UTF-8 file; existing files require confirmation or --force | Default: unset |
| `--append` | Append rendered output to a derived UTF-8 file | Default: unset |

Choose at most one: `--json`, `--text`.

Choose at most one: `--page`, `--output`, `--append`.

### `search`

Search case evidence

```text
usage: locard search [--user USER] [--ip IP] [--hostname HOSTNAME]
                     [--start START] [--end END]
                     [--process PROCESS | --process-contains PROCESS] [--ids]
                     [--event-id EVENT_ID]
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
                     [--source SOURCE] [--no-color] [--force]
                     [--page | --output FILE | --append FILE]
```

| Argument / option | Meaning | Accepted value / default |
|---|---|---|
| `-h, --help` | Display help and exit (accepted even when omitted from ordinary help). |  |
| `--user` | User filter; on source/ingest commands, analyst-supplied user assertion. | Default: unset |
| `--ip` | IP-address filter. | Default: unset |
| `--hostname` | Hostname filter; on source/ingest commands, analyst-supplied hostname assertion. | Default: unset |
| `--start` | Inclusive query start time; provide an ISO 8601 timezone. | Default: unset |
| `--end` | Query end time; provide an ISO 8601 timezone. | Default: unset |
| `--process` | Exact executable name, case-insensitive; .exe may be omitted for a bare name. Explicit paths remain exact. | Default: unset |
| `--process-contains` | Case-insensitive literal substring of the executable basename; no wildcards | Default: unset |
| `--ids` | Include full copyable evidence IDs, numbered to match table rows; display paths may be shortened. Use show for details, --json for the existing structured projection, --raw for available raw payloads. | Default: False |
| `--event-id` | Windows event type number, not EventRecordID or a Locard evidence ID. | Type: int; Default: unset |
| `--kind` | Normalized event-kind filter. | Choices: logons, failed-logons, processes, powershell, scheduled-tasks, services, account-changes; Default: unset |
| `--limit` | Maximum results (default: %(default)s) | Type: int; Default: 20 |
| `--offset` | Number of results to skip for pagination. | Type: int; Default: 0 |
| `--raw` | Include original XML or available artifact bytes/details | Default: False |
| `--artifact` | Artifact-family filter. | Choices: evtx, mft, prefetch, registry, browser; Default: unset |
| `--path` | Input file/directory for ingestion; path filter for retrieval. | Default: unset |
| `--url` | Exact browser field match | Default: unset |
| `--url-contains` | Literal browser field substring; no wildcards | Default: unset |
| `--title` | Exact browser field match | Default: unset |
| `--title-contains` | Literal browser field substring; no wildcards | Default: unset |
| `--download-path` | Exact browser field match | Default: unset |
| `--download-path-contains` | Literal browser field substring; no wildcards | Default: unset |
| `--browser` | Explicit browser product for ingestion or browser product filter for retrieval. | Choices: chrome, edge; Default: unset |
| `--profile` | Browser profile filter; report generate instead selects the report audience profile. | Default: unset |
| `--browser-kind` | Browser evidence subtype (one record per visit or download) | Choices: visit, download; Default: unset |
| `--json` | Request structured JSON output. | Default: False |
| `--key` | Registry key path: exact literal match (SQLite NOCASE); includes its values; no filesystem normalization | Default: unset |
| `--key-contains` | Registry key path: literal substring (SQLite NOCASE); no wildcards; includes matching keys and their values | Default: unset |
| `--value-name` | Registry value name: exact raw or decoded UserAssist name (SQLite NOCASE) | Default: unset |
| `--value-name-contains` | Registry value name: literal substring of raw or decoded UserAssist name (SQLite NOCASE); no wildcards | Default: unset |
| `--source` | Filter Locard source membership, not hostname identity | Default: unset |
| `--no-color` | Disable terminal styling (also respects NO_COLOR) | Default: unset |
| `--force` | Permit replacing an existing derived output file without confirmation | Default: unset |
| `--page` | Review output with the internal pager (Up/Down, PgUp/PgDn, Home/End, Q) | Default: unset |
| `--output` | Write a derived UTF-8 file; existing files require confirmation or --force | Default: unset |
| `--append` | Append rendered output to a derived UTF-8 file | Default: unset |

Choose at most one: `--process`, `--process-contains`.

Choose at most one: `--url`, `--url-contains`.

Choose at most one: `--title`, `--title-contains`.

Choose at most one: `--download-path`, `--download-path-contains`.

Choose at most one: `--key`, `--key-contains`.

Choose at most one: `--value-name`, `--value-name-contains`.

Choose at most one: `--page`, `--output`, `--append`.

### `timeline`

Browse evidence chronologically

```text
usage: locard timeline [--around AROUND] [--start START] [--end END]
                       [--user USER] [--process PROCESS] [--ip IP]
                       [--hostname HOSTNAME] [--artifact-type ARTIFACT_TYPE]
                       [--event-id EVENT_ID] [--minutes MINUTES]
                       [--limit LIMIT] [--offset OFFSET] [--raw]
                       [--json | --text]
                       [--artifact {evtx,mft,prefetch,registry,browser}]
                       [--path PATH] [--no-color] [--force]
                       [--page | --output FILE | --append FILE]
                       [timestamp]
```

| Argument / option | Meaning | Accepted value / default |
|---|---|---|
| `-h, --help` | Display help and exit (accepted even when omitted from ordinary help). |  |
| `timestamp` | Anchor time as ISO 8601 with Z or an explicit UTC offset, e.g. 2026-06-29T19:08:00Z | Arity: ?; Default: unset |
| `--around` | Anchor time as ISO 8601 with Z or an explicit UTC offset, e.g. 2026-06-29T19:08:00Z | Default: unset |
| `--start` | Start time as ISO 8601 with Z or an explicit UTC offset, e.g. 2026-06-29T19:07:30Z | Default: unset |
| `--end` | End time as ISO 8601 with Z or an explicit UTC offset, e.g. 2026-06-29T19:08:30Z | Default: unset |
| `--user` | User filter; on source/ingest commands, analyst-supplied user assertion. | Default: unset |
| `--process` | Process identity/name selector; process-tree also requires --around. | Default: unset |
| `--ip` | IP-address filter. | Default: unset |
| `--hostname` | Hostname filter; on source/ingest commands, analyst-supplied hostname assertion. | Default: unset |
| `--artifact-type` | Artifact/event type filter. | Default: unset |
| `--event-id` | Windows event type number, not EventRecordID or a Locard evidence ID. | Type: int; Default: unset |
| `--minutes` | Minutes on each side of a timeline anchor. | Type: int; Default: 5 |
| `--limit` | Maximum results (default: %(default)s) | Type: int; Default: 100 |
| `--offset` | Number of results to skip for pagination. | Type: int; Default: 0 |
| `--raw` | Include original XML or available artifact bytes/details | Default: False |
| `--json` | JSON output (default) | Default: False |
| `--text` | Compact readable output | Default: False |
| `--artifact` | Artifact-family filter. | Choices: evtx, mft, prefetch, registry, browser; Default: unset |
| `--path` | Input file/directory for ingestion; path filter for retrieval. | Default: unset |
| `--no-color` | Disable terminal styling (also respects NO_COLOR) | Default: unset |
| `--force` | Permit replacing an existing derived output file without confirmation | Default: unset |
| `--page` | Review output with the internal pager (Up/Down, PgUp/PgDn, Home/End, Q) | Default: unset |
| `--output` | Write a derived UTF-8 file; existing files require confirmation or --force | Default: unset |
| `--append` | Append rendered output to a derived UTF-8 file | Default: unset |

Choose at most one: `--json`, `--text`.

Choose at most one: `--page`, `--output`, `--append`.

### `around`

Show evidence near a specific event or timestamp

Compact text rounds timestamps and exact deltas to milliseconds (nearest, ties away from zero). JSON/raw and --ids retain full precision. Temporal proximity is not causation; timestamp meanings differ by artifact.

```text
usage: locard around [--seconds SECONDS] [--direction {before,after,around}]
                     [--limit LIMIT] [--offset OFFSET] [--raw] [--ids]
                     [--json | --text] [--timestamp-slot TIMESTAMP_SLOT]
                     [--no-color] [--force]
                     [--page | --output FILE | --append FILE]
                     evidence_id
```

| Argument / option | Meaning | Accepted value / default |
|---|---|---|
| `-h, --help` | Display help and exit (accepted even when omitted from ordinary help). |  |
| `evidence_id` | Full canonical evidence ID. | Required; Default: unset |
| `--seconds` | Time window or operation budget in seconds, according to this command. | Type: int; Default: 120 |
| `--direction` | Which side of the anchor to include. | Choices: before, after, around; Default: around |
| `--limit` | Maximum returned rows/candidates. | Type: int; Default: 100 |
| `--offset` | Number of results to skip for pagination. | Type: int; Default: 0 |
| `--raw` | Include command-specific raw/diagnostic detail. | Default: False |
| `--ids` | Include full evidence/source IDs, timestamp slots and original timestamp precision in --text output | Default: False |
| `--json` | JSON output (default) | Default: False |
| `--text` | Compact readable output | Default: False |
| `--timestamp-slot` | Select the anchor record timestamp slot explicitly. | Default: unset |
| `--no-color` | Disable terminal styling (also respects NO_COLOR) | Default: unset |
| `--force` | Permit replacing an existing derived output file without confirmation | Default: unset |
| `--page` | Review output with the internal pager (Up/Down, PgUp/PgDn, Home/End, Q) | Default: unset |
| `--output` | Write a derived UTF-8 file; existing files require confirmation or --force | Default: unset |
| `--append` | Append rendered output to a derived UTF-8 file | Default: unset |

Choose at most one: `--json`, `--text`.

Choose at most one: `--page`, `--output`, `--append`.

### `show`

Show details about an evidence record

Human summary with populated timestamps and bounded references. --json preserves the structured projection; --raw includes available XML/artifact bytes. Both retain existing 100-object/reference/value-ID bounds and truncation flags.

```text
usage: locard show [--raw] [--json] [--no-color] [--force]
                   [--page | --output FILE | --append FILE]
                   evidence_id
```

| Argument / option | Meaning | Accepted value / default |
|---|---|---|
| `-h, --help` | Display help and exit (accepted even when omitted from ordinary help). |  |
| `evidence_id` | Full canonical evidence ID. | Required; Default: unset |
| `--raw` | Include command-specific raw/diagnostic detail. | Default: False |
| `--json` | Request structured JSON output. | Default: False |
| `--no-color` | Disable terminal styling (also respects NO_COLOR) | Default: unset |
| `--force` | Permit replacing an existing derived output file without confirmation | Default: unset |
| `--page` | Review output with the internal pager (Up/Down, PgUp/PgDn, Home/End, Q) | Default: unset |
| `--output` | Write a derived UTF-8 file; existing files require confirmation or --force | Default: unset |
| `--append` | Append rendered output to a derived UTF-8 file | Default: unset |

Choose at most one: `--page`, `--output`, `--append`.

### `status`

Show case ingestion and evidence status

```text
usage: locard status [--json] [--no-color] [--force]
                     [--page | --output FILE | --append FILE]
```

| Argument / option | Meaning | Accepted value / default |
|---|---|---|
| `-h, --help` | Display help and exit (accepted even when omitted from ordinary help). |  |
| `--json` | Request structured JSON output. | Default: False |
| `--no-color` | Disable terminal styling (also respects NO_COLOR) | Default: unset |
| `--force` | Permit replacing an existing derived output file without confirmation | Default: unset |
| `--page` | Review output with the internal pager (Up/Down, PgUp/PgDn, Home/End, Q) | Default: unset |
| `--output` | Write a derived UTF-8 file; existing files require confirmation or --force | Default: unset |
| `--append` | Append rendered output to a derived UTF-8 file | Default: unset |

Choose at most one: `--page`, `--output`, `--append`.

### `ask`

Ask the local AI questions about case evidence

Deprecated CLI compatibility command; use ! in the interactive shell for advisory guidance. This legacy CLI command retains its existing evidence retrieval behavior. Deterministic search retrieves evidence by exact/filter-based criteria. Semantic retrieval discovers meaning-based candidate leads, not evidence for the queried concept. The local LLM analyzes only the bounded supplied bundle. Model analysis is not evidence.

```text
usage: locard ask [--json | --text] [--endpoint ENDPOINT] [--date DATE]
                  [--limit LIMIT] [--timeout TIMEOUT] [--dry-run]
                  [--semantic-index SEMANTIC_INDEX]
                  [--embedding-model EMBEDDING_MODEL] [--no-color] [--force]
                  [--page | --output FILE | --append FILE]
                  question
```

Hidden noninteractive compatibility command. Inside the shell, ask forwards to ! and does not use this retrieval CLI contract.

| Argument / option | Meaning | Accepted value / default |
|---|---|---|
| `-h, --help` | Display help and exit (accepted even when omitted from ordinary help). |  |
| `--json` | Structured output | Default: True |
| `--text` | Human-readable output | Default: True |
| `question` | Question/text; quote multiword input in the noninteractive CLI. | Required; Default: unset |
| `--endpoint` | Invocation-specific local model endpoint override; not a persistent provider change. | Default: unset |
| `--date` | UTC date for time-only questions | Default: unset |
| `--limit` | Maximum returned rows/candidates. | Type: int; Default: 30 |
| `--timeout` | Model-request timeout in seconds. | Type: float; Default: 120.0 |
| `--dry-run` | Show plan and evidence without contacting the model | Default: False |
| `--semantic-index` | Derived semantic-index directory override. | Default: unset |
| `--embedding-model` | Local embedding-model path override. | Default: unset |
| `--no-color` | Disable terminal styling (also respects NO_COLOR) | Default: unset |
| `--force` | Permit replacing an existing derived output file without confirmation | Default: unset |
| `--page` | Review output with the internal pager (Up/Down, PgUp/PgDn, Home/End, Q) | Default: unset |
| `--output` | Write a derived UTF-8 file; existing files require confirmation or --force | Default: unset |
| `--append` | Append rendered output to a derived UTF-8 file | Default: unset |

Choose at most one: `--json`, `--text`.

Choose at most one: `--page`, `--output`, `--append`.

### `semantic`

Search case evidence by meaning

```text
usage: locard semantic [--no-color] [--force]
                       [--page | --output FILE | --append FILE]
                       {search,status} ...
```

| Argument / option | Meaning | Accepted value / default |
|---|---|---|
| `-h, --help` | Display help and exit (accepted even when omitted from ordinary help). |  |
| `--no-color` | Disable terminal styling (also respects NO_COLOR) | Default: unset |
| `--force` | Permit replacing an existing derived output file without confirmation | Default: unset |
| `--page` | Review output with the internal pager (Up/Down, PgUp/PgDn, Home/End, Q) | Default: unset |
| `--output` | Write a derived UTF-8 file; existing files require confirmation or --force | Default: unset |
| `--append` | Append rendered output to a derived UTF-8 file | Default: unset |

Choose at most one: `--page`, `--output`, `--append`.

Required subcommand: `search`, `status`.

### `semantic search`

Search current case evidence by semantic similarity

```text
usage: locard semantic search [--json | --text] [--model-path MODEL_PATH]
                              [--index INDEX] [--limit LIMIT] [--show-weak]
                              [--artifact ARTIFACT] [--start START]
                              [--end END] [--hostname HOSTNAME] [--user USER]
                              [--path PATH] [--no-color] [--force]
                              [--page | --output FILE | --append FILE]
                              question
```

Effective --limit is 10 in interactive human output and 20 otherwise when omitted. Interactive semantic output defaults to text; CLI output defaults to JSON.

| Argument / option | Meaning | Accepted value / default |
|---|---|---|
| `-h, --help` | Display help and exit (accepted even when omitted from ordinary help). |  |
| `--json` | Full structured metadata, without terminal styling | Default: True |
| `--text` | Concise human-readable output | Default: True |
| `--model-path` | Advanced local model-directory override; does not change other commands | Default: unset |
| `--index` | Advanced case-specific derived index directory override | Default: unset |
| `question` | Question/text; quote multiword input in the noninteractive CLI. | Required; Default: unset |
| `--limit` | Maximum returned rows/candidates. | Type: int; Default: unset |
| `--show-weak` | Show candidates below the human display cutoff; JSON always retains all results | Default: False |
| `--artifact` | Artifact-family filter. | Default: unset |
| `--start` | Inclusive query start time; provide an ISO 8601 timezone. | Default: unset |
| `--end` | Query end time; provide an ISO 8601 timezone. | Default: unset |
| `--hostname` | Hostname filter; on source/ingest commands, analyst-supplied hostname assertion. | Default: unset |
| `--user` | User filter; on source/ingest commands, analyst-supplied user assertion. | Default: unset |
| `--path` | Input file/directory for ingestion; path filter for retrieval. | Default: unset |
| `--no-color` | Disable terminal styling (also respects NO_COLOR) | Default: unset |
| `--force` | Permit replacing an existing derived output file without confirmation | Default: unset |
| `--page` | Review output with the internal pager (Up/Down, PgUp/PgDn, Home/End, Q) | Default: unset |
| `--output` | Write a derived UTF-8 file; existing files require confirmation or --force | Default: unset |
| `--append` | Append rendered output to a derived UTF-8 file | Default: unset |

Choose at most one: `--json`, `--text`.

Choose at most one: `--page`, `--output`, `--append`.

### `semantic status`

Show semantic runtime, model, and current-case index status

```text
usage: locard semantic status [--json | --text] [--model-path MODEL_PATH]
                              [--index INDEX] [--no-color] [--force]
                              [--page | --output FILE | --append FILE]
```

Interactive output defaults to text; CLI output defaults to JSON.

| Argument / option | Meaning | Accepted value / default |
|---|---|---|
| `-h, --help` | Display help and exit (accepted even when omitted from ordinary help). |  |
| `--json` | Full structured metadata, without terminal styling | Default: True |
| `--text` | Concise human-readable output | Default: True |
| `--model-path` | Advanced local model-directory override; does not change other commands | Default: unset |
| `--index` | Advanced case-specific derived index directory override | Default: unset |
| `--no-color` | Disable terminal styling (also respects NO_COLOR) | Default: unset |
| `--force` | Permit replacing an existing derived output file without confirmation | Default: unset |
| `--page` | Review output with the internal pager (Up/Down, PgUp/PgDn, Home/End, Q) | Default: unset |
| `--output` | Write a derived UTF-8 file; existing files require confirmation or --force | Default: unset |
| `--append` | Append rendered output to a derived UTF-8 file | Default: unset |

Choose at most one: `--json`, `--text`.

Choose at most one: `--page`, `--output`, `--append`.

### `investigate-ai`

Analyze case evidence using the local AI model

Advanced / Diagnostic interface. Use ! <question> for normal interactive AI requests.

```text
usage: locard investigate-ai [--endpoint ENDPOINT] [--date DATE]
                             [--max-steps MAX_STEPS]
                             [--max-tool-calls MAX_TOOL_CALLS]
                             [--max-seconds MAX_SECONDS] [--dry-run]
                             [--approve-tools] [--transcripts TRANSCRIPTS]
                             [--json] [--explain] [--no-semantic]
                             [--semantic-index SEMANTIC_INDEX]
                             [--embedding-model EMBEDDING_MODEL] [--no-color]
                             [--force]
                             [--page | --output FILE | --append FILE]
                             question
```

Advanced/diagnostic command, hidden from normal discovery. Unlike the normal ! workflow, per-tool interactive approval must be requested with --approve-tools. --dry-run may contact the model once.

| Argument / option | Meaning | Accepted value / default |
|---|---|---|
| `-h, --help` | Display help and exit (accepted even when omitted from ordinary help). |  |
| `question` | Question/text; quote multiword input in the noninteractive CLI. | Required; Default: unset |
| `--endpoint` | Advanced existing loopback endpoint; overrides configured provider for this invocation | Default: unset |
| `--date` | UTC date used to interpret a time-only question. | Default: unset |
| `--max-steps` | Maximum controller steps. | Type: int; Default: 8 |
| `--max-tool-calls` | Maximum bounded forensic tool calls. | Type: int; Default: 6 |
| `--max-seconds` | Overall investigation deadline in seconds. | Type: int; Default: 300 |
| `--dry-run` | Initial retrieval plus one model proposal; no iterative tool execution | Default: False |
| `--approve-tools` | Require interactive approval for each proposed operation | Default: False |
| `--transcripts` | Sensitive local derived records, not evidence; default: DATABASE.investigations. Analyst controls retention/deletion. | Default: unset |
| `--json` | Request structured JSON output. | Default: False |
| `--explain` | Include step-by-step transcript data | Default: False |
| `--no-semantic` | Disable semantic retrieval for this operation. | Default: False |
| `--semantic-index` | Derived semantic-index directory override. | Default: unset |
| `--embedding-model` | Local embedding-model path override. | Default: unset |
| `--no-color` | Disable terminal styling (also respects NO_COLOR) | Default: unset |
| `--force` | Permit replacing an existing derived output file without confirmation | Default: unset |
| `--page` | Review output with the internal pager (Up/Down, PgUp/PgDn, Home/End, Q) | Default: unset |
| `--output` | Write a derived UTF-8 file; existing files require confirmation or --force | Default: unset |
| `--append` | Append rendered output to a derived UTF-8 file | Default: unset |

Choose at most one: `--page`, `--output`, `--append`.

### `ai-history`

Review or replay saved AI investigations

Review or replay saved derived AI investigation records for audit and review. These records are not source evidence.

```text
usage: locard ai-history [--no-color] [--force]
                         [--page | --output FILE | --append FILE]
                         {show,replay} ...
```

| Argument / option | Meaning | Accepted value / default |
|---|---|---|
| `-h, --help` | Display help and exit (accepted even when omitted from ordinary help). |  |
| `--no-color` | Disable terminal styling (also respects NO_COLOR) | Default: unset |
| `--force` | Permit replacing an existing derived output file without confirmation | Default: unset |
| `--page` | Review output with the internal pager (Up/Down, PgUp/PgDn, Home/End, Q) | Default: unset |
| `--output` | Write a derived UTF-8 file; existing files require confirmation or --force | Default: unset |
| `--append` | Append rendered output to a derived UTF-8 file | Default: unset |

Choose at most one: `--page`, `--output`, `--append`.

Required subcommand: `show`, `replay`.

Saved records are derived data; replay does not establish forensic conclusions.

### `ai-history show`

Review a saved derived AI investigation transcript.

```text
usage: locard ai-history show [--transcripts TRANSCRIPTS] [--json] [--explain]
                              [--no-color] [--force]
                              [--page | --output FILE | --append FILE]
                              investigation_id
```

| Argument / option | Meaning | Accepted value / default |
|---|---|---|
| `-h, --help` | Display help and exit (accepted even when omitted from ordinary help). |  |
| `investigation_id` | Saved derived investigation identifier. | Required; Default: unset |
| `--transcripts` | Sensitive local derived records, not evidence; default: DATABASE.investigations. Analyst controls retention/deletion. | Default: unset |
| `--json` | Request structured JSON output. | Default: False |
| `--explain` | Include step-by-step transcript data | Default: False |
| `--no-color` | Disable terminal styling (also respects NO_COLOR) | Default: unset |
| `--force` | Permit replacing an existing derived output file without confirmation | Default: unset |
| `--page` | Review output with the internal pager (Up/Down, PgUp/PgDn, Home/End, Q) | Default: unset |
| `--output` | Write a derived UTF-8 file; existing files require confirmation or --force | Default: unset |
| `--append` | Append rendered output to a derived UTF-8 file | Default: unset |

Choose at most one: `--page`, `--output`, `--append`.

### `ai-history replay`

Replay supported saved investigation operations for verification; this is not proof of conclusions.

```text
usage: locard ai-history replay [--transcripts TRANSCRIPTS] [--json]
                                [--explain] [--no-semantic]
                                [--semantic-index SEMANTIC_INDEX]
                                [--embedding-model EMBEDDING_MODEL]
                                [--no-color] [--force]
                                [--page | --output FILE | --append FILE]
                                investigation_id
```

| Argument / option | Meaning | Accepted value / default |
|---|---|---|
| `-h, --help` | Display help and exit (accepted even when omitted from ordinary help). |  |
| `investigation_id` | Saved derived investigation identifier. | Required; Default: unset |
| `--transcripts` | Sensitive local derived records, not evidence; default: DATABASE.investigations. Analyst controls retention/deletion. | Default: unset |
| `--json` | Request structured JSON output. | Default: False |
| `--explain` | Include step-by-step transcript data | Default: False |
| `--no-semantic` | Disable semantic retrieval for this operation. | Default: False |
| `--semantic-index` | Derived semantic-index directory override. | Default: unset |
| `--embedding-model` | Local embedding-model path override. | Default: unset |
| `--no-color` | Disable terminal styling (also respects NO_COLOR) | Default: unset |
| `--force` | Permit replacing an existing derived output file without confirmation | Default: unset |
| `--page` | Review output with the internal pager (Up/Down, PgUp/PgDn, Home/End, Q) | Default: unset |
| `--output` | Write a derived UTF-8 file; existing files require confirmation or --force | Default: unset |
| `--append` | Append rendered output to a derived UTF-8 file | Default: unset |

Choose at most one: `--page`, `--output`, `--append`.

### `report`

Generate a forensic investigation report

```text
usage: locard report [--no-color] [--force]
                     [--page | --output FILE | --append FILE]
                     {generate,show,validate} ...
```

| Argument / option | Meaning | Accepted value / default |
|---|---|---|
| `-h, --help` | Display help and exit (accepted even when omitted from ordinary help). |  |
| `--no-color` | Disable terminal styling (also respects NO_COLOR) | Default: unset |
| `--force` | Permit replacing an existing derived output file without confirmation | Default: unset |
| `--page` | Review output with the internal pager (Up/Down, PgUp/PgDn, Home/End, Q) | Default: unset |
| `--output` | Write a derived UTF-8 file; existing files require confirmation or --force | Default: unset |
| `--append` | Append rendered output to a derived UTF-8 file | Default: unset |

Choose at most one: `--page`, `--output`, `--append`.

Required subcommand: `generate`, `show`, `validate`.

### `report generate`

Generate a bounded derived report from evidence IDs or saved investigations.

```text
usage: locard report generate [--json | --text]
                              (--evidence EVIDENCE_IDS | --investigation INVESTIGATION_IDS)
                              [--transcript-root TRANSCRIPT_ROOT] --output
                              OUTPUT [--profile {technical,executive}]
                              [--redact {none,identifiers}]
                              [--include-source-locations]
                              [--case-name CASE_NAME]
                              [--case-identifier CASE_IDENTIFIER]
                              [--analyst-name ANALYST_NAME]
                              [--organization ORGANIZATION] [--title TITLE]
                              [--scope-note SCOPE_NOTE]
                              [--max-claims MAX_CLAIMS]
                              [--max-timeline MAX_TIMELINE]
                              [--seconds SECONDS] [--llm-narrative]
                              [--endpoint ENDPOINT] [--no-color] [--force]
                              [--page | --append FILE]
```

Interactive output defaults to text; CLI output defaults to JSON. Explicit evidence IDs and saved investigation IDs are alternative input modes. --output here is the report bundle directory, not generic text redirection.

| Argument / option | Meaning | Accepted value / default |
|---|---|---|
| `-h, --help` | Display help and exit (accepted even when omitted from ordinary help). |  |
| `--json` | Structured generation result | Default: True |
| `--text` | Human generation result | Default: True |
| `--evidence` | Explicit evidence ID (repeatable); not a complete investigation | Repeatable; Default: unset |
| `--investigation` | Same-state V4 investigation ID (repeatable) | Repeatable; Default: unset |
| `--transcript-root` | Directory containing saved investigation transcripts. | Default: unset |
| `--output` | New report directory under an existing parent | Required; Default: unset |
| `--profile` | Browser profile filter; report generate instead selects the report audience profile. | Choices: technical, executive; Default: technical |
| `--redact` | Output-only report redaction policy. | Choices: none, identifiers; Default: none |
| `--include-source-locations` | Include recorded source locations in report output. | Default: False |
| `--case-name` | Report case-name label. | Default: unset |
| `--case-identifier` | Report case identifier label. | Default: unset |
| `--analyst-name` | Report analyst label. | Default: unset |
| `--organization` | Report organization label. | Default: unset |
| `--title` | Report title. | Default: unset |
| `--scope-note` | Analyst-supplied report scope note. | Default: unset |
| `--max-claims` | Maximum report claims. | Type: int; Default: 100 |
| `--max-timeline` | Maximum report timeline entries. | Type: int; Default: 500 |
| `--seconds` | Time window or operation budget in seconds, according to this command. | Type: int; Default: 300 |
| `--llm-narrative` | Optional grounded narrative composition through local MiniCPM; rejected output falls back safely | Default: False |
| `--endpoint` | Invocation-specific local model endpoint override; not a persistent provider change. | Default: unset |
| `--no-color` | Disable terminal styling (also respects NO_COLOR) | Default: unset |
| `--force` | Permit replacing an existing derived output file without confirmation | Default: unset |
| `--page` | Review output with the internal pager (Up/Down, PgUp/PgDn, Home/End, Q) | Default: unset |
| `--append` | Append rendered output to a derived UTF-8 file | Default: unset |

Choose at most one: `--json`, `--text`.

Choose exactly one: `--evidence`, `--investigation`.

Choose at most one: `--page`, `--append`.

### `report show`

Inspect the summary of an existing report bundle.

```text
usage: locard report show [--no-color] [--force]
                          [--page | --output FILE | --append FILE]
                          directory
```

| Argument / option | Meaning | Accepted value / default |
|---|---|---|
| `-h, --help` | Display help and exit (accepted even when omitted from ordinary help). |  |
| `directory` | Report bundle directory, not a report ID | Required; Default: unset |
| `--no-color` | Disable terminal styling (also respects NO_COLOR) | Default: unset |
| `--force` | Permit replacing an existing derived output file without confirmation | Default: unset |
| `--page` | Review output with the internal pager (Up/Down, PgUp/PgDn, Home/End, Q) | Default: unset |
| `--output` | Write a derived UTF-8 file; existing files require confirmation or --force | Default: unset |
| `--append` | Append rendered output to a derived UTF-8 file | Default: unset |

Choose at most one: `--page`, `--output`, `--append`.

### `report validate`

Validate a report bundle; optionally check its case compatibility and evidence grounding.

```text
usage: locard report validate [--case CASE]
                              [--transcript-root TRANSCRIPT_ROOT] [--no-color]
                              [--force]
                              [--page | --output FILE | --append FILE]
                              directory
```

--case must be supplied explicitly for case fingerprint/grounding checks; the active shell case is not silently substituted.

| Argument / option | Meaning | Accepted value / default |
|---|---|---|
| `-h, --help` | Display help and exit (accepted even when omitted from ordinary help). |  |
| `directory` | Report bundle directory. | Required; Default: unset |
| `--case` | Optional existing schema-3 case for fingerprint and grounding checks | Default: unset |
| `--transcript-root` | Original transcripts for investigation-report grounding | Default: unset |
| `--no-color` | Disable terminal styling (also respects NO_COLOR) | Default: unset |
| `--force` | Permit replacing an existing derived output file without confirmation | Default: unset |
| `--page` | Review output with the internal pager (Up/Down, PgUp/PgDn, Home/End, Q) | Default: unset |
| `--output` | Write a derived UTF-8 file; existing files require confirmation or --force | Default: unset |
| `--append` | Append rendered output to a derived UTF-8 file | Default: unset |

Choose at most one: `--page`, `--output`, `--append`.

### `source`

Manage evidence sources

```text
usage: locard source [--no-color] [--force]
                     [--page | --output FILE | --append FILE]
                     {list,show,create,update,assign} ...
```

| Argument / option | Meaning | Accepted value / default |
|---|---|---|
| `-h, --help` | Display help and exit (accepted even when omitted from ordinary help). |  |
| `--no-color` | Disable terminal styling (also respects NO_COLOR) | Default: unset |
| `--force` | Permit replacing an existing derived output file without confirmation | Default: unset |
| `--page` | Review output with the internal pager (Up/Down, PgUp/PgDn, Home/End, Q) | Default: unset |
| `--output` | Write a derived UTF-8 file; existing files require confirmation or --force | Default: unset |
| `--append` | Append rendered output to a derived UTF-8 file | Default: unset |

Choose at most one: `--page`, `--output`, `--append`.

Required subcommand: `list`, `show`, `create`, `update`, `assign`.

### `source list`

List analyst-defined and automatically created evidence sources.

Display abbreviations (...) are not command IDs; use --ids for full copyable IDs or --json for complete values.

```text
usage: locard source list [--json] [--limit LIMIT] [--offset OFFSET] [--ids]
                          [--no-color] [--force]
                          [--page | --output FILE | --append FILE]
```

| Argument / option | Meaning | Accepted value / default |
|---|---|---|
| `-h, --help` | Display help and exit (accepted even when omitted from ordinary help). |  |
| `--json` | Request structured JSON output. | Default: False |
| `--limit` | Maximum returned rows/candidates. | Type: int; Default: 100 |
| `--offset` | Number of results to skip for pagination. | Type: int; Default: 0 |
| `--ids` | Show full copyable source IDs below the compact table; --json also retains complete values | Default: False |
| `--no-color` | Disable terminal styling (also respects NO_COLOR) | Default: unset |
| `--force` | Permit replacing an existing derived output file without confirmation | Default: unset |
| `--page` | Review output with the internal pager (Up/Down, PgUp/PgDn, Home/End, Q) | Default: unset |
| `--output` | Write a derived UTF-8 file; existing files require confirmation or --force | Default: unset |
| `--append` | Append rendered output to a derived UTF-8 file | Default: unset |

Choose at most one: `--page`, `--output`, `--append`.

### `source show`

Inspect one source and its recorded provenance.

```text
usage: locard source show [--json] [--limit LIMIT] [--offset OFFSET]
                          [--details] [--no-color] [--force]
                          [--page | --output FILE | --append FILE]
                          source_id
```

| Argument / option | Meaning | Accepted value / default |
|---|---|---|
| `-h, --help` | Display help and exit (accepted even when omitted from ordinary help). |  |
| `--json` | Request structured JSON output. | Default: False |
| `source_id` | Full immutable Locard source ID. | Required; Default: unset |
| `--limit` | Maximum returned rows/candidates. | Type: int; Default: 100 |
| `--offset` | Number of results to skip for pagination. | Type: int; Default: 0 |
| `--details` | Existing structured provenance detail, paginated with --limit/--offset; --json is equivalent | Default: False |
| `--no-color` | Disable terminal styling (also respects NO_COLOR) | Default: unset |
| `--force` | Permit replacing an existing derived output file without confirmation | Default: unset |
| `--page` | Review output with the internal pager (Up/Down, PgUp/PgDn, Home/End, Q) | Default: unset |
| `--output` | Write a derived UTF-8 file; existing files require confirmation or --force | Default: unset |
| `--append` | Append rendered output to a derived UTF-8 file | Default: unset |

Choose at most one: `--page`, `--output`, `--append`.

### `source create`

Create an analyst source identity for explicit reuse during ingestion.

```text
usage: locard source create [--json] [--name NAME] [--hostname HOSTNAME]
                            [--user USER] [--volume-root VOLUME_ROOT]
                            [--no-color] [--force]
                            [--page | --output FILE | --append FILE]
```

| Argument / option | Meaning | Accepted value / default |
|---|---|---|
| `-h, --help` | Display help and exit (accepted even when omitted from ordinary help). |  |
| `--json` | Request structured JSON output. | Default: False |
| `--name` | Source display name. | Default: unset |
| `--hostname` | Hostname filter; on source/ingest commands, analyst-supplied hostname assertion. | Default: unset |
| `--user` | User filter; on source/ingest commands, analyst-supplied user assertion. | Default: unset |
| `--volume-root` | Analyst-supplied original volume root; not the mounted evidence location. | Default: unset |
| `--no-color` | Disable terminal styling (also respects NO_COLOR) | Default: unset |
| `--force` | Permit replacing an existing derived output file without confirmation | Default: unset |
| `--page` | Review output with the internal pager (Up/Down, PgUp/PgDn, Home/End, Q) | Default: unset |
| `--output` | Write a derived UTF-8 file; existing files require confirmation or --force | Default: unset |
| `--append` | Append rendered output to a derived UTF-8 file | Default: unset |

Choose at most one: `--page`, `--output`, `--append`.

### `source update`

Preview or apply changes to a source's analyst-supplied assertions.

```text
usage: locard source update [--json] [--name NAME] [--hostname HOSTNAME]
                            [--user USER] [--volume-root VOLUME_ROOT] [--yes]
                            [--no-color] [--force]
                            [--page | --output FILE | --append FILE]
                            source_id
```

Without confirmation, noninteractive usage previews; --yes applies the mutation. This changes analyst assertions, not original evidence fields.

| Argument / option | Meaning | Accepted value / default |
|---|---|---|
| `-h, --help` | Display help and exit (accepted even when omitted from ordinary help). |  |
| `--json` | Request structured JSON output. | Default: False |
| `source_id` | Full immutable Locard source ID. | Required; Default: unset |
| `--name` | Source display name. | Default: unset |
| `--hostname` | Hostname filter; on source/ingest commands, analyst-supplied hostname assertion. | Default: unset |
| `--user` | User filter; on source/ingest commands, analyst-supplied user assertion. | Default: unset |
| `--volume-root` | Analyst-supplied original volume root; not the mounted evidence location. | Default: unset |
| `--yes` | Apply without interactive confirmation; otherwise confirm in the shell or preview in scripts | Default: False |
| `--no-color` | Disable terminal styling (also respects NO_COLOR) | Default: unset |
| `--force` | Permit replacing an existing derived output file without confirmation | Default: unset |
| `--page` | Review output with the internal pager (Up/Down, PgUp/PgDn, Home/End, Q) | Default: unset |
| `--output` | Write a derived UTF-8 file; existing files require confirmation or --force | Default: unset |
| `--append` | Append rendered output to a derived UTF-8 file | Default: unset |

Choose at most one: `--page`, `--output`, `--append`.

### `source assign`

Preview or apply an explicit retrospective source-to-file assignment.

```text
usage: locard source assign [--json] [--yes] [--file-hash FILE_HASH]
                            [--path PATH]
                            [--confirmation-fingerprint CONFIRMATION_FINGERPRINT]
                            --reason REASON [--no-color] [--force]
                            [--page | --output FILE | --append FILE]
                            source_id
```

Requires --path and/or --file-hash at runtime. Paths select recorded provenance, not a new filesystem scan. Review the selection and fingerprint before using --yes.

| Argument / option | Meaning | Accepted value / default |
|---|---|---|
| `-h, --help` | Display help and exit (accepted even when omitted from ordinary help). |  |
| `--json` | Request structured JSON output. | Default: False |
| `source_id` | Full immutable Locard source ID. | Required; Default: unset |
| `--yes` | Apply without interactive confirmation; otherwise confirm in the shell or preview in scripts | Default: False |
| `--file-hash` | Explicit existing file SHA-256; repeat or combine with --path (deduplicated union) | Repeatable; Default: unset |
| `--path` | Recorded absolute Windows file/directory path; repeatable, no filesystem scan or wildcards. Requires --path or --file-hash. | Repeatable; Default: unset |
| `--confirmation-fingerprint` | Require the case fingerprint returned by a reviewed preview before applying | Default: unset |
| `--reason` | Reason for retrospective assignment (does not reconstruct ingestion) | Required; Default: unset |
| `--no-color` | Disable terminal styling (also respects NO_COLOR) | Default: unset |
| `--force` | Permit replacing an existing derived output file without confirmation | Default: unset |
| `--page` | Review output with the internal pager (Up/Down, PgUp/PgDn, Home/End, Q) | Default: unset |
| `--output` | Write a derived UTF-8 file; existing files require confirmation or --force | Default: unset |
| `--append` | Append rendered output to a derived UTF-8 file | Default: unset |

Choose at most one: `--page`, `--output`, `--append`.

### `activity`

Review and verify analyst activity

```text
usage: locard activity [--limit LIMIT] [--json] [--verify] [--no-color]
                       [--force] [--page | --output FILE | --append FILE]
```

| Argument / option | Meaning | Accepted value / default |
|---|---|---|
| `-h, --help` | Display help and exit (accepted even when omitted from ordinary help). |  |
| `--limit` | Maximum returned rows/candidates. | Type: int; Default: 20 |
| `--json` | Request structured JSON output. | Default: False |
| `--verify` | Verify every entry and chain link in the activity sidecar | Default: False |
| `--no-color` | Disable terminal styling (also respects NO_COLOR) | Default: unset |
| `--force` | Permit replacing an existing derived output file without confirmation | Default: unset |
| `--page` | Review output with the internal pager (Up/Down, PgUp/PgDn, Home/End, Q) | Default: unset |
| `--output` | Write a derived UTF-8 file; existing files require confirmation or --force | Default: unset |
| `--append` | Append rendered output to a derived UTF-8 file | Default: unset |

Choose at most one: `--page`, `--output`, `--append`.

### `ai`

Configure AI provider and local runtime

Local uses llama.cpp / llama-server with a compatible user-selected GGUF model. Status distinguishes configuration readiness from runtime state. Cloud use sends bounded model context to the selected provider.

```text
usage: locard ai {provider,status,configure,start,stop,logs} ...
```

| Argument / option | Meaning | Accepted value / default |
|---|---|---|
| `-h, --help` | Display help and exit (accepted even when omitted from ordinary help). |  |

Subcommands: `provider`, `status`, `configure`, `start`, `stop`, `logs`.

### `ai provider`

View or select the AI provider and cloud model.

```text
usage: locard ai provider [--json] [--model MODEL] [--acknowledge-cloud]
                          [{local,openai,anthropic,gemini,deepseek,xai}]
```

| Argument / option | Meaning | Accepted value / default |
|---|---|---|
| `-h, --help` | Display help and exit (accepted even when omitted from ordinary help). |  |
| `--json` | Request structured JSON output. | Default: False |
| `provider` | Provider identifier; omitted views current settings or enters supported configuration flow. | Choices: local, openai, anthropic, gemini, deepseek, xai; Arity: ?; Default: unset |
| `--model` | Explicit cloud model name, without provider prefix | Default: unset |
| `--acknowledge-cloud` | Explicitly acknowledge transmission to the selected cloud provider | Default: False |

### `ai status`

Inspect AI configuration readiness, runtime state and compatibility status.

```text
usage: locard ai status [--json]
```

| Argument / option | Meaning | Accepted value / default |
|---|---|---|
| `-h, --help` | Display help and exit (accepted even when omitted from ordinary help). |  |
| `--json` | Request structured JSON output. | Default: False |

### `ai configure`

Configure AI provider/model settings or local runtime paths and options.

```text
usage: locard ai configure [--json] [--model MODEL] [--acknowledge-cloud]
                           [--executable EXECUTABLE] [--model-path MODEL_PATH]
                           [--context CONTEXT] [--gpu-layers GPU_LAYERS]
                           [--port PORT] [--extra-options EXTRA_OPTIONS]
                           [{local,openai,anthropic,gemini,deepseek,xai}]
```

| Argument / option | Meaning | Accepted value / default |
|---|---|---|
| `-h, --help` | Display help and exit (accepted even when omitted from ordinary help). |  |
| `--json` | Request structured JSON output. | Default: False |
| `provider` | Provider identifier; omitted views current settings or enters supported configuration flow. | Choices: local, openai, anthropic, gemini, deepseek, xai; Arity: ?; Default: unset |
| `--model` | Explicit cloud model name, without provider prefix | Default: unset |
| `--acknowledge-cloud` | Explicitly acknowledge transmission to the selected cloud provider | Default: False |
| `--executable` | Full path to the local llama-server executable. | Default: unset |
| `--model-path` | Local GGUF file for AI configuration. | Default: unset |
| `--context` | Local runtime context size in tokens. | Type: int; Default: unset |
| `--gpu-layers` | Local runtime GPU offload layer setting. | Type: int; Default: unset |
| `--port` | Preferred loopback port; 0 selects a free port | Type: int; Default: unset |
| `--extra-options` | Validated performance options; -ngl/-c update dedicated settings, never duplicate defaults | Default: unset |

### `ai start`

Start the configured Locard-owned local runtime.

```text
usage: locard ai start [--json]
```

| Argument / option | Meaning | Accepted value / default |
|---|---|---|
| `-h, --help` | Display help and exit (accepted even when omitted from ordinary help). |  |
| `--json` | Request structured JSON output. | Default: False |

### `ai stop`

Stop the Locard-owned local runtime.

```text
usage: locard ai stop [--json]
```

| Argument / option | Meaning | Accepted value / default |
|---|---|---|
| `-h, --help` | Display help and exit (accepted even when omitted from ordinary help). |  |
| `--json` | Request structured JSON output. | Default: False |

### `ai logs`

Review local runtime or cloud-provider diagnostics.

```text
usage: locard ai logs [--json] [--raw]
```

| Argument / option | Meaning | Accepted value / default |
|---|---|---|
| `-h, --help` | Display help and exit (accepted even when omitted from ordinary help). |  |
| `--json` | Request structured JSON output. | Default: False |
| `--raw` | Enable session capture and display buffered cloud output; may contain case data | Default: False |

### `ingest`

Ingest evidence directly or launch guided ingestion

```text
usage: locard ingest {all,browser,evtx,mft,prefetch,registry,wizard} ...
```

| Argument / option | Meaning | Accepted value / default |
|---|---|---|
| `-h, --help` | Display help and exit (accepted even when omitted from ordinary help). |  |

Subcommands: `all`, `browser`, `evtx`, `mft`, `prefetch`, `registry`, `wizard`.

### `ingest all`

Import all supported forensic artifacts

```text
usage: locard ingest all [--hostname HOSTNAME] [--user USER]
                         [--volume-root VOLUME_ROOT]
                         [--parser-timeout PARSER_TIMEOUT]
                         [--evtx-hard-timeout EVTX_HARD_TIMEOUT]
                         [--record-size RECORD_SIZE] [--json]
                         [--source SOURCE] [--no-color] [--force]
                         [--page | --output FILE | --append FILE]
                         path
```

| Argument / option | Meaning | Accepted value / default |
|---|---|---|
| `-h, --help` | Display help and exit (accepted even when omitted from ordinary help). |  |
| `path` | Input file/directory for ingestion; path filter for retrieval. | Required; Default: unset |
| `--hostname` | Hostname filter; on source/ingest commands, analyst-supplied hostname assertion. | Default: unset |
| `--user` | User filter; on source/ingest commands, analyst-supplied user assertion. | Default: unset |
| `--volume-root` | Analyst-supplied original volume root; not the mounted evidence location. | Default: unset |
| `--parser-timeout` | EVTX: seconds without parser advancement; other artifacts: wall-clock limit | Type: int; Default: 300 |
| `--evtx-hard-timeout` | EVTX emergency absolute ceiling in seconds (default: 21600) | Type: int; Default: 21600 |
| `--record-size` | Advanced MFT record-size override; leave unset for normal detection. Not meaningful for other parsers. | Type: int; Default: unset |
| `--json` | Request structured JSON output. | Default: False |
| `--source` | Reuse this source ID; omitted in scripts creates a NEW automatic source for this invocation, never inferred or reused | Default: unset |
| `--no-color` | Disable terminal styling (also respects NO_COLOR) | Default: unset |
| `--force` | Permit replacing an existing derived output file without confirmation | Default: unset |
| `--page` | Review output with the internal pager (Up/Down, PgUp/PgDn, Home/End, Q) | Default: unset |
| `--output` | Write a derived UTF-8 file; existing files require confirmation or --force | Default: unset |
| `--append` | Append rendered output to a derived UTF-8 file | Default: unset |

Choose at most one: `--page`, `--output`, `--append`.

### `ingest browser`

Ingest Chrome or Edge browsing history and downloads

```text
usage: locard ingest browser --browser {chrome,edge} --profile PROFILE
                             [--hostname HOSTNAME] [--user USER]
                             [--volume-root VOLUME_ROOT]
                             [--parser-timeout PARSER_TIMEOUT]
                             [--record-size RECORD_SIZE] [--json]
                             [--source SOURCE] [--no-color] [--force]
                             [--page | --output FILE | --append FILE]
                             path
```

| Argument / option | Meaning | Accepted value / default |
|---|---|---|
| `-h, --help` | Display help and exit (accepted even when omitted from ordinary help). |  |
| `path` | Input file/directory for ingestion; path filter for retrieval. | Required; Default: unset |
| `--browser` | Explicit browser product; never inferred | Required; Choices: chrome, edge; Default: unset |
| `--profile` | Explicit browser profile; separate from Windows user | Required; Default: unset |
| `--hostname` | Hostname filter; on source/ingest commands, analyst-supplied hostname assertion. | Default: unset |
| `--user` | User filter; on source/ingest commands, analyst-supplied user assertion. | Default: unset |
| `--volume-root` | Analyst-supplied original volume root; not the mounted evidence location. | Default: unset |
| `--parser-timeout` | EVTX: seconds without parser advancement; other artifacts: wall-clock limit | Type: int; Default: 300 |
| `--record-size` | Advanced MFT record-size override; leave unset for normal detection. Not meaningful for other parsers. | Type: int; Default: unset |
| `--json` | Request structured JSON output. | Default: False |
| `--source` | Reuse this source ID; omitted in scripts creates a NEW automatic source for this invocation, never inferred or reused | Default: unset |
| `--no-color` | Disable terminal styling (also respects NO_COLOR) | Default: unset |
| `--force` | Permit replacing an existing derived output file without confirmation | Default: unset |
| `--page` | Review output with the internal pager (Up/Down, PgUp/PgDn, Home/End, Q) | Default: unset |
| `--output` | Write a derived UTF-8 file; existing files require confirmation or --force | Default: unset |
| `--append` | Append rendered output to a derived UTF-8 file | Default: unset |

Choose at most one: `--page`, `--output`, `--append`.

### `ingest evtx`

Import Windows Event Logs (EVTX)

```text
usage: locard ingest evtx [--hostname HOSTNAME] [--user USER]
                          [--volume-root VOLUME_ROOT]
                          [--parser-timeout PARSER_TIMEOUT]
                          [--evtx-hard-timeout EVTX_HARD_TIMEOUT]
                          [--record-size RECORD_SIZE] [--json]
                          [--source SOURCE] [--no-color] [--force]
                          [--page | --output FILE | --append FILE]
                          path
```

| Argument / option | Meaning | Accepted value / default |
|---|---|---|
| `-h, --help` | Display help and exit (accepted even when omitted from ordinary help). |  |
| `path` | Input file/directory for ingestion; path filter for retrieval. | Required; Default: unset |
| `--hostname` | Hostname filter; on source/ingest commands, analyst-supplied hostname assertion. | Default: unset |
| `--user` | User filter; on source/ingest commands, analyst-supplied user assertion. | Default: unset |
| `--volume-root` | Analyst-supplied original volume root; not the mounted evidence location. | Default: unset |
| `--parser-timeout` | EVTX: seconds without parser advancement; other artifacts: wall-clock limit | Type: int; Default: 300 |
| `--evtx-hard-timeout` | EVTX emergency absolute ceiling in seconds (default: 21600) | Type: int; Default: 21600 |
| `--record-size` | Advanced MFT record-size override; leave unset for normal detection. Not meaningful for other parsers. | Type: int; Default: unset |
| `--json` | Request structured JSON output. | Default: False |
| `--source` | Reuse this source ID; omitted in scripts creates a NEW automatic source for this invocation, never inferred or reused | Default: unset |
| `--no-color` | Disable terminal styling (also respects NO_COLOR) | Default: unset |
| `--force` | Permit replacing an existing derived output file without confirmation | Default: unset |
| `--page` | Review output with the internal pager (Up/Down, PgUp/PgDn, Home/End, Q) | Default: unset |
| `--output` | Write a derived UTF-8 file; existing files require confirmation or --force | Default: unset |
| `--append` | Append rendered output to a derived UTF-8 file | Default: unset |

Choose at most one: `--page`, `--output`, `--append`.

### `ingest mft`

Import NTFS Master File Table (MFT) evidence

```text
usage: locard ingest mft [--hostname HOSTNAME] [--user USER]
                         [--volume-root VOLUME_ROOT]
                         [--parser-timeout PARSER_TIMEOUT]
                         [--record-size RECORD_SIZE] [--json]
                         [--source SOURCE] [--no-color] [--force]
                         [--page | --output FILE | --append FILE]
                         path
```

| Argument / option | Meaning | Accepted value / default |
|---|---|---|
| `-h, --help` | Display help and exit (accepted even when omitted from ordinary help). |  |
| `path` | Input file/directory for ingestion; path filter for retrieval. | Required; Default: unset |
| `--hostname` | Hostname filter; on source/ingest commands, analyst-supplied hostname assertion. | Default: unset |
| `--user` | User filter; on source/ingest commands, analyst-supplied user assertion. | Default: unset |
| `--volume-root` | Analyst-supplied original volume root; not the mounted evidence location. | Default: unset |
| `--parser-timeout` | EVTX: seconds without parser advancement; other artifacts: wall-clock limit | Type: int; Default: 300 |
| `--record-size` | Advanced MFT record-size override; leave unset for normal detection. Not meaningful for other parsers. | Type: int; Default: unset |
| `--json` | Request structured JSON output. | Default: False |
| `--source` | Reuse this source ID; omitted in scripts creates a NEW automatic source for this invocation, never inferred or reused | Default: unset |
| `--no-color` | Disable terminal styling (also respects NO_COLOR) | Default: unset |
| `--force` | Permit replacing an existing derived output file without confirmation | Default: unset |
| `--page` | Review output with the internal pager (Up/Down, PgUp/PgDn, Home/End, Q) | Default: unset |
| `--output` | Write a derived UTF-8 file; existing files require confirmation or --force | Default: unset |
| `--append` | Append rendered output to a derived UTF-8 file | Default: unset |

Choose at most one: `--page`, `--output`, `--append`.

### `ingest prefetch`

Import Windows Prefetch evidence

```text
usage: locard ingest prefetch [--hostname HOSTNAME] [--user USER]
                              [--volume-root VOLUME_ROOT]
                              [--parser-timeout PARSER_TIMEOUT]
                              [--record-size RECORD_SIZE] [--json]
                              [--source SOURCE] [--no-color] [--force]
                              [--page | --output FILE | --append FILE]
                              path
```

| Argument / option | Meaning | Accepted value / default |
|---|---|---|
| `-h, --help` | Display help and exit (accepted even when omitted from ordinary help). |  |
| `path` | Input file/directory for ingestion; path filter for retrieval. | Required; Default: unset |
| `--hostname` | Hostname filter; on source/ingest commands, analyst-supplied hostname assertion. | Default: unset |
| `--user` | User filter; on source/ingest commands, analyst-supplied user assertion. | Default: unset |
| `--volume-root` | Analyst-supplied original volume root; not the mounted evidence location. | Default: unset |
| `--parser-timeout` | EVTX: seconds without parser advancement; other artifacts: wall-clock limit | Type: int; Default: 300 |
| `--record-size` | Advanced MFT record-size override; leave unset for normal detection. Not meaningful for other parsers. | Type: int; Default: unset |
| `--json` | Request structured JSON output. | Default: False |
| `--source` | Reuse this source ID; omitted in scripts creates a NEW automatic source for this invocation, never inferred or reused | Default: unset |
| `--no-color` | Disable terminal styling (also respects NO_COLOR) | Default: unset |
| `--force` | Permit replacing an existing derived output file without confirmation | Default: unset |
| `--page` | Review output with the internal pager (Up/Down, PgUp/PgDn, Home/End, Q) | Default: unset |
| `--output` | Write a derived UTF-8 file; existing files require confirmation or --force | Default: unset |
| `--append` | Append rendered output to a derived UTF-8 file | Default: unset |

Choose at most one: `--page`, `--output`, `--append`.

### `ingest registry`

Import Windows Registry evidence

```text
usage: locard ingest registry [--hostname HOSTNAME] [--user USER]
                              [--volume-root VOLUME_ROOT]
                              [--parser-timeout PARSER_TIMEOUT]
                              [--record-size RECORD_SIZE] [--json]
                              [--source SOURCE] [--no-color] [--force]
                              [--page | --output FILE | --append FILE]
                              path
```

| Argument / option | Meaning | Accepted value / default |
|---|---|---|
| `-h, --help` | Display help and exit (accepted even when omitted from ordinary help). |  |
| `path` | Input file/directory for ingestion; path filter for retrieval. | Required; Default: unset |
| `--hostname` | Hostname filter; on source/ingest commands, analyst-supplied hostname assertion. | Default: unset |
| `--user` | User filter; on source/ingest commands, analyst-supplied user assertion. | Default: unset |
| `--volume-root` | Analyst-supplied original volume root; not the mounted evidence location. | Default: unset |
| `--parser-timeout` | EVTX: seconds without parser advancement; other artifacts: wall-clock limit | Type: int; Default: 300 |
| `--record-size` | Advanced MFT record-size override; leave unset for normal detection. Not meaningful for other parsers. | Type: int; Default: unset |
| `--json` | Request structured JSON output. | Default: False |
| `--source` | Reuse this source ID; omitted in scripts creates a NEW automatic source for this invocation, never inferred or reused | Default: unset |
| `--no-color` | Disable terminal styling (also respects NO_COLOR) | Default: unset |
| `--force` | Permit replacing an existing derived output file without confirmation | Default: unset |
| `--page` | Review output with the internal pager (Up/Down, PgUp/PgDn, Home/End, Q) | Default: unset |
| `--output` | Write a derived UTF-8 file; existing files require confirmation or --force | Default: unset |
| `--append` | Append rendered output to a derived UTF-8 file | Default: unset |

Choose at most one: `--page`, `--output`, `--append`.

### `ingest wizard`

Guided evidence discovery and ingestion

Guided ingestion in the interactive shell; no arguments.

```text
usage: locard ingest wizard
```

Interactive shell only. This parser entry does not make guided setup available to noninteractive scripts.

| Argument / option | Meaning | Accepted value / default |
|---|---|---|
| `-h, --help` | Display help and exit (accepted even when omitted from ordinary help). |  |

## Maintenance and implementation references

This document describes supported interfaces, not a guarantee that every artifact or AI model is compatible. Check command help after upgrading. The accepted parser remains authoritative for syntax.

- [CLI composition](../forensic_assistant/cli.py) and [command catalog](../forensic_assistant/command_catalog.py)
- [Interactive shell](../forensic_assistant/interactive/shell.py) and [guided setup](../forensic_assistant/interactive/setup.py)
- [Artifact ingestion](../forensic_assistant/artifacts/ingest.py)
- [Provider configuration](../forensic_assistant/ai/cli.py)
- [Report commands](../forensic_assistant/reporting/cli.py)
- [Project license](../LICENSE): Apache License 2.0

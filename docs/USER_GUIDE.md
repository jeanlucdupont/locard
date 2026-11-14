# Locard user guide and command reference

This guide describes the current development checkout. Command syntax, choices,
defaults and argument constraints below were checked against the actual parsers.
The application version is defined in `pyproject.toml`; run `locard --version`
or `settings version` inside the shell to identify your installed build. Reinstall after
changing a non-editable checkout so the launcher uses the updated code.
For editable development, source/version-only updates need only `git pull` and
a new process. Launch with `python locard.py`, `python -m forensic_assistant.cli`,
or `locard` using the intended environment. Reinstall for dependency, entry-point,
or packaging changes. `--version-details` distinguishes the effective source
version from installed metadata; a mismatch does not certify dependency readiness.

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

Optional extras are `evidence semantic` and `cloud`. Install only those you intend to use,
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

Launch `python locard.py`. Use `case open PATH`, or `case new` to confirm an empty managed case. Ingest separately with `evidence ingest wizard`; specialized direct modes are under `evidence ingest`.

```text
case status
evidence source list
evidence search --artifact mft --limit 20 --ids
evidence show EVIDENCE_ID
analyze correlate EVIDENCE_ID
investigation start
investigation list
investigation show latest
investigation run latest --question "What does the available evidence establish?"
```

The guided path reviews/edits a saved briefing or starts an adaptive interview, asks for an explicit time window and deterministic assessment approval, then collects separate cloud/decomposition/synthesis choices. The exact engine grant remains mandatory. Cancellation does not roll back earlier confirmed work; plan completion is not forensic completeness.

Review with `investigation history show RUN --transcripts ROOT`. Manage findings with an explicit workspace, UUID and revision. `investigation reason` retains recorded D2 preview/execution and separate proposal capture. Nothing is automatically registered, accepted or published. Reports from current evidence and recorded disclosures have separate validation contracts. Reauthorization creates a new read view, not restart continuation.

## Sources, completeness and interpretation

- The evidence database stores normalized records, source-file hashes/locations,
  artifact-specific records, timestamps, objects and provenance.
- Sources have generated identities; ingestion batches and runs record operations.
  Hostname/user/volume-root assertions are analyst metadata, not automatically
  established historical facts. `evidence source update` changes assertions; it does not
  rewrite original source bytes or artifact observations.
- `evidence source assign` retrospectively associates explicitly selected existing files.
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
evidence semantic status
evidence semantic search "downloaded executable"
```

Semantic search uses a local embedding model and derived per-case index. The
interactive workflow can offer required setup/rebuild; scripts need prepared
assets. Similarity is a retrieval aid, never a forensic correlation or confidence
score. Inspect the returned evidence IDs using deterministic commands.

`investigation advanced current-case` is an advanced/diagnostic interface with explicit budgets; normal
users should start with `!`. Its `--dry-run` may still make one model request.
This differs from the model-free dry runs of `investigation advanced local-query` and `investigation advanced timeline`.

## Outputs, privacy and troubleshooting

- Human-readable versus JSON defaults vary by command and execution mode. Use
  explicit `--json` or `--text` where supported for predictable scripts.
- `--ids` exposes full identifiers in supported human displays; JSON retains IDs.
  `--raw` is command-specific diagnostic output, not an export of an entire disk.
- `--page` uses the internal pager on supported commands. `--output FILE` and
  `--append FILE` produce derived UTF-8 output; `--force` allows replacement.
  Do not assume these switches exist on `evidence export` or `ai`; consult the exact tables.
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
  refresh the editable installation as appropriate. Use `settings version` to verify it.

## Interactive-shell commands

Use the eight families: `case`, `evidence`, `analyze`, `investigation`, `report`, `ai`, `audit`, `settings`. `help` is concise; `help all` includes advanced operations; `help evidence search` shows options. `?` means help; `quit` ends the session. `!` retains the existing advisory/per-tool-approved investigation routing.

## Complete command reference

The generated [shell reference](LOCARD_SHELL_COMMAND_REFERENCE.md) documents every current command, option, choice and default. It replaces the old duplicated flat reference. See [migration and acceptance](LOCARD_6_142_CLI_CONSOLIDATION.md) for approvals, service boundaries and manual checks. Retired command names are not compatibility aliases.

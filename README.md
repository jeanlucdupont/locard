# Locard Forensics - Local AI-Assisted Digital Forensics

|||
| :---: | :--- |
| <img width="80%" alt="image" src="https://github.com/user-attachments/assets/d98f7fa8-76a3-4d37-b796-9d2f9a27f28e" /><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; | Locard is a local Windows forensic investigation CLI, named after Edmond Locard and the principle that **every contact leaves a trace**. It preserves source provenance, normalizes events into SQLite, retrieves evidence deterministically, and optionally asks MiniCPM5 through a local llama.cpp server to analyze retrieved records.<br><br>[Watch Locard's introduction video](https://youtube.com/shorts/UTP8ayRAmsk) <br><br><br><br><br><br><br><br>|

## Reminders

Evidence establishes facts. Model output is analysis, not evidence. Locard is an
investigative aid, not a replacement for validation by a forensic analyst.

SEMANTIC SIMILARITY != FORENSIC EVIDENCE. RAG helps locate evidence; it does not create evidence.

<img width="523" height="359" alt="image" src="https://github.com/user-attachments/assets/a2c59b56-ed24-49d1-a8de-d3eaa55a14c9" />


## Locard V6

**WARNING: This project is not finalized**

The interactive CLI in V6 uses the existing V0-V5 forensic capabilities. Even though this project is its in Version 6, which is supposed to be its final form, there is still a **lot** left to be done. At this stage Locard is a solution that did not pass the test of running in a live environment. It's more like and advanced prototype.

<img width="1623" height="744" alt="image" src="https://github.com/user-attachments/assets/56802195-95b9-4f9d-8dbe-48ddc18ee59e" />

[v3 local semantic setup](docs/v3.md)

[v4 operation, privacy, budgets and replay](docs/v4.md) 




### Locard inputs

Locard reads four types of forensic evidence files.

<img width="370" height="400" alt="image" src="https://github.com/user-attachments/assets/1087ac96-3bb7-496e-8d6a-0f33aa1986be" />



| File type | Examples | What Locard extracts |
| :---: |---|---|
| <img width="50" height="50" alt="image" src="https://github.com/user-attachments/assets/e3ca6ef2-fe73-4ece-8b72-c86ad66db30b" /><br>Windows event logs | .evtx, such as Security.evtx | Events, timestamps, accounts, processes, and other recorded fields |
| <img width="50" height="50" alt="image" src="https://github.com/user-attachments/assets/1217ed71-79ad-4e78-8bce-b8de686b1a09" /><br>NTFS Master File Table | Extracted $MFT | File/directory metadata, filenames, parent references, sizes, and timestamps |
| <img width="50" height="50" alt="image" src="https://github.com/user-attachments/assets/16469abf-fc15-4ca6-a520-0fc3f9181288" /><br>Windows Prefetch | .pf files | Executable names, recorded run counts/times, referenced filenames, and volume metadata |
| <img width="50" height="50" alt="image" src="https://github.com/user-attachments/assets/c6117fc9-f49e-49a7-bd04-c2a7f8b88bc2" /><br>Windows Registry hives | SYSTEM, SOFTWARE, SAM, SECURITY, NTUSER.DAT, UsrClass.dat | Keys, values, key last-write timestamps, and selected forensic artifacts |


Locard expects already extracted artifacts. It is not designed to run on the compromised machine (That would break the chain of custody). Moreover, Locard does not directly mount disk images such as E01, RAW, or VHD, parse memory dumps or packet captures, or analyze arbitrary PDF/Word documents. Registry transaction-log replay and SAM/SECURITY decryption are also unsupported. If your evidence is stored in a disk image, you can use an external forensic tool to mount or extract the filesystem before providing the relevant artifacts to Locard. See list below.

| Tool | Description | Repository |
| --- | --- | --- |
| **ntfsdump** | Extracts files directly from NTFS disk images and supports formats including RAW, E01, VHD/VHDX, and VMDK. | [sumeshi/ntfsdump](https://github.com/sumeshi/ntfsdump?utm_source=gemini) |
| **imagemounter** | Python-based forensic image mounting utility supporting multiple forensic image formats through established forensic tools. | [ralphje/imagemounter](https://github.com/ralphje/imagemounter?utm_source=gemini) |
| **xmount** | Provides read-only access and conversion between forensic disk image formats including RAW, EWF/E01, VHD, VDI, and VMDK. | [mika/xmount](https://github.com/mika/xmount?utm_source=gemini) |

### THE LLM DOES NOT EXECUTE COMMANDS OR QUERY THE DATABASE DIRECTLY.

```powershell
locard --db data\case.db investigate-ai 'Inspect PowerShell activity' --no-semantic --explain --json
locard --db data\case.db investigate-ai 'Inspect PowerShell activity' --dry-run
locard --db data\case.db investigation show '<investigation-id>' --explain
locard --db data\case.db investigation replay '<investigation-id>' --no-semantic
```



## Description
### Architecture and workflow


<img width="6040" height="5297" alt="diagram (5)" src="https://github.com/user-attachments/assets/a48d1d86-2aaa-4fea-868b-f8b238182b40" />



Here is another representation of the architecture
<img width="4152" height="2544" alt="locard-runtime (1)" src="https://github.com/user-attachments/assets/54524163-8c67-45b6-ba56-9e4eb93881e5" />


### How it works

Acquire offline files using appropriate forensic acquisition procedures. Locard
parses supplied copies; it does not acquire live hives, unlock files, mount images,
recover deleted content, or replay Registry transaction logs. Missing companion
hives are allowed. `ingest` retains its original EVTX-only behavior. New commands
validate signatures rather than relying on filenames:

```powershell
locard --db data\case.db ingest-mft 'C:\Evidence\filesystem\$MFT' --hostname PC01 --volume-root C:
locard --db data\case.db ingest-prefetch C:\Evidence\Prefetch --hostname PC01 --volume-root C:
locard --db data\case.db ingest-registry C:\Evidence\Registry --hostname PC01
locard --db data\case.db ingest-all C:\Evidence --hostname PC01 --json
locard --db data\case.db search --path payload.exe --json
locard --db data\case.db search --artifact registry --json
locard --db data\case.db search --process powershell.exe
locard --db data\case.db timeline --start 2026-09-15T14:30:00Z --end 2026-09-15T14:32:00Z --json
locard --db data\case.db show '<evidence-id>' --raw --json
locard --db data\case.db investigate '<evidence-id>' --json
locard --db data\case.db ask 'Inspect Prefetch powershell.exe' --dry-run
```




Use the active environment's `locard` command or replace it with
`.\.venv\Scripts\python.exe -m forensic_assistant.cli`. Replace placeholder IDs
with complete IDs from search results. `--db` precedes the subcommand.
`--hostname`, `--user`, and `--volume-root` on ingestion are analyst assertions,
stored separately from raw evidence. Apply a directory-wide assertion only when
every contained source shares that context. Conflicting assertions remain visible
and prevent corroboration. Filenames, folders, and the analyst's live environment
never supply missing host, user, timezone, or drive information.

`search` counts evidence records. `timeline` counts timestamp observations and can
show one MFT record repeatedly under distinct SI/FN fields. Stable ordering is UTC,
evidence ID, then timestamp slot. Search combines filters with AND; `--start` and
`--end` supply time bounds. `--artifact` selects a source; the existing
`--artifact-type` timeline option still selects EVTX categories. Registry value
search may use its containing key's time, explicitly marked inherited; unified
timeline rows belong to the key. `around` and `investigate` accept
`--timestamp-slot` from `show` when an anchor has multiple distinct timestamps.
Investigation still retrieves object relationships without choosing an arbitrary
MFT/Prefetch timestamp for temporal neighbors.

### Stable IDs and provenance

| Source | Evidence ID locator | Preserved representation |
|---|---|---|
| EVTX | `EVTX:<sha256>:Offset:<offset>` (unchanged) | Original XML and existing fields |
| MFT | `MFT:<sha256>:Offset:<physical-byte-offset>` | Raw record, physical slot, header/attribute details, all exposed filenames |
| Prefetch | `PREFETCH:<sha256>:File` | Original file bytes, format/metrics, referenced paths and volumes |
| Registry key | `REGISTRY:<sha256>:KeyOffset:<absolute-nk-offset>` | Key path, parent linkage, raw integer last-write |
| Registry value | `REGISTRY:<sha256>:ValueOffset:<absolute-vk-offset>` | Raw bytes, typed safe decoding, containing key linkage |

Registry offsets point to the `nk`/`vk` signature, not the preceding cell-size field.
MFT identity uses physical position, independent of a corrupt or stale header record
number. SHA-256 includes the complete supplied file. Moving an identical source
does not change IDs; changed content creates a new source namespace. First-ingested
`source_file` remains immutable, and `source_locations` records every observed path
for identical file bytes. Parser/extractor versions, locators, warnings, and source
context accompany JSON evidence. Historical EVTX parser versions that were never
recorded remain unknown; migration does not invent them.

### Artifact semantics and limits

- **MFT:** Allocated and unallocated records, sequence numbers, parent references,
  multiple filenames, sizes, and attribute metadata are retained. SI and FN
  creation/modification/MFT-change/access timestamps remain separate, with original
  FILETIME integers and 100 ns precision. Parent sequence mismatch, missing parents,
  cycles, depth limits, and multiple paths remain explicit. Paths are volume-relative
  until an unambiguous analyst drive assertion is supplied. Attribute-list extension
  records remain separate; external/nonresident content is not reconstructed.
  Metadata timestamps alone do not establish download, execution, or user action.
- **Prefetch:** Validated formats 17, 23, 26, 30, and 31 retain executable name,
  identifier, run count, exposed execution slots, referenced filenames, and volume
  metadata. The identifier is not a content hash. Retained execution history is
  incomplete; count interpretation varies, files can be deleted, and Prefetch may
  be disabled or behave differently on servers. Absence does not prove non-execution.
  The Python binding does not expose standalone directory tables; Locard reports
  that limitation and preserves original bytes rather than inventing directories.
- **Registry:** Structural signatures identify SYSTEM, SOFTWARE, SAM, SECURITY,
  NTUSER, and USRCLASS where possible; ambiguous/minimal hives remain UNKNOWN.
  Keys and values retain distinct identities. Last-write belongs to the key,
  never individual value creation. Binary/undecodable values use safe base64;
  expansion strings remain unexpanded. Dirty/corrupt snapshots are flagged;
  logs, deleted-cell recovery, SAM/SECURITY decryption, and transaction replay are
  outside V2. Versioned local extractors cover Run/RunOnce, service ImagePath and
  ServiceDll, Winlogon, startup folders, profiles, USB/device, RDP, and selected
  recent-text locations. They retain key/value links and do not assert execution
  or that a particular ControlSet was active.

Path comparison preserves originals, normalizes case/slashes and unambiguous NT
prefixes, and distinguishes absolute, device, volume-relative, and unexpanded paths.
It never expands environment variables, resolves short names, follows the local
filesystem, or guesses ambiguous unquoted executable paths. Prefetch device paths
can be compared using an explicit drive assertion only when exactly one volume
provides an unambiguous device prefix. Search includes original normalized paths;
MFT absolute-path search also honors an unambiguous drive assertion.

### Correlation, detections, and model context

| Status | Deterministic meaning |
|---|---|
| CONFIRMED | Explicit identity/linkage, such as a key containing a value; not a causation claim |
| CORROBORATED | Independent observations share an exact absolute path, known same host, and compatible timestamp fields |
| POSSIBLE | Partial object/name agreement with missing path, host, or timing support |
| UNRESOLVED | Conflicting host/path assertions, competing matches, incomplete object data, or candidate cap |


### Parser validation and trust boundary

| Package | Pinned version | Upstream license |
|---|---|---|
| [dissect.ntfs](https://pypi.org/project/dissect.ntfs/3.16/) | 3.16 | AGPL-3.0-or-later |
| dissect.cstruct / dissect.util | 4.7 / 3.24 | Apache-2.0 |
| [libscca-python](https://pypi.org/project/libscca-python/20260527/) | 20260527 | LGPL-3.0-or-later |
| [libregf-python](https://pypi.org/project/libregf-python/20260526/) | 20260526 | LGPL-3.0-or-later |


## Interactive and scripted workflows

After installation, run `locard` in a terminal to start an interactive session.
Locard offers the last selected database, or asks for an existing database path.
An existing, structurally valid schema-3 Locard database is required before the
main prompt appears. Enter a path (optionally quoted), choose a recent-case number,
or press Enter, Ctrl+C, or EOF during selection to exit/cancel. Missing, inaccessible,
invalid, and legacy databases are rejected; selection never creates or upgrades a case.
To create a new case, use the existing non-interactive ingestion workflow below.

```text
Locard 0.7.0

Last database:
C:\Cases\workstation-23\forensic.db

Use this database? [Y/n]:

locard[workstation-23/forensic.db]> status
locard[workstation-23/forensic.db]> search --process powershell.exe
locard[workstation-23/forensic.db]> help report generate
locard[workstation-23/forensic.db]> case "C:\Cases\other\forensic.db"
locard[other/forensic.db]> exit
```

The prompt uses the parent directory and database filename, safely escaped and
shortened if necessary. It is a display label, not a persistent case name or unique
identifier. Selection displays the full path; `case` displays it again and offers
recent databases. A failed or cancelled switch retains the old case. If the active
case becomes unavailable, Locard requires reselection before accepting more commands.

Shell-only commands are `help [command [subcommand]]`, `case [path]`, `exit`, and
`quit`. Help comes from the ordinary CLI parser. All forensic commands retain their
existing arguments and implementations; the shell supplies `--db` internally.
Use `case` rather than a global `--db` override. Command-specific model/index/output
options apply only to that command. `report validate` still needs an explicit
`--case` to perform case fingerprint and grounding checks.

Paths with spaces must be quoted in commands. Backslashes are literal. Both single
and double quotes group arguments; double a matching quote inside a quoted argument
to include it literally. Relative paths use the launch working directory; no
shell expansion, environment-variable substitution, shell operators, or Python
execution is provided. Unicode and long local paths are tested. UNC quoting is
supported, but live UNC-share access has not been validated; existing SQLite and
read-only opener restrictions apply. Linked/reparse-point case paths are rejected.

Windows supports bounded in-memory up/down command history and basic editing.
History is cleared on case selection/switching and exit and is never written to disk.
Other terminals use their native input behavior; equivalent editing is not promised.
No autocomplete is included. Ctrl+C clears a line or interrupts an operation; EOF
(on Windows, Ctrl+Z at an empty prompt), `exit`, and `quit` close the shell. Ordinary
argument/command errors return to the prompt; unexpected internal or unconfirmed
cleanup failures terminate visibly. Completed ingestion files remain committed after
an interruption. The current run records interruption and whether its publication
committed; abrupt process/terminal termination can leave a run marked `running`.
That is incomplete state, not a completed acquisition. Partial derived staging is
not a completed semantic index, investigation, or report.

Selection performs bounded structural checks, not evidence-grounding or full database
integrity validation. It does not load models, contact MiniCPM, or compute evidence
fingerprints. Use `status` and `semantic status` explicitly; semantic status can scan
case content. SQLite connections and forensic workers are command-scoped; no model,
controller, report, or database connection is kept for the next case.

**Analyst-side privacy:** `%LOCALAPPDATA%\Locard\ui-state.json` stores at most ten
recent successfully selected absolute database paths, with the most recent first.
Those paths can identify cases. It contains no command history, evidence content,
credentials, model responses, transcripts, or reports. It is unencrypted and inherits
user-profile directory permissions. Writes use a sibling temporary file and atomic
replacement; redirected state paths are rejected. Missing recent cases are not
silently removed or recreated. Malformed state is warned about and preserved, with
persistence disabled for that session. To reset it, exit Locard and deliberately
move/remove that UI-state file; no forensic database needs changing. If the location
is unavailable or saving fails, the session remains usable with a warning.

Non-interactive automation remains available and does not alter recent-case state:

```powershell
locard --db "C:\Cases\workstation-23\forensic.db" status
locard --db "C:\Cases\workstation-23\forensic.db" search --process powershell.exe
locard report show "C:\Reports\example"
```

Commands execute once and preserve their existing exit behavior. Bare `locard` with
redirected input/output fails clearly instead of prompting. Database-independent
commands remain usable without selecting a case through this non-interactive CLI.
Interactive and scripted modes are two interfaces over the same forensic capabilities;
interactive mode adds no forensic authority. No new dependencies are required.

## Setup

### Platform support

Locard is currently developed and tested on Windows. Locard analyzes extracted Windows forensic artifacts and does not fundamentally require the source system to be Windows-mounted or live. Some underlying components are cross-platform, but Linux and macOS execution are not currently tested or officially supported.

### Windows setup

Use Python 3.11 or newer. From this project directory in PowerShell:

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[test]"
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m forensic_assistant.cli --help
```

No activation script is necessary. The implementation environment already has a populated
`.venv`; virtual environments are machine-specific and should be recreated when moved.

Runtime dependencies are pinned in `requirements.txt` and `pyproject.toml`.

Installation downloads packages, but application operation does not require Internet
access. To prepare installation on an isolated workstation, build a wheelhouse on
a compatible connected Windows/Python machine, then transfer the project and wheels:

```powershell
python -m pip wheel --wheel-dir wheelhouse ".[test]"
# On the isolated workstation, after creating a virtual environment:
.\.venv\Scripts\python.exe -m pip install --no-index --find-links wheelhouse "locard-forensics[test]"
```

### Start the local model

Run from your llama.cpp directory, adjusting the model path:

```powershell
llama-server.exe -m models\MiniCPM5-2B-Q4_K_M.gguf -ngl 99 -c 8192 --temp 1.0 --top-p 0.95 --min-p 0.0 --host 127.0.0.1 --port 8080
```

The llama.cpp build must support JSON-schema response formatting. Citation fields
are constrained during generation to the exact evidence IDs supplied, then checked
again locally. This prevents typographical ID drift without trusting model citations.

Locard uses `POST /v1/chat/completions`, requests non-streaming JSON output, sets
temperature 0.2, disables thinking through the model chat template, and limits generation to 1024 tokens. It assumes an 8192-token
context, conservatively bounds the combined prompt to 5600 UTF-8 bytes, and does not
manage or download model weights. Model reliability and latency depend on your build,
chat template, and hardware. Ingestion and all deterministic commands work without it.

Only HTTP loopback addresses are allowed. `localhost` is mapped directly to
`127.0.0.1`; numeric IPv4 loopback and `::1` are supported. No DNS lookup, proxies,
redirects, telemetry, cloud services, or automatic execution of event content are used.
Ensure your local server itself is configured for local-only processing.

## Use
### Ingest and inspect evidence

Run commands from the project directory. `--db` is a global option placed **before**
the subcommand; its default is `data/forensic.db` relative to the current directory.
Use a separate database per investigation. Keep databases outside source evidence folders.

```powershell
.\.venv\Scripts\python.exe -m forensic_assistant.cli ingest 'C:\Evidence'
.\.venv\Scripts\python.exe -m forensic_assistant.cli --db data\case1.db ingest 'C:\Evidence\Security.evtx'
.\.venv\Scripts\python.exe -m forensic_assistant.cli status
```

Discovery is recursive and case-insensitive for `.evtx`; directory symlinks are not
followed. Source files are opened read-only. Ingestion hashes each file, stages parsed
events in a temporary disk-backed SQLite database, rehashes the source, then merges
stable results transactionally in batches. Temporary staging needs free disk space.
Files changed during parsing have their staged results rejected. This detects observed
changes; it does not replace acquisition from a stable, write-protected evidence copy.

Each run reports `complete`, `partial`, `changed`, or `failed`. Parse failures and
checksum warnings are persisted in `ingestion_errors` with available record offsets
and record numbers. Record failures do not prevent parsing later readable records or
other files. Unrecoverable chunk traversal stops that chunk and is reported. No
deleted-record carving or recovery of inactive chunks is implemented. Interrupted
processes can leave `running` entries; a new ingestion safely retries with deduplication.

Checksums are parser checks, not proof of authenticity. Invalid XML is recorded as an
ingestion error and remains recoverable only from the unchanged original file; no
normalized event is manufactured for XML that could not be parsed.

### Deterministic searches

```powershell
.\.venv\Scripts\python.exe -m forensic_assistant.cli search --event-id 4688
.\.venv\Scripts\python.exe -m forensic_assistant.cli search --user bob
.\.venv\Scripts\python.exe -m forensic_assistant.cli search --user 'DOMAIN\bob'
.\.venv\Scripts\python.exe -m forensic_assistant.cli search --process powershell.exe
.\.venv\Scripts\python.exe -m forensic_assistant.cli search --ip '2001:db8::1'
.\.venv\Scripts\python.exe -m forensic_assistant.cli search --kind failed-logons --user bob
.\.venv\Scripts\python.exe -m forensic_assistant.cli search --start '2026-09-15T00:00:00Z' --end '2026-09-16T00:00:00Z'
.\.venv\Scripts\python.exe -m forensic_assistant.cli timeline '2026-09-15T14:30:00Z' --minutes 5
.\.venv\Scripts\python.exe -m forensic_assistant.cli search --limit 100 --offset 100
```

`--kind` accepts `logons`, `failed-logons`, `processes`, `powershell`,
`scheduled-tasks`, `services`, or `account-changes`. Filters combine with AND.
`logons` includes successful, explicit-credential, and privileged logon records;
failed logons have their own query. PowerShell searches include operational records
and normalized `powershell.exe`/`pwsh.exe` process names, without labeling them malicious.

Username searches match the selected normalized actor or target, not every name in
the payload. Bare names match the exact name or a domain-qualified suffix; qualified
names match exactly, case-insensitively. Process searches match a full path or exact
Windows basename, not arbitrary substrings. SQL wildcard characters in user input
are escaped. IP queries cover source and destination and recognize equivalent IPv6
spellings; IPv6 equivalence checks can require scanning rows. No LLM generates SQL.

Time bounds are inclusive. UTC timestamps have fixed nine-digit fractional seconds;
original parser-rendered timestamp strings are also retained (both `T` and space
separators are accepted). Parser-rendered precision may be lower than binary EVTX
FILETIME precision; padding does not manufacture additional precision. Missing, invalid, and timezone-ambiguous
timestamps have NULL UTC values and warnings; they are excluded from timed searches.
Untimed searches include them last. Results sort by UTC timestamp then stable evidence
ID, report total count and truncation, and support `--limit` / `--offset`. Search and
timeline omit raw XML by default; add `--raw` to include it.

Output is JSON, with untrusted control characters escaped. Exit status is 0 for
success (including no matches), 1 for incomplete ingestion/no discovered files, and
2 for invalid input, database errors, or unavailable/invalid model responses.

### Evidence IDs and source paths

```text
EVTX:<full source SHA-256>:Offset:<record byte offset>
```

Copy an ID from a search result:

```powershell
.\.venv\Scripts\python.exe -m forensic_assistant.cli show 'EVTX:<sha256>:Offset:<offset>' --raw
```

The digest identifies the exact source content; the offset identifies the binary
record location. EventRecordID, provider, channel, Event ID, original timestamp, and
parser-rendered XML are preserved. XML is the parser's representation of EVTX binary
XML, not a byte-for-byte replacement for the source file.

**`events.source_file` is the source path used by the ingestion that created that
event.** It is never changed by duplicate ingestion. **`source_locations` is the
authoritative set of all observed paths for identical evidence content.** A copied or
renamed file adds a location while retaining existing event provenance. Different
content at the same path gets a different hash and distinct IDs. `show` returns all
observed source paths. Locations are historical observations, not a guarantee that a
file still exists or contains the same data; verify the hash before re-examination.

### Ask questions

```powershell
.\.venv\Scripts\python.exe -m forensic_assistant.cli ask 'Show me suspicious PowerShell activity'
.\.venv\Scripts\python.exe -m forensic_assistant.cli ask 'What activity involved user bob?'
.\.venv\Scripts\python.exe -m forensic_assistant.cli ask 'Show failed logons for 192.0.2.10'
.\.venv\Scripts\python.exe -m forensic_assistant.cli ask 'What happened around 2026-09-15T14:31:00Z?'
.\.venv\Scripts\python.exe -m forensic_assistant.cli ask 'What happened around 14:31?' --date 2026-09-15
.\.venv\Scripts\python.exe -m forensic_assistant.cli ask 'PowerShell for user bob' --dry-run
.\.venv\Scripts\python.exe -m forensic_assistant.cli ask 'Event ID 4688' --endpoint http://127.0.0.1:8080 --timeout 120
```

The keyword planner recognizes PowerShell, processes, logons, failed/privileged
logons, scheduled tasks, services, account creation/changes, usernames, one IP address,
Event IDs, and timestamps. The displayed plan is reviewable; it is not a general
natural-language interpreter. Multiple activity categories are rejected rather than
silently choosing one. Unsupported questions require a supported concept or manual
search. A time-only question uses an explicit `--date`, a date in the question, or the
sole UTC date in evidence; otherwise it asks for a date. Assumptions are shown in the
plan. Timeline questions use a five-minute window.

`--dry-run` displays the plan and evidence bundle without contacting the model.
Initial ask retrieval defaults to 30 matching records; V1 expands deterministic context
around the first match, retaining other matches as candidates. Bundles report candidate,
sent, and omitted record counts and whether the candidate count is a lower bound.
Long field values are shortened with explicit `truncated_fields`; raw XML is not sent. Narrow the search
or use `show --raw` when details are omitted. Zero matches produce an insufficient-
evidence message without calling the model.

Model answers must be JSON with per-finding evidence IDs, interpretation, confidence,
alternative explanations, and suggested next evidence. Unparseable answers, missing
citations, or references to IDs outside the supplied bundle cause the analysis to be
withheld. There is no automatic retry loop. These structural checks **do not prove
that a cited event supports a claim**, prevent all hallucinations, or make a model
immune to prompt injection. All conclusions require analyst verification. Missing
evidence and incomplete auditing are explicit limitations, never proof of innocence
or compromise. The tool does not automatically store model conclusions as evidence.

## Event coverage and normalization

Mappings are keyed by provider, channel, and Event ID:

| Provider/channel | Explicit event coverage |
|---|---|
| Security-Auditing / Security | 4624, 4625, 4634, 4648, 4672, 4688, 4697, 4698, 4702, 4720, 4728, 4732, 4756 |
| Eventlog / Security | 1102 |
| PowerShell / Operational | 4103, 4104 |
| Sysmon / Operational | 1 process creation, 3 network connections |

Logon/logoff and account-creation usernames select `Target*`; other mapped Security
events select `Subject*`. For 4648, target credentials stay in the original payload.
For group changes, the initiating subject is normalized; group/member details remain
in the payload. Sysmon uses `User`. No SID-to-name resolution is guessed. PowerShell
4103 context text is preserved, but not parsed into an inferred username. Script-block
fragments are kept as separate events and are not automatically reassembled. Sysmon
payload `UtcTime` remains in the payload; normalized time uses System TimeCreated.

Missing values and `-` placeholders normalize to NULL. Numeric PIDs support decimal
and hexadecimal. Raw EventData/UserData leaf values, including repeated names, remain
in `event_data_json`; duplicate names are not arbitrarily selected for normalization.
XML retains hierarchy and attributes. Unknown Event IDs retain basic metadata and
raw XML. A service image string is not treated as proof of process execution.

## Project layout and testing

### Version-control hygiene

The Git repository contains only application source, synthetic unit tests, the SQL
schema, package metadata, and documentation. `.gitignore` uses an explicit allowlist
and excludes the entire `data/` tree, EVTX/forensic artifacts, SQLite databases and
sidecars, model weights, credentials, virtual environments, caches, and temporary
outputs at any depth. Runtime data directories are created locally as needed.
New file types require a deliberate allowlist change. Never force-add evidence or
secrets: Git ignore rules can be bypassed with `git add -f`, and they do not inspect
the contents of allowed source files. Review `git diff --cached` before committing.

```text
forensic_assistant/
  config.py, model.py, cli.py
  ingest/       # parser, provenance staging, explicit mappings
  database/     # SQLite connections, schema, inserts
  retrieval/    # deterministic queries and keyword planner
  llm/          # loopback client, prompts, citation validation
tests/          # parsed XML fixtures and mocked HTTP tests
data/evidence/  # optional location for analyst-supplied evidence copies
```

Run `.\.venv\Scripts\python.exe -m pytest -q`. Unit tests do not require Internet,
real evidence, or MiniCPM. They cover normalization, timestamps, IDs, inserts,
duplicates and path provenance, integrity-change rejection, queries, planner, bundle
formatting, citation validation, endpoint restrictions, and HTTP failure handling.
See `VALIDATION.md` for stage results and separate integration checks.

`database/schema.sql` retains schema version 1 as the historical V0 base schema.
New databases apply the additive schema-2 and schema-3 extensions
from `database/migrations.py` and `database/artifacts.py`; existing V0/V1 databases are rejected. Unsupported
versions are rejected. Changing normalization mappings does not automatically rewrite
existing events. Context extraction version 1 is stored separately in `event_context`.

V2 deliberately excludes embeddings, vector databases, autonomous agents, cloud
services, web interfaces, memory parsing, USN Journal, Amcache, SRUM, browser history,
LNK/Jump Lists, packet capture, and external enrichment. No detection
coverage or forensic completeness is promised by this initial event subset.

## V1 deterministic investigations

Examples below use the installed `locard` entry point. Without environment activation,
use `.\.venv\Scripts\locard.exe` or `.\.venv\Scripts\python.exe -m forensic_assistant.cli`.
All commands default to JSON; `--json` explicitly selects it and `--text` selects
readable output. Text rendering escapes untrusted control characters.

### Filtered timelines and surrounding context

```powershell
locard timeline --start '2026-09-15T14:25:00Z' --end '2026-09-15T14:40:00Z' --hostname PC.example --text
locard timeline --around '2026-09-15T14:31:00Z' --minutes 5 --user 'DOMAIN\bob' --json
locard timeline --around '2026-09-15T14:31:00Z' --process powershell.exe --event-id 4688
locard timeline --around '2026-09-15T14:31:00Z' --artifact-type process --ip 192.0.2.10
locard around '<evidence-id>' --seconds 120 --direction after --json
```

Timeline filters combine with AND. Time bounds are inclusive and equal timestamps
sort by evidence ID; this tie-break is display order, not proof of event causality.
`before` and `after` exclude events at the anchor's exact timestamp because their
relative ordering is unknown. `around` includes both bounds and the anchor.
Evidence-anchored context is restricted to the anchor's normalized hostname. Missing
host or unambiguous time prevents temporal correlation rather than widening the search.

### Process trees

```powershell
locard process-tree --evidence '<process-creation-evidence-id>' --text
locard process-tree --process powershell.exe --around '2026-09-15T14:31:00Z' --hostname PC.example --json
```

Every node is an actual process-creation record with its evidence ID and timestamp.
Text output lists nodes and parent-to-child edges; JSON includes status, supporting
IDs, reasons, limitations, and configured bounds. Ambiguous name/time searches return
candidate IDs; select one explicitly with `--evidence`.

| Status | Deterministic criteria |
|---|---|
| CONFIRMED | Unique same-host explicit parent/process GUID match, compatible timing, and no observed contradictions |
| LIKELY | Unique preceding same-host PID candidate within the configured window; matching parent image; no observed identity conflicts, intervening restart, termination, or PID reuse |
| UNRESOLVED | Missing parent, ambiguous candidates, equal-time PID ordering, contradictory fields, cycles, or exceeded candidate bounds |

Default PID fallback window is 300 seconds (`--pid-window`, maximum one day).
Each node's child search covers 300 seconds (`--seconds`, maximum one day). Graph
defaults are 100 nodes and depth 8 (`--max-nodes`, `--max-depth`). These are explicit
search limits, not assertions about a process lifetime. Long-running parents outside
the PID window remain unresolved unless GUID evidence supports a link. No parent
record is synthesized from a child's reported parent name/PID. Confirmed means
supported by supplied records, not independently authenticated or malicious.

### Authentication and sessions

```powershell
locard logons --user 'DOMAIN\bob' --json
locard logons --ip 192.0.2.10 --hostname PC.example
locard session --logon-id 0x42 --hostname PC.example --around '2026-09-15T14:31:00Z'
locard session --logon-id 0x42 --evidence '<successful-logon-evidence-id>' --json
```

Authentication views include 4624, 4625, 4634, 4647, 4648, and 4672 where available.
V1's projection recognizes 4647 as a logoff request without rewriting its V0 event.
Session IDs are canonical numeric identifiers, scoped by host and time; usernames
alone never join sessions. An observed logoff closes the interval, while a new logon
with the same ID or a restart bounds it. A logoff request does not establish completion.
The fallback ceiling is 24 hours (`--max-hours`, maximum 168); it does not invent a logoff.

Links in compatible observed start/logoff intervals can be CONFIRMED; incomplete
boundaries yield LIKELY, and conflicting account/SID fields yield UNRESOLVED.
Missing restart auditing can still conceal identifier reuse. The same Logon ID on
multiple hosts requires disambiguation. Failed logons never become successful sessions.
For 4688, `created_by_session` uses SubjectLogonId; `runs_in_session` requires an
explicit execution identifier. Explicit credentials associate with the initiating
session and do not prove creation of a target session.

Process-lifetime context recognizes Security 4689 and Sysmon 5 termination markers,
and Security 4608 startup markers, only when already present in supplied EVTX.
No additional artifact types are collected. Host keys fold case and a terminal DNS
dot; aliases are not resolved and attacker-controlled domains are never queried.

### Dynamic detections

```powershell
locard detections --start '2026-09-15T14:25:00Z' --end '2026-09-15T14:40:00Z' --json
locard detections --user 'DOMAIN\bob' --hostname PC.example --severity medium
locard detections --rule LOCARD-AUTH-001 --failure-threshold 5 --failure-window 300
```

| Rule | Observation | Severity |
|---|---|---|
| LOCARD-PROC-001 | Office parent reported for a command-interpreter child | medium |
| LOCARD-PS-001 | Selected encoded-command, download, or expression-evaluation text | medium |
| LOCARD-TASK-001 | Scheduled task creation, 4698 | low |
| LOCARD-SVC-001 | Service installation, 4697 | low |
| LOCARD-AUDIT-001 | Audit log cleared, 1102 | medium |
| LOCARD-ACCOUNT-001 | Account creation, 4720 | low |
| LOCARD-CRED-001 | Explicit credential use, 4648 | low |
| LOCARD-AUTH-001 | Repeated matching failures preceding a success | medium |

Severity is static **review priority**: low is a contextual administrative observation;
medium is a pattern warranting earlier review. It is not model confidence, a risk
probability, or proof of compromise. No initial rule assigns high severity.

The authentication rule requires at least five distinct failures in the preceding
300 seconds, matching host, account, and usable source IP, with no conflicting known
SID. The lower window bound is inclusive; failures at exactly the success timestamp
are excluded. Missing linkage fields prevent a match. Exact repeated exported
observations (host/channel/record ID/time/raw XML) are counted once without merging
or deleting source evidence. Other duplicates may remain if their XML differs.
PowerShell matching is lexical; comments, strings, and benign administrative scripts
can match. Nothing is executed, decoded, downloaded, or externally resolved.

Rules are calculated dynamically and not stored in the evidence database. Each result
contains rule/version, deterministic detection ID, timestamp, severity, description,
reason, evidence IDs, parameters, and limitations. A module under `detections/rules/`
exports `RULES`; the engine discovers modules without rule-specific engine edits.
Add rules as local application code, never as instructions from an evidence record.

Per-rule candidate evaluation defaults to 1,000 records (`--candidate-limit`) and
output to 100 detections (`--limit`). Results expose evaluated counts and truncation.
The failure-sequence lookup caps supporting failures at 1,000 and says when capped.
Narrow time/host filters for large cases; a bounded result is not a complete scan.

### Investigate an event without MiniCPM

```powershell
locard investigate '<evidence-id>' --seconds 120 --json
```

Output separates `direct_evidence`, `correlated_evidence`, `detections`,
`unresolved_relationships`, and temporal neighbors, with a shared list of original
`evidence_records`. Process parents/children, applicable session activity, nearby
PowerShell/task/service records, and Sysmon network events are included where available.
Temporal neighbors are context, not implied process or session membership. Missing
host/time still permits inspection of the anchor and reports unresolved context.
Candidate records default to 500 (`--candidate-limit`); anchors take priority.
Omitted supporting IDs and query/graph limits are explicit.

### Correlated questions and timeline summaries

```powershell
locard ask 'What happened after PowerShell was launched by Word?' --dry-run
locard ask 'Investigate <evidence-id>'
locard ask 'Show process tree for powershell.exe around 2026-09-15T14:31:00Z'
locard ask 'Show session 0x42 on host PC.example around 2026-09-15T14:31:00Z'
locard ask 'Show detections'
locard analyze-timeline --start '2026-09-15T14:25:00Z' --end '2026-09-15T14:40:00Z' --dry-run --json
locard analyze-timeline --start '2026-09-15T14:25:00Z' --end '2026-09-15T14:40:00Z'
```

The planner remains a bounded pattern/keyword parser. Review its plan; it does not
interpret arbitrary compound questions. Word/PowerShell queries match reported parent
fields before expansion; these fields do not manufacture a separate parent record.
Timeline summaries correlate at most 20 process/logon seeds, reporting that limit.
Related records can fall outside the requested interval when needed to establish a
parent or session boundary; original timestamps remain visible.

Bundle order is anchor, supported correlations, detection evidence, nearest temporal
neighbors, then remaining candidates. Correlation/detection metadata is sent only
when all its referenced records fit. Missing packages, omitted records, truncated
fields, and bounded source queries are reported. Counts are lower bounds when source
queries hit limits. The combined system/user prompt stays below 5,600 bytes, reserving
space for the chat template and 1,024 generated tokens in the 8,192-token context.
Thinking remains disabled. Very large anchors produce an actionable error rather
than silently replacing the anchor with unrelated evidence.

`analyze-timeline` returns cited `summary`, `observed_sequence`,
`possible_interpretation`, and `alternative_explanations`, plus gaps and next steps.
Claims are labeled OBSERVED, CORRELATED, HYPOTHESIS, or UNKNOWN. Deterministic supporting
relationship IDs/statuses are attached after model validation; CORRELATED summary
prose backed only by a LIKELY link receives an explicit LIKELY prefix. The validator rejects
unknown citations, hypotheses placed in the observed sequence, and CORRELATED claims
without supporting supplied relationship evidence. This is structural validation,
not proof that the model's interpretation or chosen classification is correct.

Logging configuration and supplied evidence determine what Locard can
reconstruct. No model output is inserted into the evidence database.


## License

Project source license: **Apache-2.0**. See [LICENSE](LICENSE) and
[third-party licensing](THIRD_PARTY_NOTICES.md).


Locard Forensic
Copyright © 2026 Jean-Luc Dupont

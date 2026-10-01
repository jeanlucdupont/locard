# Locard Forensics - Local AI-Assisted Digital Forensics

|||
| :---: | :--- |
| <img width="60%" alt="image" src="https://github.com/user-attachments/assets/d98f7fa8-76a3-4d37-b796-9d2f9a27f28e" /><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; | Locard is a local Windows forensic investigation CLI, named after Edmond Locard and the principle that **every contact leaves a trace**.<br><br>Locard was designed around a foundational principle: **A forensic investigation should never require sending sensitive evidence to an external AI service.** To ensure trust and accuracy in the investigative process, Locard improves reliability through strict systemic safeguards rather than relying on LLM scale. It preserves source provenance, normalizes events into SQLite, retrieves evidence deterministically, and optionally asks MiniCPM5 through a local llama.cpp server to analyze retrieved records.<br><br>[Watch Locard's introduction video](https://youtube.com/shorts/UTP8ayRAmsk) <br><br><br><br><br><br><br><br>|


| Safeguard Mechanism | Description |
|---|---|
| Deterministic Extraction | Keeps the core evidence extraction process strictly deterministic. |
| Data Provenance | Preserves original evidence IDs and their sources throughout the analysis. |
| Context Bounding | Strictly limits and controls the context supplied to the model. |
| Citation Validation | Validates all citations made by the model to ensure they map to real evidence. |
| Clear Distinctions | Distinctly separates verifiable observations, correlations, and detections from AI-generated hypotheses and unknowns. |
| Execution Prevention | Strictly prevents the model from directly executing commands or querying the database. |


## Reminders

Evidence establishes facts. Model output is analysis, not evidence. Locard is an
investigative aid, not a replacement for validation by a forensic analyst.

SEMANTIC SIMILARITY != FORENSIC EVIDENCE. RAG helps locate evidence; it does not create evidence.

<img width="523" height="359" alt="image" src="https://github.com/user-attachments/assets/a2c59b56-ed24-49d1-a8de-d3eaa55a14c9" />


## Locard V6

**WARNING: This project is not finalized**

The interactive CLI in V6 uses the existing V0-V5 forensic capabilities. Even though this project is its in Version 6, which is supposed to be its final form, there is still a **lot** left to be done. At this stage Locard is a solution that did not pass the test of running in a live environment. It's more like and advanced prototype.

<img width="1623" height="744" alt="image" src="https://github.com/user-attachments/assets/56802195-95b9-4f9d-8dbe-48ddc18ee59e" />

## Description
### Architecture and workflow

<img width="4152" height="2544" alt="locard-runtime (1)" src="https://github.com/user-attachments/assets/54524163-8c67-45b6-ba56-9e4eb93881e5" />

### MiniCPM
Locard relies on the **MiniCPM5-2B** base model, which was created and released by OpenBMB (an open-source AI project team backed by ModelBest and Tsinghua University's Natural Language Processing Laboratory).  [https://github.com/openbmb/minicpm](https://github.com/openbmb/minicpm)
<img width="510" height="269" alt="image" src="https://github.com/user-attachments/assets/d689307d-ddd5-42df-ba53-8a63d07339ad" />

MiniCPM5-2B is an incredible, highly optimized model. It packs capabilities typically reserved for much larger models (in the 4B–8B parameter range) into a lightweight 2.5B parameter footprint. This makes it perfectly designed for edge devices, laptops, and local agents. Despite its small size, MiniCPM5-2B punches well above its weight class. On benchmarking suites that measure tool calling, coding, and multi-step reasoning, it frequently matches or beats larger models like Qwen3.5-4B and Granite 4.2 3B, all while consuming a fraction of the VRAM.

By utilizing a small, efficient model like MiniCPM5-2B, Locard makes a fully local workflow practical. Analysts can run the system directly on their laptops without needing access to a massive GPU server. 

Locard does not need a massive general-purpose LLM because the AI is not responsible for uncovering the facts. The forensic facts are produced by deterministic parsers, database queries, correlation logic, and detection rules *before* the model is ever called. Locard deliberately prevents model intelligence from becoming part of the evidence chain, recognizing that simply increasing a model's size does not make its generated statements forensic evidence.

#### The Role of the AI Assistant

Locard does not ask the model to reconstruct an investigation from millions of raw events. Instead, deterministic retrieval and correlation reduce the case down to a small, bounded evidence bundle first.  The model serves as an analysis assistant layered on top of the forensic engine. **It is not the forensic engine itself.** 

| What MiniCPM DOES Do | What MiniCPM DOES NOT Do |
|---|---|
| Summarize retrieved forensic evidence. | Parse raw forensic artifacts. |
| Explain relationships between already identified records. | Generate or execute SQL queries. |
| Propose hypotheses and alternative explanations for observed activities. | Execute system commands. |
| Navigate the investigation alongside the analyst. | Modify evidence in any way. |
| Produce readable, evidence-backed analysis reports. | Decide which records constitute "forensic facts." |

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



### Correlation, detections, and model context

| Status | Deterministic meaning |
|---|---|
| CONFIRMED | Explicit identity/linkage, such as a key containing a value; not a causation claim |
| CORROBORATED | Independent observations share an exact absolute path, known same host, and compatible timestamp fields |
| POSSIBLE | Partial object/name agreement with missing path, host, or timing support |
| UNRESOLVED | Conflicting host/path assertions, competing matches, incomplete object data, or candidate cap |


## How-to

### Investigation output (Locard 0.9.0)

Locard **0.9.1** adds restrained terminal syntax colors: headings and evidence IDs
are emphasized, and keys, strings, numbers, and booleans/null have consistent type
styles. Terminal colors improve readability only; they do not indicate that
evidence is malicious, benign, or significant. Executable names and detection
values do not acquire new severity judgments through coloring.

```text
search --artifact prefetch --no-color
show <evidence-id> --page --no-color
```

Color requires an interactive ANSI-capable terminal. Windows consoles must already
have virtual-terminal processing enabled; uncertain capability falls back to plain
output. `--no-color` disables styling for a command. Starting `locard --no-color`
also starts the banner and interactive session without styling. The presence
of `NO_COLOR`, including an empty value, disables color throughout. The startup
banner follows the same policy without changing its artwork.

Explicit `--json`, `--output`, and `--append` remain plain; exported content never
contains added ANSI styling. The internal pager preserves colors and ignores ANSI
styles when calculating line width. Colors are reset before pager prompts. No
external pager, new dependency, or terminal configuration change is required.
The active-case prompt is bright white, without a background, when color is
enabled; its style resets before typed input. In the interactive shell, use
`color` to report the effective state, `color off` to disable styling, and
`color on` to restore it on a capable terminal. This preference is session-only,
can override startup `--no-color`, and is never saved. `NO_COLOR` remains
authoritative; `color on` explains when it prevents styling. A command-specific
`--no-color` remains supported and does not change the session preference.
Interactive command help omits the repeated color option; `help` and `help color`
document it. Direct CLI help continues listing `--no-color`.

Use `cls` (no arguments) to clear the screen and return to the active-case prompt.
It uses terminal controls or the native Windows console API, never an external
command. Redirected or unsupported terminals receive a short notice instead.
Clearing works independently of the color preference. `help color` and `help cls`
describe these shell-only commands; they are not OS command execution.

### Sources, ingestion batches, and evidence identity (0.10.0)

A case can contain many sources. A **source** is an analyst-defined origin, with
an immutable generated ID and a display name independent of hostname. A **batch**
records one ingestion invocation. Its per-file runs retain their paths, outcomes
and hashes. **Evidence identity** remains content hash plus record locator:
identical content imported from different sources shares evidence IDs while
retaining separate source occurrences. Source membership does not prove a machine's
identity or that an executable ran.

New cases use schema **4**. Schema-3 cases remain readable without automatic
migration. Before using source management or ingesting into a legacy case, explicitly
upgrade it (schema 1, 2 and 3 are supported upgrade inputs):

```text
locard --db case.db case-upgrade --yes
```

The upgrade creates a uniquely named SQLite-consistent backup beside the case,
validates the schema, and applies additive changes transactionally. It preserves
evidence, IDs, existing `source_contexts` and file runs. Historical sources and
batches remain unknown; dates and directories are never used to invent membership.
Keep the backup private: it contains the case's evidence. An upgrade failure rolls
back the transaction; any backup already created is retained. Case selection and
ordinary reads never perform this upgrade.

Inside an active case, or prefixed with `locard --db case.db`:

```text
source create --name "Workstation 01"
source list
source show <source-id> --limit 50 --offset 0
ingest-prefetch extracted-prefetch --source <source-id>
ingest-evtx extracted-events --source <source-id>
source update <source-id> --hostname dfir-lab-01
source update <source-id> --hostname dfir-lab-01 --yes
search --source <source-id>
```

For **non-interactive ingestion without `--source`**, every invocation creates a
new automatic source with an immutable generated ID and a neutral generated
display name. Hostname, user and volume root remain unknown unless supplied using
the existing ingestion arguments; supplied values are recorded as analyst metadata.
The creation basis explicitly records that Locard created the source automatically.
Locard never reuses a source by matching hostname, path, display name, or earlier
imports. To group several commands under one source, explicitly repeat its
`--source` ID. Metadata changes to an existing source use `source update`, not
ingestion metadata flags alongside `--source`.

Interactive case creation asks for a source name and optional metadata. Additional
interactive ingestion offers existing sources or a new source; selection is not
retained as an implicit default for later commands. A blank name produces a neutral
label, never a guessed hostname. Cancelled creation does not activate the new case.

`source update` supports `--name`, `--hostname`, `--user` and `--volume-root`.
Use an empty quoted value to clear optional metadata to unknown. Updates append
revisions linked by supersession; old assertions remain available in `source show`.
Raw evidence and artifact-derived fields are never rewritten. Legacy file-level
assertions remain intact and can still expose conflicts; a new source assertion
does not silently supersede a legacy assertion of uncertain scope.

Without `--yes`, scripted updates and assignments preview the actual scope without
applying it. Interactive mode shows the preview and requests confirmation, even if
`--yes` was supplied. If the case changes after the interactive preview, the action
is rejected so the analyst can review it again. Source commands reuse `--page`,
`--output`, `--append`, `--json` and `--no-color`; JSON remains plain structured data.
`source list` file counts are distinct content hashes, not path or import counts.
`source show` paginates revision history, batches, file occurrences and retrospective
assignments rather than dumping every file by default.

Batches distinguish complete, partial, failed, empty and cancelled operations.
Unconfirmed worker cleanup has its own `cleanup_unconfirmed` outcome and warning.
Already committed evidence survives later failures or cancellation. Abnormal
termination can leave a batch unfinished; `status` reports that limitation rather
than inferring success or retroactively grouping file runs.

For historical evidence, deliberately create a source and select existing file
SHA-256 hashes (shown by `show <evidence-id>`). For example, for the earlier Prefetch
case, repeat `--file-hash` for each of the files you have reviewed:

```text
source create --name "DFIR Lab 01" --hostname dfir-lab-01
source assign <source-id> --file-hash <sha256> --file-hash <another-sha256> --reason "Analyst reviewed selected files"
source assign <source-id> --file-hash <sha256> --file-hash <another-sha256> --reason "Analyst reviewed selected files" --yes
```

There is no assign-everything default. Assignment applies to all records of each
explicitly selected file hash and is labelled **retrospective analyst assignment**;
it creates no historical batch and does not claim that those files were imported
together. One action accepts up to 1,000 hashes. Assigning a hash already belonging
to another source preserves both memberships and exposes ambiguity; it does not
move evidence or select one origin arbitrarily.

`search --source` filters provenance membership. `search --hostname` searches
artifact/active analyst hostname assertions; it remains distinct and may find
records with conflicting assertions, which are shown in their context. The filters
can be combined. Superseded source revisions do not act as current metadata.

`around` requires an unambiguous effective hostname. For source-assigned anchors it
also restricts neighbors to the same unique source; another source is not merged
because its label or analyst hostname matches. Multiple source occurrences or
conflicting source/artifact hostnames block this correlation. An unknown hostname
still blocks it. For historical unassigned anchors, the existing conservative host
checks apply to unassigned neighbors. Returned context distinguishes artifact
hostname fields, analyst assertions and source membership; temporal proximity is
not causal evidence.

`around <evidence-id> --timestamp-slot <slot> --text` presents temporal context
with exact relative times, a selected-slot anchor marker, and shared source,
artifact and timestamp context. Dates and normalized timestamp precision remain
visible. Mixed context is shown per observation. Long object descriptions may be
shortened with `...`; context wraps to terminal width. Use `--text --ids` for full,
unabridged evidence IDs, then `show <id>` for details. `--json` and `--raw` retain
their existing complete structured/detail output (`--raw --text` retains the
legacy detailed text view). `--page`, `--output FILE` and `--append FILE` work with
the compact view; file exports contain no color codes. Shared context describes
only the displayed rows, not observations outside the current result page.
If several slots have the same anchor time, select `--timestamp-slot` to identify
one anchor row; Locard does not arbitrarily mark all slots as the anchor.

Source revisions, batches and assignments participate in the content fingerprint.
Changes make dependent semantic indexes, investigations and report/case validation
stale. Rebuild indexes explicitly; historical reports and transcripts are never
rewritten. A migrated case has a different fingerprint even if its raw evidence is
unchanged. Validate historical outputs against their original case snapshot when
appropriate; successful validation still does not prove forensic conclusions.

**Search summarizes. Show explains. Raw exposes.**

Normal deterministic `search` displays compact, escaped record summaries with
complete evidence IDs. Prefetch summaries show the executable, latest retained
execution timestamp, recorded run count, effective host, and a candidate path
when present in the bounded evidence projection. A candidate path is not a proven
executable identity. Other artifact types use their own identifying fields.
Long display fields may be shortened; evidence IDs and stored evidence are not.
Counts, offset, limit, and whether more results exist appear below the results.
Search ordering remains unchanged; a Prefetch record's displayed
latest run does not change its existing search sort order.

Use these commands inside Locard, or prefix them with `locard --db case.db`:

```text
search --artifact prefetch
search --artifact prefetch --raw --page
show <evidence-id> --page
search --artifact prefetch --output prefetch.txt
search --artifact prefetch --raw --output prefetch-details.txt
search --artifact prefetch --json --output results.json
detections --append investigation.txt
timeline --start 2020-01-01T00:00:00Z --end 2020-01-02T00:00:00Z --page
```

`search --process` performs convenient exact matching. These are equivalent
case-insensitive searches for the Prefetch executable `POWERSHELL.EXE`:

```text
search --artifact prefetch --process powershell
search --artifact prefetch --process powershell.exe
```

A bare name without an extension matches that literal name or its `.exe` form.
Explicit filenames, including other extensions such as `tool.com`, stay exact;
existing full-path searches also stay exact. `--process power` does not match
`powershell.exe`, `powercfg.exe`, or `powerpnt.exe`.

`search --process-contains` performs explicit partial matching:

```text
search --artifact prefetch --process-contains power
```

This matches a case-insensitive literal substring of the executable basename and
may return several executable names. It interprets no wildcards or regular
expressions. The two process options are mutually exclusive. Prefetch searches
match the represented executable, not arbitrary referenced files; a full-path
match still uses a candidate path and does not prove that path's identity.
Matching alone implies neither suspiciousness nor execution: existing MFT
filename and Registry target roles retain their artifact-specific meaning.
Other filters and JSON structure are unchanged. This convenience applies to
deterministic `search`, including the interactive shell; timeline and AI retrieval
retain their existing matching behavior.

`show` retains existing detailed evidence output. `--raw` retains the existing
verbose/raw representation, including its established retrieval bounds.
Explicit `--json` preserves the structured interface; scripts consuming search
results should request it. Other commands keep their existing default rendering.

| Destination | Behavior |
|---|---|
| Default | Render to the terminal |
| `--page` | Internal Python pager: Space advances a page, Enter a line, Q/q quits; Ctrl+C also leaves paging |
| `--output FILE` | Write UTF-8 output, replacing an existing derived file through a temporary file and atomic replacement |
| `--append FILE` | Append UTF-8 output, creating a missing file; separate successive outputs with a newline |

The pager uses terminal dimensions with a fallback and restores console input
mode when it exits. If stdin or stdout is not a terminal, it prints normally
without waiting for keys. Paging wraps long display lines; it does not change
stored evidence. Explicit `--json --page` is rejected. `--page`, `--output`, and
`--append` are mutually exclusive. No external pager or shell is executed.

File paths may be relative to the caller's directory or absolute; quote paths
containing spaces. Parent directories must already exist. Confirmations and errors
go to stderr; file output is not also dumped to stdout. Write failures return a
nonzero status and leave the interactive shell usable. Replacement is atomic;
an interrupted or failed append may leave a partial appended section. Appending
JSON produces separate JSON documents, not one combined JSON array.

Output guards reject the active/explicit case database and its SQLite sidecars,
recorded evidence paths (including hard-link aliases), recognized artifact/SQLite
files, symbolic-link/junction destinations, and overlapping command inputs.
These are safeguards for known inputs, not a way to identify every possible
unregistered evidence file. Choose a separate analyst output path.

For nested commands, destination options can follow the final subcommand. One
existing option is deliberately preserved: `report generate --output` still names
the new report **bundle directory**. To also save its console result, put the new
file destination before `generate`:

```text
report --output report-result.txt generate --evidence <evidence-id> --output report-bundle
report show report-bundle --output report-summary.txt
```

Locard's interactive interface is a command interpreter, not a general-purpose
operating-system shell. Use these explicit options instead of `| more`, `>`, or
`>>`; pipelines, shell operators, substitutions, and arbitrary execution remain
unsupported. Run `help search` inside Locard or `locard search --help` for options.

### Platform support

Locard is currently developed and tested on Windows. Locard analyzes extracted Windows forensic artifacts and does not fundamentally require the source system to be Windows-mounted or live. Some underlying components are cross-platform, but Linux and macOS execution are not currently tested or officially supported.


### Run the local AI model

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


### Install 

```powershell
git clone https://github.com/jeanlucdupont/locard.git
cd locard
.\install.ps1
```

### Two modes

Locard can run with arguments or without arguments. Without argument, Locard switches to interactive (shell) mode.

```
.\locard.ps1
```

<img width="558" height="349" alt="image" src="https://github.com/user-attachments/assets/e32a646d-c68a-4622-9c86-4eefde74f193" />



## Use

### General principles

<img width="1774" height="887" alt="image" src="https://github.com/user-attachments/assets/828be5d8-5c56-4735-8604-900a24462e7e" />

### Create a case

To be documented

### Ingest evidence

To be documented

### Deterministic investigation

To be documented

### Ask AI

To be documented

### Generate report

To be documented


## License

Project source license: **Apache-2.0**. See [LICENSE](LICENSE) and
[third-party licensing](THIRD_PARTY_NOTICES.md).


Locard Forensic
Copyright © 2026 Jean-Luc Dupont

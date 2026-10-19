# Locard Forensics - Local AI-Assisted Digital Forensics

Long interactive operations use a shared delayed activity line (`⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏`):
advisory context/model waits, bounded investigation phases, guided evidence
discovery and CSV dumps. Animation starts after 300 ms and refreshes every 100 ms;
fast operations stay quiet. Existing ingestion file/record counters are preserved.
It clears before approval input and final output. Color-disabled sessions can
still animate on a capable terminal; redirected, JSON, paged and file output do
not animate. DEBUG logging disables animation to keep diagnostics readable.
See [bounded investigation diagnostics](docs/v4.md#budgets-and-termination).

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

The bounded `investigate-ai` engine is assessed in [the investigation architecture
and safety review](V4.md), including its tool inventory, limits, privacy boundaries
and requirements for future reuse. The normal `!` interface supports advisory guidance and bounded investigation with per-tool approval.

For pre-model startup failures, enable the standard Python DEBUG logger
`forensic_assistant.investigation_ai`. It reports content-free phase timings,
remaining overall time and child-watchdog time. See the [startup diagnosis and
PowerShell acceptance commands](V4.md#664-startup-correction--pending-manual-acceptance).
Startup uses the remaining overall budget; it is not capped by the 45-second
tool-operation watchdog. Fingerprints still cover all authoritative case content.

`investigate-ai --max-seconds` uses one deadline, including local model calls,
worker startup, tools, transcript finalization and analyst approval waiting.
Cancellation/timeout has an additional maximum five-second cleanup allowance.
Inspect the returned `termination`; command completion does not mean a supported
forensic conclusion. Interrupted runs explicitly mark their transcript incomplete.

Investigation transcripts default to `DATABASE.investigations`. They are sensitive
local **derived output, not evidence**: questions, model responses, evidence
excerpts, IDs and source metadata may be retained. `--transcripts` must name local
storage without traversal, symlinks or Windows reparse redirection. Use a directory
with appropriate analyst-controlled permissions; Locard does not change its ACLs.
Locard does not transmit transcripts externally. Analysts control retention and
deletion according to policy; there is no automatic deletion schedule.

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

Locard reads 5 types of forensic evidence files.

<img width="450" height="365" alt="image" src="https://github.com/user-attachments/assets/8395d0a8-464f-4d49-a7dd-7a94538a933a" />



| File type | Examples | What Locard extracts |
| :---: |---|---|
| <img width="50" height="50" alt="image" src="https://github.com/user-attachments/assets/4445a55a-72fe-4f53-8c14-e5c27bab712e" /><br>Windows event logs | .evtx, such as Security.evtx | Events, timestamps, accounts, processes, and other recorded fields |
| <img width="50" height="50" alt="image" src="https://github.com/user-attachments/assets/e3a3eae7-834e-4264-b6ef-2878e5de2512" /><br>NTFS Master File Table | Extracted $MFT | File/directory metadata, filenames, parent references, sizes, and timestamps |
| <img width="50" height="50" alt="image" src="https://github.com/user-attachments/assets/db97b093-5e9b-47c6-8eaf-cf64f4544a14" /> <br>Windows Prefetch | .pf files | Executable names, recorded run counts/times, referenced filenames, and volume metadata |
| <img width="50" height="50" alt="image" src="https://github.com/user-attachments/assets/0ecccec0-91bd-4f05-b28d-2c4b78282b2e" /> <br>Windows Registry hives | SYSTEM, SOFTWARE, SAM, SECURITY, NTUSER.DAT, UsrClass.dat | Keys, values, key last-write timestamps, and selected forensic artifacts |
|<img width="50" height="50" alt="image" src="https://github.com/user-attachments/assets/cd9a816d-b40f-4878-b5f3-0b451968d7b9" /><br>Browser logs | SYSTEM, SOFTWARE, SAM, SECURITY, NTUSER.DAT, UsrClass.dat | XXXXXX | History | 


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
The active-case prompt uses the configured prompt style when color is
enabled; its style resets before typed input. In the interactive shell, use
`color` to report the effective state, `color off` to disable styling, and
`color on` to restore it on a capable terminal. This preference is session-only,
can override startup `--no-color`, and is never saved. `NO_COLOR` remains
authoritative; `color on` explains when it prevents styling. A command-specific
`--no-color` remains supported and does not change the session preference.
Interactive command help omits the repeated color option; `help` and `help color`
document it. Direct CLI help continues listing `--no-color`.

The command prompt shows only the selected database basename, for example
`[mixeddesktop]>` or `[my 3rd case]>`, retaining the current prompt style. A valid case
is still required before entering the command loop. Normal `exit`, `quit`, or EOF
prints `Locard session ended.` and the selected case path, if any. Ctrl+C continues
to cancel the current input or command without ending the session.

Human path fields retain literal separators and printable Unicode while escaping
terminal controls. Structured JSON retains standard JSON escaping.

Use `cls` (no arguments) to clear the screen and return to the active-case prompt.
It uses terminal controls or the native Windows console API, never an external
command. Redirected or unsupported terminals receive a short notice instead.
Clearing works independently of the color preference. `help color` and `help cls`
describe these shell-only commands; they are not OS command execution.

### Guided case and evidence setup

The startup menu offers **[1] Create a case**, **[2] Open a case**, and **[3] Exit**.
Create a case opens guided setup; `new-case` opens it from the interactive shell.
`case new` and direct ingestion commands remain available. The wizard
creates/ingests, then returns to the normal prompt for investigation and reporting.
It never calls a model automatically.

With a case open, type `ingest wizard` to append evidence using the same guided
scan or manual evidence selection. It preserves the active case, human case name,
analyst/organization labels and prior evidence. It never creates another workspace
or calls a model. `help ingest wizard` describes the workflow; it takes no arguments.
`ingest-wizard` and `add-evidence` remain compatibility aliases with a short notice.
Navigation help and completion prefer `ingest wizard`.

Use the existing direct `ingest mft`, `ingest registry`, `ingest prefetch`,
`ingest evtx`, `ingest browser`, and `ingest all` commands when you already know
the evidence and want explicit command options. `ingest wizard` guides discovery
and selection. Manual mode asks for an artifact type and an evidence file or
folder, then proceeds to metadata and confirmation without repeating the scan
selection menu. Browser profile selection remains explicit.

Incremental summaries show only artifact types involved in this operation; scan
summaries can include discovered types deliberately not selected. A single complete
file with new records and no duplicates, errors or limitations gets a terse
completion: the overall outcome and elapsed time follow the category result.
Multi-file, duplicate, partial, unsupported and failed outcomes retain useful
detail. Completion omits redundant case/workspace labels and source paths;
source provenance remains available through the source/detail commands. Both initial ingestion and guided additions
report whole-second elapsed time, measured with a monotonic clock after final
confirmation through ingestion and summary calculations; navigation time is excluded.
Durations under one second display `<1 sec`.

Review the selected files and confirm `Add selected evidence to this case?` before
anything is persisted. Optional source assertions apply to a new source grouping
this addition; earlier sources are unchanged. Existing duplicate rules still
apply, and duplicate-only additions are reported as adding no new evidence records.
The completion summary covers this addition only. Type `cancel` or decline the
confirmation to return without changes; if interrupted after ingestion starts,
already committed evidence and provenance remain. A mounted `$MFT` that requires
extraction can later be added as an extracted standard file through manual selection.
Direct `ingest <type>` commands remain available with their existing arguments and JSON.

Enter a case name, optional analyst name and optional organization. These are
analyst-supplied labels in the existing derived activity trail, not evidence.
The name determines `%LOCALAPPDATA%\Locard\cases\<sanitized-name>` (alongside
Locard's existing UI configuration). Spaces/unsupported characters become `_`,
repeated underscores collapse, and letters, numbers, hyphens and underscores are
preserved. Existing workspaces require another name; they are never overwritten.
Each workspace contains `case.db`, `reports`, `exports`, and `workspace` directories.
Existing sidecar and explicit report/export paths remain unchanged; evidence is
not copied. External case identifiers remain available in report metadata.

Type `cancel` at any wizard prompt to stop. Enter accepts a displayed default or
leaves optional input blank; required values are requested again. Nothing is created
before final confirmation. Optional source metadata is offered **after** evidence
selection. Hostname, username and original drive remain unknown unless supplied.
One analyst source groups approved files, with individual ingestion batches/runs.
Directory labels never become asserted source identities. Interactive volume-root prompts
accept `C:`/`c:` and normalize a lone ASCII drive letter such as `C` to `C:`.
Malformed values reprompt without discarding the evidence selection; blank means
unknown. Folder paths and UNC paths are not volume roots. This input convenience
does not change direct command-line argument validation.

Choose automatic discovery (default), manual evidence selection, or an empty case.
Automatic discovery checks the supplied directory and at most two container levels
for `Windows/System32`, `Windows/System32/config`, and `Users`. Multiple installations
require selecting one. Root discovery is bounded to 256 directories; inventories to
100,000 entries. Scanning visits known locations only:

- Root `$MFT`;
- SYSTEM, SOFTWARE, SAM and SECURITY hives, NTUSER.DAT and UsrClass.dat;
- Registry `.LOG1`/`.LOG2` companions (classified, **not replayed**);
- Windows Prefetch and Event Log directories;
- Chrome/Edge profile `History` files under accessible Windows user directories.

On Windows, non-elevated scans offer cancellation/restart or explicit continuation
with limited access. Locard never elevates or requests credentials. Administrator
status does not guarantee access. User-profile counts distinguish inaccessible paths
from skipped junction/reparse entries. Details remain available in path review;
recognized unsupported artifacts have their own informational section.

Known browser paths provide product, owner-path label and profile context. A profile
must contain a supported artifact such as `History`. Select **all**, **none**, or
profile numbers explicitly; multiple profiles have no default-to-all. Manual browser
files require explicit product/profile values. Selection confirms browser context,
not a Windows identity. When scanning finds none, the final summary says
`no supported history found`, scoped to accessible scanned locations; this is not
a claim that browser evidence exists nowhere. `not selected` means candidates were
available but not chosen (or that browser discovery was not requested). Existing
snapshot-companion handling is unchanged.

The numbered artifact menu offers all categories, selected categories, path review,
or cancellation. Manual selection uses shared discovery/ingestion, bounded to eight
folder levels. Candidates still require parser validation. An inaccessible mounted
`$MFT` is marked **requires extraction** and excluded from ingestion: Locard requires
an extracted MFT and does not implement raw NTFS access. Other artifacts may proceed.

Final confirmation precedes workspace, database and activity-sidecar creation. Output
must be outside every selected evidence directory. Discovery rejects symlinks/reparse
points and opens evidence only for reading. It writes no evidence-folder files and
does not intentionally change timestamps; OS access-time policy remains outside its
control. Mount evidence read-only when appropriate. Only reviewed files are ingested.

Progress shows completed/selected files, percentage, elapsed time and returned stored
record counts **between files**, with no ETA or fabricated mid-file progress. Capable
terminals reuse one line; fallback output is throttled. Semantic colors distinguish
records, duplicates, partial outcomes and failures. Raw error counters remain intact;
only verified retained-record EVTX header/tail diagnostics are grouped as verification
limitations, separately from other errors.

Completion distinguishes success, limitations, no ingestion, and failed ingestion.
Committed evidence survives later failures. A case with no stored records requires
explicit activation unless an empty case was requested. Cancellation preserves the
previous active case; published databases, committed work and requested directories
are retained. Post-creation guidance explains adding evidence,
investigating with commands, and requesting advisory guidance with `!`.
Case creation success stays green independently of amber limitations or red failures.
Mounted MFT requiring extraction is red, not partial. Human Registry messages explain
that unreplayed logs may leave recent uncommitted changes missing; EVTX messages
distinguish retained records from unsuccessful ingestion. Detailed/raw diagnostics
and machine-readable counters retain their original meaning.

Disk images (`.E01`, `.raw`, `.dd`, `.img`, `.vhd`, `.vhdx`) must be mounted or extracted
externally. Locard does not mount them. Root memory/page/hibernation files are reported
as unsupported; automatic discovery is not a claim of complete acquisition.

Bare `ingest` shows usage without ingesting anything. `help ingest` lists all seven
subcommands; `help ingest mft` (or `locard ingest mft --help`) shows direct options.
The flat aliases `ingest-all`, `ingest-browser`, `ingest-evtx`, `ingest-mft`,
`ingest-prefetch`, and `ingest-registry` remain accepted for existing scripts with
unchanged arguments, counters, provenance and JSON. They reuse the same parsers and
implementations; no deprecation text is added to scripted JSON output.

### Advisory AI in the shell

There is one shell prompt, always `[my 3rd case]>`, using the normal prompt style.
The human case name is read from the existing creation activity entry on activation,
including reopening. If unavailable, managed cases use their workspace name; older
standalone databases use their filename. Labels are escaped and bounded for display.

Prefix a natural-language request with `!` to ask the local AI assistant directly:

```text
[my 3rd case]> ! What evidence is available?
[my 3rd case]> search --path coreupdater.exe --ids
[my 3rd case]> ! How should I investigate this?
```

The first `!` and one optional following space are removed; remaining text is passed
literally. Unprefixed text, including command typos, stays a Locard command. Empty
requests never invoke the model. `!` is never an OS shell escape.

`ai` controls provider/runtime settings. `expert` retains its single-mode compatibility notice.
Interactive `ask <question>` prints a deprecation notice and forwards to the same
advisory path as `!`. These compatibility names are hidden from primary help and
completion; `help ask` and `help expert` explain compatibility behavior; `help ai` documents provider controls. Separately, the
hidden **non-interactive** `locard ask` command retains its existing bounded
retrieval behavior and options for scripts; this does not add retrieval to `!`.

New sessions no longer emit `SHELL_MODE` UI transition events because no transition
occurs. Historical activity entries remain readable and verifiable with the same
audit schema and hash-chain rules. AI request audit records are unchanged.

Advice uses the configured generative provider. It does not use the embedding model.
Requests are independent and bounded
to 4096 UTF-8 bytes. Before each request a short read-only snapshot supplies the human
case name, version, actual retained record counts by supported artifact category,
and current analyst-supplied source metadata. The first eight sources in creation/ID
order are shown with exact total/shown counts; each label/metadata field is capped at
160 characters and truncation is explicit. Source assertions are not verified findings.
Compact command purposes and input/usage guidance come from the command catalog.
Inventory questions can be answered directly from the supplied counts without first
running `status`. Zero means no retained records in this case, not that the source
system never contained that artifact. Case inventory, record inspection, and forensic
conclusions are separate: inventory alone establishes no conclusion.
For filename lookup, use `search --path coreupdater.exe --ids`; use `show <evidence-id>` only
after obtaining an actual record ID. `artifact_inventory` is an internal context field,
not a command. This guidance reduces invalid recommendations but cannot guarantee
that a small model will always follow instructions. When concrete filenames are supplied,
the assistant is prompted to use exact command examples rather than generic command names.
A compact available/unavailable category summary is derived from those same counts,
without additional record retrieval. Advisory instructions use the counts and summary: zero-count categories
may be mentioned only as unavailable limitations, not recommended as available evidence.
Positive counts permit relevant inspection but do not establish that a particular event
or filename is present. Artifact categories are distinct from analysis commands such as
`process-tree`, `timeline`, `search` and `show`.

For relationship questions, guidance should test the analyst's hypothesis: locate each
entity, inspect returned IDs with `show`, establish record meaning, timestamps and any
execution-specific evidence, then correlate. With no individual records inspected, the
prompt prefers an empty assessment and prospective steps over unsupported entity-level
claims from aggregate counts. A generic sequence example reinforces inspection before correlation. File/ZIP presence alone establishes neither
execution nor download. Unknown IDs and timestamps stay placeholders. Command context
reinforces those input prerequisites without changing command behavior.

These are model-agnostic prompt rules, not guarantees of semantic correctness. Locard
does not rewrite, reorder or fill in model reasoning after inference, and adds no
artifact-keyword rejection heuristic. The existing internal-terminology guard also covers
the new availability field name. The advisory JSON schema, deterministic inventory
rendering and manual-execution boundary remain unchanged.

If safe case context cannot be built, the request fails closed without contacting the model.
Recognized transient SQLite lock/deadline failures get at most one silent fresh read attempt.
No case data is written by that retry. Standard Python DEBUG logging for
`forensic_assistant.interactive.ai_context` exposes only stage, failure category, SQLite
code and retry outcome; tests capture these diagnostics. No log file or logging handler
is enabled automatically, and exception contents, paths and prompts are not logged.

No individual records, EVTX bodies, Registry values, MFT filenames, browser URLs,
Prefetch contents, command outputs, analyst/organization names, conversation or command
history are automatically included. Ingestion limitations are omitted rather than inferred
from terminal output. New evidence is reflected in the next request without reopening
the case. Context strings are untrusted data in a separate structured message; the analyst's
request remains the task. High-level counts do not establish findings about individual records.

Manual smoke test (requires your existing local model): open a case with MFT, Registry,
Prefetch and EVTX, then ask both questions directly:

```text
! What evidence is available in this case?
! We suspect coreupdater.exe executed after loot.zip was downloaded. How should I investigate this?
```

For the Standard2 manual scenario, use its actual inventory (approximately 825,888
Registry, 40,917 EVTX, 196 Prefetch, 82 MFT and zero browser records). Repeat the inventory
request to check consistency; a successful transient-read retry should be invisible.
Expect concrete `search --path coreupdater.exe --ids` and `search --path loot.zip --ids`
examples for the investigation question, followed by `show <evidence-id>` only when an
ID is known. Timeline/session suggestions must follow their documented selectors.

Expect the first answer to give available categories/counts directly, acknowledge that
individual records have not been inspected, and avoid claiming no evidence was supplied
or requiring status. For the second, expect filename search followed by show only with
a known evidence ID, using the available artifact categories and real Locard commands,
without claiming specific records were inspected or the hypothesis proved. No command
should run automatically, and the AI prompt should return. Automated tests mock inference;
they do not establish the quality or factual accuracy of every model response.

Clear inventory questions (for example, `! What evidence is available in this case?`,
`! What artifacts are available?`, `! What does this case contain?`, and
`! What sources are loaded?`) use a small exact-match list after case/whitespace
normalization. Locard answers these from the current bounded case summary without
model inference. Compound or uncertain questions continue through the advisory model.
Inventory and sources always use the existing context order and comma-formatted counts:

```text
AI assistant — advisory, not evidence

Case inventory
  evtx      40,917 records
  mft       82 records
  prefetch  196 records
  registry  825,888 records
  browser   0 records

Sources
  2 sources; showing 2 (analyst-supplied metadata).
  1. G drive — host: desktop-test, user: J Smith
  2. MFT from DFIR — volume: C:

Current assessment
  - Individual records have not been inspected.
  - No forensic conclusions have been reached.
```

The example is synthetic. Zero means no retained records in the case, not that the
source system never contained that artifact. Version/mode metadata is omitted from
normal answers; unsolicited model echoes are rejected. Explicit version/mode questions
may include it. Interpretive guidance uses strict structured local-model JSON:

```json
{
  "goal": "Determine the sequence of events.",
  "assessment": [],
  "steps": [{"text": "Inspect returned records.", "commands": ["show <evidence-id>"]}],
  "cautions": ["File presence alone does not prove execution."]
}
```

All four keys are required; `goal` may be null or empty. Limits are 500 characters
for goal, six assessment items of 500 characters, eight steps with text of 800
characters, six single-line commands of 500 characters per step, and eight cautions
of 500 characters. The entire response is limited to 16,384 UTF-8 bytes. Unknown
keys, duplicate keys (including nested keys), invalid types, internal vocabulary,
and wholly empty responses fail closed. The local validator enforces these limits
independently of the model server.

Investigation guidance instructs the model to use exact analyst-supplied values in
supported command syntax, address every relevant entity, and locate/inspect both
sides before comparing timing. Unknown evidence IDs, timestamps, and logon IDs stay
placeholders. Inventory contains categories/counts, not filename-level contents.
Assessment and cautions should describe the forensic situation; operating rules
are applied silently. These are model guidance, not guaranteed semantic validation:
Locard does not extract entities, fill placeholders, add omitted commands, reorder
reasoning, or reject safe advice solely for incomplete entity coverage. Commands
remain display-only. Prompt tests and mocked fixtures do not establish live model
accuracy or completeness.

Fallback policy is **strict structured advisory**: no legacy `{"advice": "..."}`
or unstructured prose fallback for interpretive answers. Deterministic inventory
remains available without the model. Inventory/source fields are not part of model
JSON and cannot override Locard's authoritative data. No bracket-section parser
remains in this advisory path.

Locard owns headings, ordered step numbers, command indentation, blank lines,
colors, and word-boundary wrapping. Commands appear beneath their associated step;
empty Goal, Current assessment, Suggested approach, or Important cautions sections
are omitted. Overlong tokens may wrap to fit the terminal. Commands are strings
for display only: the renderer never parses or executes them. Catalog grounding
is supplied to the model; schema validity does not establish command correctness
or forensic truth.

A labeled, terminal-escaped diagnostic preview (up to 6,000 characters before
indentation) shows rejected output with a concise failure category. It is not an
accepted answer and is not stored in the activity log. Headings retain the heading
style, commands cyan, cautions amber, and ordinary text neutral; AI claims are
never styled as verified successes.

Illustrative advisory output for the Standard2 smoke-test question above:

```text
AI assistant — advisory, not evidence

Goal
  Test the proposed execution/download sequence.

Suggested approach
  1. Locate both filenames.
     search --path coreupdater.exe --ids
     search --path loot.zip --ids
  2. Inspect returned records, then compare timing and execution indicators.
     show <evidence-id>

Important cautions
  - MFT presence alone does not prove execution.
  - Individual records have not been inspected.
```

For the inventory question, expect separate Case inventory, Sources, and Current
assessment sections with aligned counts, source rows, and separate caution bullets.
For the investigation question, expect both filename lookups, numbered steps, and
separate cautions, without internal vocabulary or a redundant status step. These are
manual visual acceptance checks; mocked tests do not guarantee model advice quality.

The response is labeled advisory, not evidence. Suggested commands must be entered by
the analyst: the assistant cannot dispatch commands, ingest, create cases, modify evidence
or run tools. Structured advice can be wrong and is not report-style evidence grounding.
Failures, malformed replies, timeout and Ctrl+C leave the normal shell prompt usable.
There are no downloads, automatic installations, Internet calls or persistent investigation
plans. Normal case creation and ingestion remain deterministic.

Existing derived activity records `SHELL_MODE` transitions and `AI_ADVICE` success/failure/
cancellation with text lengths (response length counts structured text fields, not keys). Request/response prose is not written to the activity
sidecar or evidence database. Ordinary in-memory shell recall remains available. Audit
hashing and chain verification are unchanged.

### Analyst activity

Each selected case has a derived `<case-path>.audit.jsonl` activity sidecar.
It is not forensic evidence, never participates in evidence counts or queries,
and is excluded from artifact discovery. Protect it as analyst work product:
explicit query filters, paths, and source assertions can themselves be sensitive.

```text
activity
activity --limit 50 --json
activity --verify
```

Records contain an audit-format version, microsecond UTC `timestamp_utc`, a unique
active-case `session_id`, monotonic per-case `sequence`, `action`, `outcome`, and
action-specific fields. Each script invocation gets its own session. Switching
cases ends the previous session. Normal exit/EOF records an end; a fatal crash
does not fabricate one. Successful case activation appends `CASE_OPEN` before
`SESSION_START`; a failed open starts no session. New-case creation/ingestion
events precede activation. Historical log entries are never reordered.
The dispatcher owns command invocation/completion and
show/around/investigate anchors; the shell owns session/open/create events;
source, ingestion, and output adapters own their semantic actions. Successful
shell help/version/color commands are also recorded. Blank input, completion,
unknown-command typos, and harmless menu navigation are not logged.

Source updates record actual before/after values. Ingestion records batch and
per-file outcomes/counts alongside the authoritative database provenance. Output
records distinguish write, overwrite, and append, with previous/resulting SHA-256
where applicable; report bundles record their completed member-file hashes.
Returned evidence objects, browser URLs, and result lists are not copied into
the log. Explicit analyst query strings are retained. Recognized long-option
values are replaced by `<redacted>` for names ending at a hyphen/underscore word
boundary in `password`, `passwd`, `token`, `secret`, `credentials`, `authorization`,
or `api-key`/`api_key` (for example `--access-token` and `--client-secret`). Both
`--option value` and `--option=value` are supported. This is deterministic option
redaction, not a general secret detector for arbitrary positional text.

Appends use short-lived interprocess locks, bounded tail reads, flush and fsync.
No persistent database or log handle is retained between commands. Mutations
require a durable `pending` intent before changing sources, ingesting, or writing
output; completion follows the database commit/file publication. SQLite and the
sidecar are **not one transaction**. If completion logging fails, Locard reports
that the action completed and leaves its intent for reconciliation against
database provenance/output. A crash can likewise leave an unresolved intent.
Read-only commands warn visibly if logging fails and may continue. Failed or
cancelled actions are recorded where the sidecar remains writable. Logging is
otherwise silent. Case creation is recorded after database publication; failure
there retains the database and reports failure without automatically activating it.

Each entry hashes canonical JSON (sorted keys, compact separators, ASCII escapes,
no non-finite numbers), excluding its own `entry_hash` and including
`previous_entry_hash`; the first previous hash is `null`. `activity --verify`
streams and checks every entry, sequence and link and reports the first invalid
entry. Ordinary appends validate only the tail for bounded work, not the entire
history. Verification detects altered, reordered or missing interior records and
partial/malformed tails. Without an externally trusted head hash or signature,
it cannot detect deletion of a valid suffix, deletion of the whole log, or a
fully recomputed replacement chain. This is tamper evidence, not signing or
non-repudiation. No automatic repair or history rewriting occurs.

`activity` displays a verified snapshot with at most 20 recent records by default
(maximum requested limit 1000). Its own command-completion event is appended
after the snapshot, so it appears on the next invocation. Verification is linear
in log size; routine appends do not rescan the evidence database or audit history.

### Creating a case interactively

The selector offers `Create case`, `Open case`, and `Exit`, and still accepts an
existing case path. Creation asks for a case name/path and evidence, discovers
supported artifacts, and requires explicit browser product and profile for each
Chromium History database. A source display name defaults to the case filename;
an optional override lets analysts label the source independently. Hostname,
user, and original drive remain unknown unless supplied. A concise preview and
affirmative confirmation precede filesystem changes. Progress shows record
counts and meaningful duplicates/errors rather than Python dictionaries. An
explicit empty case creates no placeholder source and asks no source metadata.
Existing directories are rejected with a create-specific destination message.

On a capable terminal, case-creation phases use the existing cyan key style;
successful counts/completion use green, limitations use yellow, and actual errors
use red. Prompts reuse the existing prompt style. `color off`, `NO_COLOR`, and
redirected output suppress these styles. JSON, audit records, and exported files
receive no presentation escape sequences.

During case creation, filenames are neutral, positive retained-record counts are
green, partial outcomes are yellow, and actual error counts/failed outcomes are
red. Repeated stored diagnostics are grouped by exact stage and message in the
final human summary, with occurrence and distinct ingestion-attempt counts (not
unique-file counts). Individual diagnostic rows and provenance remain unchanged.

Registry creation progress shows primary hive results first, then groups
identified unsupported `.LOG1`/`.LOG2` companions under **Skipped companion
transaction logs**, with one replay limitation. The stored attempts remain
`unsupported`, not failed or successfully parsed hives. If there are only
limitations, the summary says **completed with limitations**; actual errors and
partial/failed runs remain explicit. No transaction-log replay is performed.

Tab completion after `help` or `?` reuses the same command/parser hierarchy:
`help sour<Tab>`, `help source <Tab>`, and `help source up<Tab>` navigate to
`source` and its subcommands. Help-target completion does not suggest options.

### Sources, ingestion batches, and evidence identity (0.10.0)

The ingestion commands are `ingest all`, `ingest browser`, `ingest evtx`,
`ingest mft`, `ingest prefetch`, and `ingest registry`. Explicit `ingest evtx`
discovers both `.evtx`-named files (including damaged headers, so attempts and
errors retain provenance) and signature-recognized EVTX files with other names.
The existing parser decides their outcomes; discovery does not assert validity.
Directory traversal retains its symlink exclusions. General artifact discovery
remains signature-based.

A case can contain many sources. A **source** is an analyst-defined origin, with
an immutable generated ID and a display name independent of hostname. A **batch**
records one ingestion invocation. Its per-file runs retain their paths, outcomes
and hashes. **Evidence identity** remains content hash plus record locator:
identical content imported from different sources shares evidence IDs while
retaining separate source occurrences. Source membership does not prove a machine's
identity or that an executable ran.

New cases use schema **5**. Schema-3 and schema-4 cases remain readable without
changes to their schema. In-place case upgrades are not supported. Source management
requires schema 4 or 5; browser ingestion requires schema 5. To use features unavailable
in an older case, create a new case and ingest the original evidence with explicit
source metadata. Preserve the older case and its provenance separately.

Inside an active case, or prefixed with `locard --db case.db`:

```text
source create --name "Workstation 01"
source list
source show <source-id> --limit 50 --offset 0
ingest prefetch extracted-prefetch --source <source-id>
ingest evtx extracted-events --source <source-id>
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

Interactive case creation asks for a source name and optional metadata when ingesting evidence.
Explicit empty-case creation asks for no source metadata and creates no source or ingestion batch. Additional
interactive ingestion offers existing sources or a new source; selection is not
retained as an implicit default for later commands. A blank name produces a neutral
label, never a guessed hostname. Cancelled creation does not activate the new case.

`source update` supports `--name`, `--hostname`, `--user` and `--volume-root`.
Human results summarize the actual old/new values and retained prior assertion;
`--json` returns the complete structured result.
Use an empty quoted value to clear optional metadata to unknown. Updates append
revisions linked by supersession; old assertions remain available in `source show`.
Raw evidence and artifact-derived fields are never rewritten. Legacy file-level
assertions remain intact and can still expose conflicts; a new source assertion
does not silently supersede a legacy assertion of uncertain scope.

Without `--yes`, scripted updates and assignments preview the actual scope without
applying it. Interactive mode shows the preview and requests confirmation unless
`--yes` was supplied. With `--yes`, both modes validate and apply without prompting.
If the case changes after the interactive preview, the action is rejected so the
analyst can review it again. Source commands reuse `--page`,
`--output`, `--append`, `--json` and `--no-color`; JSON remains plain structured data.
`source list` file counts are distinct content hashes, not path or import counts.
Its aligned table adapts to terminal width and uses restrained, optional colors.
Shortened display fields end in `...`; abbreviated IDs must not be used as command
arguments. `source list --ids` provides full copyable IDs, and `--json` retains all
values. Very narrow terminals use labelled rows instead of a wide table.
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

For bulk retrospective selection, `--path` searches only historical
`source_locations` recorded in the case database. It never scans or imports the
current filesystem. Preview before applying:

```text
source assign <source-id> --path "C:\Evidence\PC01\Prefetch" --reason "Analyst reviewed legacy collection"
source assign <source-id> --path "C:\Evidence\PC01\Prefetch" --reason "Analyst reviewed legacy collection" --yes --confirmation-fingerprint <preview-fingerprint>
```

Repeat `--path` or combine it with repeated `--file-hash`: selectors form a
deduplicated union. Every supplied path must match at least one recorded location.
At least one selector is required; there is no `--all` or implicit selection.
Comparison is lexical and case-insensitive, treats `/` and `\` alike, ignores
trailing separators, and respects whole path components (`PC01` does not match
`PC010`). A selector matches an exact recorded file path and/or descendants of a
recorded directory. It does not resolve aliases, links, short names, environment
variables or the current working directory. Use absolute drive paths or UNC
shares; relative/device paths, `.`/`..`, wildcards, streams and components ending
in spaces/dots are rejected. Brackets are literal, not glob patterns. For other
historical path forms, use the precise `--file-hash` selector.

The text preview shows source metadata, selected paths, distinct content count,
artifact-record counts, reason and existing provenance. `--json` includes the
complete selected hashes and matched recorded locations. Provenance counts are
per distinct hash and may overlap: "ambiguous" means membership in multiple
sources; multiple recorded locations are counted separately. Selection attaches
the **content hash**, not one particular path occurrence. Other memberships and
paths remain intact, so adding another source may create visible ambiguity and
prevent source-aware correlation. A path does not establish machine identity.

Application reports its actual scope and holds the same database transaction
through selection and assignment. The optional `--confirmation-fingerprint`
requires the unchanged case state returned by a preview; use the same selectors
and reason when applying it. Without this token, `--yes` selects the current
recorded scope, which may differ from an earlier preview. Interactive confirmation
always checks the preview fingerprint. Selection is bounded to 1,000 distinct
hashes, 100 path arguments and 10,000 matching recorded locations; narrow larger
selections explicitly.

Schema 4 is unchanged. Path-selected assignments retain the original analyst
reason and store the supplied paths and explicit hash selectors as JSON text
appended to the existing retrospective `basis` field. `source show` exposes this
in its bounded assignment history. The selected content hashes remain in
`source_assignment_files`; no historical batches or ingestion-run batch IDs are
created. `status`, `search --source`, and `around` use the existing membership and
ambiguity rules.

`search --source` filters provenance membership. `search --hostname` searches
artifact/active analyst hostname assertions; it remains distinct and may find
records with conflicting assertions, which are shown in their context. The filters
can be combined. Superseded source revisions do not act as current metadata.

Host context is resolved per evidence record against the current source assertion.
Matching normalized artifact/source hostnames resolve by agreement; a contradictory
artifact hostname remains conflicted. With only one available hostname, existing
artifact-derived or analyst-supplied context is retained; with neither, it stays
unknown. Superseded source revisions are retained for audit, not current resolution.
Source `artifact_hostnames` and `host_conflict` remain coverage diagnostics: a mixed
source does not invalidate its agreeing records. Same-host timeline, around, and
investigate selection use resolved record hosts. Broad `search --hostname` still
finds artifact/analyst assertions, including conflicts. Short names and FQDNs are
not aliases; no DNS, NetBIOS, or fuzzy matching is performed. Same source does not
imply same host, and temporal proximity does not establish causality.

`around` requires an unambiguous effective hostname and retrieves all supported
artifact families within the requested window on that host, including different
sources. A shared source or display name alone does not establish the host.
Multiple source occurrences, record-level conflicting hostnames, and unknown
hostnames still block same-host selection. Each neighbor retains its own evidence
identity, source membership, user attribution and timestamp semantics. Temporal
proximity does not establish causality or a combined execution.

Mixed `timeline --text` and `around --text` show artifact types, meaningful objects,
short source labels and exact timestamp slots in chronological order. Excess
generic Registry LastWrite observations are summarized after three rows per page,
with an explicit omitted count; the selected anchor is never summarized away.
Use JSON/raw observation pagination, `around --text --ids`, or a Registry-only
timeline to inspect all observations. Text windows are bounded to 10,000 timestamp
observations, with complete MFT/EVTX display groups. Around text reserves an anchor
group and selects the nearest remaining groups before displaying them chronologically.

`around <evidence-id> --timestamp-slot <slot> --text` presents temporal context
with a concise object/window header, source label, and selected-slot anchor marker.
Compact timestamps and deltas are rounded to the nearest millisecond, with exact
ties rounded away from zero; deltas are calculated from the original nanosecond
values before display rounding. Small deltas can therefore display as `0.000s`
without representing identical timestamps. Dates carry correctly across midnight.
Shared methodology is omitted, while mixed source/artifact/timestamp meanings stay
visible per observation. Duplicate source labels include their IDs to distinguish
them within the displayed context. Long objects may be shortened with `...`.
Use `--text --ids` for full evidence/source IDs, timestamp slots, original timestamp
precision and shared timestamp meaning; `show <id>` provides details. JSON and raw retain
their existing complete structured/detail output (`--raw --text` retains the
legacy detailed text view). `--page`, `--output FILE` and `--append FILE` work with
the compact view; file exports contain no color codes. Shared context describes
only the displayed rows, not observations outside the current result page.
If several slots have the same anchor time, select `--timestamp-slot` to identify
one anchor row; Locard does not arbitrarily mark all slots as the anchor.

Sysmon Event 11 (qualified by its provider and Operational channel) is normalized
as `file_create`: **file creation/overwrite**, not proof of a previously absent
file, execution, download, or malicious activity. `Image` is the actor process;
`TargetFilename` is a separate `file_create_target` object. Process search matches
the actor; path search can match the target. `show` exposes the actor PID/GUID,
target, and timestamp meanings without inferring a username from a path or SID.
The primary EVTX time remains `SystemTime`. When present, `Sysmon.UtcTime` and
`Sysmon.CreationUtcTime` preserve separate payload observations, original values,
and source precision. Timeline retains both even when their values coincide.
For temporal context, explicitly choose the intended slot, for example:

```text
around <event11-id> --timestamp-slot SystemTime --text
investigate <event11-id> --timestamp-slot SystemTime
```

Distinct times require disambiguation; investigation without a selected slot
leaves ambiguous temporal context unresolved. Automatic EVTX cross-artifact
timing uses only `SystemTime`; the target object is excluded from automatic
cross-artifact comparison. Event 11 adds no process-tree node or detection rule.
These projections apply to newly ingested evidence. Existing stored records are
not backfilled; re-ingesting an existing evidence ID does not rewrite it.

Compact search/timeline output omits repeated generic forensic cautions. This is
not a change in interpretation: temporal proximity does not establish causation,
timestamp meanings differ by artifact, and retained timestamps/run counts do not
establish complete execution history. Specific warnings and safeguards remain,
including truncated results, unknown/conflicting host context, ambiguous source
membership, parser failures and partial operations. Full structured/raw output
retains its existing information.

Direct command help uses `usage: locard ...`. Interactive help uses contextual
syntax such as `usage: source assign ...`; unknown commands receive a short
message, and argument errors show relevant usage and a help hint. Explicit `help`
and `help <command>` remain comprehensive, and errors return to the active prompt.

Source revisions, batches and assignments participate in the content fingerprint.
Changes make dependent semantic indexes, investigations and report/case validation
stale. Rebuild indexes explicitly; historical reports and transcripts are never
rewritten. Validate historical outputs against their original case snapshot when
appropriate; successful validation still does not prove forensic conclusions.

**Search summarizes. Show explains. Raw exposes.**

Normal deterministic `search` displays compact, escaped artifact tables.
Add `--ids` for full copyable evidence IDs. Prefetch summaries show the executable, latest retained
execution timestamp, recorded run count, effective host, and a candidate path
when present in the bounded evidence projection. A candidate path is not a proven
executable identity. Other artifact types use their own identifying fields.
Long display fields may be shortened; evidence IDs and stored evidence are not.
Only partial pages show a concise displayed-count or range footer; pagination metadata remains in JSON.
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

`search` defaults to 20 evidence records across all artifacts, including JSON.
Use `--limit` and `--offset` to select another page; `--ids` retains copyable IDs.

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

`show` presents an artifact-aware human summary, including full evidence ID and source path, populated timestamp slots, and a bounded reference sample. `--raw` retains the existing
verbose/raw representation, including its established retrieval bounds.
Explicit `--json` preserves the structured interface; scripts consuming search
results should request it. Plain `source show` also uses a human summary; `--details` or `--json` preserves its existing structured view.

Registry search supports `--key "Software\Example"` for an exact literal key
path and `--key-contains "Example"` for a literal substring. Both use SQLite
NOCASE matching (ASCII case-insensitive; non-ASCII characters compare exactly),
include the matching keys and their independent values, and do not expand
wildcards or normalize filesystem paths. Use `--artifact registry` or omit the
artifact filter. `--path` retains its existing filesystem/target-path meaning.
`--value-name` (exact) and `--value-name-contains` (literal substring) match raw
value names and, only under UserAssist GUID/Count keys, ROT13-decoded names.
They use the same NOCASE rules and can be combined with `--source` and key
filters. For example: `search --artifact registry --value-name-contains coreupdater --ids`.
The search default remains 20 records.
Registry search identifies Key/Value rows and shows dirty-hive warnings once
per hive/source context; structured warnings remain per record.

Registry `show` uses friendly type names and literal string backslashes without
expanding environment variables or interpreting escapes. Values inherit their
containing key's LastWrite, never a fabricated value creation time. Key `show`
lists at most 20 values with explicit omission/truncation notices. Text data is
bounded to 240 characters (and 10 entries for multi-strings); the key-value
projection reads at most 4,096 JSON characters per value. Binary data is
summarized rather than printed. `show --json` retains full provenance, numeric
types and existing value IDs; `show --raw` retains the raw projection.

UserAssist Count values additionally expose `detail.userassist`, including the
decoded name, declared format, interpretation status and supported binary fields.
Declared version 3 requires exactly 16 bytes; version 5 requires exactly 72 bytes.
Locard reads the recorded counter and internal FILETIME only. Version-3 counters
remain explicitly unadjusted; uncertain focus/session fields are not interpreted.
Missing/unknown versions, wrong lengths/types, and special UEME control entries
retain their raw data without invented execution fields. Zero/invalid FILETIMEs
do not produce a usable execution time. Known-folder GUIDs are not expanded.

`UserAssist.LastExecution` is attached to the existing Registry value ID, separate
from inherited key `LastWrite`. Both are eligible timeline observations; `around`
requires `--timestamp-slot` when multiple populated semantics exist, even when
their times coincide. Search continues to display **key time**, not silently
substitute the UserAssist time. New ingestion stores supported slots in the
existing timestamp table. Older cases derive the same slots read-only from stored
bytes, without migration, re-ingestion or duplicate observations. Status counts
include these projected observations. Raw names/bytes, source membership and
evidence IDs are unchanged. UserAssist can indicate recorded execution or user
interaction; it does not prove process creation, command lines or intent. Strict
effective-host validation remains in effect; cross-source temporal neighbors keep
their separate provenance and do not establish a combined execution.

UserAssist layouts follow the [libyal format reference](https://github.com/libyal/winreg-kb/blob/main/docs/sources/explorer-keys/User-assist.md).
The libregf key-corruption flag is retained in structured warnings. Human output
describes it as a parser flag and consolidates repeated key warnings. In the
tested hive, empty Count keys with a `0xffffffff` value-list offset trigger that
flag; populated Count keys remain readable. The flag alone therefore does not
establish unreadable data, and it is not suppressed for other keys. See the
[upstream flag implementation](https://github.com/libyal/libregf/blob/main/libregf/libregf_key_item.c).

Normal `status` is a bounded human summary of evidence, ingestion attempts,
sources, unfinished batches and limitations. `status --json` preserves the
existing structured status interface. Historical ingestion statuses are never
rewritten by this view.

Registry `.LOG1`/`.LOG2` companions with REGF (or HvLE) signatures are discovered
as Registry inputs but intercepted before standalone hive traversal. Their
filename-based classification and any possible same-directory companion-hive
association are recorded in `artifact_runs.parameters_json`; filename matching
does not verify hive identity. Hashes, observed paths and batch membership are
retained, with an `unsupported` run status and no fabricated Registry records.
Replay is unsupported. Dirty-hive warnings remain: an unreplayed snapshot may
be inconsistent, which does not itself mean corruption. Older companion-log
attempts are labeled historical in human status, retaining their original
statuses/errors in the database and JSON output.

MFT text uses Allocated/Unallocated state and SI/FN timestamp labels; `show`
retains exact copyable timestamp slots. `timeline --text` and `around --text`
group only observations with the same evidence ID and exact timestamp value.
For MFT text timelines, limits and offsets count complete groups. MFT text
`around` always includes the anchor within the limit, fills remaining places
with nearest groups, and displays them chronologically. Its offset skips
nearest non-anchor groups; the anchor remains visible even past the last page.
EVTX text timelines and EVTX-anchored text `around` also paginate complete
groups, retaining each timestamp slot's label. Equal-valued Event 11
CreationUtcTime/UtcTime observations share a display group; a different
SystemTime remains separate. Process parent/child paths and file actor/target
paths are shown separately, with optional restrained type/anchor coloring.
EVTX text `around` keeps the selected anchor within the limit; offsets skip
nearest non-anchor groups. Prefetch/Registry observations remain separate.
Complete text windows are bounded to 10,000 timestamp observations; narrow the window/filters if that
bound is exceeded. JSON/raw retain observation-level pagination, individual
observations and full precision.
Multiple MFT timestamp slots require an explicit `--timestamp-slot` for `around`,
even when their values coincide. Timeline arguments require ISO 8601 with `Z`
or an explicit UTC offset; timezone-less input is rejected.

| Destination | Behavior |
|---|---|
| Default | Render to the terminal |
| `--page` | Internal Python pager: Up/k and Down/j/Enter scroll a line; Space/PgDn and b/PgUp scroll a page; Home/g and End/G jump to top/bottom; Q/q/Esc quits (also Ctrl+C) |
| `--output FILE` | Write UTF-8 output; existing files require interactive confirmation (default No) or `--force` |
| `--append FILE` | Append UTF-8 output, creating a missing file; separate successive outputs with a newline |

The pager navigates buffered, already-rendered rows without rerunning queries.
It shows a footer such as `Lines 81-120 of 437 | Up Down PgUp PgDn Home End Q`.
Navigation clamps at either end; End displays the final page, which may be short.
Each redraw clears stale rows and rechecks terminal dimensions, with a fallback;
width changes rewrap the buffered text. Console input mode is restored on exit.
If stdin or stdout is not a terminal, it prints normally
without waiting for keys. Paging wraps long display lines; it does not change
stored evidence. Explicit `--json --page` is rejected. `--page`, `--output`, and
`--append` are mutually exclusive. No external pager or shell is executed.

File paths may be relative to the caller's directory or absolute; quote paths
containing spaces. Parent directories must already exist. Confirmations and errors
go to stderr; file output is not also dumped to stdout. Write failures return a
nonzero status and leave the interactive shell usable. Scripts fail without
prompting when an output file exists unless `--force` is supplied. `--yes` is
for action confirmation and does not authorize output replacement. First writes
need no confirmation; append never asks to overwrite. Success distinguishes
`Output written to:`, `Output overwritten:`, and `Output appended to:`.
Replacement uses a complete temporary file and atomic publication, with target
identity/content checked again before publication. These checks detect observed
concurrent changes but are not an adversarial filesystem transaction. Explicitly
requested failure/partial-result diagnostics remain exportable. Replacement is atomic;
an interrupted or failed append may leave a partial appended section. Appending
JSON produces separate JSON documents, not one combined JSON array.

Output guards reject audit sidecars, the active/explicit case database and its SQLite sidecars,
recorded evidence paths (including hard-link aliases), recognized artifact/SQLite
files, symbolic-link/junction destinations, and overlapping command inputs.
These are safeguards for known inputs, not a way to identify every possible
unregistered evidence file. Choose a separate analyst output path.

For nested commands, destination options can follow the final subcommand. One
existing option is deliberately preserved: `report generate --output` still names
the new report **bundle directory**. Bundles remain create-only; `--force` does
not replace an existing bundle. To also save its console result, put the new
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

In the Windows interactive command editor, Tab completes commands, nested
commands, and visible command options. Ambiguous prefixes extend to their common
prefix; another Tab lists the matches. Tab on an empty line lists command names.
Values, quoted arguments, evidence IDs, and filesystem paths are not completed.

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

Generate a bounded, derived report from explicit evidence IDs or selected same-state
investigations. Explicit evidence selection does **not** imply a complete investigation.

```text
report generate --evidence <evidence-id> --output "C:\Cases\reports\selected-records"
report show "C:\Cases\reports\selected-records"
report validate "C:\Cases\reports\selected-records" --case "C:\Cases\case.db"
```

Repeat `--evidence` for multiple records, or use repeatable `--investigation` with
`--transcript-root`. The destination must be new and its parent must already exist.
Locard does not create parent directories automatically. Interactive generation
shows the directory, bounded scope, output files, and ready-to-use commands.
Direct CLI output remains JSON; `--json` and `--text` override generation output.
`report show` accepts a **directory**, not a report ID; there is no report-ID index
or filesystem search.

Each atomically published bundle contains:

- `report.json`: authoritative structured claims, evidence, graph, timestamps,
  inventory, scope, omissions, provenance, and narrative metadata.
- `report.md`: canonical human-text report.
- `report.html`: standalone offline visual report, without scripts or external assets.
- `manifest.json` and `checksums.sha256`: output hashes and provenance.

Markdown and HTML share one presentation view. Related observed fields are grouped
by evidence record without merging evidence or claim identities. The executive
summary avoids JSON pointers and claim-ID noise. MFT allocation state is explicit;
SI/FN timestamp observations retain their distinct meanings. Parser warnings,
compact projection omissions, and report bounds are separate limitations.
`--profile technical` retains full timestamp detail and claim references, with compact
primary source/parser/context references. Deep source assertions and ingestion details
remain in JSON. `--profile executive` uses compact evidence descriptions and up to 20
time observations grouped by record, retaining separate timestamp sources and meanings
without raw timestamp values, precision or slot internals. Full timestamp detail remains
in JSON and the technical profile. Empty analyst metadata tables are omitted. Output-only `--redact identifiers` remains
available; it is not anonymization.

`--llm-narrative` optionally asks the existing loopback model to compose paragraphs,
key points and limitations from a bounded catalog of claim-backed sentences and
approved phrasings. Joint MFT wording combines validated record observations into one
connected paragraph without asserting a relationship. Each returned statement must cite
the exact supporting claim set. Separately cited `boundary_ids` permit only deterministic
report boundaries (MFT interpretation cautions and, when no relationship claim is present,
absence of a relationship assertion). These are not new evidence claims or proof of absence.
When joint wording fits the prompt budget, the generation grammar requires it rather than
separate MFT record sentences. Deterministic limitations render once; repeated or composed
narrative limitations are suppressed in human output because their approved items are
already shown. Full narrative text and mappings remain in JSON and the manifest. **Unrestricted paraphrases are deliberately rejected:** valid citation IDs alone
cannot prove a sentence is supported. This is controlled-language composition, not
a general factual verifier or unrestricted creative writing. The model cannot add
claims, evidence, graph edges, relationships or conclusions. Deterministic artifact
cautions and material limitations remain visible regardless of narrative selection.

Malformed, unsupported or oversized narrative is marked `REJECTED`; a transport
failure is marked `FAILED`. Both retain a useful deterministic report and record a
fallback reason. Accepted narrative records prompt hash, configuration, validation,
and server-reported model/token metadata when available. Model identity is not attested.
No model is contacted unless requested; rendering itself needs no network, model,
optional package installation, or download.

New JSON reports use `presentation_format: 3` while retaining the existing report data
schema. The human AI disclosure is compact; prompt hashes, token metadata and full support
mappings remain in JSON/manifest. Existing format-2 bundles retain their original view and
narrative validation contract. Older four-file bundles remain readable and verifiable with
their original renderer and limitation projection. New validation
checks Markdown and HTML hashes **and** re-renders both from structured data. Validation
still distinguishes file integrity, structure, case-fingerprint compatibility and
evidence grounding; none proves forensic conclusions. COMPLETE means completion of
the requested bounded report, not completeness of a forensic examination.


## License

Project source license: **Apache-2.0**. See [LICENSE](LICENSE) and
[third-party licensing](THIRD_PARTY_NOTICES.md).


Locard Forensic
Copyright © 2026 Jean-Luc Dupont


### Compact evidence and source views

Normal `search` uses artifact-specific tables with millisecond timestamps.
`search --ids` places each full copyable evidence ID directly beneath its result
for every artifact family, for use with `show` and `around`. IDs are never moved
into a detached numbered list. Without `--ids`, compact tables remain available;
JSON selection, ordering, and fields are unchanged.

Registry search groups exact dirty-hive limitations under **Forensic notes**,
once per hive/source context. Ambiguous hive names retain identifying path/hash
and source information. Dirty does not mean corrupted: transaction logs were not
replayed and the snapshot may be inconsistent. Record-specific anomalies, including
key-corruption flags, stay beneath their records. Full warnings/provenance remain
in JSON; UserAssist interpretation and timestamp semantics are unchanged.
Table paths may be shortened for terminal width; full projected values remain
available through `show`, `--json`, and `--raw`. No values in evidence are changed.
`around --text` begins with anchor time and source/artifact context; `--ids`
retains exact timestamps and slot identifiers. Complete result pages have no
pagination footer; partial pages report the displayed count or range.

Plain `show <id>` is human-readable. Scripts should specify `show <id> --json`.
`show --raw` preserves the existing structured raw representation with available
XML/artifact bytes. Neither mode changes the established retrieval bounds:
objects, Prefetch references, and Registry key value IDs are limited to 100,
with the existing truncation flags (and reference total where available).
These are bounded projections, not exhaustive collection exports. Human Prefetch
summaries display up to five references and observed source paths, with counts.
Use the existing structured views to inspect the larger projected lists.

`source show <id>` summarizes current analyst metadata and provenance counts.
Effective hostname is resolved for each evidence record, including file-specific
assertions; a source label alone does not establish a host. Distinct source files
and retrospective assignment-to-file links are separate counts: overlapping
assignments legitimately produce more links than distinct files.
`source show <id> --details` or `--json` exposes the existing provenance structure;
use `--limit`/`--offset` to page its histories and file/hash lists.
`source list --ids` provides complete command IDs; table abbreviations are for
presentation only. All human views support the existing pager and plain UTF-8
output/append destinations and session color controls.


Bare interactive `help` is an alphabetical command catalog; `help <command>`
and `help <command> <subcommand>` retain contextual usage and options.
Compact paths preserve whole trailing components when space permits; an oversized
final component is visibly shortened only when necessary. Normal search/show
omit routine object-projection notices when a candidate path is available, but
still warn when that field is unavailable in the bounded projection or when
context/data-quality problems affect interpretation. JSON/raw projection fields
and existing bounds are unchanged.

Evidence `show` keeps source names and host basis, showing source IDs only for
multiple source memberships. Full source IDs remain in `--json`/`--raw`.
A meaning shared by all displayed timestamp slots is printed once; differing
meanings remain attached to their slots. Referenced files remain the first five
in retrieval order, with a count when sampled, not a ranking of importance.


EVTX ingestion preserves XML `System/EventRecordID` as `events.record_id`.
The EVTX record-header identifier may differ. A valid numeric difference is
retained as a non-fatal validation note, including the header identifier, XML
identifier, and record offset, in the existing event normalization warnings and
evidence warning projection. This difference alone establishes neither corruption
nor failed ingestion. Ingestion results expose aggregate `validation_notes`, and
interactive case creation summarizes the retained notes once. Search does not
repeat them; evidence `show` and JSON/raw retain the detail.

Missing or invalid XML identifiers with an available header identifier continue
through the existing ingestion-error path; the header is never substituted for
XML-derived metadata. Genuine parser, normalization, structural and integrity
failures retain their existing handling. Historical runs and errors are not
rewritten. Re-ingesting creates new run history and does not repair old partial
runs or replace deduplicated evidence.

### Authentication and investigation text views

In the interactive shell, `logons`, `detections`, `session`, `process-tree`, and
`investigate` default to human-readable text. Direct CLI invocations retain their
JSON default. Explicit `--json` and `--text` select the format in either context
and remain mutually exclusive. `--raw` retains its existing diagnostic behavior,
defaulting to JSON even in the shell; `--raw --text` retains the detailed legacy
view. Other commands' defaults are unchanged.

`--output` and `--append` use the resolved format and always write plain UTF-8
without presentation ANSI escapes. Interactive `--page` uses the human view;
direct CLI paging requires `--text`. JSON paging is not supported. Audit argv
records what the analyst entered, without an invented `--text`; the existing
command parameters separately record the resolved `text`/`json` flags.

`logons` reviews the normalized Windows Event Log kinds `logon`, `failed_logon`,
`privileged_logon`, `explicit_credentials`, `logoff_request`, and `logoff`.
The human view groups category, time, user, available logon type/source IP/process
and host with the full evidence ID. No service/system-account noise filter is
applied. Green logons, red failed logons, yellow privilege/credential observations,
and cyan logoffs identify event categories, not maliciousness. Missing fields
remain `-`. Empty results distinguish no EVTX records in the case from no matching
events; neither establishes that no logons occurred or that Security logs are absent.
Partial ingestion history for file bytes represented on the page is noted once
per file, without claiming which run created each event or that every partial
attempt was a recovery. This text-only context does not change JSON.

`detections --text` groups each finding with its complete detection/evidence IDs,
reason, and record-specific limitations. Shared cautions appear once. Severity
is static review priority: high is red, medium yellow, low cyan; it is not
confidence or probability of compromise. **DETECTION != COMPROMISE.** Missing
matches do not prove absence of activity. Rule coverage summarizes evaluated
rules, rules with displayed matches, candidate evaluations across rules (not
unique evidence), and candidate truncation. Counts are bounded by evaluation and
display limits; full rule coverage remains in JSON.

`process-tree --text` presents supported parent/child links with Unicode tree
connectors (ASCII fallback), four-space metadata indentation, and an accented anchor,
retaining `CONFIRMED` versus `LIKELY` status and reasons. Unresolved or undisplayed
relationships remain separate with full references; no missing parent or child
is invented. PID lookback, child window, maximum nodes/depth, and reached limits
are explicit. Color emphasizes structure rather than maliciousness.

Human EVTX `show` displays the full stored normalized Logon ID whenever present,
without shortening it or extracting additional identifiers from raw XML. Account
names retain literal backslashes and readable Unicode; control characters remain
escaped. Structured JSON continues using standard JSON escaping.

`search --kind logons --ids` displays the normalized target Windows Logon ID
for successful logons, in hexadecimal for reuse with `session --logon-id`.
Subject and linked IDs are not substituted. Failed authentication does not
establish a session; unavailable IDs display as `-`. Numbered search rows still
map to full evidence IDs for that output only, not persistent shell identifiers.

`session --logon-id 0x123 --text` distinguishes an observed, confirmed logoff
from a correlation boundary. A fallback ceiling, restart or later logon is not
shown as an observed session end. Missing or uncertain logoff evidence remains
explicit, together with the maximum correlation window and result limits.

`investigate <evidence-id> --text` shows the anchor, relationships with their
existing statuses and reasons, temporal neighbors, unresolved relationships,
deterministic detections and retrieval coverage. Nearby evidence is not causal
evidence. Multiple in-window timestamps retain their slot labels; ambiguous
anchor timestamps still require explicit selection for temporal analysis.
Unresolved anchors return their available timestamp slots before correlation,
detection evaluation or temporal retrieval. Resolved temporal retrieval uses the
same bounded, strict same-host window as `around`. Nearby observations are shown
nearest first, with stable timestamp, evidence-ID and slot tie-breakers.
The compact text view shows meaningful artifact objects and summarizes excess
Registry LastWrite observations with an omitted count. UserAssist and other
artifact observations remain visible; JSON/raw retain the full retrieved evidence.
Artifact-family forensic notes and parser warnings are grouped rather than repeated.
Coverage and absent detections describe the bounded returned result, not a
complete forensic examination.

`investigate --text` adds a deterministic Investigation summary after the anchor.
It selects at most eight already-retrieved, same-host observations in the selected
window, then displays those selections chronologically. Selection ranks exact
object comparisons first, followed by semantic class (service, process, file
creation, UserAssist, Prefetch, MFT, Registry, other EVTX), detection relevance,
temporal distance, and stable timestamp/evidence-ID/slot tie-breakers. Comparisons
use normalized paths, exact basenames, service names or Registry keys; basename
agreement does not establish identical paths or the same file.

Unrelated Prefetch, generic Registry LastWrite and unmapped EVTX are normally
excluded from the summary unless an exact object match or existing detection
qualifies them. Exact names `cmd.exe`, `Command Prompt.lnk`, `conhost.exe` and
`sc.exe` also qualify as named-tool temporal context for supported UserAssist,
Prefetch or process observations. This display priority does not create a forensic
relationship or establish program authenticity, intent, or a process chain.
UserAssist execution/interaction wording requires its internal LastExecution slot;
a containing-key LastWrite is never described as execution. Service accounts are
labelled separately from users; attribution is not copied between observations.

Fixed assessment templates retain causality and process-instance cautions. Brief
rule references point to the existing Detections section without repeating its
explanations. No model, embedding, additional case search, schema change or new
evidence ID is involved. The summary leaves Nearby evidence and JSON/raw intact,
including their existing limits and compaction. An unresolved timestamp produces
no summary; empty summaries describe only the returned bounded evidence.

Both commands retain JSON as their direct CLI default and use human text by
default in the interactive shell. `--json` preserves the structured contract
and `--raw` retains detailed evidence. Human text uses existing color,
`--page`, `--output` and `--append` behavior; output files are plain text.
Process-tree reconstruction semantics are unchanged. The mixed-artifact `around` view is described above.

#### Linked logons: investigated, not correlated

Microsoft's [Event 4624 documentation](https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4624)
defines Linked Logon ID (version 2) as a reference to a paired logon session,
with `0x0` indicating no associated session. Locard retains `TargetLinkedLogonId`
in original EventData but does not normalize it into a session lookup key.
Current session correlation uses role-specific target, subject and process
Logon IDs; reciprocal linked values do not change those associations.

A future evidence-driven implementation could expose an explicit **paired-session
reference** in session output and investigation context. It should not merge
activity windows, replace ProcessGuid relationships or infer causation, token
elevation or maliciousness. Before implementation, define and test host/boot
scope and identifier reuse, duplicate-field rejection, unique target anchors,
missing/nonreciprocal references, contradictory accounts, duplicate exports and
source provenance. Documentation establishes the field's meaning, but these
Locard identity and ambiguity rules need a separate design and validation task.

### EVTX recovery and Service Control Manager

EVTX ingestion validates fixed chunk boundaries, chunk checksums, and record
signatures/sizes before decoding records. A localized failure is recorded;
recovery proceeds only at a validated record boundary or a later complete chunk.
It never scans arbitrary bytes for apparent events. For a dirty file with a
checksum-valid header, independently valid chunks beyond its declared count are
accepted only while both chunk record ranges continue consecutively. Clean,
stale, discontinuous, unsupported, and unvalidated tails are not imported.

Parser anomalies keep an ingestion partial even when later records are recovered.
`status --json` exposes existing ingestion-error rows with optional structured
EVTX diagnostics: chunk/file offsets, binary record numbers, resume offset, and
successful XML records parsed after the anomaly. This last count describes parser
recovery, not necessarily new inserts (normalization failures, duplicate ingestion,
or source-change rejection can affect publication). Unknown locations remain null.
Counts are per anomaly and may overlap; do not sum them. A header warning that
does not interrupt parsing has no resume offset. Header/XML EventRecordID
differences remain non-fatal validation notes.

EVTX recovery has forward-only bounds and cooperative deadline checks using the
parser-timeout setting. These checks run between parser operations; EVTX parsing
is not subprocess-isolated and an individual third-party XML decoding call cannot
be forcibly interrupted by this deadline. Other artifact worker timeouts are unchanged.

Service Control Manager Event 7045 in the System channel is normalized as `service`
and rendered as a service-installation observation. Its preserved EventData provides
service name, image path, service type, start type and service account; the account
is not assigned as the actor username and the image is not treated as an observed
process execution. `search --kind services` includes these records. The existing
`LOCARD-SVC-001` service-installation observation rule (now version 2) also recognizes
7045; no separate duplicate rule is added. Installation alone does not prove that
the service successfully started or executed. Host context follows the per-record
resolution rules above. Existing ingested rows are not rewritten automatically.

### Chromium browser History and downloads

`ingest browser` imports one acquired Chrome or Edge `History` SQLite file.
Product and profile are explicit analyst metadata, never guessed from paths or
URLs. Profile names do not establish Windows user identity. This command is
explicit rather than part of `ingest all` discovery, which cannot safely infer a
browser product/profile from an arbitrary SQLite file.

The interactive new-case wizard also discovers Chromium History candidates by
validating the supported SQLite schema on private copies in a bounded worker.
A filename alone is insufficient. Each detected History requires explicit `chrome`
or `edge` and a nonempty profile before confirmation; directory names are only
path hints. The wizard reuses the existing ingestion commands. Original databases
and companions are not opened by SQLite during discovery.

```powershell
locard --db case.db ingest browser C:\Acquired\Chrome\Default\History --browser chrome --profile Default --hostname lab-host --user analyst
locard --db case.db ingest browser C:\Acquired\Edge\Profile1\History --browser edge --profile "Profile 1" --source src-<existing-id>
locard --db case.db search --artifact browser --browser-kind visit --url-contains example.com
locard --db case.db search --artifact browser --browser-kind download --download-path-contains tool.exe --browser chrome
locard --db case.db show BROWSER:<id> --json
locard --db case.db timeline --artifact browser --start 2020-01-01T00:00:00Z --end 2020-01-02T00:00:00Z --text
locard --db case.db around BROWSER:<download-id> --timestamp-slot Browser.DownloadStart --text
locard --db case.db investigate BROWSER:<download-id> --timestamp-slot Browser.DownloadStart --text
```

`--browser-kind visit` selects BrowserVisit records; `--browser-kind download`
selects BrowserDownload records, not separate start/end observations. Default
ordering is unchanged. Human browser search keeps metadata, optional full IDs,
and record-specific warnings directly under each result. Exact shared forensic
notes appear once per result set; readable Unicode is retained while terminal
controls remain escaped. JSON retains the complete structured records.

Use actual IDs returned by `search --ids`/JSON. Omission of `--source` in scripts
creates a new automatic source for each invocation; use an existing explicit
source ID to retain an unambiguous source across repeated ingestion.

Browser ingestion requires schema 5. Existing cases are **never upgraded by
ingestion**. For an older case, create a new case and ingest the original evidence.
Older Locard releases reject schema 5. Existing case evidence and non-browser source
semantics remain unchanged; no legacy source links are inferred. Schema 5 includes
`browser_contexts` and
`browser_record_occurrences`, with indexes. A logical context identifies the
main/WAL snapshot, product, and exact supplied profile; occurrences link each
record to a specific run/batch/source. File-hash membership and retrospective
file assignments **do not establish browser record provenance**. The same
History bytes supplied as Chrome/Default and Edge/Profile 1 remain distinct.
The same logical context ingested into multiple sources is explicitly ambiguous,
not silently attributed to one host.

Original files are read only as bytes. The bounded parser worker opens a private
copy with SQLite `mode=ro`, extension loading disabled, a restrictive authorizer,
and the existing worker timeout/memory/process-cleanup controls. Main database
and available WAL are copied and verified; SHM is reconstructed only in the
private working directory. Original main/WAL/SHM hashes are checked again before
publication. Changing/live inputs are rejected; acquire a stable snapshot first.
A supplied rollback journal is rejected rather than repaired. No checkpoint,
repair or write is performed on original evidence. If no WAL was supplied,
records explicitly warn that uncheckpointed activity may be absent. SQLite reads
committed WAL content; this is not WAL carving. Input files are bounded to 8 GiB,
SQLite values to 16 MiB, and URL chains to 1,000 entries. Missing required tables,
columns or stable primary row identities fail cleanly; unavailable optional
fields are recorded as limitations. This supports current Chromium schemas with
1601-epoch microsecond timestamps, not historical Unix-second download schemas.

Normalized visits retain URL, title, raw transition, URL-row visit/typed counts,
product/profile and `Browser.VisitTime`. Counts describe the URL row, not the
individual visit. Downloads retain supplied target/current/full paths, stored
URL/referrer, ordered URL chain, MIME/byte counts, raw state/danger type and
separate `Browser.DownloadStart`/`Browser.DownloadEnd`. Known state codes are
rendered as in progress, complete, cancelled or interrupted; unknown codes stay
unknown. Zero/null timestamps remain unset; invalid/out-of-range values remain
invalid. UTC conversion uses integer arithmetic and preserves microseconds.

Search supports `--url`, `--url-contains`, `--title`, `--title-contains`,
`--download-path`, `--download-path-contains`, `--browser`, `--profile`, and existing
time/host/user/source filters. URLs/titles/profile comparisons are literal and
case-sensitive; contains searches have no wildcard meaning. Exact download-path
matching uses existing Windows normalization; path substrings use SQLite's
case-insensitive ASCII matching. URL search includes each recorded redirect-chain
entry without conflating the first/last URL. JSON retains normalized fields and
run provenance. Human views use the existing palette and show literal Windows
paths. Queries use the case database, never reopen History or visit URLs.

Mixed timelines and same-host windows retain timestamp semantics. Deterministic
summaries may highlight matching download basenames/paths and exact URLs while
leaving unrelated visits in the nearby evidence. Navigation does not prove that
a person read a page; download history does not prove file execution or continued
file existence; missing history is not proof of absence. Matching basenames or
paths do not establish binary identity or causality. No browser URLs are fetched,
resolved or sent to a model. Firefox, cookies, credentials, cache and other browser
stores are outside this feature.


## Semantic search: a reusable model and a separate index for each case

In the interactive shell, start with:

```text
semantic search "core updater executable"
semantic status
```

Semantic search uses a small local embedding model, separate from the analysis
LLM. When needed, interactive search offers to download the pinned embedding
model and build (or rebuild) this case's index, then continues the original query.
Each action requires confirmation. Declining cancels the operation. A current index
is reused across sessions. `--json` requests full structured metadata and does not
prompt; normal interactive output is concise text. Direct CLI defaults to JSON;
use `--text` for human output.

The default model is BAAI/bge-small-en-v1.5, stored once under
`%LOCALAPPDATA%\Locard\models\bge-small-en-v1.5`. Confirmed interactive setup
remembers the directory in `%LOCALAPPDATA%\Locard\semantic-state.json`.
`--model-path` overrides it for one search/status command. Explicit setup
with a custom directory updates the remembered model only after verification.
The case-specific index remains `<database-path>.semantic-index`.

Optional runtime packages remain optional: neither the base installer nor a running
Locard process installs Torch/FAISS automatically. Native libraries may already be
loaded, and an interrupted in-place installation cannot reliably be rolled back.
`semantic status` checks actual importability and the project's pinned versions in
this process, reports the actual Python executable, and provides its exact pinned
pip command from installed Locard package metadata. Run that command, then restart
Locard. Models are not bundled with the source or package. Setup explicitly downloads
pinned files from Hugging Face; it receives no evidence or query text. Once set up,
building and searching are offline.

Advanced/scripted lifecycle (no prompts):

```powershell
locard --db case.db semantic search "core updater executable" --text
locard --db case.db semantic status --json
```

Only `semantic search` and `semantic status` are public commands. Interactive
search offers model download and index build/rebuild with explicit confirmation.
Scripts require prepared local assets and never silently download or build.
Use `--model-path`, `--index`, and `--max-vectors` on search/status as applicable.
`--max-vectors N` is a hard safety cap, not sampling: exceeding it aborts without
publishing an index. Retry interactive search with a higher cap when appropriate.
Incomplete model directories are preserved; choose a new destination.

Status distinguishes missing dependencies, missing/malformed models, missing,
current, stale and malformed indexes. Case content fingerprints, model/runtime
identity, and mapping/vector hashes remain mandatory. Representation version 2
uses compact labeled text and deterministic bounded chunks measured by the actual
tokenizer, including special tokens. Version 1 indexes require rebuilding.
Build manifests separately report `over_limit_records`, `chunked_records`,
`chunks_created`, and `truncated_records`. The existing field/collection bounds,
65,536-character representation bound, and 16-chunk-per-record bound still apply;
clipping at any bound is counted. Unsupported evidence representations or embedding
failures abort the entire build rather than silently skipping evidence. Current
representation coverage is EVTX, MFT, Prefetch and Registry; a case containing an
unsupported source such as browser evidence fails clearly rather than claiming
complete semantic coverage.

Human builds report model, CPU device, progress, vectors, elapsed time and final
counts. Progress is throttled and appears only on a terminal in human mode.
Cancellation preserves the previous published index; only the current invocation's
unpublished staging generation is cleaned up, when its path can be safely verified.
Prior published generations remain intact. JSON retains full model/index metadata
and contains no ANSI styling. Search displays full evidence IDs, scores and concise
excerpts; scores are similarity, not probability or confidence of maliciousness.

Semantic retrieval locates evidence; it does not create evidence. Its representations,
vectors, chunks and scores are derived sensitive retrieval data. Original evidence,
IDs and forensic conclusions are unchanged. See [semantic architecture](docs/v3.md).

### Legacy CLI ASK and semantic presentation

The hidden non-interactive compatibility command `locard ask "question"` uses deterministic retrieval first and the same reusable model
configuration and case index as `semantic search`. Precise supported queries do
not need embeddings. Set up the optional model and case index explicitly before
using semantic retrieval in this compatibility command; it never prompts. Missing optional runtime
dependencies require manual installation; no package installation is automatic.
If semantic retrieval is unavailable, a recognized deterministic query remains
usable with a visible limitation, including an empty/insufficient-evidence result.
A meaning-based question with no deterministic
selection instead reports the actionable semantic failure.

CLI ASK defaults to JSON and accepts `--text` and `--json`. `locard ask "question" --dry-run` shows the plan and bounded evidence
bundle without contacting the analysis LLM (local embedding retrieval may still
run). Explicit `--embedding-model` and `--semantic-index` overrides remain available
without changing the saved model preference.

Human ASK separates selected evidence, deterministic relationships, detections,
unresolved relationships and model analysis. Full evidence IDs remain visible.
Limitations disclose omitted records, fields, relationships and bounded retrieval.
Use `show <ID>` for the full normalized record; EVTX raw XML is available through
`show <ID> --raw`. Other artifacts have their own parsed context, not event XML.
MFT presence/access timestamps do not prove execution. Model confidence is retained
in JSON as model assessment metadata only; it is not shown as forensic certainty.
Citation validation checks references, not the factual correctness of model prose.

JSON, CLI text, and saved/appended text keep the original question for
context. Interactive `ask` follows the advisory behavior documented above instead. Human plans say `deterministic search` for exact/filter-based retrieval
or `semantic` for meaning-based discovery; internal JSON planner values remain
compatible.

Semantic-only selections are shown separately as candidate leads, with full IDs
and their selection basis. Engine-assigned relationships between records do not
automatically establish the activity asked about. Model assessments involving
candidate leads are labeled as having unverified relevance. The prompt requires
independent support in the artifact fields rather than similarity or suggestive
filenames. These instructions and citation validation are not a general proof of
model correctness.

ASK has a narrow deterministic suitability guard for questions explicitly about
credential use/usage/handling when the selected records are all MFT metadata.
It retains those records and their provenance, reports scoped insufficient evidence,
and does not contact the analysis LLM for a speculative finding. `--dry-run` still
shows the selection and limitation. This guard does not classify other question
types or assert that credential activity was absent from the case. The additive
JSON `grounding` object records retrieval roles, limitations and that decision;
the existing evidence bundle and selection metadata remain available.

Artifact guidance treats MFT timestamps as filesystem activity context, not proof
of execution or meaningful usage. Prefetch, EVTX, Registry and browser cautions
remain specific to their artifact semantics. Normal embedding-model loads disable
third-party progress bars through the supported Transformers control (which also
controls Hub progress). Errors, warnings and Locard's own build progress remain
visible; stderr is not redirected or discarded.

Semantic search defaults to 10 results in interactive human mode and 20 in direct
CLI or JSON mode. `--limit` overrides either default. Human Windows paths preserve
literal separators and Unicode while escaping terminal controls; JSON escaping is
unchanged. Confirmation explanations print once before a single-line input prompt.
Informational forensic notes use muted amber on extended-color terminals, dark
yellow otherwise, and plain text with color disabled. Actual warnings retain their
warning style.

For the pinned BGE model and representation 2 only, human semantic search hides
scores below **0.500** by default. `--show-weak` displays all returned candidates;
JSON and ASK selection are never filtered by this display rule. The centralized
cutoff is a presentation heuristic, **not a relevance classifier or proof of
irrelevance**. Nearest neighbors can be unrelated even above the cutoff.

An offline synthetic study compared file-only and mixed file/process cases:
top scores for updater/backup queries were 0.673/0.704, photograph 0.594,
`abracadabra` 0.451–0.470, and `banana spaceship orchestra` 0.424.
Another nonsense query scored 0.502–0.517, demonstrating overlap. The 0.500
display cutoff suppresses some weak neighbors but cannot identify every useless
query. It is not calibrated across real cases, languages or other models; other
model/representation combinations retain all results with the same caution.

### Case-local CSV dumps

Use `dump browser`, `dump mft`, or `dump all` to export retained records. Supported
categories are browser, evtx, mft, prefetch and registry. Files always go beside
the active case database in `dump/<type>.csv`; managed cases use
`%LOCALAPPDATA%\Locard\cases\<case>\dump\`. There is no output-path or filename option.
For scripts: `locard --db C:\Cases\Example\case.db dump all`.

Single-category dumps report elapsed time. `dump all` also reports elapsed time
beside each created CSV and a total. Durations use a monotonic clock. Per-category
times include attributed validation, reads, normalization, CSV encoding/write,
publication, checksumming and output-audit work. Shared setup and small unassigned
overheads are included in the total, so category times need not sum to the total.
The total covers the dump operation and cleanup, not outer CLI/session audit work.

For developer diagnostics, the `forensic_assistant.dump_cli` Python logger emits
phase durations at DEBUG level when logging is explicitly configured. No new CLI
option is required, and normal output does not include these details. Diagnostics
separate database open/schema/counts, destination validation, database and
provenance reads, Python row normalization, CSV encoding/write/flush, publication,
checksum and output-audit overhead. Read timing includes SQLite execute/fetch;
normalization excludes those measured reads. These are practical phase boundaries,
not a CPU profiler. Timings contain no paths, SQL or evidence values and are not
added to CSVs or audit records. Compare repeated runs with cache/filesystem
variability in mind before choosing an optimization.

For detailed Registry diagnostics, run a single `dump registry` with the dump
logger enabled. From the repository's PowerShell prompt:

```powershell
.\.venv\Scripts\python.exe -c "import logging; from forensic_assistant.cli import main; logging.basicConfig(level=logging.WARNING, format='%(message)s'); logging.getLogger('forensic_assistant.dump_cli').setLevel(logging.DEBUG); raise SystemExit(main())" --db "$env:LOCALAPPDATA\Locard\cases\Standard2\case.db" dump registry --force
```

This uses Python's existing logging configuration, not a new environment variable
or CLI option. It replaces only the derived Registry CSV through normal overwrite
validation and audit handling. The `Registry dump performance` DEBUG summary
contains seconds, calls, average and maximum call times, page/row counts, and a
completion flag (false means a failed/partial attempt). Normal output is unchanged.

The primary Registry and parent-timestamp phases measure the **whole `groups()`
call**, including SQLite execution/fetch, dictionary construction, safety-bound
checks and grouping. Parent-ID collection measures the existing Python set/sort.
Row normalization measures per-row Python construction/JSON decoding/provenance
selection. CSV time includes cell conversion, formula protection and serialization;
publication includes final flush/fsync/close and link/replace. Buffered writes may
also occur during CSV serialization. These nonoverlapping phases leave all other
work (including base record pages, own timestamps, provenance queries, destination
validation, checksums, audit and instrumentation overhead) in `other_seconds`.
The general dump timing summary supplies additional context for that remainder.
Nested components now separate value conversion from `writerow`, plus final
flush/fsync and Python materialization/bound-check work. `writerow` includes
buffered writes that occur inside it; these cannot be treated as separate disk
I/O measurements. Components overlap their parent phases and are excluded from
the top-level sum used for `other_seconds`. Registry exports reuse bounded,
page-local source projections while preserving identical CSV bytes.

`parent_ids` is the sum of **page-local unique** parent counts, not a globally
distinct count: a parent needed by multiple pages is counted each time. Timestamp
and primary-row counters likewise count materialized rows across calls. No global
ID set is retained. The configured page size is 128; the summary also reports the
largest and average nonempty page sizes. Detailed Registry metrics are enabled
only for the single-category command above, so totals cannot accidentally include
other categories from `dump all`. No query plans or evidence content are logged.

These CSV files are **derived analyst output, not evidence**. Each row includes its
canonical evidence ID for `show <evidence-id>`. Zero-record categories produce no
file. `dump all` reports those categories as skipped. Existing files require
`--force` and must have the expected dump header; linked paths, hard-linked targets,
known source evidence, and database/artifact destinations are rejected.

Exports use a consistent read-only SQLite snapshot, keyset pages, fixed columns,
evidence-ID row ordering, UTF-8 and Windows-compatible CSV newlines. Collections
are deterministic JSON cells: MFT names and separate SI/FN timestamp slots;
Prefetch candidate paths and all retained run slots; Registry key/value data and
hive dirty-state warnings; EVTX normalized event data; browser history/download
records, profile/context and run occurrences. Raw binary evidence is not exported.
Timestamp collections retain original values, status, precision and meaning.
Registry value key-time describes the parent key, not the value's creation time.
Browser rows use explicit occurrence provenance, never file-hash source membership.

Source ID, display name, hostname, username and volume-root columns are aligned
JSON arrays of current source assertions, in source-ID order. Multiple memberships
are retained without choosing an identity. Artifact-reported host/user fields and
legacy context assertions are separate columns. Empty arrays mean no such
assertions; null array entries mean unknown. Scalar nulls use empty cells (as do
empty scalar text values); JSON cells preserve null versus empty text. No identity
is inferred from paths. Exported source metadata remains analyst supplied.

For spreadsheet safety, scalar text starting with an apostrophe, tab, CR/LF, or
with `=`, `+`, `-`, `@` after leading whitespace gets one leading apostrophe.
Remove exactly that one prefix to recover the original text. JSON cells preserve
nested text verbatim. CSV quoting alone does not guarantee safe spreadsheet import;
import text columns as text and keep the case authoritative. Oversized records,
related-record pages or cells fail explicitly rather than silently truncating data
(2 MiB per cell; 32 MiB per query page; 100,000 related rows per query page).

All requested files are staged before publication. Conflicts are checked before
export; each CSV is published atomically, with no-overwrite publication unless
`--force` is supplied. Multi-file publication is not a filesystem transaction:
if cancellation or an I/O/audit failure occurs during publication, already
published complete files remain and are reported. Temporary files are cleaned up.
The existing analyst activity sidecar records command and OUTPUT_WRITE/OVERWRITE
intent/completion, relative filename, category, count and checksum; the evidence
database, semantic indexes and investigations are not modified. A long export's
read snapshot can retain WAL pages until staging finishes; it closes before
publication. No checkpoint or database repair is performed.

### Bounded-investigation consistency and grounding

`investigate-ai` uses a private, SQLite-consistent temporary case snapshot for all
read-only tools, then compares the live case's full content fingerprint at completion.
Allow temporary disk space approximately equal to the case size. A changed live
case stops final acceptance; an unconfirmed comparison explicitly limits results
to the original snapshot. Copies are removed after worker cleanup; uncertain cleanup
surfaces `CLEANUP_LIMITATION`. See [the consistency design and measurements](docs/v4.md#snapshot-validation-gate-and-chosen-consistency-model).

Missing or truncated fields must be retrieved through allowed tools before they
can support factual findings. Grounding validation remains strict. When unsupported
final proposals leave an interactive investigation without a supported conclusion,
Locard displays a concise rejection notice based on controller state. `--json`
remains machine-readable. The `!` routing described below reuses this same bounded engine.

### Interactive AI questions and investigation output

Use `! What evidence is available in this case?` for deterministic inventory.
General guidance and uncertain questions remain advisory. Clear factual queries
beginning with `did`, `was`, `were`, `has`, `have`, `when did`, `when was`,
`which records`, `show evidence for`, or `inspect evidence for`, together with a
recognized file extension or canonical evidence-ID reference, use bounded
investigation. Examples include `! Did example.exe execute?` and
`! Inspect evidence for EVTX:<hash>:Offset:<offset>`. This deliberately narrow
routing is not a general intent classifier; use `investigate-ai` explicitly for
questions outside it.

Locard announces this transition and asks **[y/N] before each proposed tool**.
Only `y` approves; declining or timing out prevents that operation. Each later
tool needs a new approval. The same read-only engine, snapshot, grounding,
audit and transcript protections apply. Initial deterministic retrieval is part
of investigation startup; it is not a model-proposed tool. There is no AI mode or
second prefix. Default bounds are 8 steps, 6 tool calls and 300 seconds; `!` adds
no advanced flags. The explicit command retains its existing advanced controls
and policy; use `--approve-tools` for per-operation approval there.

`investigate-ai "question"` now renders concise human text, including canonical
IDs, completed operations, rejection notices, termination, exceptional integrity warnings and
material limitations. Observed values are reported fields, not proof of execution or
causation. Unverified model hypotheses/unknowns remain in the full JSON, labelled
as unverified. `investigate-ai --json "question"` preserves the complete result;
approval interaction uses stderr and requires an interactive stdin. Redirected
human output is static; JSON has no animation or human summary. Transcript review
commands retain their existing output.

Time filters supplied by the model remain paired with `start <= end` and a
maximum span of 24 hours. Rejections return compact contract corrections; Locard
does not repair arguments or expand permissions.

Normal help presents `!` as the AI interface. For explicit budgets, dry-run or JSON,
`help investigate-ai` documents the retained Advanced / Diagnostic command.
Human results use existing terminal colors, semantic timestamp labels where
available, and grouped material caveats. Successful integrity checks and generic
boilerplate remain in JSON rather than normal output. Dry-run displays one proposal
block and no zero-operation counter. Color-off and redirected output remain plain.

AI proposals use **Proposed forensic lookup** and **Approve this lookup? [y/N]**.
Each lookup remains strictly read-only and requires its own approval through `!`.
Normal results show concise rejection/outcome messages and material case warnings;
full diagnostics remain in JSON. Final integrity hashing can use the remaining
investigation deadline rather than the shorter individual-tool timeout.

### Protected-file validation metadata

`scripts/protected_manifest.py` creates or verifies SHA-256 validation metadata
for an explicit JSON list of root-relative file paths. It records path, byte size
and SHA-256 in deterministic path order; it reads evidence without opening SQLite
or invoking parsers. Symlink/reparse paths and traversal are rejected, files that
change during hashing fail validation, and existing manifests are never overwritten
by `create`. Keep selection lists and manifests outside the repository and evidence
folders; they may reveal sensitive filenames.

```powershell
python scripts/protected_manifest.py create --root C:\Evidence --paths C:\Validation\selected.json --manifest C:\Validation\baseline.json
python scripts/protected_manifest.py verify --root C:\Evidence --manifest C:\Validation\baseline.json
```

Verification covers the selected files, including missing or changed files; it
does not discover unlisted additions. Keep evidence quiescent while comparing.
This is analyst-side validation metadata, not evidence or a forensic conclusion.
A newly generated baseline establishes only current bytes, not equivalence to a
historical state whose hashes were never recorded. Report unreadable exclusions
explicitly; do not equate size/mtime equality with cryptographic integrity.

### AI command discovery

Use deterministic commands such as `investigate <evidence_id>` to gather and
correlate bounded evidence without AI. Use `! <question>` for interactive AI
assistance, with approval required for each proposed forensic lookup.
`investigate-ai` remains a hidden Advanced / Diagnostic interface.

`ai-history show <investigation-id>` reviews saved derived AI records;
`ai-history replay <investigation-id>` replays their lookups against the current
case. These records support audit/review/replay and are not source evidence.
Use the canonical `ai-history` command for saved AI records.

`analyze-timeline --start <timestamp> --end <timestamp>` remains a specialized
workflow: bounded deterministic time-range retrieval/correlation followed by
configured-provider AI analysis. `--dry-run` builds the bundle without calling the model.


## Generative AI providers and managed local runtime

Local is the default and recommended provider. With Local selected, generative
inference uses numeric loopback and evidence supplied to the model stays on this
computer. Cloud providers are optional and may receive the bounded case context
and evidence disclosed to the model. They do not preserve local confidentiality.
Embedding/indexing remains separate and local regardless of generative provider.

| Provider | Mode | Environment variable |
| --- | --- | --- |
| Local | Local | none |
| OpenAI | Cloud | `OPENAI_API_KEY` |
| Anthropic Claude | Cloud | `ANTHROPIC_API_KEY` |
| Google Gemini | Cloud | `GEMINI_API_KEY` |
| DeepSeek | Cloud | `DEEPSEEK_API_KEY` |
| xAI Grok | Cloud | `XAI_API_KEY` |

Provider names/keys follow the [LiteLLM provider documentation](https://docs.litellm.ai/docs/providers).
Install cloud support explicitly with `python -m pip install ".[cloud]"` from the
checkout. The base installation does not install LiteLLM. Configure a model that
supports the requested structured response format; unsupported models fail without
switching provider or dropping the schema. Model availability is provider-specific.

```text
ai status
ai configure
ai configure local --executable "C:\Tools\llama.cpp\llama-server.exe" --model-path "C:\Models\Qwen3-4B-Q4_K_M.gguf"
ai start
ai stop
ai provider local
```

After case selection, an unconfigured interactive shell offers `Configure AI now?
[Y/n]`, defaulting to Yes. Declining skips setup for that session; deterministic
commands and inventory-only advice remain available. Future sessions may offer
again until configuration is valid. Setup never launches or loads a model.

`ai configure` offers Local first. Local means llama.cpp / llama-server, with no
engine selector. Basic setup asks only for the executable and GGUF paths. Both
must be accessible regular files; Windows executables require `.exe`, and models
require `.gguf` (case-insensitive). Invalid input can be retried or cancelled without
replacing previous settings. The local display name is derived from the model
filename, never configured independently; `--model` is for cloud identifiers only.
Qwen3-4B-Q4_K_M.gguf is the currently tested/recommended model, not a requirement.
Other llama.cpp-compatible GGUF models may work: ability to load/serve a model is
separate from reliably following Locard's structured-output, grounding, forensic,
and tool-proposal contracts. Compatibility with every GGUF is not guaranteed.

Status distinguishes provider selection, configuration readiness, and runtime
state. Fresh configuration is `not_configured`, invalid paths are
`configured_invalid`, and valid paths are `configured_ready`; path validation does
not attest model behavior. Status displays configured paths and derives the model
label only when a model path is supplied. Runtime-reported model IDs are separate
diagnostics and do not override that configured label. Real readiness is checked
on first inference or `ai start`, using the existing filename comparison.

Selecting cloud first requires acknowledgement that supplied evidence may leave
this computer, then asks for an explicit model identifier. Declining
preserves the previous configuration. Scripts can use `ai provider openai --model
MODEL --acknowledge-cloud`. Set credentials in the documented environment variable
before launching Locard; never put a key in a command argument or configuration file.
A provider/model can be saved without a key, but status reports `credential_missing`
and the required variable name. Model calls fail without fallback until it is set. `ai status --json`
reports availability only. Live cloud validation is optional and analyst-controlled.

Preferences are in `%LOCALAPPDATA%\Locard\ai\config.json`, outside cases.
Runtime state uses format 1 in `runtime.json` in that private directory: a random
instance ID, authenticated loopback control endpoint/token, child PID for status,
and start time. The control token is local authorization material, not a cloud key;
it is never printed by status. No PID read from state is used to terminate a process.
The supervisor owns its process/job handles; stale/unreachable state does not authorize
killing another process. Directory redirection through symlinks/reparse points is rejected.

On first inference Locard starts the configured llama.cpp executable, waits for the
configured model to become ready, and reuses the runtime. Inventory-only advice does not start a model. Timeline dry runs do not call
the model; investigation dry runs retain their existing one-model-proposal behavior
while suppressing iterative tools. Fresh Local configuration has no executable or
model path: a suggested filename is not a configured model. Supply the executable
and GGUF paths; normalized absolute paths are saved. With the recommended model,
the default runtime options produce:

```text
llama-server.exe -m models\Qwen3-4B-Q4_K_M.gguf -ngl 99 -c 4096 --host 127.0.0.1 --port 8080
```

Launch uses an argument list, without a shell. Nothing downloads llama.cpp or model
weights. Port 8080 is preferred. Before starting a child, Locard checks the configured
numeric-loopback endpoint for a successful `/health` response and a nonempty
`/v1/models` list. A compatible endpoint is reused as **external**, without gaining
process ownership. An incompatible occupied port fails safely; its occupant is never
terminated. `ai configure --port 0` requests a free loopback port (no external discovery).
The persistent supervisor survives direct CLI and interactive launcher exit. Windows
launcher jobs allow explicit breakaway for this hidden supervisor only by launch flags;
ordinary children remain contained, and installer jobs do not permit breakaway. The
supervisor owns the server's separate cleanup job. Both processes use hidden-console
creation flags. If the enclosing environment disallows breakaway, startup fails rather
than silently creating a client-bound runtime. It shuts down
its owned runtime after 15 minutes without successful inference and no active bounded
request. `ai stop` requests owned shutdown and checks completion; active requests
prevent an explicit stop. Startup cancellation asks the owner to clean up, and
unconfirmed cleanup is surfaced as `CLEANUP_LIMITATION`.

`ai status` shows `running` or `stopped`, and `Ownership: Locard-managed` or
`Ownership: external` when running. Stale control-state details are DEBUG diagnostics,
not a normal runtime status. External runtime settings are not controlled or attested
by Locard: restart that server manually to apply changes. `ai stop` refuses to stop
external processes, and Locard's idle timer never applies to them. Status polling does
not reset the managed idle timer.

Advanced local performance settings can be saved with:

```text
ai configure --extra-options "-ngl 99 -c 4096 --flash-attn on"
```

The supported options are `-ngl`/`--gpu-layers`, `-c`/`--ctx-size`,
`-fa`/`--flash-attn` (`on`, `off`, `auto`), `-t`/`--threads`, `--threads-batch`,
`-b`/`--batch-size`, and `-ub`/`--ubatch-size`. Quoted scalar values are accepted;
shell syntax, paths, unknown flags, and duplicate aliases are rejected. Model, host,
port, credential, template, and logging flags cannot be overridden here. `-ngl` and
`-c` update the dedicated saved settings, replacing their defaults without duplicate
argv entries. Supplying the same setting through both CLI forms is rejected. Other
extra options replace the previously saved extra-options list; an empty string clears
that list. These preferences remain outside the evidence database.

The managed supervisor reports a non-secret configuration fingerprint covering paths,
context, GPU layers, port and extra options. Changes show `restart required` in status.
The next human model request offers `Restart the managed AI runtime now? [Y/n]:`.
Declining preserves the running server and cancels that request; unattended/JSON requests
do not assume consent. Configuration and deterministic commands never restart it.

`ai logs` shows recent private diagnostics from
`%LOCALAPPDATA%\Locard\ai\llama-server.log` (bounded to 32 KiB). Server stdout/stderr
are drained, but raw lines are **not retained**: only fixed lifecycle and warning/error
categories are recorded to avoid exposing forensic prompts, paths, or credentials.
This intentionally limits diagnostic detail. External runtime logs are not captured.

`!`, `investigate-ai`, `analyze-timeline`, hidden scripted `ask`, and optional report
narrative assistance share the backend. An explicit `--endpoint` on supported
advanced commands selects that numeric-loopback endpoint for that invocation only;
Locard neither manages nor terminates that external server. No session preference
changes implicitly. Human `ai-history show`/`replay` uses the shared activity indicator;
JSON and non-terminal output remain spinner-free.

Locard controls evidence retrieval, disclosure, tool authorization, approval, and
grounding independently of the provider. LiteLLM receives only caller-built bounded
messages and the response schema, with no provider-native tools, router, fallback,
or automatic retry. Responses still pass the existing Locard validators. The SDK
runs in a bounded disposable process, with request/response logging disabled; provider
exceptions are replaced with generic errors. API keys are not stored in preferences,
case databases, transcripts, or audit records. Configured provider/model identifiers
are metadata, not proof of provider execution or model-weight identity.


To manually test first-run AI setup without altering existing user preferences,
use a temporary LOCALAPPDATA for this PowerShell process and select an existing
case explicitly. This isolates all Locard user-level UI/AI preferences for the test;
it does not copy or reset the case. Restore the environment after exiting:

```powershell
$previousLocardAppData = $env:LOCALAPPDATA
$env:LOCALAPPDATA = Join-Path $env:TEMP ("Locard-AI-UX-" + [guid]::NewGuid())
try { .\locard.ps1 } finally { $env:LOCALAPPDATA = $previousLocardAppData }
```

The original configuration remains untouched. Test configuration persists only
under that temporary directory; no model or executable is copied there.

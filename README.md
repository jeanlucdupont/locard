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
`[mixeddesktop]>` or `[case.db]>`, retaining the current prompt style. A valid case
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

The ingestion commands are `ingest-all`, `ingest-browser`, `ingest-evtx`,
`ingest-mft`, `ingest-prefetch`, and `ingest-registry`. Explicit `ingest-evtx`
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

To be documented


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

`ingest-browser` imports one acquired Chrome or Edge `History` SQLite file.
Product and profile are explicit analyst metadata, never guessed from paths or
URLs. Profile names do not establish Windows user identity. This command is
explicit rather than part of `ingest-all` discovery, which cannot safely infer a
browser product/profile from an arbitrary SQLite file.

The interactive new-case wizard also discovers Chromium History candidates by
validating the supported SQLite schema on private copies in a bounded worker.
A filename alone is insufficient. Each detected History requires explicit `chrome`
or `edge` and a nonempty profile before confirmation; directory names are only
path hints. The wizard reuses the existing ingestion commands. Original databases
and companions are not opened by SQLite during discovery.

```powershell
locard --db case.db ingest-browser C:\Acquired\Chrome\Default\History --browser chrome --profile Default --hostname lab-host --user analyst
locard --db case.db ingest-browser C:\Acquired\Edge\Profile1\History --browser edge --profile "Profile 1" --source src-<existing-id>
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
semantic rebuild
```

Semantic search uses a small local embedding model, separate from the analysis
LLM. When needed, interactive search offers to download the pinned embedding
model and build (or rebuild) this case's index, then continues the original query.
Each action requires confirmation. Declining cancels the operation. A current index
is reused across sessions. `--json` requests full structured metadata and does not
prompt; normal interactive output is concise text. Direct CLI defaults to JSON;
use `--text` for human output.

The default model is BAAI/bge-small-en-v1.5, stored once under
`%LOCALAPPDATA%\Locard\models\bge-small-en-v1.5`. Successful `semantic setup`
remembers the directory in `%LOCALAPPDATA%\Locard\semantic-state.json`.
`--model-path` overrides it for one build/search/status command. Explicit setup
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
locard semantic setup --download
locard --db case.db semantic build --text
locard --db case.db semantic search "core updater executable" --text
locard --db case.db semantic status --json
```

Advanced controls include `semantic setup --model-path <directory>` (with
`--download` in scripts), `semantic build`, `semantic rebuild`, `--model-path`,
`--index`, and `--max-vectors`. Setup's legacy positional directory remains optional.
`--max-vectors N` is a hard safety cap, **not sampling**: exceeding it aborts without
publishing an index and reports the known lower bound. Use explicit build/rebuild
with a higher cap when necessary. Incomplete model directories are preserved and
reported as malformed; choose a new destination rather than overwriting them.

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

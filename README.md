# Locard V1 — Local AI-Assisted Digital Forensics

Locard V1 (package version 0.2.0) is a Windows EVTX investigation CLI, named after Edmond Locard and the
principle that **every contact leaves a trace**. It preserves source provenance,
normalizes events into SQLite, retrieves evidence deterministically, and optionally
asks MiniCPM5 through a local llama.cpp server to analyze retrieved records.
V1 adds deterministic timelines, process/session correlations, eight dynamic review
rules, investigation assembly, and evidence-backed timeline summaries on top of V0.

**Evidence establishes facts. Model output is analysis, not evidence. Locard is an
investigative aid, not a replacement for validation by a forensic analyst.**

<img width="1054" height="1897" alt="locard" src="https://github.com/user-attachments/assets/4e9b9aac-0b74-4fb8-9eb7-b7435626647b" />


## Installation on Windows

If upgrading an existing V0 database, use the explicit migration below before other
commands. V0 CLI commands remain available, including positional timeline syntax.

Use Python 3.11 or newer. From this project directory in PowerShell:

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[test]"
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m forensic_assistant.cli --help
```

If a different Python 3.11+ version is installed, select it instead. No activation
script is necessary. The implementation environment already has a populated
`.venv`; virtual environments are machine-specific and should be recreated when moved.

Runtime dependencies are pinned in `requirements.txt`: `python-evtx==0.8.1` and
`defusedxml==0.7.1`. SQLite, CLI, hashing, HTTP, and time handling use Python's standard
library. `pytest` is a development dependency. Parser upstream:
<https://github.com/williballenthin/python-evtx>.

Installation downloads packages, but application operation does not require Internet
access. To prepare installation on an isolated workstation, build a wheelhouse on
a compatible connected Windows/Python machine, then transfer the project and wheels:

```powershell
python -m pip wheel --wheel-dir wheelhouse ".[test]"
# On the isolated workstation, after creating a virtual environment:
.\.venv\Scripts\python.exe -m pip install --no-index --find-links wheelhouse "locard-forensics[test]"
```

## Start the local model

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

## Ingest and inspect evidence

### Upgrade a V0 database

```powershell
.\.venv\Scripts\python.exe -m forensic_assistant.cli --db data\case1.db migrate
```

V1 requires schema version 2. Migration creates a uniquely named local SQLite backup
beside the original database, then adds `event_context` and compound indexes in a
transaction. It derives context from stored evidence without modifying any existing
event, evidence ID, raw XML, source path, or source-location record. Failure rolls
back the migration. Repeating a completed migration is a no-op. Normal commands do
not silently migrate V0 databases. Never delete your only database to resolve a
migration error; inspect the reported error and retain the backup.

`event_context` stores normalized host keys, event categories, GUIDs, role-specific
Logon IDs/accounts/SIDs, source IP keys, extraction version, and warnings. It is a
derived lookup projection, not new evidence. Schema and context extraction versions
are separate from the unchanged V0 normalizer version. Sysmon GUIDs and lifecycle
markers already retained in EVTX become usable without re-ingesting sources.

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

## Deterministic searches

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

## Evidence IDs and source paths

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

## Ask questions

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
New databases apply the additive schema-2 extension
from `database/migrations.py`; existing V0 databases require `migrate`. Unsupported
versions are rejected. Changing normalization mappings does not automatically rewrite
existing events. Context extraction version 1 is stored separately in `event_context`.

V1 deliberately excludes embeddings, vector databases, autonomous agents, cloud
services, web interfaces, MFT, Prefetch, Registry, and memory parsing. No detection
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

**DETECTION != COMPROMISE. CORRELATION != CAUSATION. ABSENCE OF EVIDENCE != EVIDENCE
OF ABSENCE.** Logging configuration and supplied evidence determine what Locard can
reconstruct. No model output is inserted into the evidence database.

# Locard — Local AI-Assisted Digital Forensics

Locard V0 is a Windows EVTX investigation CLI, named after Edmond Locard and the
principle that **every contact leaves a trace**. It preserves source provenance,
normalizes events into SQLite, retrieves evidence deterministically, and optionally
asks MiniCPM5 through a local llama.cpp server to analyze retrieved records.

**Evidence establishes facts. Model output is analysis, not evidence. Locard is an
investigative aid, not a replacement for validation by a forensic analyst.**

<img width="1054" height="1897" alt="locard" src="https://github.com/user-attachments/assets/4e9b9aac-0b74-4fb8-9eb7-b7435626647b" />


## Installation on Windows

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

The V0 keyword planner recognizes PowerShell, processes, logons, failed/privileged
logons, scheduled tasks, services, account creation/changes, usernames, one IP address,
Event IDs, and timestamps. The displayed plan is reviewable; it is not a general
natural-language interpreter. Multiple activity categories are rejected rather than
silently choosing one. Unsupported questions require a supported concept or manual
search. A time-only question uses an explicit `--date`, a date in the question, or the
sole UTC date in evidence; otherwise it asks for a date. Assumptions are shown in the
plan. Timeline questions use a five-minute window.

`--dry-run` displays the plan and evidence bundle without contacting the model.
Ask retrieval defaults to 30 records; the context budget may include fewer. Bundles
report matching, retrieved, included, and omitted counts. Long field values are
shortened with explicit `truncated_fields`; raw XML is not sent. Narrow the search
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

Schema version 1 is in `database/schema.sql`; other nonzero schema versions are
rejected. Changing normalization mappings does not automatically rewrite existing
events. Use a fresh database when testing a changed normalizer against originals.

V0 deliberately excludes embeddings, vector databases, autonomous agents, cloud
services, web interfaces, MFT, Prefetch, Registry, and memory parsing. No detection
coverage or forensic completeness is promised by this initial event subset.

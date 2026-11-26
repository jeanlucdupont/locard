# Locard 6.178 — Security Signal Discovery

Implementation ready for manual acceptance; no live investigative success claimed.

## Why

The analyst-reported 6.177 blind investigation demonstrated working cross-artifact reasoning but missed the incident. Early chronological samples also overloaded working context. This release supplies better starting points rather than prescribing a workflow or promising incident detection. No actual case was opened during development.

## Implementation

`detections/discovery.py:Discovery` is a provider-free application service. `conversational_ai/tools.py:Tools.execute` exposes `discover_security_signals` and `activity_overview` through the existing protected read-only conversation worker. The system instruction recommends alert-led discovery for broad questions, original inspection, alternatives and continued exploration. Specific questions can bypass discovery. There are no required investigation stages or new session quotas.

Existing services reused: `EvidenceQueries._where/search`, `get_evidence`, EventData `payload` and `BLOCK_NOTE`, source membership, original-field verification, conversation notebook, transaction read view, worker cancellation and progress. Existing detection engine and its twelve registered rules remain unchanged.

### Qualified signal catalog

Event ID alone never qualifies an event. Provider and channel must also match exactly.

| Provider / channel | Event IDs | Meaning preserved |
|---|---|---|
| Microsoft-Windows-Windows Defender / Microsoft-Windows-Windows Defender/Operational | 1116 | Recorded malware/PUA detection |
| Same | 1117 | Recorded action; inspect original action and status, which can include Allow |
| Same | 1118, 1119 | Failed action / critical action failure |
| Same | 1121, 1122 | ASR block / audit; audit is not blocking, blocking is not successful script execution |
| Same | 5001, 5004, 5007 | Protection disabled / protection configuration / configuration change; not inherently malicious |
| Microsoft-Windows-Security-Auditing / Security | 4698, 4697, 4720, 4648, 4719 | Task creation, service installation, account creation, explicit credentials, audit-policy change |
| Service Control Manager / System | 7045 | Service installation |
| Microsoft-Windows-Eventlog / Security | 1102 | Audit clearing |

Definitions checked against Microsoft's [Defender event reference](https://learn.microsoft.com/en-us/defender-endpoint/troubleshoot-microsoft-defender-antivirus), [ASR event reference](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-windows-events), and [4719 reference](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4719). Interpretations are read-time labels, never replacement original values or proof of compromise.

The five existing single-event rules TASK-001, SVC-001, AUDIT-001, ACCOUNT-001 and CRED-001 provide ordinary security observations. PS-001 and PROC-001 supply existing PowerShell and Office-child heuristics, gated by qualified Security 4688, Sysmon 1 or PowerShell 4103/4104 candidates as appropriate to their existing normalized kinds. Heuristic matches are explicitly separate from recorded alerts.

AUTH-001 and X-001 through X-004 are explicitly **not evaluated** by discovery: their lookback/corroboration/support queries require further source-aware integration. Calling the legacy detection engine unchanged would risk extending authorized scope. Their legacy behavior remains available unchanged outside this new tool. AppLocker, Code Integrity, unlisted Defender IDs and other security-product semantics are not implemented. Unknown providers remain visible through event distribution.

### Selection, coverage and context

SQL applies artifact/source/time restrictions and provider/channel/Event-ID predicates before original-record hydration. Priority is a static review order, not severity or probability: Defender detections/actions/ASR and disablement first; configuration/audit changes and heuristic candidates next; other ordinary observations afterward. Ties use recorded timestamp then exact evidence ID. Security results are individual event leads, not merged incidents; population summaries provide grouping separately.

Defaults: five returned items, 200 examined candidates per signal page; request maxima ten items and 1,000 candidates. These are pageable response bounds, not investigation quotas. No preliminary exact candidate count. `next_offset` continues deterministically within the pinned read view. A byte-limited unreturned candidate is revisited. `candidates_evaluated` can include that candidate; `candidates_consumed` drives continuation.

`complete` means the requested supported candidate population was covered from offset zero. `remaining_complete` means no further page remains after this offset. Neither proves complete endpoint logging, complete ingestion, or absence of an incident. Per-rule evaluated/returned counts concern the current page; deferred and unselected rules are distinct. Missing scoped Defender records are distinguished from no matches among supported events. A qualified unknown Defender event does not acquire invented semantics.

Each response is capped at 12,000 serialized bytes or the analyst's smaller result limit. Entire items are omitted with continuation; a capacity too small for an item fails explicitly instead of returning a nonadvancing cursor. Original scalar summaries carry exact pointers, bounded values and truncation/redaction flags. Selected EventData retains names and original ordinal-based pointer positions. At most eight selected EventData fields appear initially; full original inspection remains available. Values are clipped to 192 encoded bytes, names to 80. Evidence IDs are never clipped.

Only returned, authorized evidence IDs enter the known-reference set. Aggregations expose an actual representative ID, never a fictional aggregate evidence ID. Only complete, unredacted original fields enter the verification exposure map. Interpretations, counts, priorities and group labels cannot masquerade as original fields. `show_evidence` and `verify_observation` retain their existing restrictions.

Complete returned tool results remain in the local conversation journal. Five sequential discovery results were tested within the existing request budget. This is not hierarchical context management: sufficiently large exchanges or unusually small custom budgets may still require existing context-capacity handling. No local-model compatibility claim is made from scripted-provider tests.

### Activity overview

| `kind` | Population and count meaning |
|---|---|
| `event_distribution` | Provider/channel/Event-ID groups; exact retained-record count per group |
| `process_images` | Non-null normalized EVTX process-image groups; record counts, not unique executions |
| `prefetch_executables` | Executable groups with an authorized timestamp observation; record counts, not Prefetch run counts |
| `browser_downloads` | Compact individual download records, target/URL/referrer details; no full-population count |

Groups sort by descending count and stable group keys. Representative examples are explicit. Group values have truncation flags and stable full-value group identities. No rarity-based maliciousness classification, organizational baseline, Registry optimization, domain aggregation or MFT summary is introduced. Those are remaining extensions, not silently covered categories.

## Authorization and operational behavior

Source and exclusive time bounds may only narrow the approved grant; artifact families must be approved. Ambiguous source membership is excluded using existing membership semantics. No cross-artifact detection support queries run. Schema 4/5 is required for source-aware discovery. No schema changes, writes, ingestion, or migrations occur.

Operations use existing query cancellation and worker integrity checks. No mandatory short discovery timeout is added. Optional analyst time budgets remain available. Progress reports elapsed operation activity, not invented scan percentages. Recoverable query rejection does not end an otherwise healthy conversation. The diagnostic uses the same worker, without constructing a model backend.

## Validation recorded on 2026-11-26

Starting clean revision: `eda57a2` (6.177). Development used existing `.dependency-check-6175` Python environment; no dependencies installed. LiteLLM remains pinned to 1.111.0.

- Conversation, resource, resilience, legacy detection, source membership, browser integration and provider regressions: **129 passed in 129.48 s**.
- Final new discovery plus EVTX-content run: **46 passed, 1 failed in 18.67 s**. All **26 new discovery tests passed**. Failure: existing `test_cli_and_show_offset_preserve_existing_json` invokes removed top-level `search`; the unchanged parser expects `evidence search`.
- Earlier targeted detection/query/correlation run: **36 passed, 1 failed in 28.01 s**. Existing `test_new_cli_mixed_directory` invokes removed top-level `ingest-all`. Neither stale command-surface test nor production command parsing was changed.
- New tests cover qualified event semantics, collisions, missing fields, unknown categories, 1,500 preceding ordinary events, deterministic continuation, incomplete candidate coverage, scope rejection, ambiguous sources, exclusive end, grouping, Prefetch record-vs-run counts, original-field verification, injection/truncation, actual diagnostic subprocess/worker, cancellation/recovery, unchanged synthetic database bytes, scripted cross-artifact investigation and notebook reconstruction.
- Scripted provider tests use real scoped SQL and worker execution; they establish integration, not model intelligence or live incident discovery.
- Full suite intentionally not run. No live provider requests or protected case access.

Synthetic timing (one local in-process read-only run; 10,000 ordinary events plus one later ASR event): discovery **0.0281 s**, one result, **3,464 bytes**; event distribution **0.0306 s**, two groups, **2,242 bytes**. This excludes worker startup and is not a real-case forecast. An initial measurement harness left its SQLite connection open during temporary-directory cleanup; the corrected harness closed it and completed successfully. Production worker cleanup was not implicated.

## Windows manual acceptance

Use the existing environment, no pip installation required. User performs Git operations:

```powershell
cd C:\tmp\locard
git pull
python .\locard.py --version
```

Expected `Locard 6.178`.

Run local-only discovery (no model/provider needed):

```powershell
python .\scripts\discover_security_signals.py --db 'D:\Locard\Cases\KFI-5070790-V2\case.db' --source src-d3c195d3068e4906a805082df44c1a57 --start 2026-11-17T06:00:00.000000000Z --end 2026-11-18T06:00:00.000000000Z
```

Append `--json` for structured output. Append `--offset <next_offset>` using the returned numeric continuation until exhausted. `--category recorded`, `--category observations`, or `--category heuristics` narrows candidate discovery; `recorded` includes Defender control-change observations with their explicit non-alert classification. `--limit 5` controls returned items, `--candidate-limit 200` controls candidate work per page. `--tool-seconds <seconds>` is optional; omitted permits waiting. `--progress-seconds 30` controls stderr activity updates; Ctrl+C cancels. End is exclusive.

For population overview use the same command with `--overview event_distribution` (or `process_images`, `browser_downloads`, `prefetch_executables`). Overview uses `--limit` and `--offset`; category/candidate-limit concern signal discovery only. Inspect provider/channel distribution if no supported security signals exist. Counts and representatives do not establish complete incident coverage.

Then launch the selected case:

```powershell
python .\locard.py --db 'D:\Locard\Cases\KFI-5070790-V2\case.db'
```

Inside Locard, retaining the configured OpenAI model:

```text
investigation chat --source src-d3c195d3068e4906a805082df44c1a57 --start 2026-11-17T06:00:00.000000000Z --end 2026-11-18T06:00:00.000000000Z
```

Use the unchanged neutral question:

> Analyze the evidence discovered within the authorized November 17, 2026 time window. Identify potentially suspicious user activity, unusual process execution, browser navigation, downloads, file changes and persistence indicators. Correlate evidence across artifact families, establish a supported chronology, and propose specific follow-up investigations. Distinguish observed evidence from hypotheses. Do not assume that a security incident occurred.

Assess discovery coverage and usefulness separately from model reasoning and actual incident identification. Approval, progressive original inspection, verification, alternatives and cancellation must continue working. A polished narrative is not investigative acceptance.

## Change inventory

- New: `forensic_assistant/detections/discovery.py`, `scripts/discover_security_signals.py`, `tests/test_security_discovery.py`, this document.
- Updated: `conversational_ai/contracts.py`, `tools.py`, `service.py`, `activity.py`, `cli.py` (under `forensic_assistant`); `pyproject.toml`; `.gitignore` artifact allowlist.
- No parser, ingestion, database schema, legacy detection engine, worker protocol, provider adapter or forensic data changes. No commit or push.

Final checks: session-recording regressions **34 passed in 28.88 s**; `git diff --check` passed (only Git's informational LF/CRLF warning). Version command returned **Locard 6.178**, exit 0, with isolated temporary application state. An initial version check using ambient application state also printed a required-audit-coverage warning; this was not repaired or bypassed. Live acceptance should resolve any such existing audit warning before attempting required actions.

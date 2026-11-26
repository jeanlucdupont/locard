# Locard 6.179 — Microsoft Defender Forensic Artifacts

Implemented for manual acceptance, 2026-11-26. Starting clean revision: `7d905c8`, application 6.178. Working tree version: **6.179**, from `pyproject.toml`. No commit/push or actual case access occurred.

## Scope and format research

Defender is now a sixth evidence family (`defender`), separate from EVTX. The implementation parses locally acquired MPLog and MPDetection text without Defender installation, licensing, cloud connectivity or a model. File names designate ingestion candidates; contents must contain a recognized marker in the first 64 KiB. Explicit Defender ingestion also accepts renamed files based on contents. Unrecognized named candidates produce recorded ingestion failures, not fabricated evidence.

Research reviewed:

- Microsoft's [ASR troubleshooting documentation](https://learn.microsoft.com/en-us/defender-endpoint/troubleshoot-asr): Support diagnostic collection, distinct from event-log acquisition.
- [Dissect MPLog implementation](https://github.com/fox-it/dissect.target/blob/main/dissect/target/plugins/os/windows/defender/mplog.py): corroborates multiline BM, LowFi, mini-filter and detection-add format families. Its [AGPL-3.0 license](https://github.com/fox-it/dissect.target/blob/main/LICENSE) was checked; no code was incorporated.
- [Intrinsec mplog_parser](https://github.com/Intrinsec/mplog_parser): MIT-licensed forensic parser assessed, not added as a dependency or copied.
- [NXLog's SCEP log documentation](https://docs.nxlog.co/integrations/network/microsoft-system-center-endpoint-protection.html): primary product documentation includes a service-start MPDetection example and UTF-16LE file handling. A file named MPDetection need not contain malware detections.
- [DetectionHistory parser](https://github.com/jklepsercyber/defender-detectionhistory-parser), GPL-3.0, and [libyal's working format specification](https://github.com/libyal/dtformats/blob/main/documentation/Windows%20Defender%20scan%20DetectionHistory%20file%20format.asciidoc), GFDL-1.3: binary support needs a separately validated implementation and is deferred. No binary parsing code incorporated.

This is an independently written standard-library text parser, tested against synthetic format examples. It is not a claim of complete coverage of every Defender engine revision. Unknown lines in recognized inputs remain retained and searchable. Format recognition is not authenticity verification.

Deferred: DetectionHistory binary decoding, WPP, MPDeviceControl, MPScanSkip, quarantine payloads and sensor databases. The direct-file diagnostic can inventory regular files as unsupported. Guided Support-folder discovery lists other files as unsupported. It does not recursively parse DetectionHistory.

## Parsing and persisted contracts

`artifacts/defender.py` supplies a streaming generator to the existing `artifacts/worker.py` and `artifacts/ingest.py` staging/publication pipeline. No separate importer or evidence database exists.

| Concern | Implementation |
|---|---|
| Encodings | UTF-8, UTF-8 BOM, UTF-16LE/BE BOM, conservative null-byte inference for BOM-less UTF-16 |
| Original bytes | Base64 bytes retained per record, including BOM and line endings; concatenation in ordinal order recreates the input |
| Original text | Strict decoding first; invalid bytes use visibly escaped text with a limitation, while exact bytes remain retained |
| Location | Zero-based record ordinal, one-based start/end lines, byte start and exclusive end offsets |
| Identity | `DEFENDER:<file SHA-256>:Offset:<byte offset>` |
| Duplicate attempts | Existing evidence-ID deduplication; attempts remain separately recorded |
| Rotations | Different source hashes create separate provenance, even when observations repeat |
| Multiline | BEGIN/END BM telemetry; repeated and unknown fields retained in ordered arrays |
| Large records | 1 MiB bounded chunks; oversized lines/blocks are explicitly partial fragments, never silently dropped |
| Unknown content | Preserved as unknown observations, not alerts |
| Malformed/incomplete | Original retained; partial records generate persisted parse diagnostics and partial ingestion outcomes |
| Source changes | Existing pre/post hashing and size validation reject changed staged input |

The effective existing schema is sufficient: `evidence_records.original_json` stores original bytes/text and parsed fields; `evidence_timestamps` stores qualified observations; `evidence_objects` indexes paths, process images and exact scalar identifiers/actions/group keys. Existing source/run/batch relationships apply. **No schema change or migration is required.** Existing evidence, timestamps and IDs are not rewritten; no reingestion of other families is needed. Older applications may not render the new family; use 6.179 for Defender evidence.

Group metadata is derived application data. It is not an original evidence identity. Default original retrieval excludes raw Base64 and internal grouping metadata; explicit local raw inspection retains these. The conversational verifier refuses derived Defender category/group/parser metadata as original observations.

### Supported recognition

| Category | Fields and interpretation boundaries |
|---|---|
| `lowfi` | Complete command retained. A unique `.exe(` boundary and closing delimiter allow image/command splitting. Nested arguments remain intact; ambiguous boundaries are not guessed. Not a detection. |
| `behavior_telemetry` | Ordered field names/values including repeated/unknown fields; ProcessID, ImagePath, signature fields and times where present. Taint text retained, with recognized labeled components. Parent/module references are not process-tree or execution proof. |
| `asr_notification` | Ordered Process/Action/Target/Reason/Persisted/Rule variant; malformed delimiters retain raw text and a partial outcome. BLOCK and AUDIT remain distinct. No abbreviated-rule-to-GUID fabrication. |
| `injection_monitoring` | Target PID, source executable reference and original notification. Not a verdict, prevention result or verified process instance. |
| `file_scan` | RTP minifilter/MinFil and `[Mini-filter]` observations, original path/process/status/request/file ID/reason/state/attributes when recognized. Unsuccessful scan status is not malware or bypass proof. |
| `detection` | Explicit detection-add/DETECTION_ADD/threat-detected message variants; original descriptors retained. |
| `remediation` | Explicit remediation message and available original action/status fields; no invented success. |
| `signature_observation`, `signature_throttling`, `signature_update` | Recognized diagnostic message variants; signature identifiers/hashes do not become executable hashes or confidence scores. |
| `service_start`, `version`, `configuration`, `cloud_diagnostic` | Operational recognition; configuration changes are not inherently suspicious and cloud diagnostics do not establish transmission of a specific report. |
| `unknown` | Searchable original text with no invented semantic interpretation. |

A category is parser recognition, not an independently established forensic conclusion. Unsupported delimiters and additional formats remain available through raw text, not speculative field meanings. There is no comprehensive proprietary numeric-status decoder.

## Timestamp semantics and an important acceptance limitation

Explicit ISO `Z`/offset values use existing normalization, preserving fractional precision and original values. Timezone-free strings retain their original value and `timezone_unknown`; invalid values remain invalid. The recognized ProcessCreationTime FILETIME variant uses existing integer conversion at 100 ns precision, retaining hexadecimal/decimal original representation. Other numeric telemetry timestamps are not silently interpreted as FILETIME.

Log observation time, process creation and telemetry creation have distinct meanings/slots. No timestamp is borrowed from adjacent records. File modification time is not substituted for record time. Source timezone metadata is not silently applied to these logs.

**Consequently, many timezone-free MPLog observations may not qualify for an approved UTC window.** They remain locally searchable/inspectable without a time filter, and grouped discovery reports the count without a usable normalized timestamp. Do not widen authorization by inventing UTC or by treating this count as an in-window count. `coverage.complete` is false when such records exist; `timed_population_complete` separately describes eligible timed records. Establishing a validated timezone-assignment policy would be separate work.

## Retrieval, grouping and authorization

Existing `evidence search`, timeline, show, source inventory, guided setup and explicit ingestion accept the family. New optional search filters require `--artifact defender`:

- `--defender-category`: exact normalized category.
- `--defender-action`, `--defender-rule`, `--defender-signature`, `--defender-pid`: exact recorded scalar values; case preserved.
- `--defender-text`: literal substring of retained original text (SQLite LIKE ASCII case behavior, escaped wildcards).
- `--defender-group`: exact returned group ID, combined with the same source/time scope.

Existing path/process and basename discovery use existing object/path semantics. Original source mount letters do not create source attribution. Explicit `--source` reuses the selected source through ingestion batches. Ambiguous membership is excluded from conversational disclosure.

`artifacts/defender_query.py:groups` applies source and exclusive time restrictions before counting. It groups by category and exact original message payload after removing only the leading log-observation timestamp. All remaining arguments, actions, rule IDs, statuses and unknown text remain distinct. This is conservative: changing request IDs or otherwise differing diagnostic text can produce separate groups. It does not merge process instances based on PID equality or infer related MPLog/EVTX events are duplicates.

The complete eligible population determines group counts, representative evidence ID and first/last in-window timestamp observations. Counts are **retained records**, not unique incidents, blocked actions or processes. Counts never combine EVTX and Support-log populations as unique events. Group IDs are content-derived; always use their explicit source/time scope. They are not evidence IDs.

Static review priority presents detections/ASR, remediation/monitoring, behavioral/LowFi, scan/configuration and then other categories. It is not confidence. Stable ties and continuation allow all groups to be reached. Counts are not ranked by frequency, so repetitive groups do not displace distinct groups merely because they are common. No exact total-group count is required.

Presentation defaults to five groups, maximum ten, under the existing 12,000-byte discovery envelope or smaller analyst limit. Full original records remain in the case. Results identify representative originals, field truncation/redaction, member-search filters, omitted pages and unknown-time coverage. These presentation limits do not cap the population counted locally.

Conversational tools:

```json
{"tool":"discover_security_signals","arguments":{"artifact":"defender"}}
{"tool":"activity_overview","arguments":{"kind":"defender_groups"}}
```

For Defender discovery, omit EVTX-specific `category` and `candidate_limit`. The model can use returned member filters with `search_evidence`, then `show_evidence` and `verify_observation`. Existing EVTX discovery is unchanged. Guidance recommends both sources without mandatory steps. Source/family/time restrictions, worker read views, journal accounting and credential redaction remain enforced. Grouping metadata cannot ground original-field claims. Legacy closed S4 contracts and specialized export schemas are not silently expanded.

## Containment and operational behavior

Defender reuses the existing protected subprocess, atomic stage publication, 2 GiB worker memory and 8 GiB stage safeguards. It uses existing progress snapshot supervision: default 900 seconds without actual parser advancement, 60-second startup bound and separate six-hour emergency ceiling. No other family's timeout changes. `--parser-timeout` narrows/sets Defender inactivity, not cumulative healthy-runtime allowance. The internal snapshot protocol is shared with MFT; no new IPC protocol is added.

Byte and record advancement are available to normal progress presentation. Cancellation and worker cleanup use the existing path; rejected stages do not publish. Successfully parsed partial records can publish with explicit incomplete outcomes. Required audit handling remains fail-closed. Discovery uses existing cooperative SQLite cancellation and optional analyst time budgets; no new short query watchdog.

## Provider-independent diagnostics and acceptance

After the analyst's Git workflow, use the existing Python environment. No pip installation or new dependency is required. LiteLLM stays pinned to 1.111.0.

```powershell
cd C:\tmp\locard
git pull
python .\locard.py --version
```

Expected: `Locard 6.179`.

### Inventory and direct-file parsing

Prefer acquired copies for formal ingestion. The following commands only read their supplied files; they do not change Defender permissions or invoke Defender/AI:

```powershell
python .\scripts\defender_artifacts.py 'C:\ProgramData\Microsoft\Windows Defender\Support' --inventory
python .\scripts\defender_artifacts.py 'C:\ProgramData\Microsoft\Windows Defender\Support' --limit 0 --json
python .\scripts\defender_artifacts.py 'C:\ProgramData\Microsoft\Windows Defender\Support' --contains 'command line reported as lowfi:' --limit 3
python .\scripts\defender_artifacts.py 'C:\ProgramData\Microsoft\Windows Defender\Support' --contains 'BEGIN BM telemetry' --limit 3

python .\scripts\defender_artifacts.py 'E:\ProgramData\Microsoft\Windows Defender\Support' --inventory
python .\scripts\defender_artifacts.py 'E:\ProgramData\Microsoft\Windows Defender\Support' --limit 0 --json
```

Directory inspection covers its direct regular files, not a recursive live-volume search. `--json` emits one JSON object per file. It reports hashes/sizes, supported status, record categories, parse outcomes, timestamp statuses, matched-record counts, source stability and elapsed time. Unsupported files are inventoried but not parsed. `--limit 0` omits examples without limiting counting. `--contains` selects examples/match counts, not what is processed. `--ordinal` is zero-based and should be used with one file. Examples include exact original Base64 in JSON and safe terminal text in human output. Ctrl+C reports incomplete diagnostics. An error or detected source change returns exit 2; no permissions are adjusted.

To inspect an exact record, substitute a file actually returned by inventory:

```powershell
$log = 'E:\ProgramData\Microsoft\Windows Defender\Support\MPLog-REPLACE-WITH-ACTUAL-NAME.log'
python .\scripts\defender_artifacts.py $log --ordinal 0 --limit 1 --json
```

### Existing case ingestion and local retrieval

```powershell
python .\locard.py --db 'D:\Locard\Cases\KFI-5070790-V2\case.db' evidence ingest defender 'E:\ProgramData\Microsoft\Windows Defender\Support' --source src-d3c195d3068e4906a805082df44c1a57
python .\locard.py --db 'D:\Locard\Cases\KFI-5070790-V2\case.db' case status --details
python .\locard.py --db 'D:\Locard\Cases\KFI-5070790-V2\case.db' evidence search --artifact defender --source src-d3c195d3068e4906a805082df44c1a57 --defender-category lowfi --limit 5 --ids
python .\locard.py --db 'D:\Locard\Cases\KFI-5070790-V2\case.db' evidence search --artifact defender --source src-d3c195d3068e4906a805082df44c1a57 --defender-action BLOCK --limit 5 --ids
```

Use `--defender-text 'literal text'` for original text/command-line searches. Repeat with explicit UTC `--start`/`--end` only where timestamps support it; deterministic search retains its existing inclusive-end convention. The grouped diagnostic and conversation below use exclusive end. Use an actual returned evidence ID with `evidence show '<EID>'`; add `--raw --json` for the complete stored byte/text representation. The ordinal and EID are not guessed in these instructions.

### Grouped scoped discovery, without a provider

```powershell
python .\scripts\discover_security_signals.py --db 'D:\Locard\Cases\KFI-5070790-V2\case.db' --source src-d3c195d3068e4906a805082df44c1a57 --start 2026-11-17T06:00:00.000000000Z --end 2026-11-18T06:00:00.000000000Z --overview defender_groups
```

Append `--json` for full structured coverage; use returned `--offset` continuations. Repeat without `--overview` for the existing EVTX signals. Do not interpret empty timed groups as absence if unknown-time observations exist. For individual members, use the returned `members_filter` with the same source/window (the conversation handles exclusive-end conversion).

### Blind conversational acceptance

```powershell
python .\locard.py --db 'D:\Locard\Cases\KFI-5070790-V2\case.db'
```

Inside Locard:

```text
investigation chat --source src-d3c195d3068e4906a805082df44c1a57 --start 2026-11-17T06:00:00.000000000Z --end 2026-11-18T06:00:00.000000000Z
```

Default approved families now include Defender; inspect the authorization screen. Retain the configured OpenAI reference model and the neutral question from 6.178. Supply no incident hints. Evaluate useful grouping, original inspection, alternatives, cross-artifact pivots and actual incident identification separately. Scripted testing does not establish live reasoning quality.

## Validation and measured performance

All execution used synthetic disposable data and mock/scripted providers. No actual forensic disk, personal Defender logs, case database or live provider was accessed.

- Initial Defender + security discovery + conversation integration: **63 passed in 61.00 s**.
- Expanded Defender tests: **15 passed in 12.39 s** at that stage.
- Conversation/discovery/correlation integration after further verification controls: **81 passed in 76.72 s**.
- Final Defender/discovery check: **47 passed in 39.08 s**, including **21 new Defender tests**.
- MFT/progress/transport, Prefetch, Registry, source/model/schema compatibility, Browser, resilience and session-recording focused set: **139 passed, 2 failed in 104.71 s**. Both failures arose from sandbox denial of synthetic hard-link creation; isolated tests outside the sandbox subsequently **2 passed in 0.25 s**, without changing assertions or permissions.
- Guided setup/ingestion presentation/namespace plus Defender checks: **99 passed, 3 failed in 60.36 s**. Synthetic junction creation and audit writer failures passed when isolated with private application state outside the sandbox: **2 passed in 4.93 s**. Remaining unrelated failure: `test_help_completion_and_shell_entry` expects the old phrase `no evidence ingestion` in case-new help. Production help and that stale test were left unchanged.

Tests cover encodings/BOMs, nested command arguments, original-byte reconstruction and offsets, repeated/unknown BM fields, partial/truncated records, malformed bytes and times, duplicate ingestion, real staged publication, immutable input bytes, existing schema preservation, scope/ambiguity/time-end rejection, whole-population counts, action separation, original verification restrictions, production diagnostic subprocess, query cancellation/recovery and scripted real-worker cross-artifact pivots.

The synthetic benchmark generates two approximately 32 MiB rotated logs with repeated scans, long commands, BM blocks, unknown records and a rare ASR notification. It uses production worker ingestion and published-case retrieval. Exact final measurements are recorded below. Peak RSS was not instrumented; existing memory containment remained active. These measurements do not predict mounted forensic-disk performance.

## Remaining limitations

- Engine format drift, field delimiter ambiguity and unsupported variants remain possible; preserved originals and explicit partial/unknown status are the fallback, not invented parsing.
- Timezone-free logs may be largely unavailable to timed AI authorization; no source timezone inference was added.
- Exact payload grouping is conservative. Variable IDs/formatting can generate more groups; it does not claim incident-level deduplication.
- DetectionHistory/WPP and other binary formats remain deferred.
- Text substring/grouping queries operate on persisted JSON; exact scalar/path/basename filters use existing indexes. Grouping may be expensive on much larger populations but remains cancellable.
- The 1 MiB record-fragment boundary is explicit; full byte reassembly remains possible, but fragmented semantic fields are not claimed complete.
- The direct parser diagnostic is a local read-only Python process, not the protected ingestion worker; formal ingestion and conversational tools use protected workers.
- Specialized legacy S4/semantic/export workflows have not been given new Defender contracts. Current supported integration is common ingestion/retrieval, guided selection and the conversational investigator.
- No full regression suite was run. Live acceptance remains the analyst's responsibility.

## Changed files

New: `artifacts/defender.py`, `artifacts/defender_query.py`, `retrieval/defender_display.py` under `forensic_assistant`; `scripts/defender_artifacts.py`; `tests/test_defender_artifacts.py`; this document.

Updated under `forensic_assistant`: `artifacts/ingest.py`, `progress.py`, `storage.py`, `worker.py`; `command_catalog.py`, `command_surface.py`, `v2_cli.py`; `conversational_ai/contracts.py`, `service.py`, `tools.py`; `detections/discovery.py`; `interactive/discovery.py`, `setup.py`, `setup_display.py`; `retrieval/evidence.py`, `object_discovery.py`, `search_display.py`, `show_display.py`. Also `pyproject.toml` and `.gitignore` artifact allowlisting.

## Final synthetic performance measurements

Production worker ingestion, two generated rotated logs; Windows/Python 3.14.6. No real evidence or provider calls.

| Operation | Result |
|---|---|
| Input per file | 33,557,652 bytes |
| First file ingestion/publication | 8,526 records; 7.0615 s; zero errors |
| Second file ingestion/publication | 8,526 records; 7.0528 s; zero errors |
| Total | 17,052 records from 67,115,304 input bytes |
| Published database size | 362,754,048 bytes |
| Full-population grouped discovery | 2.1729 s; counts 2 / 16 / 16 / 17,000 / 16; 8,714-byte result |
| Indexed exact-action search | 0.1628 s; two records |
| Original record inspection | 0.0025 s |

Original text plus exact byte representation and normalized data intentionally consume more storage than input logs. Peak memory was not measured; these timings establish synthetic functionality, not a real-case performance guarantee.

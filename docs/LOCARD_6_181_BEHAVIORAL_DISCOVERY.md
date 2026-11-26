# Locard 6.181 — Deterministic behavioral discovery

Status: implemented for manual acceptance, 2026-11-26. No live case or provider was accessed during development. Version remains authoritative in `pyproject.toml`.

## Purpose and architecture

This release makes execution-related leads available without known incident indicators. It does not determine whether an incident occurred. Existing security alerts, heuristic detections, search semantics, forensic parsers and conversational authorization remain separate and unchanged.

`detections/execution_observations.py:Population` reads slim retained columns under strict source membership and an explicit half-open time interval. `execution_features.py:features` derives static lexical features. `execution.py:discover` processes the entire eligible population, computes frequencies, groups observations and only then selects a bounded result page. The conversational `Tools` adapter grants disclosure authority only to the returned, unredacted, untruncated original fields. `show_evidence`, `verify_observation`, search and temporal pivots continue to use existing original-record controls.

There is no case schema change, migration, persistent cache, new evidence database or new dependency. Original records are not rewritten. Repeating a page recomputes the population; the read-view worker retains its pinned view. Separate diagnostic invocations establish separate views, so compare their evidence-state bindings before combining results from a changing case.

## Supported population and meanings

| Family | Eligible records | Meaning and limitations |
|---|---|---|
| EVTX | Provider/channel-qualified Security 4688, Sysmon 1 | Recorded process creation; parent fields do not independently establish a process instance or ancestry |
| EVTX | PowerShell Operational 4103/4104; classic Windows PowerShell 400/403/600 | Retained script/host content where available; not proof that every statement executed |
| Registry | Registered Run/RunOnce, services ImagePath/ServiceDll, Winlogon values; RunMRU except MRUList | Configured execution versus user-entered command are separate classes. Key last-write is not value creation or execution time |
| Defender | Existing LowFi, BM telemetry, injection monitoring and ASR notification categories | Selected recorded telemetry, not complete process history or a verdict. An ASR action does not establish successful target execution |
| Prefetch | Existing parsed records with eligible timestamps | Historical execution indicator; referenced files are not treated as executed images |
| Browser/MFT | Existing search/inspection pivots | Not execution-observation populations in this release; explicitly reported as unsupported by this tool |

`execution-observation-v1` retains exact evidence IDs, source binding, artifact and effective host context, original field pointers/values, timestamp meaning, semantic class and limitations. Registry views are defensively checked against registered path/value extractors. Ambiguous source membership and conflicting host attribution are excluded before feature processing. Optional hostname narrows effective host context; it does not establish independent attribution.

Untimed records are counted but cannot enter a time-authorized population. The output reports source totals, unsupported types, ambiguous source exclusions, unknown/outside time, host exclusions and eligible observations per family. Qualified EVTX provider/channel/Event ID population counts support independent comparison with Security 4688 inventory. Counts describe retained observations, not unique processes, executions or incidents; duplicate exports can affect frequencies.

## Structural features and grouping

`execution-features-v1` recognizes interpreter tokens, nested interpreters, chaining, quoting ambiguity, escaping, unexpanded environment references, encoded arguments, indirect construction, concatenation, interpreter options, remote/local references, output redirection, Registry operations, service/task syntax, potentially user-writable paths, long commands and recorded document/browser-parent/interpreter-child combinations.

These lexical patterns can occur in legitimate administration, comments or quoted text. They are not a Windows shell emulator. ACLs are not checked. Variables are not expanded from the analyst machine. No command, script, URL, DNS query or decoded content is executed or contacted.

Only a recognized PowerShell encoded-command argument is decoded: strict Base64 to UTF-16LE, one level, bounded by 32 KiB. Unsupported forms remain undecoded. Decoding is a separately labeled derived interpretation, never an original field. Feature analysis uses at most the first 32 KiB of a command and reports prefix truncation. Exact command identity still hashes the whole recorded string.

- **Exact mode:** unchanged original command plus semantic/host/image/parent context. Missing commands are grouped by their available original fields.
- **Behavioral mode:** conservative literal lexical token sequence, with every path, domain and argument retained; ambiguous or prefix-limited commands fall back to whole original text. This primarily coalesces external whitespace. It intentionally does not aggressively generalize commands with materially different arguments.
- Stable `EXEC:` group IDs bind the feature version, mode, source/time/family/host scope and grouping content. They are derived references, not forensic EIDs.
- Full-population frequencies include exact commands, executables, recorded parent/child pairs, literal argument patterns and features. Representative frequencies may differ from group counts.
- Priority is explainable: feature count, +2 for remote/local combination, +2 for nested/chained combination. Lower command/pair frequency then stable digest break ties. Category round-robin provides diversity; it is neither a probability nor a family quota. No vendor/domain allowlist or incident-specific ranking is used.

A representative is chosen by stable evidence-ID ordering, not latest activity. Each result includes member-request arguments. Group-member pages return exact original EIDs. Matching filters narrow presentation, not the frequency baseline. Population processing never stops after the first 100/200 candidates.

## Bounds, disclosure and resilience

The tool defaults to five results, permits up to ten and fits the actual serialized response within the existing result ceiling (at most 12,000 bytes). Response packing removes whole result records, including their feature definitions, until the envelope fits. A record that cannot fit fails explicitly rather than returning a nonadvancing continuation. Original fields are bounded/redacted through existing helpers; at most eight distinct fields are shown per representative and omitted-field counts are explicit. Inspect the original record for remaining fields.

`analysis_complete/counts_complete` mean the supported eligible population was traversed. They do not imply complete endpoint telemetry or full command analysis when prefix truncation is reported. `presentation_complete`, `next_offset` and `truncated` independently describe page coverage. Omitted candidates are not declared irrelevant. Failure/cancellation produces no completed-population/absence claim.

Production runs inside the existing protected read-only worker, with authorization checks, SQLite interruption, memory containment, read-view verification, WAL-growth guard and cancellation/cleanup. Numeric computational progress is emitted at most twice per second plus completion. It carries no forensic strings and never resets a deadline. Python processing checks cancellation as well as SQL execution. No arbitrary new operation quota is added; optional analyst tool-time and existing conversation limits still apply. Memory grows with distinct groups/commands; very large high-cardinality populations may hit existing containment, in which case narrow the explicitly approved scope rather than trusting partial counts.

The conversational tool `discover_execution_behaviors` accepts source/time, optional artifact, mode, limit/offset, group_id, feature, category_filter, executable, parent and hostname. Executable/parent filters are case-insensitive exact full value or basename. Returned `members` arguments preserve the grouping scope. Prior tools remain available; the prompt suggests discovery without imposing a fixed sequence. Evidence strings remain untrusted data. Features, decoding and group labels cannot pass original-field verification.

## Provider-free diagnostics

`scripts/discover_execution_behaviors.py` uses the production protected worker, never a provider. Its JSON contains the result, evidence-state binding and wall time; human output includes semantic classes, features, original fields, frequencies, coverage and elapsed time. Progress goes to stderr.

`scripts/db_keyword_search.py` is deliberately independent: stdlib SQLite, no Locard retrieval imports. It opens `mode=ro` with `uri=True`, query-only, disabled extensions, a restrictive authorizer and one read transaction. It enumerates tables/columns dynamically, scans each table once for all supplied keywords and reports every matching column's cell count with bounded examples. Primary keys identify examples when available; otherwise scan ordinals are explicitly not stable IDs.

Matching is Python Unicode `casefold()` literal substring, without Unicode normalization. `%` and `_` are literal. Counts are matching cells, not occurrences or distinct evidence. BLOBs are counted but not decoded; compressed/Base64 material, escaped JSON representations and views have explicit limitations. Table errors and cancellation retain partial counts labeled incomplete. `--seconds` is an optional diagnostic deadline, not a silent sample limit. JSON is control-character escaped. CSV identifier/keyword columns contain JSON string representations to prevent formula interpretation; examples are bounded JSON. The utility does not redact analyst-requested diagnostic examples: protect saved output as potentially sensitive derived data.

## Validation and performance

Focused synthetic validation uses no case evidence or provider calls. Coverage includes late candidates beyond 1,500 common records, stable pagination/membership, exact command verification, scope and time exclusions, cross-family Registry/Prefetch/Defender original fields, lexical/Unicode/missing/encoded content, malformed decoding, literal argument distinctions, serialized limits, scripted discovery/inspection/verification/pivots, cancellation/deadline recovery and read-only byte preservation. Independent utility tests cover unusual SQL names, Unicode, literal wildcards, one traversal per table, denied writes and incomplete cancellation counts. Existing conversational/provider/security discovery/retrieval/Defender suites protect compatibility.

Recorded focused integration run: **133 passed in 97.79 s**, one warning. Final discovery/keyword test run: **22 passed in 10.99 s**, one warning; an additional host-conflict/filter test was run afterward. These overlap the 133-test set and must not be added as unique test counts. No full suite was run.

Synthetic benchmark (5,003 qualified process records, four groups, 22,573,056-byte database; warm local filesystem, not the reference case):

| Measurement | Result |
|---|---:|
| Whole-population discovery | 0.510 s |
| Repeated discovery | 0.490 s |
| Protected-worker diagnostic including startup/closure | 1.301 s |
| Four-result response | 11,960 bytes |
| Three-keyword single traversal, 28 tables / 30,022 rows | 0.289 s |
| Same keywords, three independent traversals | 0.769 s |

The comparison is a synthetic repeated-scan control, not a measurement of the previous private diagnostic or the multi-million-record case. A preliminary benchmark harness forgot to close its direct SQLite connection and failed temporary-directory cleanup after measurements; it was rerun with explicit closure and completed successfully. No production recovery change was needed.

## Deferred work and limitations

No new process-taint parser category is introduced. Existing original Taint Parents/Taint Info/Operations fields remain inspectable where present. A new category would require format validation and an explicit compatibility/repair policy; 6.180 repair currently prevents category-changing repair. Numeric taint values remain opaque. This release makes no claim to parse all Defender formats.

No perfect shell equivalence, process-instance ancestry, complete behavior graph, malware classification, local-model integration or incident-specific detector is implemented. Large-field prefixes and conservative grouping can miss or separate related behaviors. Repeated pages recompute statistics. Real-case scale, ranking usefulness and blind investigative quality require analyst acceptance.

## Windows manual acceptance

The analyst handles Git/update/install. No dependency installation is required. Use the installed test checkout; do not run pip for this change.

```powershell
Set-Location C:\tmp\locard
python locard.py --version
# Expected: Locard 6.181
$db = 'D:\Locard\Cases\KFI-5070790-V2\case.db'
$source = 'src-d3c195d3068e4906a805082df44c1a57'
$start = '2026-11-17T06:00:00.000000000Z'
$end = '2026-11-18T06:00:00.000000000Z'
```

### A. Literal retrieval controls

Supply your own literal keywords locally; no known incident indicators were used in development.

```powershell
$keyword = Read-Host 'Literal original command/EventData keyword'
python locard.py --db $db evidence search --artifact evtx --source $source --start $start --end $end --evtx-text $keyword --evtx-match contains --json
# Continue using --evtx-after with the returned cursor and identical filters.
$key = Read-Host 'Literal Registry key substring'
python locard.py --db $db evidence search --artifact registry --source $source --key-contains $key --json
$valueName = Read-Host 'Literal Registry value-name substring'
python locard.py --db $db evidence search --artifact registry --source $source --value-name-contains $valueName --json
```

Registry key/value-name filters are not value-content filters. There is no new `--value-contains` flag. For arbitrary retained Registry content use the independent utility below, then inspect identified original EIDs with `evidence show`. Registry controls above intentionally omit a value-time constraint because key last-write and value timestamps differ.

### B–C. Population and blind behavioral discovery

```powershell
python scripts\discover_execution_behaviors.py --db $db --source $source --start $start --end $end --json
python scripts\discover_execution_behaviors.py --db $db --source $source --start $start --end $end --artifact evtx --mode exact --json
python scripts\discover_execution_behaviors.py --db $db --source $source --start $start --end $end --artifact registry
python scripts\discover_execution_behaviors.py --db $db --source $source --start $start --end $end --artifact defender
```

Compare `statistics.event_populations` for qualified Security 4688 with your previous baseline. Inspect all coverage exclusions. For another page repeat identical arguments plus `--offset <next_offset>`. For members repeat the returned `members` scope and mode plus `--group-id <EXEC:...>` and its page offset. Optional `--feature`, `--category`, `--executable`, `--parent` and `--hostname` narrow results; choose them from observed candidates, not hidden incident hints. `--tool-seconds` is an optional analyst deadline. Ctrl+C cancels under existing worker containment.

```powershell
$eid = Read-Host 'Original evidence ID from a candidate'
python locard.py --db $db evidence show $eid --json
```

### D. Independent SQLite controls

```powershell
$keyword1 = Read-Host 'First literal diagnostic keyword'
$keyword2 = Read-Host 'Second literal diagnostic keyword'
python scripts\db_keyword_search.py --db $db --keyword $keyword1 --keyword $keyword2 --examples 3 --format json
# Optional CSV; identifiers are JSON string representations:
python scripts\db_keyword_search.py --db $db --keyword $keyword1 --keyword $keyword2 --format csv
```

This independent utility searches the whole selected database, not a source/time-filtered population. Reconcile matching EIDs and timestamp/source scope before comparing counts with production discovery. Record timing, scanned tables, errors and completeness; compare the prior diagnostic only on equivalent keywords and scope.

### E. Blind conversational acceptance (analyst only)

After deterministic acceptance:

```powershell
python locard.py --db $db investigation chat --source $source --start $start --end $end
```

Use the configured OpenAI reference model and review authorization. Ask without known indicators:

> Analyze the evidence discovered within the authorized November 17, 2026 time window. Identify potentially suspicious user activity, unusual process execution, browser navigation, downloads, file changes and persistence indicators. Correlate evidence across artifact families, establish a supported chronology, and propose specific follow-up investigations. Distinguish observed evidence from hypotheses. Do not assume that a security incident occurred.

Assess discovery, candidate diversity, original verification, correlations, chronology, false conclusions and explicit coverage limits. Record duration/provider usage/operation counts separately. A detailed answer alone is not acceptance.

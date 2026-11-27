# Locard 6.183 — Reusable behavioral populations and compact discovery

Implementation and synthetic validation: November 26–27, 2026. Starting revision: `68f60f0` (accepted 6.182). Application version is defined only in `pyproject.toml`. Changes are uncommitted; real-case manual acceptance is pending.

## Architecture and authority

The conversational worker already owns one `Tools` adapter and one pinned `ReadView` for the session. This release does not change that lifecycle, provider routing, authorization, timeouts, read-only SQLite controls or the existing 2-GiB worker memory containment.

```
authorized tool request
  → Tools validates current authorization and requested source/time/family
  → PopulationCache validates the pinned view and complete authorization
  → completed population hit OR full supported-population construction
  → presentation filters, unchanged ranking/category round-robin, page selection
  → selected EIDs rehydrated from original evidence in the same read view
  → original pointer/value and group identity checked again
  → redaction, compact/detailed presentation, actual serialized-byte packing
  → existing tool-result recording and provider disclosure accounting
```

`detections/execution.py::build_population` computes all eligible observations, features, frequencies and groups before returning a reusable population. It retains group/member EIDs, selection fields, feature names, counts, timestamps and grouping hashes. It does not retain complete original records, command bodies, decoded payloads or model responses. Image/parent strings needed for exact presentation filters remain retained.

`execution_observations.py::Population.rows(evidence_ids=...)` restricts rehydration to selected identities using existing source/time/host eligibility. `execution.py::discover` checks the reconstructed group identity and original field values. Cache entries never grant original-field verification authority.

### Identity and invalidation

`detections/execution_cache.py::PopulationCache` is worker-owned, in-memory and session-local. Its key includes:

| Binding | Contents |
|---|---|
| Authoritative view | View UUID, file identity, exact connection identity and active locked transaction |
| Authorization | Canonical complete grant, including case path, sources, interval, families and limits |
| Requested population | Actual source, normalized interval, selected families and hostname restriction |
| Analysis | Exact/behavioral mode, feature version and explicit ranking version |

Page size/offset, category, feature, executable, parent, group selection and presentation mode reuse a compatible population. Narrowing the population's source/time/families/host or changing analysis versions builds a separate population. Changing the authoritative grant or view fails closed. Authorization is still checked on every cache hit.

Only fully completed construction can enter the cache. Exceptions/cancellation discard reusable state; the worker's existing recovery rules determine whether further operations are possible. Worker closure clears the cache and closes the pinned view; process termination releases its memory. There is no disk cache or cross-investigation reuse.

### Memory

Retention has a **256-MiB byte budget**, one eighth of existing worker containment. This is a cache-retention policy, not a candidate or evidence quota. Deep unique-object `sys.getsizeof` measurement estimates retained Python memory. Least-recently-used populations are evicted to fit. An oversized completed population can serve its current page without being retained; a later call recomputes it. Eviction never changes statistics or drops candidates from the completed analysis.

The estimate excludes SQLite/native allocations, interpreter overhead and peak transient construction memory. The existing worker memory guard remains authoritative. This is not a new promise that arbitrarily large populations fit in RAM. No operating-system memory-pressure monitor was added.

## Presentation contracts

The conversational default is `execution-discovery-compact-v1`, requesting up to the existing maximum of ten candidates. The unchanged **12,000-byte** discovery ceiling is enforced using the actual ASCII-escaped UTF-8 JSON encoding. It can be narrowed by the approved result budget.

Shared scope, semantic meanings, frequency/ranking explanations, timestamp qualifications, navigation and common limitations appear once. Packet-local host-context mappings preserve artifact host, derived context host and assertion basis without repeating them per candidate; analyst-supplied context remains explicitly unverified. Candidates retain exact EIDs/group IDs, artifact/kind/category, group counts, qualified first/last times, features, score, population frequencies, up to three bounded original previews and all candidate-specific limitations. Preview fields retain exact JSON pointers and explicit truncation/redaction flags. Omitted original-field counts remain explicit. Group first/last times are derived eligible-observation bounds, not new event times or proof of execution.

The category inventory supplies `category_filter`, observation count, group count, command-bearing observation count and whether groups remain outside the current page. Selection retains the previous category round-robin, feature weights, frequency tie-breaks and stable digest order. There are no incident indicators, vendor allowlists or mandatory category sequences.

| Next action | Existing tool arguments |
|---|---|
| Next page | Same population arguments, `offset=next_offset` |
| Category/feature | `category_filter` / `feature` |
| Group members | Same scope/mode/hostname, returned `group_id` |
| Detailed candidate/group | `presentation="detailed"`, optionally `group_id` |
| Original inspection | `show_evidence`, exact returned `evidence_id`; paginate fields |
| Independent verification | `verify_observation`, inspected exact pointer/value and timestamp meaning where required |

Detailed mode preserves `execution-discovery-v1`, including original fields, static decoding, qualifications and member arguments. Its default remains five records when called directly through the tool adapter. The diagnostic script explicitly requests ten by default to compare density at equal page limits.

**Compact previews cannot be independently verified just because they were displayed.** Original inspection or an eligible untruncated/unredacted detailed original field must first establish disclosure. Verification still re-reads the authoritative original through the existing service. Derived values and redacted/truncated fields gain no authority. Previously established valid authority is not revoked by a later compact page.

Packing removes complete trailing candidates, never their essential caveats. If one candidate with its mandatory caveats cannot fit, compact mode reports an explicit omitted EID/group and advances one position. Its EID is accounted as disclosed and can be inspected using original field pages; no scalar verification authority is added. If the common envelope itself cannot fit, the request fails explicitly. Detailed oversized candidates retain the prior fail-closed behavior.

## Accounting and progress

Worker replies carry a separate `computation` diagnostic, recorded as a `behavioral_computation` notebook event. It contains population identity, constructed/reused status, hit/retention status, approximate retained bytes, eviction/invalidation counters, population/group/candidate counts and serialized bytes. Timings distinguish construction, filtering, selected-candidate rehydration and serialization. `presentation_seconds` includes filtering and rehydration; do not sum it with those subphases.

Population identity is deliberately outside the model-visible evidence result: adding it there could change page packing between cached and uncached calls. Identical requests therefore return identical evidence payloads. The session separately counts constructed and reused populations. Reuse still performs scoped original hydration and counts as a forensic tool operation; it is not a second independent population examination.

The existing per-provider-request accounting continues to charge repeated evidence-result bytes and all serialized message content, including repeated cached-page disclosures. No generalized tool-result cache was introduced. Original verification, search and unrelated tools retain their execution paths.

Construction emits numeric records/groups/elapsed progress. Hits emit `reused` with completed population counts instead of pretending to scan again. Existing generic elapsed activity, deadlines, cancellation, notebook recording and worker recovery remain in effect. Successful subsequent computations report cache counters; failed operations remain recorded through the existing failure diagnostics, rather than being published as completed populations.

## Synthetic measurements

Provider-free benchmark: `tests/benchmark_execution_6183.py`. It creates a disposable synthetic SQLite case with **12,007 eligible observations, 12,004 command-bearing observations and 3,007 groups**, using EVTX, Registry, Defender and Prefetch fixtures. There are 12,000 ordinary events distributed over 3,000 distinct command arguments, plus contrasting low-frequency observations. It does not read a real case.

The benchmark executes the committed 6.182 discovery function from `68f60f0` against the same synthetic case. Detailed result equality is asserted, including exact IDs, groups, ordering, fields, statistics and coverage. Every compatible reused request is also compared with fresh computation. Measurements below are one local warm-process sample, not projected real-case timings or isolated OS-cold-cache measurements.

| Operation | Seconds | Candidates | Serialized bytes |
|---|---:|---:|---:|
| 6.182 detailed full computation | 1.337 | 3 | 10,408 |
| 6.183 initial compact | 1.331 | 5 | 11,054 |
| Reused next page | 0.027 | 7 | 11,981 |
| Reused category | 0.007 | 1 | 6,331 |
| Reused feature | 0.008 | 1 | 6,829 |
| Reused members | 0.013 | 1 | 6,829 |
| Identical compact repeat | 0.032 | 5 | 11,054 |
| Reused detailed | 0.035 | 3 | 10,408 |

Initial construction was 1.295 s. The total initial operation was essentially equal to the old full computation (1.331 vs 1.337 s). An earlier sample measured a roughly 12% initial overhead before the final host-context presentation adjustment; repeated operations consistently avoided the full scan. Do not infer a cold-start speedup from these short, non-isolated measurements.

The final compact first page increases candidate count from three to five and uses about **2,211 bytes/candidate**, versus **3,469** for detailed presentation. The next compact page fits seven candidates. The compact initial page exposes **11 original preview fields across five representatives**, versus eight detailed original fields across three; both report zero omitted behavioral-projection fields in this particular fixture. This does not mean the complete original records are exposed. Richer records explicitly report omitted fields, and original inspection remains necessary.

Density varies with fields and qualifications; this is not a guaranteed number of candidates. Rehydration can examine up to ten selected representatives before packing trims the visible page. Complete population analysis and counts do not imply complete presentation; all measured first pages remain partial.

Retained population estimate: **7,536,412 bytes (7.19 MiB)**. Peak process RSS was not measured. Fresh/cached result equality and committed-6.182 detailed equality passed. The supplied real-case counts and prior 19.837371-second discovery timing remain analyst-reported acceptance baselines, not measurements performed here.

## Focused validation

- `test_execution_population_reuse.py`: compatible/fresh equality, source/time/family/host/mode/version isolation, changed grants/views/connections, closed views, byte eviction and uncached oversized populations, cancelled construction, compact verification rejection followed by original verification, density/pagination, oversized caveats, redaction/Unicode, script sequence/fresh comparisons, notebook reconstruction and repeated disclosure accounting, numeric CLI progress and small user-entered-command category preservation.
- `test_execution_discovery.py`: prior feature/group semantics, cross-artifact original-field verification, authorization/exclusions, real supervised cancellation/deadline/recovery, scripted discovery → inspect → verify → cross-artifact pivots. Tests requiring original fields now explicitly select detailed presentation; compact conversational tests inspect originals first.
- Relevant 6.182 retrieval, security-discovery, conversational provider/service, resilience and UserAssist regressions retained.
- No full suite, paid provider call, real ingestion or protected-case access. No dependencies, schema, indexes, stored evidence or audit records changed.

Focused results: **42 passed** (population reuse + behavioral discovery); **39 passed** (6.182 retrieval + security discovery, within the earlier 77-test run); **99 passed** (conversational service/provider, retrieval resilience and UserAssist). **180 distinct focused tests passed.** The pytest cache-write warning is environmental; test assertions passed. `git diff --check` passed.

## Manual acceptance commands

After the analyst's commit/push/update/install workflow, run in the existing environment:

```powershell
Set-Location C:\tmp\locard
python locard.py --version
# Expected: Locard 6.183
$db = 'D:\Locard\Cases\KFI-5070790-V2\case.db'
$source = 'src-d3c195d3068e4906a805082df44c1a57'
$start = '2026-11-17T06:00:00.000000000Z'
$end = '2026-11-18T06:00:00.000000000Z'
$scopeArgs = @('--db',$db,'--source',$source,'--start',$start,'--end',$end)

# One pinned worker: initial, next page, category, feature, members, repeat, detailed.
# Then separate fresh protected workers recompute each operation for comparison.
python scripts\discover_execution_behaviors.py @scopeArgs --sequence --compare-fresh --json
```

Check `repeat_equal`, all `fresh_comparisons[].equal`, identical population identities within the sequence, one construction followed by hits, and at most 12,000 serialized bytes/result. Fresh worker identities appropriately differ. A category/feature/member step explicitly reports skipped if the population cannot supply one. Seven fresh comparisons incur seven full scans intentionally; independent script invocations alone cannot demonstrate reuse.

Expected unchanged **analyst-provided** reference population: 11,853 observations; 9,964 with commands; 1,889 without; 2,854 distinct commands; 3,109 groups; 4,882 qualified Security 4688 events. Compare full coverage and source/time scope, not only these totals.

```powershell
# Separate compact and detailed human-readable inspection; these are fresh runs.
python scripts\discover_execution_behaviors.py @scopeArgs --presentation compact
python scripts\discover_execution_behaviors.py @scopeArgs --presentation detailed
python scripts\discover_execution_behaviors.py @scopeArgs --category user_entered_command --json
$group = Read-Host 'Exact returned group ID'
python scripts\discover_execution_behaviors.py @scopeArgs --group-id $group --presentation detailed --json

# Original evidence and independent verification; no provider required.
$eid = Read-Host 'Exact returned evidence ID'
python scripts\benchmark_forensic_retrieval.py @scopeArgs --operation show --evidence-id $eid --repeat 2 --diagnostics --json
$field = Read-Host 'Exact original JSON field pointer'
$value = Read-Host 'Exact scalar encoded as JSON (quote a string)'
python scripts\benchmark_forensic_retrieval.py @scopeArgs --operation verify --evidence-id $eid --field $field --value-json $value --repeat 2 --diagnostics --json
# For timestamp verification also pass --timestamp-meaning with the exact displayed meaning.

# Selected accepted 6.182 controls, using the same literals as that acceptance.
$key = Read-Host 'Previous exact Registry key control'
python scripts\benchmark_forensic_retrieval.py @scopeArgs --operation search --artifact registry --registry-key $key --repeat 2 --diagnostics --json
$part = Read-Host 'Previous Registry substring control'
python scripts\benchmark_forensic_retrieval.py @scopeArgs --operation search --artifact registry --registry-key-contains $part --repeat 2 --diagnostics --json
$path = Read-Host 'Previous exact MFT path control'
python scripts\benchmark_forensic_retrieval.py @scopeArgs --operation search --artifact mft --path $path --repeat 2 --diagnostics --json
$basename = Read-Host 'Previous exact basename control'
python scripts\benchmark_forensic_retrieval.py @scopeArgs --operation search --artifact mft --object-basename $basename --repeat 2 --diagnostics --json
```

Use the existing 6.182 diagnostic document for the identical narrow MFT timeline control. The diagnostic script uses production protected read-only workers and no model backend. It writes results to stdout; any redirected result file may contain sensitive original evidence and should be handled accordingly.

## Scope and remaining limitations

No broader result caching, durable model memory or reasoning redesign. Category filtering still sorts the retained group population; only the expensive full observation analysis is reused. Selected originals are intentionally rehydrated on every request. Large observations, mandatory caveats and common-envelope size may reduce density or cause an explicit capacity failure. Timeout and cancellation may discard useful cached work to preserve fail-closed behavior. A new session always starts a new population.

Changed production areas: execution population/cache/projection, conversational tool contract/adapter, worker diagnostics, progress validation/rendering and notebook accounting. Supporting changes: diagnostic script, focused tests/benchmark, documentation allowlist and version. The source case is unchanged, and no new database schema or dependencies are required. Manual acceptance remains the next user-controlled step; no commit or push was performed.

### Changed files

| File | Change |
|---|---|
| `forensic_assistant/detections/execution_cache.py` (new) | Completed-population identity, retention measurement and eviction |
| `forensic_assistant/detections/execution.py` | Separate computation/presentation, rehydration, compact contract and diagnostics |
| `forensic_assistant/detections/execution_observations.py` | Identity-restricted original-observation rehydration |
| `forensic_assistant/conversational_ai/tools.py` | Cache ownership, compact default and original-verification separation |
| `forensic_assistant/conversational_ai/contracts.py` | Explicit presentation option and navigation guidance |
| `forensic_assistant/conversational_ai/worker.py` | Bind cache to read view, failure/closure disposal and computation diagnostics |
| `forensic_assistant/conversational_ai/supervision.py` | Validate the reused progress phase |
| `forensic_assistant/conversational_ai/service.py` | Notebook computation events/counters; omitted-identity disclosure accounting |
| `forensic_assistant/conversational_ai/cli.py` | Numerical progress display |
| `scripts/discover_execution_behaviors.py` | Compact/detailed rendering and same-view sequence/fresh controls |
| `tests/test_execution_population_reuse.py` (new) | Focused reuse, isolation, disclosure and integration regressions |
| `tests/benchmark_execution_6183.py` (new) | Disposable mixed-artifact benchmark and committed baseline comparison |
| `tests/test_execution_discovery.py` | Explicit detailed expectations, compact inspection flow and worker checks |
| `pyproject.toml` | Version 6.183 |
| `.gitignore` | Allow the release document |
| `docs/LOCARD_6_183_POPULATION_REUSE.md` (new) | Design, measurements, limitations and manual acceptance |

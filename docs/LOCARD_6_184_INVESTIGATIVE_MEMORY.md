# Locard 6.184 — Investigative memory

## Pre-implementation inspection

Starting accepted revision: `93eeb76` (6.183), clean working tree. `conversational_ai/service.py::messages` currently keeps only the last three notes and six verified references in the deterministic context prefix, then omits whole history blocks to fit provider capacity. Original tool results remain in `events.jsonl`, but there is no indexed, selectively queryable projection. `submit` mandates an analyst pause after 600 seconds, irrespective of an absent active-time budget. These are source-confirmed limitations; the historical model's specific reasoning failure is not proven to have been caused solely by omission.

## Approved SQLite amendment

The session-specific `case.db.conversations/<session_id>/workspace.db` is derived investigative state, never evidence. `events.jsonl` remains authoritative. Journal publication precedes projection transactions; idempotent sequence/hash processing must recover lagging projection state. No persisted grant authorizes execution or a new read view. Original evidence remains read-only. Selective SQL queries, bounded context, explicit epistemic classes, historical revisions and private storage apply to the implementation below.

## Implementation and data flow

Implemented in the uncommitted 6.184 working tree, November 27, 2026. `pyproject.toml` remains the application version authority. No dependency installation is required.

`Session.event` publishes through the existing `Transcript.append` (event write, flush/fsync and manifest confirmation), then calls `Workspace.apply`. The projection consumes the same sanitized event. Evidence stays in the pinned read-only case connection owned by the existing forensic worker. Provider calls still use the existing provider abstraction, grants, resource accounting and original-field verification.

```text
authorized operation → protected read-only worker → result
    → authoritative events.jsonl + manifest → SQLite projection transaction
    → bounded indexed memory query + recent complete exchanges → provider
memory evidence reference → show_evidence → original disclosure → verify_observation
```

`Workspace`, `reconstruct`, `Session.messages` and `Session.checkpoint` are application services, not CLI/provider-specific implementations. Reconstruction does not instantiate a provider or open the case. A new investigation always requires a new approval and read view.

### Schema version 1

`PRAGMA user_version=1`; no case schema migration. Foreign keys are enabled. SQL parameters carry all user/model filter values. Table and ordering names come from fixed application allowlists.

| Table | Purpose and keys | Important indexes |
|---|---|---|
| `meta` | Session, canonical authorization/read-view binding, processed frontier and latest repeated-action reference | Primary key |
| `events` | Processed journal sequence and unique event hash; not duplicate event payloads | Sequence PK, unique hash |
| `actions` | Stable `A<sequence>` identity, canonical arguments/signature, status, duration, result-event pointer, digest, coverage and computation-reuse diagnostics | Signature/sequence, status/sequence, tool/sequence, result digest/sequence |
| `evidence` | Exact original EID, artifact, first/latest retrieval event, approved scope, group and exposure state | EID PK, disclosure/latest event, latest event |
| `fields` | EID + exact pointer + originating event; timestamp meaning, preview/redaction/truncation flags; **no original value column** | Composite PK, originating event |
| `action_evidence` | Retrieval action-to-EID relationships | Composite PK and FKs |
| `disclosures` | EIDs represented by tool messages in journaled provider attempts | Event/EID PK |
| `field_exposures` | Exact field origin represented in a provider attempt | Event/EID/pointer/origin PK; original-field FK and lookup index |
| `verifications` | Stable `V<sequence>` identity; original-field equality verification reference and temporal meaning | ID PK, EID/event |
| `notes` | `N<sequence>` identity, author, kind/status, text, support references, alternatives, superseded-note link | Kind/status/event, status/event, supersession |
| `populations` | Behavioral population identity and complete common compact-result metadata | ID PK; event FK |

Sequence-based identities are local to the bound session. Original forensic IDs are unchanged. Event/result pointers recover provenance from the authoritative journal without copying complete original payloads. Exact original values must be rehydrated through existing tools. Repeated population metadata is retained in the journal; the projection exposes its latest representation under the population identity.

### Transactions, reconciliation and crash recovery

Each projection event uses one SQLite transaction: insert event identity, apply all derived rows, update frontier, commit. Duplicate sequence with the same hash is a no-op; a changed hash, gap, wrong predecessor, session mismatch or binding change fails closed. SQL errors roll back the whole projection event.

| Interruption point | Result and recovery |
|---|---|
| Before durable journal publication | No projected event or authorized dispatch based on it |
| Journal published, before/during projection transaction | Journal is ahead; replay applies missing events idempotently |
| After SQLite commit | Replay recognizes the event and does not duplicate rows |
| Projection failure during execution | Stop execution, preserve journal, close worker; do not continue with stale memory |
| Unconfirmed journal/manifest publication | Existing journal-publication failure semantics apply; no automatic repair or retry |
| Partial/truncated journal, mismatched manifest, conflicting hash | Reconstruction refuses it; a valid hash chain alone is not proof of evidence grounding |

`Workspace.reconcile` first verifies the entire journal/manifest frontier, then streams events into the projection. No complete-journal list is required by this service. A new private reconstruction directory is the supported historical recovery path; existing `workspace.db` files are never opened as trusted state or silently overwritten. Rebuilding a crashed workspace from the validated journal also avoids trusting damaged SQLite pages. Reconciliation of a live, healthy projection supports journal-ahead recovery, but cross-process investigation resumption is **not implemented**. Rebuild is historical inspection, not grant renewal.

Historical `conversational-v1` journals without explicit action IDs remain supported using event sequences and their pending-operation order. Existing journals are not rewritten. Other investigation engines are deliberately rejected by this reconstruction entry point.

### Storage security and memory

The workspace inherits the existing private transcript directory protections: protected owner/SYSTEM ACL on Windows, private directory permissions on POSIX. The original case and its evidence tables remain read-only. Directory guards pin the parent path; local-path validation rejects symlink/reparse redirection. Fresh exclusive file creation, single-link checks, database file-identity checks and companion-path checks cover `workspace.db`, `-journal`, `-wal` and `-shm`.

SQLite uses `journal_mode=DELETE`, `synchronous=FULL`, foreign keys, disabled extension loading and untrusted schema mode. A rollback journal is created inside the same protected directory. WAL is not enabled. A pre-existing companion or workspace prevents creation; invalid redirected/replaced files prevent use. These controls do not purport to defend against an administrator or the same user intentionally rewriting both journal and manifest.

The SQLite page-cache target is 4 MiB; this is not a total-process memory ceiling. Queries read at most one requested page plus one row, use indexed identity/status/order predicates, and enforce serialized result capacity. Free-text note matching is literal `instr`, potentially scanning notes; FTS5 compile availability is reported, but no FTS table or mandatory extension is used. Event processing holds one bounded journal event at a time. Existing worker caches, evidence-ID/exposure sets and recent conversation state still consume memory; this release does not replace their security roles. Explicit diagnostic fingerprinting streams table rows rather than loading the workspace.

## Memory contract and authority

One new tool, `memory`, offers `state`, `evidence`, `fields`, `actions`, `notes`, `verified` and `populations`, with bounded pagination and applicable EID, status or literal query filters. Results use `investigative-memory-v1`, explicit continuation/completeness and a warning that historical references are not current original values. An oversized indivisible result fails with `MEMORY_ITEM_CAPACITY`; it is not silently presented as complete.

Notes support observations, interpretations, hypotheses, relationships, open questions, next actions and interim conclusions. Optional supporting/contradictory evidence, operation references, missing evidence, alternatives and `supersedes` preserve revision history. Unknown or locally retrieved-but-not-disclosed EIDs are rejected as note supports. Unknown operations and invalid supersession references are rejected. Model notes cannot assign themselves deterministic verification status. Analyst instructions and model text remain separately attributed and unverified.

Retrieval is distinct from possible provider exposure. Dispatch-attempt journaling establishes **possible exposure**, not successful transport or comprehension. Field-level exposure links resolve the exact recorded result represented in that request. Workspace references do not grant original-field verification authority. To recover a scalar, use `show_evidence` within the unchanged approval/read view, then `verify_observation` through existing disclosure and temporal-meaning checks. Redacted/truncated previews retain their flags and do not become complete originals.

Action statuses distinguish pending, completed, partial, failed and cancelled. Counts, continuation and coverage remain attached to the original result. A completed operation does not prove the entire case was searched. A zero-match partial page is not proof of absence. Exact repeated arguments expose the earlier action to the model; successful repetition is allowed. Repeated actual failures and nonadvancing pagination still stop safely.

## Context and autonomous continuation

`Session.messages` projects bounded SQL-selected active notes, unresolved questions, verification references and incomplete actions alongside the current objective and unchanged authorization instructions. It retains recent **complete** tool-exchange blocks, preserving native provider tool-call sequencing. Capacity checks use existing model-capability handling and actual UTF-8 serialized request sizes. Mandatory instructions/tool contracts are never removed to fit. Insufficient capacity pauses explicitly.

Omitted exchanges remain in the journal and indexed memory. Each consolidation records omitted-block counts, projection frontier and before/after serialized sizes. Automatic projection omissions are labeled; all bounded pages remain explicitly queryable. No model summarization call or second reasoning engine is introduced. This is recoverability, not a promise that every relevant finding is selected automatically or that a small model will reason well.

Default checkpoints every 600 active seconds persist progress, validate the current view/workspace and continue within approval. `--checkpoint-seconds` changes the interval; `--pause-at-checkpoint` preserves deliberate analyst pauses. Explicit budgets, provider failures/uncertain outcomes, authorization expiry, failed audit persistence and lost read views still stop or suspend execution. Checkpoints occur between synchronous provider/tool calls; they do not interrupt an otherwise permitted long-running operation or extend its deadline.

Cancellation regression testing exposed a pre-existing between-call signal-clearing race made easier to reach by projection persistence. The supervisor now consumes cancellation when handling it, rather than clearing it when starting a new call. Existing cooperative SQLite cancellation, bounded containment and uncertain-cleanup handling remain. A timing-dependent test now starts cancellation at its intended second lookup and preserves its original retained-evidence assertions; a separate regression checks between-call cancellation.

### Repeated metadata assessment

The existing population cache and scoring/grouping remain untouched. Population metadata can be queried through memory. This release does **not** strip common statistical definitions/qualifications from subsequent original tool messages: doing so safely requires a provider-visible reference contract ensuring the definitions remain available in each relevant context. Removing them solely for density would risk changing meaning. Savings here come from bounded history/reference projection; no billed-token improvement is claimed without live measurements.

## Validation and measurements

Only synthetic, scripted/mock-provider and focused regression execution is authorized for this implementation. The diagnostic uses production Session, protected worker, original inspection/verification, SQLite projection, context sizing and two independent historical reconstructions. No actual forensic case or external provider is opened.

Synthetic provider token usage is deliberately artificial and must not be compared with billed live usage. Python allocation measurements exclude worker RSS, SQLite native allocations and OS page cache.

Measured default synthetic diagnostic on this working tree:

| Measurement | Result |
|---|---|
| Context ceiling / actual serialized request range | 32,000 / 18,409–31,789 UTF-8 bytes |
| Scripted requests / successful operations | 26 / 25 (5 forensic, 18 notes, 2 memory) |
| Serialized request bytes / external message-content bytes | 769,845 / 423,421 |
| Repeated original evidence-result bytes / memory-result bytes | 48,483 / 3,696 |
| Automatic workspace-context bytes / projected items | 54,924 / 43 (repeated projections counted) |
| Context consolidation events | 17 |
| Automatic checkpoints / analyst-required pauses | 51 / 0; diagnostic-only 0.01-second interval |
| Original inspection pages | 2; first inspection and explicit recovery |
| Workspace | 471,040 bytes; 2 EIDs, 104 field-origin references, 25 actions, 1 verification, 20 notes/instructions/model responses |
| Recorded journal events | 196 |
| Python traced peak allocation | 14,046,274 bytes; not total process memory |
| Active session / complete diagnostic elapsed | 12.90 / 21.62 seconds, including traced execution and independent reconstructions |
| FTS5 compile support | Available in this Python SQLite build; unused |

All ten diagnostic assertions passed: original omitted before recovery, original and verification recovered, incomplete search recovered, equal reconstructions, unchanged synthetic case SHA-256, omitted history, automatic checkpoints, closed worker, preserved request ceiling. Both reconstructions yielded `22c961eebc2804d981af353b67b4a2dfcc4b3ee7a01a8d824a048fb4e15e5a3d`. The digest is specific to this journal, including its timing/session data; independent runs need not have the same digest.

Focused coverage includes journal-first rollback/idempotency, changed bindings, manifest/hash validation, private companion/hardlink checks, revisions, unknown references, current field exposure versus retrieval, complete/partial zero results, cancellation/failures, context ceilings at 28,000/32,000/40,000 bytes, mandatory-envelope failure, checkpoint continuation/pause/exhaustion and provider-free reconstruction without a case. Existing conversational/provider, authorization, original verification, population reuse, behavioral discovery, security discovery and 6.182 retrieval regressions are included. Tests are synthetic/mock-provider; no live forensic or AI acceptance is claimed. The hardlink rejection test uses a mocked link count when Windows prevents creating the synthetic hardlink.

Final focused execution: **199 passed, 1 warning in 311.24 seconds**, covering `test_investigative_memory.py`, `test_conversational_ai.py`, `test_conversational_provider.py`, `test_conversation_resources.py`, `test_retrieval_resilience.py`, `test_execution_population_reuse.py`, `test_execution_discovery.py`, `test_retrieval_performance_6182.py` and `test_security_discovery.py`. Two additional boundary tests added after that run's collection passed separately: **2 passed, 1 warning in 4.25 seconds** (expired checkpoint cannot dispatch; failed memory operation retains identity). Total: **201 distinct passing tests**, without counting overlapping development runs. Earlier interrupted/failing development runs are not included. The final run incorporates the corrected repeat/checkpoint tests and retained activity notice.

`git diff --check` passed. `python locard.py --version` reported **Locard 6.184**. The first invocation emitted an audit-storage warning in the default sandbox environment; repeating with disposable `LOCALAPPDATA` reported the version without that warning. No audit permissions or configuration were changed. Full-suite and live acceptance remain unperformed as requested.

## Windows manual acceptance

After your normal Git/install workflow, using the checkout's installed Python environment:

```powershell
Set-Location C:\tmp\locard
python locard.py --version
# Expected: Locard 6.184
python scripts\diagnose_investigative_memory.py
python scripts\diagnose_investigative_memory.py --context-bytes 28000 --checkpoint-seconds 0.01
python scripts\diagnose_investigative_memory.py --context-bytes 40000 --checkpoint-seconds 0.01
```

The short interval is a synthetic diagnostic setting only. Require every `checks` value to be true. The disposable diagnostic removes its synthetic case/journals afterward.

For a retained conversation journal, rebuild twice into **new** private directories; this reads only the journal, never the original case or saved workspace:

```powershell
$journal = Read-Host 'Complete conversation session directory containing manifest.json and events.jsonl'
$out1 = Read-Host 'New reconstruction directory 1 (must not exist)'
$out2 = Read-Host 'New reconstruction directory 2 (must not exist)'
python scripts\diagnose_investigative_memory.py --reconstruct $journal --output $out1
python scripts\diagnose_investigative_memory.py --reconstruct $journal --output $out2
# Compare projection_sha256 and counts. No historical grant authorizes new execution.
```

Provider-free original inspection/verification and 6.183 cache controls, run only by the analyst on the approved reference case:

```powershell
$db = 'D:\Locard\Cases\KFI-5070790-V2\case.db'
$source = 'src-d3c195d3068e4906a805082df44c1a57'
$start = '2026-11-17T06:00:00.000000000Z'
$end = '2026-11-18T06:00:00.000000000Z'
$scopeArgs = @('--db',$db,'--source',$source,'--start',$start,'--end',$end)
python scripts\discover_execution_behaviors.py @scopeArgs --sequence --compare-fresh --json
$eid = Read-Host 'Exact returned evidence ID'
python scripts\benchmark_forensic_retrieval.py @scopeArgs --operation show --evidence-id $eid --repeat 2 --diagnostics --json
$field = Read-Host 'Exact original field pointer'
$value = Read-Host 'Exact scalar encoded as JSON, including quotes for a string'
python scripts\benchmark_forensic_retrieval.py @scopeArgs --operation verify --evidence-id $eid --field $field --value-json $value --repeat 2 --diagnostics --json
# Timestamp fields additionally require --timestamp-meaning with the displayed meaning.
```

Preserve all seven fresh-comparison equalities, population identity/coverage and original scalar semantics. Existing exact Registry/MFT/timeline controls remain in `LOCARD_6_182_RETRIEVAL_PERFORMANCE.md` and `LOCARD_6_183_POPULATION_REUSE.md`.

Only after deterministic acceptance, with the reference provider configured and explicit external-disclosure approval:

```powershell
python locard.py --db $db investigation chat --source $source --start $start --end $end
# Enter the SAME neutral investigative question used for the 6.181 reference.
# Do not add known incident indicators. Review and approve the displayed scope.
# Optional analyst-controlled checkpoint mode:
python locard.py --db $db investigation chat --source $source --start $start --end $end --checkpoint-seconds 600 --pause-at-checkpoint
```

Compare discovery, correlation, inspection/verification, chronology, coverage, report quality, duration, real token usage, repeated evidence bytes, memory-result bytes, consolidation and analyst interventions. The synthetic diagnostic cannot establish live investigative quality or token savings.

## Compatibility and limits

- Case database schema/evidence, provider abstraction and existing population cache are unchanged. Only a new session-derived SQLite schema is introduced.
- Historical reconstruction is supported; automatic restart/resume is deliberately not. Corrupt or unconfirmed journal frontiers require separate diagnosis.
- A journaled provider attempt means possible exposure. Historical exposure never guarantees that a field is present in the current prompt.
- Unknown provider usage remains unknown; no automatic repair/retry calls or hidden consolidation requests.
- Existing transcript event/byte ceilings, worker memory controls and optional grant limits still apply. SQLite adds local disk use and transaction latency; no arbitrary successful-operation quota is added.
- FTS5 is optional and currently unused. Note-text filtering can scan notes; indexed identity/status retrieval and page-size limits avoid loading the complete workspace.
- The final prose remains model interpretation; stored notes/citations are not proof of causality, execution or compromise. Live reasoning acceptance remains pending.

## Changed files

`conversational_ai/workspace.py` (new projection/reconstruction), `service.py` (journal integration/context/checkpoints/accounting), `contracts.py` (memory and typed notes), `cli.py` (controls/status), `supervision.py` (pending cancellation), `scripts/diagnose_investigative_memory.py` (new), `tests/test_investigative_memory.py` (new), `tests/test_retrieval_resilience.py` (deterministic cancellation coverage), `tests/test_conversation_resources.py` (approved repetition/continuation expectations), `pyproject.toml`, `.gitignore` and this document. No commit or push.

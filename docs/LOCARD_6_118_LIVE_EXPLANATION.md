# Locard 6.118 — Incremental live explanation persistence

Development inspection and synthetic validation: 2026-11-09. Starting commit:
`5c004ecf7bda4812e01ec407ad927a23ca2161c8` (6.117). This document describes
uncommitted 6.118 work. `pyproject.toml` is the application-version authority.
Manual/live acceptance is **pending**. No additional model request, lookup,
investigation step, forensic rule, report-import permission or restart capability
is introduced.

## Execution and authority boundary

The explicit `--live-explanation` option requires the existing
`briefing --investigate --autonomous --decompose --synthesize` workflow. It selects
the local `local-explanation-v1` manifest profile, not a new evidence/provider grant.
Without it, existing behavior remains unchanged.

`autonomous.run` calls `organization.Live.update` after the accepted analysis/B2
event and at finalization. Only after C1 append and in-memory commit does C1 return
`organization-commit-v1`. `explanation_live.Live.update` then validates that receipt,
prepares references, checks reservations, appends a checkpoint, and commits the
reference overlay. It never calls `explanation.open_history` in the live loop.

The receipt contains run/read-view identity, C1 profile/rules, previous and current
C1 digests, revision, confirmed checkpoint sequence/hash, accepted source frontier,
changed entity/link keys and the finalization marker. Changed relationship and
question entities carry membership and assessment changes. Coverage is considered
on every update. The receipt is compared with C1's retained receipt, committed
state digest and the journal's confirmed current event. Exact duplicates are no-ops.

`Sources` borrows the committed C1 graph and restricts S1 lineage to the references
C1 actually admitted. It validates original support, view and qualifications.
`Reducer` has no file, SQLite, provider or network access. `Live` owns persistence;
`Replay` is the provider-free acceptance boundary. These are reusable backend
services, independent of terminal rendering.

## Reference contracts and incrementality

| Contract | Content and authority |
|---|---|
| `explanation-frontier-v1` | Confirmed C1 receipt plus D1a rule/statement versions and deterministic ordering version. |
| `explanation-revision-v1` | Logical component keys, canonical IDs, section membership, dependency indexes, pending/omitted keys, coverage and cumulative counters. No original values or rendered prose. |
| `explanation-checkpoint-v1` | Previous revision/digest, candidate digest, examined prefix, complete atomic operations, charged-visit accounting, stop reason and result digest. Its own event hash remains outside its payload. |
| `local-explanation-v1` | Opt-in local processing profile; unknown profiles are rejected. |

A source clause/entity ID is a stable logical key. Its canonical D1a statement ID
may change with objective associations, lineage or relationship membership. The
reducer uses `admit`, `replace`, `retire_current_membership` and `update_coverage`.
Replacement records the expected old reference and complete new reference.

Source/entity keys directly index their components. Per-component dependency
indexes retain objective and relationship/support endpoints; changed dependencies
invalidate their dependents. Objective changes also invalidate existing components
whose associations may change. Pending keys are reconsidered. Ordering is grounded
interpretations, observations, objectives/coverage, relationships, then unverified
proposals, with stable source keys as tie-breakers. Only affected candidates are
constructed. D1a's canonical builder is reused; its optional objective index avoids
repeated scans of unrelated graph entities without changing historical output.

Canonical IDs, field pointers, original-value/premise digests, interpretation
limitations, timestamps, source uncertainty, B2 request-local aliases and the
original S3 assessment retain their existing meanings. A hypothesis remains
unverified. Current/historical/current relationship transitions replace membership
without asserting that an earlier comparison was disproven. A lagging explanation
is identified by its committed C1 frontier. There is no direct-S1 fallback when C1
fails or omits a component.

## Limits, priority and failure handling

The fixed ceilings are nine checkpoints, 32 operations/checkpoint, 288 committed
operations, 2,048 charged dependency visits, 192 lifetime canonical admissions and
active references, 8,192 encoded bytes/event, 65,536 additional journal bytes,
128 KiB reference state, 2,048 index edges, 192 pending keys and 4 MiB owned heap.
Replacements consume lifetime admissions. The final opportunity reserves 32
operations, 128 visits and 8,192 journal bytes. Overflow keys are explicitly
omitted, not called irrelevant. A complete operation is never shortened to fit.

Before append, the actual UTF-8 event (including journal envelope, hash and newline)
is measured. Higher-priority reservations retain 1,264 KiB per remaining analysis
cycle, 96 KiB per remaining B2 cycle, 512 KiB terminal capacity and 64 KiB for C1,
plus conservative future event slots. The existing 4 MiB/256-event journal limits
remain unchanged. A reservation failure preserves the last committed revision.

Local work is charged across callbacks, including skipped preparation and append.
Preparation cooperatively checks a 100 ms slice and remaining one-second allocation.
Blocking filesystem I/O cannot be preempted by that cooperative check. Existing
parent supervision still bounds the investigation; an observed local overrun
disables further D1b work and records `local_time_overrun`. No timeout is extended.
Deep-size accounting conservatively includes borrowed source graphs as well as
owned overlays, rather than equating JSON length with Python heap usage.

The corrected 6.117 writer remains authoritative: exact integer write counts,
no append retry, fail-closed manifest publication, and strict tail validation.
Append uncertainty invokes existing fatal containment. A failure after confirmed
append but before overlay commit also stops ordinary publication, preventing a
terminal summary falsely describing predecessor state. Disk-confirmed checkpoints
can still be validated by strict replay. No repair, salvage or permission change
is performed. Primary accepted findings are not rolled back.

## Replay and presentation

`organization.reconstruct` first validates existing analysis/B2 history, then feeds
confirmed C1 receipts into the D1b reconstructor. It recomputes candidate and canonical
identities, validates dependencies and applies exactly the recorded prefix, never
reselecting according to replay speed. Unknown profiles, forged receipts, changed
IDs/digests, bad predecessors and unprofiled checkpoint events fail closed. A
terminal event is not sufficient to establish C1 finalization or explanation
completeness. Historical transcripts acquire no checkpoints.

`explanation_live.reconstruct` exposes the committed reference state and validated
canonical material for diagnostics. `session`, `page` and `render` reuse compact
D1a rendering on demand. Expanded canonical JSON supplies exact support and
qualifications. Cursors bind run, view, revision, state/checkpoint identity and rule
versions. Header/status distinguish persisted versus retrospective, partial/stale,
accepted/pending/omitted counts and final-assessment availability/representation.
Processing completion never means forensic completeness or supervisor cleanup
confirmation. Failed source/checkpoint validation produces an unavailable JSON
diagnostic with a nonzero exit code, not a valid partial report.

## Recorded focused validation

Before implementation, the mandatory journal publication/final-anchor gate passed:
**50 tests in 24.26 s**. The expanded focused regression set subsequently passed
**292 tests in 146.02 s** (journal, C1, D1a/display, S1/S2, B2, decomposition and D1b).
The changed-path/resource follow-up passed **88 tests in 104.96 s**. After the
final bounded-view/CLI adjustments, **12 targeted checks passed in 25.54 s**.
These sets overlap and must not be added as a unique-test count. No complete-suite
run was performed. Final `git diff --check` passed.

New tests use mock providers and disposable synthetic journals. They cover receipt
forgery, prefix/digest tampering, two independent process reconstructions, missing
terminal/final anchors, post-append failure, prior-checkpoint preservation,
duplicate no-op, original support/ASR qualification checks, membership reappearance,
objective replacement, dependency resolution, resource reservations, Unicode display,
and unchanged request/lookup/step counts. Existing tests continue to protect
historical report-import and grounding restrictions. Backend read-only tests block
provider and SQLite entry points and compare journal bytes before/after inspection.

### Matched mock measurements

Each paired investigation uses identical synthetic records, two analyst-asserted
source IDs and fake model actions. Both pairs completed six analysis batches,
two B2 decisions, nine mock requests, six lookups and ten existing steps. C1 committed
six checkpoints in each run. The larger variant adds distinct unverified proposals
and questions; it does not grant them factual authority.

| Measurement | Regular enabled | Larger enabled |
|---|---:|---:|
| Accepted source frontiers | 8 | 8 |
| Persisted D1b checkpoints | 6 | 5 |
| Candidate generation | 0.00490 s | 0.00720 s |
| Dependency/statement resolution | 0.01924 s | 0.01972 s |
| Reference serialization/deep-size checks | 0.01605 s | 0.01726 s |
| Append/flush/fsync/manifest publication | 0.124 s | 0.061 s |
| Total charged D1b local work | 0.172 s | 0.186 s |
| D1b final opportunity | 0.032 s | 0.047 s |
| Additional journal bytes | 27,498 | 28,990 |
| Committed operations / charged visits | 46 / 211 | 74 / 308 |
| Conservative deep Python bytes | 231,252 | 313,331 |
| Final accepted / pending / omitted components | 34 / 0 / 0 | 64 / 0 / 0 |
| Entire mock run, disabled → enabled | 1.522 → 1.695 s | 1.593 → 1.644 s |
| Existing C1 work, disabled → enabled | 0.267 → 0.328 s | 0.406 → 0.420 s |
| Process peak working set, disabled → enabled | 57,663,488 → 58,703,872 bytes | 61,046,784 → 61,706,240 bytes |

These are single paired measurements, not statistical latency claims. Process
numbers are the Windows process high-water mark, not isolated D1b allocations.
Phase times overlap the preparation aggregate; total run differences also include
ordinary filesystem/C1 variation. The larger run skipped one explanation append
for journal reservation and later caught up. Byte-limited prefixes were explicit.

A separate benign administrative fixture (Browser/MFT/EVTX, two sources) verifies
no attack/identity inference. Its expanded 244-entity reference stress test took
0.00603 s and conservatively occupied 266,061 bytes. It reported 192 pending and
50 omitted components, with zero operations: the large changed-key receipt already
exceeded the useful checkpoint envelope. The live gate refuses that event; it does
not enlarge the cap. This is a deliberate bounded-stop limitation, not evidence of
complete coverage. Later smaller C1 receipts may allow catch-up, never guaranteed.

### Historical compatibility

Read-only inspection of the approved 6.111 fixture preserved 21 observations, one
ASR interpretation, seven current and three historical relationships, four B2
proposals and original S3 `NOT_ASSESSABLE`. All 61
canonical statements retained digest
`0a449bb4cde578094d5f6145769ca0a0c5cf34eb984299eccdb4c1441b62ca5a`;
the seven compact pages retained digest
`79bb708cbcca853cd8d4c3b168150353d5ad0cdd32c4ead34fc427af911297da`.
No historical source was written or migrated. SHA-256 before/after inspection:

- `manifest.json`: `ac4ad6337ef9ec1de08cffca3f0872a0d51afc872191c7da4cfc774b4c9d2a1d`
- `events.jsonl`: `8672cf41cbefde86d315d177cb0c6e99a20c26a3f11ed306c837026631138256`

These hashes establish unchanged bytes across this inspection, not a new claim
about integrity before the supplied baseline.

## Manual acceptance

After the analyst commits/pushes and updates the separate test checkout:

```powershell
Set-Location C:\tmp\locard260927\locard
.\.venv\Scripts\python.exe -m pip install -e .
.\locard.ps1 --version
.\locard.ps1
```

Expected installed version: 6.118. In the shell, explicitly opt in:

```text
briefing --investigate latest --autonomous --decompose --synthesize --live-explanation --question "What does the approved evidence support, and what remains unresolved?"
```

For provider-free inspection of a readable copied run, substitute its actual
parent directory and original run ID (do not use a historical grant for execution):

```powershell
$root = 'C:\tmp\locard-diagnostics\YOUR-NEW-RUN-PARENT'
$runId = 'ACTUAL-32-CHARACTER-RUN-ID'
.\.venv\Scripts\python.exe -B -m forensic_assistant.investigation_ai.synthesis $root $runId --live-explanation
.\.venv\Scripts\python.exe -B -m forensic_assistant.investigation_ai.synthesis $root $runId --live-explanation --json
.\.venv\Scripts\python.exe -B -m forensic_assistant.investigation_ai.synthesis $root $runId --live-explanation --canonical --json
```

JSON is one page; pass its `next_cursor` through `--cursor` with the same mode.
Human mode streams all bounded pages. For historical runs, use `--explanation`;
`--live-explanation` reports disabled/no persisted checkpoints. None of these
diagnostic commands opens the case database or contacts a provider.

Live storage latency and parent cleanup remain manual acceptance concerns. D2/D3,
integrated model narrative, autonomous continuation, durable restart recovery and
broadened report import are not implemented.

## Changed files

- `forensic_assistant/investigation_ai/explanation_live.py`: new backend, reducer,
  persistence, replay and diagnostic projections.
- `forensic_assistant/investigation_ai/organization.py`: confirmed receipts and
  validation hooks; expanded D1b material is not added to the bounded public C1 view.
- `forensic_assistant/investigation_ai/autonomous.py`: explicit profile and callbacks.
- `forensic_assistant/investigation_ai/explanation.py`: indexed objective lookup,
  sealing and persisted-mode label; canonical statement rules unchanged.
- `forensic_assistant/investigation_ai/explanation_display.py`: reusable bounded
  display envelope and admitted-context filtering.
- `forensic_assistant/investigation_ai/presentation.py`: compact completion status.
- `forensic_assistant/investigation_ai/synthesis.py`: read-only diagnostic mode.
- `forensic_assistant/briefing_cli.py`,
  `forensic_assistant/assessment_handoff_cli.py`: explicit local opt-in.
- `tests/test_explanation_live.py`, `tests/test_explanation_live_resources.py`:
  focused regressions and synthetic measurements.
- `pyproject.toml`: application version 6.118.
- `.gitignore`: permit this exact documentation file.
- `docs/LOCARD_6_118_LIVE_EXPLANATION.md`: implementation/acceptance record.

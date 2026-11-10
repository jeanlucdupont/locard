# Locard 6.112: local investigative organization (S4-C1)

## 6.113 correction: relationship frontiers and revision accounting

Implemented on 2026-11-09 against `e3fd261fe6b202123679244e68f08e8914c005fc`.
This section supersedes the relationship/count descriptions below for new output.
The earlier implementation and measurements are retained as release history.

The 6.112 defect mixed the accumulated union of S2 relationships from accepted
batch frontiers with a counter for only the latest S2 snapshot. The existing S2
policy compares adjacent recorded timestamps: newly admitted timestamps can split
an earlier pair without invalidating its recorded-coordinate ordering.

6.113 preserves exact S2 IDs, comparison rules, original endpoints, qualifications
and source/read-view bindings. Each relationship now has `present_frontiers`,
`first_frontier`, `last_frontier`, `membership_frontier`, `current_final` and
`membership` (`current_final` or `historical_only`). Each presence entry binds an
accepted delta ID/batch/disclosure digest to its source event sequence and hash.
Missing event provenance is explicitly `unknown`. Endpoint lineage references
resolve through the original S1 finding dependencies and the recorded delta, rather
than duplicating original evidence values. Membership frequency is not confidence.

Contracts: `investigative-organization-v1`, `organization-checkpoint-v1` and
`organization-dependency-v1` remain envelope contracts; new semantics use
`organization-rules-v2`, `local-organization-v2` and `relationship-frontier-v1`.
S2 still uses its existing registered rule, including `recorded-utc-interval-v1`.
Historical derived organization is explicitly retrospective; it does not assert
that individual S2 derivation events were persisted during the original run.

New v2 checkpoints hash the prospective membership history, candidate ordering,
frontier and coverage. Replay regenerates these from validated source events and
rejects inconsistent classifications/digests. Old 6.112 `local-organization-v1`
checkpoints are explicitly refused by the v2 reader, with an original-reader
diagnostic, rather than reinterpreted or rewritten. Use the original reader for
those runs. Profile-free historical 6.111 B2 transcripts remain supported.

Coverage separates `relationships_current_final`, `relationships_historical_only`
and `relationships_accumulated_distinct`. Legacy `relationships` remains defined
as `latest_s2_snapshot` and is omitted from human coverage output. If resource
exhaustion leaves entity membership updates pending, those references are counted
under `relationships_membership_pending` and displayed separately rather than
misrepresented as current-final. Whole-source and partially materialized counts
can differ only with explicitly incomplete organization.

Readable chronology now has separate current and historical sections. Historical
ordering is not labeled rejected or disproven. The display retains clock, source,
precision and causality qualifications. Original questions, proposals, legends and
unassigned findings retain their prior behavior.

Resource accounting now reports `retrospective_revisions`,
`persisted_organization_checkpoints`, `organization_revision` and
`organization_processing_complete`. Persisted checkpoints are counted from actual
journal events, not processing phases. Interrupted journals retain the exact last
committed prefix. No historical checkpoint is manufactured.

The accepted 6.111 copy reconstructed in two fresh processes with identical full
canonical digest:
`13c40a473c56f9e13ad498cee2fb73cd546c4d8fd64382901642018806bed6e8`.

| 6.113 historical validation | Result |
|---|---:|
| Current / historical-only / accumulated S2 relationships | 7 / 3 / 10 |
| Observations / ASR interpretations | 21 / 1 |
| B2 / total model-originated proposals | 4 / 25 |
| Authorized / examined evidence references | 6 / 6 |
| Retrospective revisions / persisted checkpoints | 9 / 0 |
| Operations / dependency visits | 223 / 563 |
| Serialized view | 244,935 bytes |
| Full reconstruction duration | 0.839 s / 0.847 s |

All ten relationship IDs, endpoints, rule results, qualifications and frontier event
bindings were checked. Original S3 remained `NOT_ASSESSABLE`; two unresolved
objectives remain. Provider and SQLite connection entry points were blocked during
these diagnostics. Both historical transcript hashes remained unchanged.

Focused organization, S2, B2 and S3 tests passed **138/138 in 41.88 seconds**.
Additional focused checks cover exact live event bindings and the explicit legacy
profile diagnostic; the final organization suite passed **30/30 in 19.68 seconds**.
Synthetic coverage includes seven-final/ten-union sparse
frontiers, first/last/repeated membership, possible reappearance, partial membership
updates, tampering, interrupted replay and journal reservation/failure. No complete
suite or live provider call was run.

All C1 and B2 resource ceilings are unchanged. The historical view is near the
256-KiB ceiling; larger provenance histories may stop explicitly at an atomic
boundary. No new inference, model calls, evidence access, report-import permission
or restart capability was introduced. Manual acceptance remains pending.

Provider-free acceptance after installing the changed checkout:

```powershell
.\locard.ps1 --version
.\.venv\Scripts\python.exe -B -m forensic_assistant.investigation_ai.synthesis C:\tmp\locard-diagnostics\6.111-b2 ec81a1af5b1f471ca4f3a4c0bb917fa2 --organization
.\.venv\Scripts\python.exe -B -m forensic_assistant.investigation_ai.synthesis C:\tmp\locard-diagnostics\6.111-b2 ec81a1af5b1f471ca4f3a4c0bb917fa2 --organization --json
```

Expect version 6.113, separate 7/3 relationship sections, accumulated count 10,
nine retrospective revisions and zero persisted checkpoints.

Implementation and provider-free validation recorded on 2026-11-09. Starting
revision: `bfc32219e574556e9c78c970f2d6ef009b198849`; these changes are uncommitted.
`pyproject.toml` is the application version authority. Manual acceptance is pending.

## Scope and authority

`investigation_ai/organization.py` is a backend reference service, independent of
CLI rendering. It organizes already accepted findings and proposals; it neither
queries evidence nor calls a model. It does not create a forensic narrative,
execution conclusion, causal rule, grant, or report-import permission.

`_Sources.analysis` consumes the existing accepted S1 reducer and invokes existing
bounded S2 derivation. `_Sources.synthesis` consumes a durably accepted B2 decision.
`_Sources.final` retains the existing original S3 assessment and provisional S4-A
objectives. Public `reconstruct` first validates original B2 history through
`synthesis_consumer.reconstruct`, then rebuilds the reference graph. Private fixture
adapters are not an arbitrary JSON import interface.

| Contract | Meaning |
|---|---|
| `investigative-organization-v1` | Typed materialized reference view, run/view binding, revision and coverage |
| `organization-rules-v1` | Stable-ID navigation, dependency ordering and exact duplicate links |
| `organization-checkpoint-v1` | Durable committed operation prefix and resulting digest |
| `organization-dependency-v1` | Original unit/EID/pointer, descriptor, provenance, source context and lineage references |
| `local-organization-v1` | New-run manifest profile enabling checkpoint validation |

Finding nodes retain S1 IDs, predicates, qualifications and support lineage without
copying original field values. Relationship nodes retain S2 IDs, endpoints, rule,
semantics, assumptions and qualifications. An organization reference does not grant
future model disclosure: any future AI use still needs original-support rehydration.

## Entities and links

| Entity | Meaning and authority |
|---|---|
| Finding | Accepted observation or registered deterministic interpretation reference |
| Relationship | Existing S2 recorded comparison, not new inference |
| Theme | Registered-predicate navigation bucket or visibly unverified B2 group |
| Hypothesis | Existing analysis/B2 proposal; alternatives and origin retained |
| Question | Original question, provisional objective, unknown or future objective |
| Proposal | Unverified B2 relationship explanation with its validated relationship reference |
| Gap | Recorded coverage limitation; never evidence of absence |

Implemented links are `contains_reference`, `proposed_member`, `context_for`,
`cites_original_support`, `references_validated_relationship`, `registered_conflict`,
`asks_about` and exact `duplicate_of`. Other proposed future transitions are not
invented when upstream contracts provide none. All links retain origin, read view
and epistemic classification. Process status `active` does not mean verified.

Analysis hypotheses with only record-level citations retain that weaker granularity.
No field is inferred from another clause having the same EID. Proposals retain
separate origins even when exact semantic duplicate links are added. Similar prose
is not merged. Repetition adds no evidentiary confidence. Model contradictions are
not automatically registered conflicts.

B2 aliases are resolved using `(request_id, packet_digest, alias)` and preserved
in per-proposal legends. `O1` from two requests is never a global identifier.

## Incremental persistence and replay

New B2 runs update organization after accepted analysis deltas, accepted B2
decisions and final scoped assessment. Stage A/S4-A without B2 remains unchanged.
The B2 6+1+2 allocation, six lookups, ten steps and existing overall supervisor
deadline remain unchanged.

`_Reducer.prepare` computes only changed entities/new links, with findings before
dependent proposals and relationships, then links. Existing S2 derivation remains
a bounded whole-input operation. Candidate ordering is deterministic, not semantic
similarity. Required entity endpoints must already exist before admission; links
cannot reference absent endpoints. No original evidence graph is recopied into
checkpoints.

`Live.update` prepares a prospective revision, reserves primary journal capacity,
appends its checkpoint, and only then commits it. Checkpoints record source frontier
sequence/hash, previous digest/revision, candidate digest/order, exact operation
prefix, resulting digest/revision, small coverage counters and stop reason. A tiny
`organization_final` anchor identifies final scoped-assessment reconstruction.
Append failure disables further local organization while retaining original
accepted findings and the last committed revision.

Recorded replay recomputes candidate content and validates the recorded exact
prefix. It does not use replay machine speed to decide how many operations were
committed. Hash-chain validity alone is insufficient: upstream disclosure,
decisions and checkpoint content must also validate. An unknown profile, forged
support, altered prefix, foreign frontier or digest mismatch fails closed.

Historical B2 transcripts without the profile receive a **retrospective** view.
Their nine possible reduction points are in-memory revisions, not newly written
historical checkpoints. Nothing is appended, and no old grant authorizes execution.

## Bounds and coverage

| Resource | Ceiling |
|---|---:|
| Entities / links | 256 / 512 |
| Revisions per entity / checkpoints | 8 / 9 |
| Operations per checkpoint / run | 128 / 1,024 |
| Dependency visits | 4,096 |
| Materialized view | 256 KiB |
| Checkpoint / organization journal | 8 KiB / 64 KiB |
| Cumulative organization processing | 2 seconds |

The final update reserves 128 operations and 8 KiB. Existing 4-MiB journal,
256-event limit, 600-KiB event ceiling and 512-KiB terminal reserve remain unchanged.
Conservative reservation for remaining analysis/synthesis events can skip early
organization checkpoints. Their source references remain pending for later updates.
Organization never consumes an eleventh investigation step.

Time is checked before work and at bounded operation boundaries, against both the
cumulative meter and existing execution deadline. Source preparation and durable
I/O time are charged. This is cooperative local budgeting, not a new filesystem
preemption mechanism; the existing parent supervisor retains containment authority.
Recorded replay validates prefixes independently of timing; retrospective generation
on a sufficiently slow machine can return an explicit partial view.

Coverage separates authorized/examined references, observations, interpretations,
S2 relationships, model proposals, rejection/duplicate counts, organized findings,
AI-theme membership, unassigned findings, unrepresented supports, unassessed
candidates, unresolved objectives, processing stops and known unfinished work.
Rejection counts inherit the controller's recorded rejected-request granularity;
they are not an invented per-item count. Unavailable authoritative support fails
validation instead of being treated as a usable partial citation. A missing graph
endpoint stops that operation explicitly. Successful reference processing does not
establish forensic completeness or relevance of omitted material.

## Provider-free inspection and manual acceptance

After installation, verify the installed version:

```powershell
.\locard.ps1 --version
```

From the checkout containing the installed environment:

```powershell
.\.venv\Scripts\python.exe -B -m forensic_assistant.investigation_ai.synthesis C:\tmp\locard-diagnostics\6.111-b2 ec81a1af5b1f471ca4f3a4c0bb917fa2 --organization
.\.venv\Scripts\python.exe -B -m forensic_assistant.investigation_ai.synthesis C:\tmp\locard-diagnostics\6.111-b2 ec81a1af5b1f471ca4f3a4c0bb917fa2 --organization --json
```

For a future new run substitute its readable transcript parent directory and actual
run ID. This command validates committed checkpoints when present. It does not
open the case database, call a provider, renew authorization or write sidecars.

Readable output includes finding references, relationship endpoints, qualifications,
unverified proposals, request-local alias legends, unresolved objectives and
unassigned findings. Full IDs, pointers and provenance remain in JSON. Model text
and terminal control characters are escaped. The view intentionally does not
duplicate original evidence values; existing S1 diagnostics remain available for
the original factual display.

Acceptance checks: all 21 observations and one ASR interpretation must remain,
including findings absent from B2 packets; all four B2 proposals must retain two
request origins; original question/objective uncertainty must remain; unassigned
MFT/Prefetch findings must remain visible. Neither an ASR block nor adjacency
establishes successful execution or a complete attack chain.

## Recorded validation and measurements

Two independent processes reconstructed the accepted historical copy on 2026-11-09:

| Measurement | Result |
|---|---|
| End-to-end validation plus reconstruction | 1.454 s / 1.171 s |
| Serialized materialized view | 231,264 UTF-8 bytes |
| Entities / links | 67 / 104 |
| Operations / dependency visits | 202 / 500 |
| Retrospective revision points | 9 |
| Original observations / ASR interpretations | 21 / 1 |
| B2 proposals / request origins | 4 / 2 |
| Organized findings / AI-theme members / unassigned | 22 / 6 / 16 |
| Unresolved objectives | 2 |
| Incomplete / processing stops | false / none |

Both full canonical output digests were
`ec4894fe669a5b00ab89b2f8e87172fcfa7c2097fe14f95f704b08143c7bf460`.
Both internal state digests were
`813aea4fed3e39e7ae888553e90e1953096975f6526cf6fb6236d688f44f0d1d`.
The copied manifest and event-file SHA-256 values remained unchanged:
`ac4ad6337ef9ec1de08cffca3f0872a0d51afc872191c7da4cfc774b4c9d2a1d`
and `8672cf41cbefde86d315d177cb0c6e99a20c26a3f11ed306c837026631138256`.
These checks concern the supplied transcript copies, not historical case integrity.

Focused regression runs: 156 passed in 43.48 s across organization, packet,
Stage A, decomposition and 6.111 correction suites. The expanded organization,
B2, S2 and S3 run passed 131 tests with one new test-fixture expectation failure:
the test incorrectly assumed different sources prohibit comparing recorded UTC
coordinates. The existing S2 rule permits that comparison while explicitly denying
physical event order. The new test was corrected to assert preservation of that
qualification; production S2 behavior was not changed. The final organization
suite then passed all 23 tests in 16.18 seconds.

Tests cover durable mock-run checkpoints, exact-prefix replay, corruption,
append failure, cancellation, cumulative bounds, final reservation, alias
separation, historical read-only/provider-free reconstruction, multi-source clock
qualifications and large bounded streams. Existing B2/Stage A suites cover unchanged
authorization and disclosure behavior. No full suite or live model request ran.

## Remaining limitations

This is C1 reference organization, not integrated reporting, semantic verification,
restart continuation or model-driven graph editing. The historical view occupies
most of the 256-KiB allowance; larger cases can stop partially without losing
underlying accepted evidence. Conservative journal reservation can skip local
updates. No new inference bridges unassigned findings into AI themes. Historical
read-view validation does not establish current case equality or parent-process
cleanup. No paid live investigation is needed for initial C1 acceptance.

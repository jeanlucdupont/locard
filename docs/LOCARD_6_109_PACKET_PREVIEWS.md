# S4-B1: bounded local evidence packet previews

Implementation milestone, 2026-11-08. Baseline main:
`e8d7fbd86375bf1bd6416ba4377afcab36852695`. Application version is supplied only
by `pyproject.toml`. This implements B1 of the approved S4-B rehydration design;
Stage A, S4-A, provider grants, report-import permissions and evidence storage
are unchanged. Live manual acceptance is pending.

## Boundary and API

`investigation_ai/packets.py:reconstruct(root, identity)` is the saved-transcript
entry point. It uses `transcript.load`, `autonomous.reconstruct`, the S1 reducer,
S2 relationship builder and S4-A journal/terminal assessment validation. The hash
chain is necessary but not sufficient: accepted deltas are replayed through the
existing grounding checks. Original S3 assessment and historical decomposition
are returned separately without repair or promotion.

`plan(Context(...))` accepts **trusted application reducer state**, not arbitrary
JSON clauses. It reuses State's records/exposure store rather than creating a new
evidence database. `validate_preview` rebuilds from that trusted state and compares
the entire preview, including aliases, exact values and membership. Digests alone
do not authorize a packet. Saved-result reconstruction adds transcript provenance
and S3 metadata around the core preview; these are not packet content.

There is no provider, worker, case opener, refill, persistence event or dispatch
transition. Previewing does not mutate the supplied State, actual current-request
membership or cloud allocations. No report importer accepts these packets as new
evidence authority. Future consumption still requires a separately reviewed
`build → validate → persist intent → commit membership → charge → dispatch`
contract, including response grounding. B1 does not implement that contract.

## Contracts and exact support

| Contract | Meaning |
|---|---|
| `synthesis-packet-v1` | Original question/hash, provisional objective, recorded view/grant, complete source and lineage dictionaries, exact support, qualifications and selection digest |
| `synthesis-support-v1` | Original EID/pointer/typed value, semantic descriptor, S1 clause ID, exact projection digest/version, accepted delta/disclosure lineage and timestamp metadata where applicable |
| `synthesis-interpretation-support-v1` | Registered interpretation with original premise pointers; Defender ASR metadata remains explicitly derived |
| `synthesis-binding-v1` | Separate technical binding decision, candidate domain, provisional intent and unchanged historical proposal |
| `synthesis-selection-v1` | Stable unit decisions, examined/unassessed counts and omission reasons; heuristic ranking is not a relevance finding |

`_rehydrate` requires an exact retained record digest matching accepted S1
lineage, the same view, source/provenance/context, approved evidence/source/family,
projection contract, pointer and typed value. A later replacement is never used
as an earlier projection. Missing versions yield `support_unavailable`, not a
case read. Retained original-field eligibility is checked against State.

All original limitations survive in the source context and qualification set.
Each relationship brings both endpoint bundles and its assumptions. Contradictory
field dependencies bring their paired support. Dependencies are flat registered
S2-to-S1 edges; unknown endpoints, invalid contracts/epochs and cyclic chronology
are rejected. Interpretation bundles include provider/channel/event ID and the
registered ASR metadata/premises. ASR blocking does not prove script execution.

`P1` source and `D1` lineage aliases have complete same-packet dictionaries.
Values are never newly truncated to fit. If mandatory support does not fit, the
whole bundle is omitted. The represented-support manifest records exact EIDs,
pointers and value hashes alongside the actual original values in the packet.

## Bindings and selection

Supported positive binding domains are exact browser download target/current
paths, absolute MFT path objects, and integer EVTX event IDs. Each must occur in
a complete typed accepted S1 field. Uniqueness is over accepted findings in this
recorded view, **not the whole case**. Separate EID/source occurrences remain
ambiguous even with equal values. Missing or incomplete candidate support cannot
produce a positive binding. A successful match establishes a recorded typed
occurrence, not execution, causation or analyst intent.

Generic script roles are unsupported. Neither `execute` nor `the PowerShell
script` becomes a filename. Historical span classification remains intact; the
binding decision is separate. Statuses distinguish resolved-within-domain,
ambiguous, unsupported role, unavailable support, incomplete candidates and
invalid technical referent. An incomplete accepted field conservatively makes the
binding domain incomplete; this may decline a binding that a future broader
semantic contract could establish.

Selection prioritizes direct typed objective support, its atomic dependencies,
other unrepresented typed objectives, then heuristic question-term overlap and
stable EID/clause identity. Already represented record support is deprioritized
for the next packet. No batch recency or artifact-family quota is used. At most
two provisional objectives receive separate packets in one operation; this is
not an exhaustive objective assessment. Unavailable and budget-omitted units
remain distinguishable from unassessed units and historical disclosures.

## Limits and diagnostics

| Bound | Maximum |
|---|---:|
| Packets per operation | 2 |
| Serialized message-content UTF-8 bytes per packet | 5,600 |
| Candidate assessments per packet | 192 |
| Support resolutions per operation | 512 |
| Support leaves per packet, including interpretation premises | 12 |
| Recognized interpretations per packet | 4 |
| Local in-memory planning | 5 seconds |

Existing S1/S2/S3/S4-A limits remain. The byte count includes system instruction,
escaped JSON, mappings, qualifications and final omission metadata. It excludes
role/wire framing because this is the existing **content** budget, not a token
estimate. Full selection decisions live in the bounded preview envelope; each
packet contains their digest and omission counts. Final metadata growth can
remove a whole bundle. Budget exhaustion never triggers a model call or a refill.

Deadline checks cover bounded planning/rehydration/selection and final packet
serialization. They do not impose an OS-level preemption or deadline on reading
the transcript from disk. Deadline interruption can discard an incomplete
preview with `no_supported_packet`. Retained input state and logs are unchanged.

From a checkout with Locard installed, using a synthetic example path/ID:

```powershell
.\.venv\Scripts\python.exe -m forensic_assistant.investigation_ai.synthesis `
  C:\tmp\saved-investigations 0123456789abcdef0123456789abcdef --packet-preview
.\.venv\Scripts\python.exe -m forensic_assistant.investigation_ai.synthesis `
  C:\tmp\saved-investigations 0123456789abcdef0123456789abcdef --packet-preview --json
```

These commands require the parent directory and original investigation ID, not a
case DB path. `--relationships`, `--assessment` and `--decomposition` retain their
existing behavior. Configured cloud providers do not affect local previews.

## Recorded copy measurement and limitations

Read-only reconstruction of the authorized 6.108 acceptance copy validated its
chain, accepted batches, view bindings and original S4 terminal assessment.
Repeated previews were equal. All 20 clauses (seven relationships, six records)
had exact retained support; 24 support resolutions were used. Browser, EVTX,
MFT and Prefetch were available, including earlier batches. The unchanged
historical `execute` binding was invalid; original S3 remained NOT_ASSESSABLE.

Two packets measured **5,421 and 5,075 bytes**, representing Browser and EVTX
original fields from two records. First selection: 23 byte-budget omissions;
second: 19 byte-budget omissions and four already-selected units. No candidate
was left unassessed by the selection loop. Omitted MFT/Prefetch and relationship
support is not declared irrelevant. The ASR bundle alone measured 5,134 bytes
without an objective and with minimal selection metadata; it cannot simply be
added to an already-full packet. This is a measured capacity limitation, not
permission to remove its qualifications or raise the budget. No final narrative
or cross-record completeness is claimed.

Replay plus preview took approximately 0.17 seconds in this checkout; repeatability
and exact bytes matter more than a single timing. Both copied files' SHA-256 values
were unchanged during inspection. This establishes copy stability, not historical
authenticity or original-case integrity. The previously documented difference
between historical runtime code hash and checkout hash remains unresolved; replay
compatibility does not prove byte-identical historical execution.

Synthetic tests in `tests/test_synthesis_packets.py` cover original rehydration,
replacement/missing projections, alias/value/lineage tampering, interpretation and
relationship closure, ambiguity, invalid/generic references, Unicode accounting,
ordering, limits, empty support, no ledger mutation and provider/case-free replay.
Existing S1–S4-A and compact-disclosure regression files are run alongside them.
No full suite or live provider request is part of B1 validation.

Recorded focused run: **231 passed in 36.27 seconds** across packet previews,
factual clauses, relationships, question assessment/decomposition, autonomous
Stage A and compact disclosure. The diagnostic CLI JSON path also produced the
same measured packet sizes. `git diff --check` passed. New-file whitespace checks
reported no errors. Changes remain uncommitted for manual review.

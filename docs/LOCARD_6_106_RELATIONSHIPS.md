# Locard 6.106 — S2 typed relationships and qualified chronology

S2 is an optional, deterministic recorded-view analysis over validated S1 clauses.
It neither adds model requests nor changes Stage A, S1 identities, transcript
events, case data, authorization limits or report-import permissions.

## Interface and grounding

The existing inspection utility gains an explicit `--relationships` option:

```powershell
Set-Location C:\tmp\locard260927\locard
.\.venv\Scripts\python.exe -m pip install .

$runRoot = 'C:\path\to\case.db.investigations'
$runId = '<original 32-character investigation ID>'
.\.venv\Scripts\python.exe -m forensic_assistant.investigation_ai.synthesis $runRoot $runId --relationships
.\.venv\Scripts\python.exe -m forensic_assistant.investigation_ai.synthesis $runRoot $runId --relationships --json
```

Without the option, the S1 interface and output remain unchanged. The backend
entry point is `investigation_ai.relationships.reconstruct(root, identity)`, which
calls the existing S1 grounding/reconstruction service. It opens no case database.
The complete original S1 result remains under `factual` in structured S2 output.
The human display uses short local clause labels with an exact EID/pointer key;
JSON retains full clause IDs, original values, support and lineage.

The private `_build` service consumes trusted reconstructed S1 state, not arbitrary
external JSON. A recomputed clause hash is not evidence authority. The renderer
rechecks registered derivations for consistency, but is not an independent forensic
grounding importer. Historical evidence is not revalidated against today's case.
All existing transcript integrity, disclosure and read-view checks still execute.

## Relationship contract

`synthesis-relationship-v1` carries predicate/rule versions, endpoint clause IDs,
exact original supports, interpretation references, view identity, typed semantics,
explicit assumptions, inherited qualifications and validation classification.
Its full SHA-256 identity covers the canonical semantic body. Derivation lineage
is separate and retains both endpoints' accepted delta/disclosure references.
Changing endpoints, supports, rules, assumptions, qualifiers or view changes the
identity. Relationships never replace observations or become independent evidence.

`recorded-relationships-v1` contains the original S1 result, relationships,
chronology entries/explicit-edge graph, rejected candidates, coverage and limits.
Cross-view inputs fail closed. No new persistent events or evidence schema exists.

## Implemented predicate registry

| Predicate | Domain and qualifications |
|---|---|
| `recorded_time_before` | Strict order of conservative enclosures of explicit recorded UTC coordinates; no physical-event ordering or clock synchronization claim |
| `exact_recorded_path` | Exact complete Windows path strings from recognized S1 path fields, including referenced MFT/Prefetch objects; no normalization, volume equivalence or file identity |
| `exact_recorded_identifier` | Exact original EVTX `ProcessGuid`, `ParentProcessGuid` or `LogonGuid` strings, separately scoped by field name and one explicit common source ID; no case/braces normalization or independent process/session identity claim |
| `incompatible_recorded_field` | Unequal complete values for the same original EventData EID/pointer/name/ordinal/provenance/source occurrence; a recorded projection inconsistency, not proof of which value is correct |

Unrelated timestamp differences, different filenames, absent records and shared
basenames are not conflicts. Conflicts do not withdraw/supersede clauses or build a
dependency graph; that is outside S2. Source IDs and their original assertion basis
are preserved, never merged into inferred host or volume identity. Equal paths
across sources are labeled **string equality only**.

Paths are not equated through environment variables, short names, case changes,
aliases, drive letters or volume GUID resolution. URLs, executable basenames and
command lines do not become path operands. No normalized-comparison predicate is
enabled: current S1 support does not establish the context required for it.

## Timestamp semantics and deliberate limitations

Only original timestamp-slot UTC fields and `/timestamp_utc` are candidates.
Original values, SI/FN slots, browser start/end meanings, Prefetch metadata, source
context and available precision metadata remain intact. Unknown timezone, invalid
date/offset formats and shortened timestamp projections are incomparable.

The registered comparison parses an explicit `Z`/numeric offset into a recorded
UTC coordinate using exact decimal fractions (up to nine digits, without silently
rounding to Python microseconds). It uses a conservative closed enclosure from the
serialized value through one unit of its last serialized digit. For example,
`...00Z` encloses recorded coordinates through `...01Z`, whereas `...00.100Z`
uses a 0.001-second enclosure. **Serialized resolution is not acquisition precision
or clock accuracy.** Original precision remains unknown unless recorded metadata
states it; no physical uncertainty bound is inferred from that statement alone.

Strict recorded ordering requires `upper(A) < lower(B)`. Equal, overlapping and
touching enclosures do not produce a strict edge. This conservative policy can omit
some otherwise plausible recorded comparisons; it never invents extra precision.

S1 has no reviewed clock-domain/synchronization/skew-bound contract. Therefore:

* Recorded UTC coordinates may be ordered across sources, explicitly without
  establishing their real-world event order.
* A `Z` suffix does not imply synchronized clocks.
* Same-source, same-clock and skew-conditional **physical-event** edges are not
  generated. Arbitrary `clock_domain` or `clock_skew_seconds` fields do not unlock
  that authority.
* Conditional event order is stated only as an unestablished possibility requiring
  independently justified bounds, never as a validated edge.

This limitation follows the S2 fail-closed gate. Validated domain membership and
clock/measurement-error bounds would require a separately reviewed input contract;
this implementation does not invent one. No causal, execution-success or general
question-level predicates are introduced.

## Partial-order display

Chronology entries retain each original timestamp slot. The graph contains only
explicit accepted recorded-coordinate edges. Topological layers and stable tie
breaks are display aids, not additional chronological assertions. No transitive
edges are inferred, especially not across incompatible clock assumptions.

Human output separates comparable recorded coordinates from incomparable entries,
states that conditional physical-event ordering is unavailable, and lists typed
relationships. It is not an attack sequence. A defensive cycle check reports cycle
or dependent nodes without discarding observations; valid strict numeric-coordinate
edges cannot themselves create a cycle.

All S1 qualifications remain in structured output and human qualifications.
Hypotheses remain separate in `factual.hypotheses`; they are not relationship
inputs. The original S1 inspector remains available for their full display.

## Bounded candidate generation and coverage

No unrestricted all-pairs traversal occurs:

* sort eligible UTC timestamps and compare adjacent candidates;
* index exact path, typed GUID and original-occurrence keys;
* perform a deterministic star comparison within each bucket.

Sorting is O(n log n), and candidates are O(n) per predicate. The existing S1
96-clause and six-batch ceilings remain. S2 caps evaluated candidates at 192,
retained relationships at 64, and total serialized derived output at 1 MiB.
These are independent derived-output bounds, not increased investigation or
transcript budgets. Exceeding the S1 input ceiling fails closed. Comparison/output
limits retain the accepted prefix and report remaining coverage.

Coverage distinguishes examined clauses, indexed/considered candidates, accepted
relationships, rejected/equal/overlapping candidates, incomparable entries,
validated-but-unretained relationships and budget-unassessed candidates. It also
counts pairs not generated by the sparse policy within its candidate domains.
That count is not a claim to have evaluated all conceivable semantic relationships.
Nonmatching path buckets, unsupported predicates and clock domains are not assessed.
An empty candidate set is not proof of no relationship.

There is no implicit transitive closure filling sparse omissions. In particular,
an overlapping adjacent interval can leave a non-adjacent ordering unassessed;
this is reported as incomplete comparison coverage, not absence of evidence.

## Validation and manual acceptance

Synthetic tests in `tests/test_synthesis_relationships.py` cover exact support,
timestamp fractions/offsets, overlap, unknown timezone, distinct slots, fail-closed
clock assumptions, paths/aliases/source boundaries, typed GUID domains, narrow
conflicts, malformed IDs/contracts, cross-view rejection, stable identities,
deduplication, sparse growth/budgets, cycles and unchanged S1/Stage A/report import.
Existing S1, Stage A, compact-disclosure and presentation tests are also relevant.

Final focused run on 2026-11-08: **122 passed in 25.10 seconds** across those five
modules. `git diff --check` and new-file whitespace checks passed. The full suite
was not run. No provider requests, evidence writes, permission changes, commit or
push were performed.

On 2026-11-08 the approved 6.103 diagnostic copy was read through the public
reconstruction path. It retained all **22 S1 clauses**, found **nine timestamp
observations**, and accepted **seven recorded-UTC ordering relationships** out of
eight sparse candidates. One comparison had equal/overlapping intervals. Twenty-eight
non-adjacent timestamp pairs were not generated. No path/identifier/conflict edge
was manufactured to fill a quota. Repeated reconstruction matched, and both input
file SHA-256 hashes remained unchanged. The temporary correctly named copy was
removed; no original case/sidecar or provider was accessed.

For acceptance, use the same saved investigation as S1. Confirm the 22-clause S1
subdocument is unchanged, the ordering language is explicitly recorded-value only,
clock limitations and incomplete comparison coverage are visible, and exact
references remain available in JSON. No new OpenAI request is needed. Stop at
manual acceptance before any S3 implementation.

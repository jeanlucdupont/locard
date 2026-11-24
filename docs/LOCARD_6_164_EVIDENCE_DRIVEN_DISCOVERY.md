# Locard 6.164 — Bounded evidence-driven discovery

Implementation and synthetic validation: 2026-11-23. Live acceptance remains pending.

## Delivered increment

`investigation run <assessment> --follow-up` enables a standalone, opt-in
evidence-analysis workflow. It uses the existing briefing, saved assessment,
authorization, supervised controller, read-view worker, original record
projections, disclosure ledger and grounded incremental observations.

The model can propose a temporal follow-up using an **exact original timestamp
field represented in its current request** and an authorized artifact family.
The application derives a five-minute neighborhood on either side, intersected
with the approved UTC window. There are no model-supplied timestamps, source IDs,
SQL, paths, domains, filenames or free-text search expressions in this contract.

This is the smallest end-to-end slice permitted by the request, not the entire
discovery roadmap. It supports temporal neighbors in Browser, EVTX, Prefetch,
MFT and Registry. Filename/path/key pivots are **not implemented**. This mode does
not run question decomposition or B2 synthesis; the existing workflow without
`--follow-up` remains available, including those options. No existing assessment
or historical investigation is rewritten.

## Execution and authorization

1. Prepare seed references from the saved assessment, within its source/time
   scope. Review the exact new grant before approving it.
2. Establish the existing pinned read transaction and inspect an authorized seed.
3. Disclose bounded original fields. The model either returns grounded findings
   for that batch or proposes `follow_up` with `evidence_id`, `field`, `family`
   and a short investigative reason.
4. Validate the proposal against the **current** disclosure, not merely an ID
   encountered in an earlier request. Only `/timestamp_utc` or
   `/timestamps/N/utc` is eligible. The anchor must itself be inside the approved
   half-open UTC window.
5. Persist the proposal and derived scope, authorize the operation, and record
   mandatory audit approval before entering the worker.
6. The worker independently revalidates the live grant, derives the same window
   from its retained original projection, enforces search counts/deduplication,
   and checks source membership before reading candidate record content.
7. Persist the bounded result and its coverage, then use the ordinary disclosure
   and citation validators for the next model response. A match is neither a
   finding nor evidence of suspiciousness. Invalid later batches cannot publish
   findings or erase previously accepted batches.

The authorization contract is `investigation-temporal-follow-up-v1`, an explicit
extension of the Stage A execution path. Old grants do not authorize this tool.
Every operation still validates case identity, provider/model, expiry, source
IDs and artifact families. Search results may contain new IDs, but only inside
the newly approved temporal-search authority. A record with source memberships
outside the grant is refused; sharing one authorized source is insufficient.

| Resource | Ceiling |
|---|---:|
| Potential assessment seeds | 12 |
| Total tool operations, including searches | 6 |
| Follow-up searches | 2 |
| Returned records per search / across searches | 3 / 6 |
| Distinct records potentially disclosed | 18 |
| Model attempts, including tool proposals | 6 |
| Steps / overall execution budget | 8 / 300 seconds |
| Candidate timestamp entries per search | 1,000, plus two bounded sentinels |
| Search execution | 5 seconds maximum |
| Serialized OpenAI message content | 5,600 UTF-8 bytes |
| Output token allowance | 1,024 per request |
| Automatic retries / cross-session grant reuse | 0 / 0 |

These are ceilings, not promises of coverage. With two three-record searches
and four single-record inspections, at most ten distinct records can actually
be returned in this slice. The 18-record disclosure guard is an independent
upper bound. A tool proposal consumes an existing model attempt; it does not
add a paid request allocation. Normal analysis, search and model failures retain
prior accepted findings. Empty searches stop with a scoped unresolved result;
duplicate search windows are not retried. Cancellation, cleanup, process
containment and parent deadlines use the existing infrastructure.

## Selection and temporal meaning

Only the opt-in mode changes seed sampling. It retains artifact/subtype coverage
and explicit analyst reference priority, then uses deterministic farthest-time
sampling among eligible retained assessment timestamps. The first choice is near
the window midpoint; later choices seek temporal separation. Stable evidence-ID
tie-breaking makes repeated planning reproducible. This can select a late-day
seed despite many routine early records. It cannot recover time coverage absent
from the saved assessment itself.

For follow-ups, two indexed scans examine up to 500 timestamp entries before
and after the anchor. Candidates are ordered by distance, timestamp, original
evidence ID and slot. Already retrieved records are excluded. Source, family and
time restrictions are rechecked before original record projection. The existing
first-32-timestamp eligibility bound remains explicit. A returned projection
must retain a timestamp witnessing eligibility.

Result, candidate and execution limits are reported as incomplete coverage, not
as absence. The candidate bound counts timestamp entries, not physical index
pages or unique records. Unrelated source entries can consume candidate capacity;
there is no automatic continuation in this increment. Query interruption fails
the operation safely rather than asserting an empty, complete result.

Browser visit/download, EVTX event, Prefetch run, MFT SI/FN and Registry LastWrite
meanings remain in their original projections. Timestamp proximity does not
establish a common host, causality or execution. Full-record context may contain
other timestamps; those are not silently promoted to in-window events.

## Provenance, disclosure and history

`follow_up.py` provides proposal validation, deterministic retrieval, historical
validation and concise presentation. `autonomous.py` integrates it with existing
analysis requests; `worker.py` enforces independent search limits and original
anchor resolution. `autonomous_policy.record_scope` reuses the existing source
and timestamp authorization checks. `assessment_selection.py` implements the
opt-in temporal sampling.

The private investigation transcript records:

- Proposal, origin evidence/field, reason, derived source/time/family scope and
  current disclosure digest.
- Authorized operation, grant ID, ordinary required audit approval/completion
  references, result IDs and bounded coverage diagnostics.
- Charged model attempts, disclosure packets, accepted deltas, rejected responses
  and final resource/termination accounting.

The OpenAI adapter recognizes only the exact new application-owned tool/final
schema. Canonical validation remains strict. Final message sizing includes the
OpenAI transport instruction. No additional readiness or provider calls are
made inside the grant.

Provider-free reconstruction checks the transcript chain using the existing
loader, then revalidates follow-up scope, current-disclosure anchoring, operation
budgets, returned sources/families/times, read-view bindings and original finding
citations. It does not reopen the case or assert that recorded data still matches
the live database. A hash chain alone is not grounding validation.

Structured accounting distinguishes retrieved records, records included in
dispatched model attempts, and records supporting accepted observations or
interpretations. Dispatch may expose data even if the provider fails; it is not
proof of provider receipt. Structurally valid search proposals are counted even
when their evidence binding is rejected; malformed responses remain rejection
diagnostics. Matching records do not automatically resolve leads: deterministic
lead resolution is not claimed.

Normal output separates observations, interpretations, relationships, unverified
hypotheses, unresolved questions and coverage. URL query/fragment values are
omitted from this concise rendering; original evidence and structured diagnostics
are unchanged. This is not a general-purpose redaction/export guarantee.

## Focused validation

Synthetic/mock coverage includes current-request anchoring; invented IDs and
fields; forbidden source/time arguments; unauthorized families; old and expired
grants; deduplication; empty/partial searches; retained findings after failure and
cancellation; required audit boundaries; exact OpenAI schema adaptation and UTF-8
message budgets; independent deterministic reconstruction; temporal seed
sampling; and all five artifact-family retrieval adapters.

A real contained worker reads a disposable SQLite fixture with 1,100 routine
morning events and a separate late-evening sequence. It reaches the late records,
reports result truncation, rejects repeated queries, releases its process and
leaves the database byte-for-byte unchanged. Separate fixtures exercise source
isolation, Browser neighbors and temporal cross-artifact retrieval.

Recorded focused results (overlapping sets, not additive totals):

| Check | Result |
|---|---|
| Discovery, Stage A, seed selection, handoff, OpenAI schema, CLI, startup containment and synthesis regressions | **192 passed**, 135.04 seconds |
| Final discovery + CLI regressions after support-expansion, precision and single-grant refinements | **73 passed**, 34.69 seconds |
| Final audit failure/completion correlation checks after correcting the rejected-tool label | **2 passed**, 2.07 seconds |
| `git diff --check` | Passed |

The new discovery file contains 30 focused tests. An older synthesis test still
invoked the removed top-level `briefing --show --synthesize` syntax. Its setup
now checks rejection by the current CLI and independently verifies that the
application service rejects synthesis without autonomous decomposition. The
security assertion was retained; no production behavior was restored to satisfy
obsolete syntax. An initial expanded run stopped at that stale test after
183 passes; it is corrected in the passing results above.

No live case, original transcript, provider request, full suite, commit or push
was part of this development task.

## Changed areas

| Files | Purpose |
|---|---|
| `investigation_ai/follow_up.py` | Typed temporal search, source/current-disclosure validation, replay and concise presentation |
| `investigation_ai/autonomous.py`, `autonomous_policy.py`, `worker.py` | Explicit grant, bounded scheduling, worker checks, audit and incremental analysis integration |
| `investigation_ai/recorded.py`, `presentation.py` | Recorded-history integration and opt-in result rendering |
| `ai/openai_schema.py` | Exact new tool-schema recognition through the existing adapter |
| `assessment_selection.py`, `assessment_handoff.py`, `assessment_handoff_cli.py` | Opt-in temporal seeds and reviewable authorization |
| `investigation_workflow.py`, `workflow_cli.py` | One opt-in flag and one exact grant approval |
| `tests/test_follow_up_discovery.py`, `tests/test_synthesis_consumer.py` | New focused coverage and stale CLI test correction |
| `pyproject.toml`, `.gitignore`, this document | Version 6.164, tracked documentation allowance and acceptance guide |

Application paths above are relative to `forensic_assistant/`; tests and root
files are repository-relative. The inspected starting commit was `487df06`;
these development changes remain uncommitted.

## Manual acceptance

After your normal commit/pull/install workflow, in PowerShell:

```powershell
.\.venv\Scripts\python.exe locard.py --version
.\.venv\Scripts\python.exe locard.py
```

The version should be **6.164**. In the Locard shell:

```text
case open "D:\Locard\Cases\KFI-5070790-V2\case.db"
ai status
ai check --full
investigation run 3aa7e12d14d94720b172ad072c56f92d --follow-up
```

Complete the separately authorized compatibility check in this same session.
At the question prompt, enter the original neutral question unchanged; do not
add known incident indicators. Review the sources, UTC bounds, artifact families,
temporal sampling limitation, search capability and budgets before approval.

Look for an evidence-backed proposal, its bounded search, and any resulting
records in later validated observations. A model is not required to propose a
search, and a match is not proof of compromise. A run that proposes no search
does not establish live acceptance of lead-following behavior. Review empty,
truncated or rejected attempts in recorded diagnostics before changing limits.

Use the actual run ID printed by that investigation:

```text
investigation history show <actual-run-id> --json --explain
```

This recorded-history review is provider-free. Do not use a historical grant to
dispatch new operations. Existing show-only/S4 workflows remain available by
omitting `--follow-up`.

## Deferred work

- Exact filename/path/key pivots, explicit continuation and richer lead tracking.
- Combining this temporal discovery contract with decomposition and B2 synthesis.
- Better search selection when authorized-source candidates are crowded out by
  unrelated timestamp entries, and assessment coverage beyond retained records.
- Evidence-grounded incident reconstruction at larger scale; no completeness or
  causal conclusion is implied by exhausting an approved plan.

These are limitations, not automatically authorized follow-on implementation.

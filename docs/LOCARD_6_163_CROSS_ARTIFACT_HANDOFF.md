# Locard 6.163 — Coverage-aware autonomous handoff

## Confirmed cause

`assessment_handoff.references` sorts evidence IDs; `prepare` previously selected explicit E aliases followed by the first remaining IDs, capped at 12. `BROWSER:` sorts ahead of the other five-family prefixes. With at least twelve Browser records and no explicit references, the handoff therefore becomes Browser-only. `investigation_ai.autonomous.prepare` derives permitted families and source IDs from selected records; it does not independently authorize all available assessment families. This was deterministic and bounded, but unsuitable as the default cross-artifact sample.

The previous scheduler also used evidence ID as a tie-breaker after previous-delta word overlap, so merely balancing twelve seeds could still consume all six lookups within early Browser IDs. Synthetic saved assessments reproduce both selection and scheduling effects. The real assessment and historical cancellation were not inspected or changed.

## Correction

The autonomous handoff opts into `assessment_selection.select`; legacy non-autonomous handoff selection remains compatible. Existing E aliases remain stable and exact requested aliases take priority. Other candidates are selected round-robin across eligible categories, with original evidence-ID ordering inside each category. Browser visits/downloads are distinct categories when retained presentation metadata identifies them; otherwise Browser stays a generic category. No subtype is invented.

Small lexical objective hints prioritize available categories: browser/navigation/download/visit, EVTX/event/process, Prefetch, MFT/file/filesystem, and Registry/persistence. A single recognized family plus an explicit “only” restriction narrows the sample; “not only” does not. Unrecognized or broad wording falls back to diversity. These hints express requested topics, not verified facts, technical indicators, causal conclusions, rarity or maliciousness. Analyst review of the exact grant remains essential.

New selection requires explicit retained source membership and at least one of the first 32 retained timestamps in the half-open approved window. Missing/ambiguous temporal eligibility is counted as excluded. If the assessment has a source_id, candidates whose memberships are not wholly within that source are excluded, consistent with the existing worker's source-subset requirement; conflicting provenance is not erased to force eligibility. Without a single saved source restriction, selected recorded sources remain explicitly listed in the grant. A new override cannot expand the saved assessment window.

Selection is capped at twelve IDs and does not modify the original assessment. A versioned selection summary travels with the new handoff and grant, including available counts, eligible families, selected counts/IDs, bucket order, exclusion counts, omitted eligible count and matched objective categories. Selected ID and source authority are checked against the assessment when creating the grant.

For this profile the scheduler first honors explicit requested IDs, then prefers least-inspected selected categories. Existing previous-delta term matching remains the tie-breaker within a category. With no overriding explicit-reference demands, six categories (Browser visit/download and four other families) can occupy the existing six lookup slots. Missing categories are not fabricated. Older grants retain their original scheduling behavior.

## Authorization, audit and limits

The preview lists assessment, question, available family counts, selected seed counts, eligible families, omitted/excluded counts, exact E aliases and evidence IDs, source restrictions, UTC window and all retained route limitations/warnings. New count fields use the shared semantic presentation helpers. Structured selection metadata is JSON-compatible and contains no ANSI.

Eligible assessment families are not blanket retrieval authority. Only selected IDs are authorized; only show_evidence is permitted. At most six can actually be inspected. No additional searches, refill lookups, automatic continuation or retries are introduced. Model counts, six lookups, 300 seconds and 5,600-byte model budgets remain unchanged. Worker-side current-view source/time checks still apply; historical selection is not current evidence authority. Existing bounded full-record-context permission remains unchanged.

The new cancellation audit event records the declined selection with zero provider requests/lookups, using required existing activity persistence. It does not alter the previous cancellation or invent findings. Accepted grants continue through existing transcript/worker authorization. Original assessments, briefing revisions and case evidence are untouched.

## Remaining limits and extension boundary

This produces a useful diverse starting sample, not a full-day chronology or comprehensive persistence analysis. Timestamp truncation may hide eligibility; unknown timestamps are not inferred. Evidence can change between assessment and investigation, and the current-view checks may reject selected IDs. Browser records with no retained subtype cannot be guaranteed visit/download balance. Explicit E requests can consume slots and reduce diversity. Lexical question hints are intentionally limited and do not certify semantic understanding.

Current Stage A is deliberately show_evidence-only. Selecting different explicit E aliases already permits another bounded investigation of saved references, subject to fresh authorization; it does not grant broader autonomous search. Legacy non-autonomous handoff uses its existing individual lookup approvals. No existing setting turns this Stage A grant into unrestricted search. If more than six inspections or new searches are needed, propose a separate authorization-contract extension; do not increase budgets or add tools as part of seed correction.

## Validation

Synthetic saved assessments exercise the actual storage → handoff → autonomous grant path, Browser-first ordering, all five families, Browser-only/missing families, source exclusions, out-of-window/absent timestamps, explicit-reference priority, deduplication, repeated equality, truncated timestamp metadata, selected-ID-only policy, six-category scheduling, JSON equality and declined CLI authorization with no worker dispatch. Existing handoff, Stage A and preflight suites preserve authorization and historical behavior. Focused run: `test_assessment_seed_selection.py test_assessment_handoff.py test_autonomous_stage_a.py test_investigation_preflight.py`: **63 passed in 47.69 seconds**. After adding selection metadata to the structured result and deriving availability counts from exact ID prefixes, the selection suite passed again: **8 passed in 6.04 seconds**. Initial new-fixture failures used a malformed Prefetch ID and an over-specific time-error assertion; fixtures were corrected without relaxing production validation. `git diff --check` passed.

## Manual acceptance

After installation, verify `python .\locard.py --version` reports 6.163. In the same interactive process:

```text
ai check --full
investigation run 3aa7e12d14d94720b172ad072c56f92d
```

Approve the separately requested synthetic diagnostic only if intended, then reuse the neutral question. Review all grant details before accepting. Expect eligible multiple-family representation when retained source/time evidence permits it, not necessarily equal counts. Check Browser subtype counts indirectly through selected references/details and the actual retained record metadata. Decline if scope is unsuitable: no retrieval or model execution should follow.

No real-case workflow, live AI call, full suite, commit or push was performed during development. Real-case acceptance remains pending.

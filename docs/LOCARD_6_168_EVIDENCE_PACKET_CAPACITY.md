# Locard 6.168 — Practical bounded evidence disclosure

Date: 2026-11-24. Baseline: `3aaed90` (6.167). These uncommitted changes await manual acceptance. No real case, transcript or provider was accessed.

## Confirmed synthetic failure

The committed 6.167 controller was executed against a disposable synthetic fixture: Browser seed, two three-record EVTX temporal searches, actor inspection, then distinct object inspection. It stopped during the second context packet with `PROMPT_BUDGET_EXHAUSTED`, seven retrieved records and four model attempts. The next request was never sent.

This establishes a matching implementation failure, not the exact content of the uninspected live run. It was **not solely a ledger problem**. The allocator reserves incremental context plus transport margins before allocating original evidence, then another 180 bytes for omission accounting. In the reproduction:

- Reserved outer overhead: **2,822 bytes**.
- Effective inner admission limit: **2,598 bytes** (`5600 - 2822 - 180`).
- Smallest current-record candidate: **2,650 inner bytes**; rejected by 52 bytes.
- Materializing that minimal candidate with the outer context measured **5,227 bytes**, below the nominal limit. Conservative admission margins therefore contributed to the stop.
- That minimal candidate exposed just one field; fitting a bare identifier is not equivalent to conveying useful context. The corrected useful packet measured **6,475 bytes**, above the old nominal ceiling.

Measured serialized-content partition (UTF-8 after OpenAI instruction adaptation):

| Component | Old rejected minimal candidate | Corrected useful packet |
|---|---:|---:|
| Instructions, transport, keys and framing | 3,161 | 3,321 |
| Investigative question | 478 | 478 |
| Original observation/interpretation tuples | 43 | 1,236 |
| Evidence identity, provenance, semantics envelope and qualifications outside those tuples | 539 | 539 |
| Model-facing completion history | 480 | 375 |
| Other incremental history/optional instructions | 526 | 526 |
| **Total** | **5,227** | **6,475** |

The partitions sum to the actual candidate content. Observation tuples include exact values, pointers and field labels; framing is attributed to instructions/transport rather than guessed as provider tokens. The corrected packet represents seven fields. The old candidate was only measured locally; it was not dispatched.

## Versioned authority and guards

New contextual approvals use **`investigation-context-follow-up-v2`**, with exactly **24,576 serialized input-content bytes/request**. The approval display shows this ceiling and its potential disclosure/cost impact. There is no arbitrary budget CLI switch.

Historical context-v1 and temporal grants remain capped at 5,600. Grant shape checks require the exact budget for each version; changing the number on an old grant fails closed. Ordinary `Budget` still rejects values above 5,600. `ContextBudget` is selected only after validating the new authorization, and recorded reconstruction selects the same fixed type from the grant.

The new `compact-disclosure-v2` encoding retains the existing tuple structure and original field semantics, but permits a larger bounded payload. State validation rejects it under an old budget. Transcript loading, autonomous replay, recorded-history reconstruction and original-support rehydration recognize it only under the corresponding new grant. Other synthesis, decomposition, D2 and reporting request ceilings are unchanged.

Relevant implementation: `context_inspection.supported`, `follow_up.shape`, `autonomous_policy.validate`, `state.ContextBudget/recorded_budget`, `disclosure.decode/_validate`, `transcript.load`, `autonomous._replay`, `recorded.open_history`, and `packets._rehydrate`. Worker-side policy validation continues through the same grant checks; worker IPC and memory ceilings are unchanged.

## Model progress versus local audit history

`progress.ledger` remains the full local record with exact IDs, categories, field counts and slot/original-ordinal inventories. Every exposure retains this ledger for independent validation.

`progress.summary` creates a separate `context-progress-summary-v1` model representation: completed exact record/category pairs; empty, omitted, partial or disclosed status; repeat prohibition; remaining calls/searches; and other supported categories. Detailed column definitions and ordinal inventories are not retransmitted. Empty/omitted statuses never assert absence from original evidence. The controller independently checks duplicates regardless of model compliance.

Replay recomputes both representations from validated result/exposure events. The summary is planning metadata, never a citation source. A field is usable only through its actual current original disclosure.

## Allocation and analysis

The new contextual path starts with concise instructions/history rather than retaining optional prior unknowns and redundant returned-ID lists. It allocates a required current original field first, then attempts up to eight contextual fields (still within the existing 12-observation cap), exact prior factual support, and remaining optional candidates. Complete interpretations retain their limitations. No value, evidence ID or pointer is shortened to fit.

Actual final system/user content is measured after provider instruction adaptation. The fixed 24,576-byte guard is enforced before dispatch. Conservative internal packing reserves remain; a genuine admission failure is diagnosed as evidence-size pressure or overhead/reservation pressure rather than assumed to prove that the evidence alone is too large.

The 6.167 analysis-only rule is retained: the last available attempt and a deterministic continuation after a redundant proposal forbid tools through the strict final-response schema. Earlier findings survive. No failed packet or completed tool is presented as grounded analysis.

## Numerical diagnostics

`packet_capacity.measure/validate` records `packet-capacity-v1` for prepared v2 packets and packet-size failures. It contains no field values:

- authorized ceiling;
- required candidate bytes and actual serialized candidate bytes;
- total evidence bytes, field-tuple bytes and identity/provenance/envelope bytes;
- model-history, optional-context, question and instruction/transport bytes;
- mandatory field count, disclosed field count and omitted field count;
- `fits`, `mandatory_evidence`, or `overhead` cause.

“Required” measures the allocator's smallest mandatory-field candidate with the associated context, not a mathematical optimum across every possible serialization. On failure, “actual” is a measured attempted candidate, not a claim that a provider request occurred. The full local audit ledger is separate from the model-history byte count. A missing original record still uses its existing specific validation diagnostic.

Replay checks numerical structure, sums, grant ceiling and consistency with the persisted exposure and model summary. Ordinary failure output identifies the capacity cause and numeric requirement; it does not print original values or exception text.

## Resource and cost implications

Six attempts can now carry up to **147,456 input-content bytes**, versus 33,600 under the old ceiling: approximately **4.39 times** the maximum. These are ceilings, not fixed request sizes. Repeated disclosures count again. Larger actual content can increase OpenAI input-token charges; byte counts are not token counts or price estimates. Provider schema overhead is separate from this defined system/user content ceiling.

Six tool operations, two searches, six model attempts, the five-minute deadline, 1,024 output tokens/request, source/time/family restrictions, pinned read view, cancellation and containment remain unchanged. There are no automatic retries or additional requests. Context inspection itself retains its original eight-entry/1,800-byte selection bound.

## Validation and limitations

The synthetic acceptance completes two searches and two distinct inspections, retains seven records, and produces one validated analysis in five model attempts/five tool operations. Both a grounded original-object observation and an honest insufficient-evidence response pass. Requests remain within the new authorized ceiling and replay independently without provider/case access.

Tests cover old grant rejection of a raised limit, unchanged old packet capacity, altered disclosure/summary/byte counts, original fields exceeding the new limit, optional-history removal, real disposable read-only worker execution and cleanup, and recorded-history reconstruction. Existing context, progress, temporal, compact-disclosure and Stage A tests cover authorization, cancellation, deadlines, prior findings and legacy replay.

| Check | Result |
|---|---|
| Focused capacity, progress, context, temporal, packet, compact-disclosure and Stage A regressions | 126 passed, 1 warning; 69.12 seconds |
| Final capacity/optional-history checks | 11 passed, 1 warning; 8.19 seconds |
| `git diff --check` | Passed |
| Version in `pyproject.toml` | 6.168 |

No full suite was run. This improves communication capacity, not investigative completeness. Large fields, extensive qualifications, original acquisition omissions, bounded worker projections and the unchanged field-count limit can still restrict useful context. Hypotheses remain unverified; no successful execution or compromise is inferred from capacity alone.

## Manual acceptance

After installing the development checkout in the test environment:

```powershell
.\.venv\Scripts\python.exe locard.py --version
```

Expect `Locard 6.168`. Reuse the saved assessment and neutral question:

```text
investigation run 3aa7e12d14d94720b172ad072c56f92d --follow-up
```

Before approval, verify the explicit **24576 input-content bytes** ceiling and unchanged six-attempt/six-operation limits. Successful acceptance may produce partial findings or an honest insufficient-evidence answer; it need not prove compromise.

Provider-free review of the actual new run:

```text
investigation history show <actual-run-id> --json --explain
```

Inspect the v2 grant, full `operation_ledger`, compact `progress_summary`, numerical `packet_capacity`, exact original disclosures and validated delta. Ensure no duplicate lookup, extra provider retry or unsupported citation occurred. Do not reuse or renew a historical grant to authorize a new provider request.

# Locard 6.130 — Investigative evidence selection quality

## Status and scope

Implemented 2026-11-12 in the working tree on `main`, starting from
`f32dc6c0fb0c11156e6d0a7455ab6e6d54687cdc` (6.129). `pyproject.toml` is now
**6.130**, the single application-version authority. Ready for manual provider-free
acceptance, not a claim of real-model investigative usefulness.

No paid provider call, live case DB access, transcript modification, permissions
change, full suite, commit or push. Existing D2 execution/authorization, response
contract, source validation and all resource ceilings remain unchanged. The separate
zero-analysis Cross-view explanation defect was not touched.

## 1. Confirmed diagnosis before implementation

Read-only reconstruction used the exact requested question and copied run:

- Root: `C:\tmp\locard-diagnostics\6.118-live`
- Run: `6ad0c85499564406aa4d949f3b0e72e5`
- Question: “What evidence connects the recorded download and subsequent filesystem observations? Which links remain hypotheses and what additional examination would discriminate?”

The committed selector reproduced **16,330 bytes**, five original fields, two
recorded-time relationships and 25 complete-request-byte omissions. The fields
were Browser DownloadEnd and referrer, MFT FN Created and FN Accessed (different
records), and Prefetch LastRun. Neither required identifying path was present.

All 24 available S1 units, including the Browser `/target_path`, MFT `/objects/1`
path observations and URL-chain fields, passed exact B1 source-bound restoration.
These were not merely references in an AI summary. `_rehydrate` verified the recorded
grant, EID, view, accepted disclosure lineage, original projection digest, field,
source context and provenance. Ineligibility did **not** explain their omission.

| Factor | Source-confirmed/measured effect |
|---|---|
| Lexical scoring | Scored serialized support objects, including metadata. Common “and,” “the,” “recorded,” and “filesystem” words inflated time bundles. |
| Candidate ranking | Score dominated; relationships beat individual fields on ties. Stable IDs broke remaining ties. |
| Bundle closure | Time relationships correctly retained endpoints, source context, clock/precision semantics and qualifications, but were expensive. |
| Order/cost | First admitted time bundle cost **10,443 bytes**; the second expanded the request to **16,149 bytes**. No alternative primary bundle evaluation or replacement occurred. |
| Final admission | Additional temporal bundles measured **20,300** and **19,875 bytes** and were rejected. Later identifying fields could not fit the already packed context. A referrer did fit, producing 16,330 bytes. |
| Support cap | Only five supports were selected. The 12-support cap did not cause this baseline failure. |
| Byte cap | All 25 recorded omissions were byte-budget omissions, not authorization failures. |

References: `investigation_ai/d2_cross.py::History.preview` at the starting commit;
`packets._rehydrate`, `_bundle`, `_assemble`; `d2._closure`, `_encode`;
`synthesis._Reducer`; `relationships._build`, `_time`, `_path`.

The two paths are **not identical full strings**: the Browser value includes a
drive prefix while the MFT value is volume-relative. No new S2 exact-path relation
was fabricated. Their original values permit qualified analyst comparison; neither
a common volume/object nor a causal chain is established.

## 2. Pre-implementation gate

Before editing production, an ignored diagnostic prototype combined exact restored
identifying fields with available recorded time context, preserving original
values and qualifications. Complete bodies measured:

| Prototype | Bytes |
|---|---:|
| Historical target/path + two recorded timestamps | 6,902 |
| Synthetic download/filesystem pair + time context | 5,653 |
| Synthetic Registry/process identifying pair | 4,561 |

The historical copied files were hashed before/after. The gate demonstrated room
for useful identifying bundles without increasing the limit. These prototype sizes
are not the final implementation sizes; final coverage and sufficiency metadata
are included in the measurements below.

## 3. Implemented selection algorithm

No new production module or evidence authority was introduced. The reusable backend
remains `d2_cross.History.preview`, `prepare`, and `preview`; CLI parsing remains an
adapter in `d2_reasoning.main`.

1. Validate history and restore S1 originals through the existing B1 resolver.
2. Assign conservative **field roles** using known pointers/descriptor labels,
   original timestamp metadata and registered identifier semantics. Paths, names,
   references, URLs, declared hashes and identifiers are distinct from time/context.
   EventData explicitly named SHA256/SHA1/MD5 can supply recorded hash fields; an
   arbitrary command line containing a path is not reclassified as a path.
3. Map only a small inspectable set of comparative question patterns to input roles:
   pathname, recorded identity context, hash or URL comparison. Identity-context
   patterns require complementary name/identifier roles (or a reference plus
   name/identifier/path for a Registry question), not two arbitrary references. Explicit temporal
   language also requests recorded time context. Otherwise sufficiency is unknown.
4. Build identifying pairs across distinct EIDs, not across matching values alone.
   A comparison pair retains registered non-temporal relationships over its endpoints,
   contradiction closure, interpretation premises where applicable and all qualifications.
   One available original timestamp per endpoint is considered as contextual support.
5. Shortlist at most **24** pair candidates by requested role fit, exact recorded
   value equality, bounded lexical overlap and stable IDs. Evaluate contextual and
   core variants using exact complete SDK body cost. Choose by input-role coverage,
   role fit, then a deterministic utility/byte ratio. Utility is
   `1 + 8*exact_value + 2*min(shared_terms,8) + min(question_overlap,8)`; this is a
   packing heuristic, **not forensic confidence or proof of correspondence**.
6. Add complementary originals with identifier roles ahead of additional timestamps.
   Relevant recognized interpretations and contradictions receive priority. A time
   relationship is considered only for explicit temporal questions, with at most
   one per packet. Selected time relationships retain their complete semantics and
   assumptions; none are shortened to reduce size.
7. Re-measure the final body including final omissions and sufficiency metadata.
   Remove only whole bundles if necessary. Never shorten original evidence.

This is bounded candidate-group evaluation, not an optimal solver. It avoids making
the first large lexical bundle irrevocable. Pair ranking uses case-folded tokens
only as a selection aid; original strings are unchanged. No case-specific filenames,
event IDs, attack types or artifact-specific selection branches were added.

The five-second planning meter, 512 support resolutions, 192-unit examination bound,
12-support/four-interpretation ceilings remain. Pair calculations derive from the
existing bounded S1 state; only 24 pairs are materialized. Pair candidates/evaluated/
unexamined counts are separate from unit examined/omitted counts. Final historical
selection evaluated all 15 available pairs.

### Complete-bundle cost and reporting

`selection.bundles` records considered unit groups, exact serialized candidate-body
bytes where count-admissible, rationale and admission result. Costs are the **whole
candidate request at that evaluation stage**, not marginal field sizes or necessarily
the final request after subsequent complements/coverage changes. Final `body_bytes`
is always authoritative for admission. Values exceeding support counts have no
admissible typed schema and report a null byte cost rather than an invented estimate.

`selection.field_roles`, `decisions`, `relevance`, `omitted_counts` and pair accounting
make choices inspectable. Unexamined is not irrelevant. Coverage remains bounded to
validated history, not the case. A record with one selected field is only partially
represented; a family count is not completeness.

## 4. Context sufficiency is separate from security and size

New local contract: `cross-context-sufficiency-v1`.

| Status | What it establishes |
|---|---|
| `comparison_inputs_present` | Identifying fields from two distinct records, plus recorded time context when the recognized question pattern requests it. |
| `comparison_inputs_missing` | Recognized input roles are absent from the selected context. Missing roles distinguish available-but-omitted from unavailable. |
| `question_sufficiency_not_established` | The bounded pattern mapper cannot establish the question's input requirements. This is not arbitrary-language understanding. |

The identifying role is `identifying_fields_from_two_distinct_records`. Distinct
EIDs do not imply independent acquisitions, independent witnesses, common objects,
causality or cross-host equivalence. Recorded time context can be uncertain; it does
not establish synchronized clocks or a valid temporal ordering.

`fits` remains byte admission. Public preview separately exposes
`context_sufficiency` and `investigative_admission`. For a recognized comparison with
missing inputs, public `prepare` rejects with `D2_CROSS_CONTEXT_INSUFFICIENT` before
execution; the preview remains available. This is an investigative admission
limitation, not a new security-validation rule. Unmapped questions remain visibly
unestablished and do not silently inherit a supported assessment.

Cross-artifact eligibility still requires at least two families. An explicit
single-family question is not padded with unrelated families. A two-record hash
comparison within EVTX can have its required inputs while still failing the
cross-artifact family gate. No new retrieval is performed to repair either gap.

## 5. Measured historical improvement

| Metric | 6.129 | Final 6.130 |
|---|---:|---:|
| Complete request bytes | 16,330 | **16,268** |
| Required identifying fields selected | **0/2** | **2/2** |
| Original support fields | 5 | 12 |
| Registered time relationships | 2 | 1 |
| Sufficiency assessment | None | `comparison_inputs_present` |
| Candidate omissions | 25 byte-budget | 14 support-count; 5 temporal comparisons not prioritized |
| Provider requests | 0 | 0 |

The success criterion is **2/2 required identifying fields**, not the larger field
or family count. The final packet contains:

- Browser `/target_path`, `/timestamps/1/utc` (DownloadStart), `/referrer`, and both
  original URL-chain fields.
- The corresponding MFT `/objects/1` and its `/timestamps/0/utc` context, plus two
  other original MFT path observations.
- Prefetch `/executable`.
- EVTX `/event_id` and `/original_event_data/0/value`.

All six historical records have some representation across four families. **This
is not a complete EVTX or ASR disclosure**: the interpretation and some command/time
context remain omitted. The request must not be used to infer execution/prevention
from the mere event identifier. Original omissions and qualifications remain visible.
The only included S2 relationship is a qualified recorded-time comparison; no full
pathname-equality or common-object finding is invented for the drive-relative pair.

Actual OpenAI SDK serialization through mock HTTP exactly matched the final
**16,268-byte** sealed body. A synthetic abstention exercised parent validation;
it is a fixture, not a real model's assessment. Two independent complete
reconstructions produced identical request identities.

## 6. Independent synthetic evaluation

Expectations were declared before running selection in `tests/test_d2_selection.py`.
The 6.129 baseline was loaded from an untouched ignored source copy for comparative
measurement. Final body sizes below include current policy/schema/coverage metadata.

| Scenario / predeclared expectation | Baseline bytes | Final bytes | Result |
|---|---:|---:|---|
| Browser/MFT: retain both paths | 9,307 | 7,325 | Identifying inputs present; qualified comparison preserved |
| Registry/process: retain Run reference and process name | 4,850 | 5,389 | Inputs present; not proof of Run-triggered execution |
| EVTX/Prefetch: retain executable/name context | 4,804 | 5,343 | Inputs present; referenced/executed semantics remain distinct |
| Same recorded SHA256, distinct EVTX records | Not cross-admissible | Not cross-admissible | Both fields selected; one family remains one family |
| Same filename, different full paths | 4,670 | 5,201 | Original differing paths retained; no exact-path relation |
| Timestamp-only, identifiers missing | 7,200 | 7,884 | Fits, but comparison inputs missing; execution blocked |
| Unmapped intent question | 9,307 | 7,260 | Sufficiency not established |
| Different paths, no registered relation | 4,658 | 5,189 | Fields enable comparison; no relationship manufactured |

Additional fixtures verify different hosts/ambiguous authorized source context,
large versus small complete bundles, high-lexical low-value text, low-lexical typed
comparisons, loss of authorization, unavailable original projections, strict budget
omission, one-family questions, uncertain times, original-data injection, complete
interpretation premises, contradiction closure and multiple unverified explanations.
A deliberately stricter test-only 2,000-byte planning ceiling verifies the distinction
between available-but-omitted roles and unavailable fields; it does not alter or
increase the production policy. Actual production-ceiling admission is tested separately.

Known restrictions are preserved rather than normalized away: removed authorization
raises the existing scope error; unavailable original projection cannot reappear;
ambiguous source metadata is only allowed when all recorded source IDs are in scope.
Existing compact histories may lack useful fields entirely; selection cannot create
new disclosures from unhashed summaries or undisclosed database content.

## 7. Security, provenance and execution boundaries

Reused without replacement: `d2.open_history`, B1 restoration, S1/S2 constructors,
`d2._closure`, `_encode`, wire restoration, packet-specific enums, request sealing,
Windows supervisor, IPC, ModelBackend, guarded OpenAI transport and parent validation.
No second database, ledger, provider executor or factual authority was introduced.

The new question retains its own assessment context and original S3 is unchanged.
The selected packet, question, policy, schema and full body remain sealed. Original
EIDs, pointers/values, source identity, view, projection digest, lineage, truncation,
interpretations, relation endpoints/assumptions and mandatory qualifications remain
subject to the same validation. Model prose cannot authorize retrieval or become a
forensic finding through valid citations alone.

Limits remain: single-packet 5,600 bytes; cross-artifact 16,384; one round/request;
1,024 output tokens; 60-second supervised envelope; 32-KiB terminal/128-KiB receive;
no retry, fallback, continuation or additional lookup. Canonical `d2q1` is unchanged.
The cross prompt's selection disclaimer now describes structural roles/sufficiency
rather than claiming all selection is lexical; no response-schema change was made.

## 8. Validation results and accounting

- Broad focused suite: **365 passed**, one warning, **196.26 s**. Includes the initial
  65 selector/cross cases and 300 existing single-packet/execution/transport/typed-
  reference/preview/B1/S2 regressions.
- Final selector/cross suite after final role-label and accounting changes:
  **68 passed**, one warning, **35.21 s**. Includes three additional admission/omission/role-pair
  tests. All actual SDK and Windows mock tests ran (no skips in this run).
- **368 distinct passing cases** overall; these overlapping runs must not be added.
- A preliminary development-environment run reported 59 passed/6 SDK-dependency
  skips; those skips were subsequently covered by the SDK-equipped final run.
- `git diff --check` passed. No full regression suite.

The SDK-equipped interpreter was
`C:\tmp\locard260927\locard\.venv\Scripts\python.exe`, importing this development
checkout. Because 6.129 SDK test hosts lingered after pytest completion, an ignored
main-guarded harness flushed the returned pytest result and explicitly exited after
`pytest.main()` returned 0. This is test-host shutdown handling, not a production
cleanup change or proof of natural SDK interpreter shutdown. Windows worker tests
still exercised real spawn, IPC, parent revalidation, timeout/cancellation and
confirmed controlled cleanup. No background user processes were terminated in this task.
The warning is the existing Pydantic ReadOnly warning from the mock SDK path.

Existing cross tests were adapted only for intentional selection behavior:
non-temporal questions no longer expect every time edge; explicit temporal tests
still assert qualifications and forbid ordering an uncertain timestamp; changed
questions assert distinct assessment/binding even when the same small record set
fits both. No authorization, evidence/provenance, reference or negative security
assertion was removed.

### Historical integrity

`d2.open_history` performs integrity and accepted-state replay before use. The copied
files had identical SHA-256 hashes before and after diagnosis/final measurements:

- manifest: `23a6e2c496b2e34aa20810e08c152e37b8b51afacde0a3dba1a074e16e7e350f`
- events: `a943a1e2bf39d8f2aafca6f374804f1cefb20b080bc2cdf0a46d2c050625ac28`

This proves these copies were unchanged during this task, not historical integrity
of uninspected case data. No live forensic DB or original sidecar was opened.

## 9. Manual provider-free acceptance

After your commit/pull/install workflow, in the test checkout:

```powershell
.\.venv\Scripts\python.exe -m pip install -e .
.\.venv\Scripts\locard.exe --version
# Expect 6.130.

$root = 'C:\tmp\locard-diagnostics\6.118-live'
$run = '6ad0c85499564406aa4d949f3b0e72e5'
$question = 'What evidence connects the recorded download and subsequent filesystem observations? Which links remain hypotheses and what additional examination would discriminate?'
.\.venv\Scripts\python.exe -m forensic_assistant.investigation_ai.d2_reasoning $root $run --cross-artifact --question $question
.\.venv\Scripts\python.exe -m forensic_assistant.investigation_ai.d2_reasoning $root $run --cross-artifact --question $question --json
```

Neither command requests a provider response. Default output is concise: field
pointers/families/roles, byte admission, sufficiency and omissions. `--json` exposes
complete original provenance plus `selection.bundles`, `field_roles`, candidate
costs, pair counts and `context_sufficiency`. It does not disclose new source content
solely for display. Repeat with identical model/config/history/question to compare
body, packet and schema digests. The measured model is `openai / gpt-6.1-sol`.

Confirm both required identifying fields, distinct original record identities,
clock/source/identity qualifications and the explicit limitations of the volume-
relative pathname. Do not accept merely because multiple families are listed.

After **separate live authorization**, the same command with `--execute` asks for
approval of one exact request. No live request was made during implementation.
Evaluate actual usefulness separately: identifying comparison, non-causal chronology,
plausible alternatives and a specific unexecuted discriminating examination. A
synthetic response or input-sufficiency label does not demonstrate those qualities.

## 10. Remaining limitations and architectural debt

- The English question mapper is deliberately small. Unsupported questions report
  unknown sufficiency; structural input presence is not semantic entailment or
  proof that the whole question can be answered.
- Token overlap, exact recorded-value equality and utility/byte ratios guide packing
  only. The 24-pair shortlist is not exhaustive optimization. Large candidate sets
  report unexamined pairs; omitted is not irrelevant.
- Contextual timestamp choice is bounded and deterministic, not a universal forensic
  preference between SI/FN or start/end. Original semantics remain visible.
- Some necessary context can still be missing due to prior disclosure limits,
  original projection availability, support caps or request size. In particular,
  partial EVTX representation is not a complete security-event assessment.
- Role mappings and question patterns are inspectable backend code but need ongoing
  generic regression coverage. They should not grow into a speculative semantic
  classifier or artifact-specific incident rules.
- Existing private B1/D2 helper coupling remains; no broad refactor was attempted.
  Repeated restoration and preview checks remain at security boundaries.
- SDK-host natural interpreter shutdown remains outside this selection change.
- No persistence, report, web UI, new retrieval or zero-analysis repair was added.

Changed files: `d2_cross.py`, the cross-preview adapter in `d2_reasoning.py`,
`pyproject.toml`, `tests/test_d2_cross.py`, new `tests/test_d2_selection.py`, this
report and its exact `.gitignore` exception. Existing execution/provider/validation
modules and canonical response contracts were not changed.

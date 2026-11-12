# Locard 6.129 — Bounded cross-artifact investigation

## Implementation status — 2026-11-12

Implemented in the working tree on `main`, based on
`792175bf5828142089afb3d01a6285a27f64a86e`. Application version in
`pyproject.toml` is **6.129**. No commit or push. The earlier feasibility report
is preserved below as a dated development-stage record; its stop decision and
6.128 version describe that earlier stage, not this implementation.

**Final three-family gate passed:** the complete SDK request is **13,074 UTF-8
bytes**, versus the separately authorized **16,384-byte** ceiling. It contains
Browser, MFT and EVTX support: eight original fields, three registered S2
relationships and their qualifications. Actual OpenAI SDK serialization over
mock HTTP matches the sealed bytes exactly. This is a mechanical implementation
result, not evidence that a real model produces useful investigative reasoning.

The single-packet 5,600-byte policy is unchanged. No provider calls, live-case
access, original/copy transcript changes, permissions changes, automatic queries,
new persistence, report generation or continuation were performed/implemented.

## Application architecture and workflow

| Component | Responsibility |
|---|---|
| New `investigation_ai/d2_cross.py::History` | Adapts authenticated D2 history to an explicitly supplied question; deterministic combined selection, B1 restoration/closure, per-family coverage and final-body admission. Not an alternative evidence authority. |
| `d2_cross.prepare`, `preview` | Reusable backend entry points. Return sealed existing `d2_execution.Prepared` or a provider-free insufficient-coverage result. |
| Existing `d2.open_history` | Hash-chain, recorded-view and accepted-delta reconstruction, including original exposure/interpretation validation; never opens the case DB. |
| Existing `packets._validate_context`, `_rehydrate`, `_bundle`, `d2._closure` | Original pointer/value/source/view/lineage restoration and complete interpretation, relationship and contradiction dependencies. |
| Existing `d2._encode`, `d2_wire`, `d2_schema` | Fresh context-local O/I/R/E/C/P/D namespaces, reversible wire view, packet-specific response enums. |
| Extended `d2_execution.Prepared`, `_Permit`, `_child`, `execute` | Same one-attempt authorization/supervision/IPC architecture. Explicit cross profile; child independently reconstructs history/question/packet; parent independently validates response against its frozen authority. |
| Existing `ModelBackend.complete_d2`, OpenAI adapter, extended `ai/d2_transport.guarded_client` | Exact-schema selection, zero-retry adapter, final SDK-body comparison and separate policy ceiling at the network boundary. |
| Extended `d2_reasoning.main`, `d2_presentation` | Thin CLI adapter; explicit question/policy/coverage authorization and separate unverified reasoning presentation. |

Trace: saved validated history + analyst question -> bounded deterministic
selection -> combined original-support packet -> exact model/config/schema/body
seal -> explicit approval -> existing Windows supervised worker -> one mocked or
analyst-authorized provider attempt -> independent parent response validation ->
ephemeral structured result. No model output can initiate retrieval.

### Selection and coverage

The question is limited to 1,600 UTF-8 bytes. Relevance uses deterministic lexical
matching against original support fields/semantics, not historical AI summaries.
Candidates sort by descending match score, then contradiction/relationship/
interpretation/observation role, then stable original unit ID. Context candidates
remain available when there is no lexical match. This is deliberately not a claim
of semantic relevance or a guarantee of optimal packing.

The same B1 meter bounds each planning pass to five seconds and 512 resolutions;
selection examines at most 192 units and retains at most 12 support entries/four
interpretations. No artifact-specific rules, event identifiers, filenames or
incident logic exist in the new selector. It requires at least two represented
families before authorization. It does not force a family quota or imply that two
families exhaust the question.

Each addition is a complete restored bundle. Unsupported bundles are omitted;
count and exact final-provider-byte failures are recorded explicitly. A final
coverage-size adjustment removes a whole bundle, never shortens its original
values or qualifications. Candidates have explicit selected, unavailable,
unexamined or budget-omitted decisions and lexical/contextual/contradictory
classifications. The packet includes available/represented record counts by
artifact family within the validated history, not the entire case. Unit counts
are not case record counts. Missing evidence requires a separately authorized
retrieval plan; this release does not generate or execute such a plan.

### Question, provenance and alias authority

Historical manifest/question/grant/S3 remain untouched. A private question
projection has its own question ID and freshly computed registered S3 assessment;
it does not imply that arbitrary natural-language objectives have typed bindings.
The original S3 is still returned separately. The original recorded grant restricts
which fields may be restored, but never authorizes fresh cloud execution.

Aliases are regenerated over the combined original support, not concatenated
from old packets. Identical values in different records retain distinct IDs and
source contexts. Full original IDs, lineage and read-view identity remain in the
frozen local mapping; the reversible provider representation uses aliases for
opaque identities. Exact field values, source context, temporal meaning,
truncation and qualifications remain provider-visible. The question, coverage,
packet mapping, schema, model, complete body, config and request policy are sealed.
Changing them invalidates approval or fails independent child reconstruction.

Registered S2 relationships remain application context with original endpoints,
semantics and assumptions. The model cannot emit a new registered relationship
or cite R as an O/I alias. Contradiction closure requires both restorable endpoints;
where the existing original store cannot restore incompatible historic values,
the whole bundle is unavailable, rather than choosing a winner.

## Request and response contracts

| Control | Single-packet D2 | Cross-artifact |
|---|---|---|
| Request policy | `d2-single-packet-request-v1` | `d2-cross-artifact-request-v1` |
| Wire marker | Existing `d2q1` / legacy `d2c1` | `d2x1` |
| Complete SDK body | 5,600 bytes | 16,384 bytes |
| Approval | Existing D2 grant | Separate cross-policy authorization contract |
| Attempts / rounds | 1 / 1 | 1 / 1 |
| Output / terminal / receive | 1,024 tokens / 32 KiB / 128 KiB | Unchanged |
| Envelope | 55 seconds work + 5 cleanup | Unchanged |
| Retry / fallback / refill | None | None |

No new response shape is necessary: cross requests explicitly reuse canonical
`d2-quality-proposal-v1` (`v: d2q1`) and the existing typed-reference/duplicate
normalization policies. The request marker and response marker intentionally differ.
No field is silently reinterpreted and no relationship-reference field is added.

Complete compact response fields:

| Field | Meaning and canonical bound |
|---|---|
| `v` | Exactly `d2q1` |
| `o` | `new_inference`, `competing_explanations`, `no_material_inference`, or `insufficient_packet_support` |
| `a` | At most two accounts; 1–2 for inference, zero for abstention |
| `r` | Abstention reason, at most 240 UTF-8 bytes; nonempty for abstention, empty for inference |
| Account `s` | Unverified explanation, 400 bytes |
| Account `e`, `c` | Current supporting/contrary O aliases, at most six each; support nonempty |
| Account `i` | Current I aliases, at most four; requires original premises in e/c |
| Account `a`, `u` | Alternative (240 bytes), assumptions (320 bytes) |
| Account `d`, `n` | Discriminator and proposed unexecuted examination, 400 bytes each |

The optional account texts retain their existing empty-string semantics. Prompt
instructions request family/field, competing outcomes and missing coverage for
d/n; structural validation cannot certify their substantive specificity. A
competing-explanations result needs two accounts or an explicit alternative.
Unknown fields/status/tools, wrong namespaces, missing premises, malformed JSON,
UTF-8 excesses and unsupported references are rejected. Exact duplicate aliases
alone use the existing bounded normalization before strict canonical validation.

Established context comes from original fields and deterministic rules, not AI
prose. Every accepted account remains `mechanically_accepted_unverified`. Correct
citations do **not** validate causality, successful execution, attribution,
prevention or prose entailment. A synthetic bad causal sentence demonstrates this
boundary: it can be mechanically valid but cannot become an established finding.
The UI labels it unverified; live usefulness review must reject such reasoning.
Analyst-approved findings are not created by this release.

### Admission, failure and supervision

`Prepared.preview()` reports policy/model/question/source/view, selected fields,
relationships, per-family coverage, omissions, exact complete bytes and admission.
Approval binds the exact request and allocation; a single-packet grant cannot be
substituted. Parent expiration checks precede spawn. Child restoration and provider
work remain within parent supervision. `guarded_client` checks actual outgoing SDK
bytes against the frozen body immediately before its sole transport entry.

Provider refusal/truncation, malformed or unsupported references, timeout and
cleanup outcomes reuse existing bounded sanitized diagnostics and usage reporting.
No raw rejected-response persistence was added. Cancellation before spawn performs
zero attempts. Worker acceptance alone cannot supply authority: a forged accepted
IPC result with an invalid alias is independently rejected by the parent.

## Measured implementation validation

SDK interpreter: `C:\tmp\locard260927\locard\.venv\Scripts\python.exe`, running
source from the development checkout. No dependency installation. Synthetic
fixtures and mock HTTP only for execution. Tests include real Windows spawn,
Job containment and pipe exchange; the paid provider boundary is mocked.

| Run | Recorded result |
|---|---|
| D2 compatibility group plus initial 31 cross tests | **386 passed**, 2 warnings, **334.59 s** |
| Final cross-artifact suite after coverage additions | **44 passed**, 1 warning, **36.80 s** |
| Additional parent-authority/grant/cancellation checks | **3 passed**, **4.51 s**, normal exit |
| D2 preview + B1 packets + S2 relationships | **99 passed**, **21.97 s**, normal exit |

This covers **501 distinct passing test cases**: 355 existing D2 cases, 99
preview/closure cases and 47 new cross cases. Counts above overlap; they must not
be added as independent cases. No full suite was run.

**Test-host limitation:** the three SDK-enabled pytest processes (including an
intermediate failed-fixture run) lingered after printing completed pytest summaries.
Only those command-line-identified test processes were stopped. Their clean
interpreter exit is not claimed. The underlying shutdown cause was not diagnosed
or patched. The completed Windows worker tests separately reported confirmed
cleanup, including timeout and forged-result rejection. Existing SDK tests emitted
Pydantic warnings concerning ReadOnly and synthetic list-content serialization.

Initial fixture failures were corrected: an alleged oversized sample still fit;
a larger sample initially exceeded the existing six-batch fixture budget; a
malformed transport response requires downstream canonical validation rather than
assuming raw transport rejects JSON. A local file-encoding error was also corrected
before the passing runs. No evidentiary assertions were weakened.

Generic scenarios cover Browser/MFT, Browser/MFT/EVTX, Registry/process,
EVTX/Prefetch, same paths/distinct IDs, similar filenames, different hosts,
uncertain times, contradictory dependency closure, missing families, large values,
budget omissions, interpretations, injection-as-data, abstention, competing
accounts, examinations, malformed/refused/truncated output, alias tampering,
source changes, request/grant changes, one attempt, timeout, cancellation, usage,
parent authority and unchanged S3. Existing single-packet tests retain their exact
byte expectations. See `tests/test_d2_cross.py` and the test files in commands below.

### Final SDK measurement and historical compatibility

The predeclared three-family test in `test_d2_cross.py::rows` uses unrelated
synthetic download/metadata/process observations. Final request: **13,074 bytes**,
eight support entries, three records/families, three S2 relationships. Original
values, qualifications and contextual ordering semantics round-trip exactly.
No repeated-value dictionary prototype was adopted. The earlier 12,115-byte
feasibility figure below is not the implementation's admission result.

Copied historical run:
`C:\tmp\locard-diagnostics\6.118-live\6ad0c85499564406aa4d949f3b0e72e5`.
Two independent provider-free reconstructions produced identical request identities
and bytes. Final context: **16,214 bytes**, nine support entries, Browser and MFT,
two registered relationships, no interpretation. It represented one Browser and
two MFT records; the available EVTX, Prefetch and third MFT record were not
represented. Omissions: 20 complete-request-byte and one support-count candidate
omissions. **This historical preview is not a complete attack-sequence assessment**;
its exclusions are visible, and it is not the three-family acceptance fixture.

SHA-256 before/after the final reconstruction matched:

- `manifest.json`: `23a6e2c496b2e34aa20810e08c152e37b8b51afacde0a3dba1a074e16e7e350f`
- `events.jsonl`: `a943a1e2bf39d8f2aafca6f374804f1cefb20b080bc2cdf0a46d2c050625ac28`

These prove those copies were unchanged during this check, not historical
integrity of unrelated case data. Original/live evidence was not accessed.

## Acceptance and commands

Implementation is ready for manual review; genuine investigative usefulness
remains pending a separately authorized live request. Before inspecting such a
response, judge whether it distinguishes recorded download, MFT metadata and EVTX
activity, recognizes qualified correspondences without common-identity/causality
claims, considers materially different explanations, proposes an available-or-
missing discriminating examination, and preserves clock/coverage uncertainty.
A mock response cannot establish these capabilities in a real model.

After the analyst's commit/pull/install workflow, from the chosen test checkout:

```powershell
.\.venv\Scripts\python.exe -m pip install -e .
.\.venv\Scripts\locard.exe --version
# Expect Locard 6.129; source version authority remains pyproject.toml.

$root = 'C:\tmp\locard-diagnostics\6.118-live'
$run = '6ad0c85499564406aa4d949f3b0e72e5'
$question = 'What connects the recorded download, subsequent filesystem observations and later security activity? Which links remain hypotheses and what examination would discriminate?'
.\.venv\Scripts\python.exe -m forensic_assistant.investigation_ai.d2_reasoning $root $run --cross-artifact --question $question --json
```

That command makes **no provider request**. It uses the configured provider/model;
OpenAI must be selected. Do not alter configuration simply to reproduce a size.
Review `fits`, `body_bytes`, `request_policy`, `issue.artifact_coverage`, `selection`,
`question_assessment` and `original_s3`. A missing-family result is nonadmissible.
Repeated identical question/history/model/config should produce identical digests.

Only after separate live authorization, the same entry point with `--execute`
prompts to approve the exact request:

```powershell
.\.venv\Scripts\python.exe -m forensic_assistant.investigation_ai.d2_reasoning $root $run --cross-artifact --question $question --execute
```

There is no `--yes`, automatic continuation or implicit provider call. Preview
approval is not saved for later execution. JSON output contains complete ephemeral
provenance; default output separates recorded facts, relationships, hypotheses,
alternatives, gaps and unexecuted examinations.

Focused reproduction (no paid requests):

```powershell
.\.venv\Scripts\python.exe -B -m pytest -q -p no:cacheprovider tests/test_d2_cross.py
.\.venv\Scripts\python.exe -B -m pytest -q -p no:cacheprovider tests/test_d2_execution.py tests/test_d2_quality.py tests/test_d2_transport.py tests/test_d2_quality_transport.py tests/test_d2_typed_references.py tests/test_d2_normalization.py tests/test_d2_result.py tests/test_d2_diagnostics.py
.\.venv\Scripts\python.exe -B -m pytest -q -p no:cacheprovider tests/test_d2_preview.py tests/test_synthesis_packets.py tests/test_synthesis_relationships.py
git diff --check
```

## Remaining limitations and architectural debt

- Selection is a bounded lexical heuristic with atomic closure, not optimal
  packing or calibrated semantic relevance. Relevant families may be omitted;
  the recorded example demonstrates this. Do not infer case-wide absence.
- Only previously accepted, restorable fields in saved investigation history
  participate. No live refresh, case-wide discovery, or model-directed query.
- Original D2/B1 internal helper reuse avoids duplicate authority but increases
  coupling to private APIs; a future architecture review may formalize these
  interfaces. No speculative abstraction layer was introduced.
- Preparation repeats deterministic planning/source checks at security boundaries.
  Selection work is metered; pre-approval history reconstruction can be costly.
  Post-approval reconstruction remains inside the existing supervised envelope.
- One 1,024-token response cannot promise complete explanations of every selected
  field. Canonical size and grounding reject invalid responses without retry.
- Response text is unverified, not semantically proved; next-examination quality
  and actual model usefulness require live review. S3 is not upgraded by prose.
- D2 IPC limits were preserved. No raw failures, durable new investigation state,
  reports or analyst-approval-of-findings store was added.
- Test-process shutdown after SDK tests remains an observed environment/tooling
  limitation, distinct from the controlled worker lifecycle assertions.
- The previously identified zero-analysis Cross-view explanation issue remains
  out of scope and untouched.

Changed deliverables: `pyproject.toml`, `d2_cross.py`, `d2_execution.py`,
`d2_wire.py`, `ai/d2_transport.py`, `d2_reasoning.py`, `d2_presentation.py`,
`tests/test_d2_cross.py`, this report and its exact `.gitignore` exception.
`git diff --check` passed. No commit/push and no full-suite run.

---

# Preserved earlier feasibility stage (before expanded-budget authorization)

The following section records the earlier 5,600-byte gate. Its version/status and
"no production changes" statements apply to that earlier stage only.

# Locard 6.129 — Cross-artifact investigation feasibility report

**Status: partial feasibility; implementation stopped at the budget gate.**
Application version remains **6.128**. No cross-artifact execution feature or
6.129 release is claimed by this document.

Inspected 2026-11-12, branch `main`, starting revision
`792175bf5828142089afb3d01a6285a27f64a86e` (`Full AI investigation 16`). The
tracked tree was clean. The strategy read was
`C:\Users\jl-du\Documents\LOCARD_DEVELOPMENT_STRATEGY_2026-11-12.md`.
Its acceptance statements are analyst-reported evidence; this task did not repeat
the accepted live 6.128 request.

## 1. Decision and its limits

**Some useful narrow cross-artifact questions fit 5,600 bytes. It would be
incorrect to report that all cross-artifact reasoning is impossible.** A synthetic
Registry/process question fits at 4,313 bytes. A two-record path comparison fits
at 4,881 bytes, including its registered relationship and qualifications.

However, the requested sequence-oriented workflow does not fit the measured
representative contexts while retaining original times, relationships and
qualifications. Even a two-family Browser/MFT sequence requires 8,525 bytes.
A three-family sequence requires 12,115 bytes. A selected, rather than full,
historical Browser/MFT/EVTX sequence requires 9,543 bytes. A reversible shared-value
dictionary prototype does not bring any of these three below 5,600 bytes.

The gate is therefore **not established for the requested milestone as a whole**.
This is not a mathematical impossibility result for every conceivable encoding.
It is a measured limit of the existing reusable representations and the evaluated
lossless compaction. Treating only a small Run-entry/process pair or a path-only
comparison as completion of the broader sequence milestone would reduce the
acceptance scope. Such a narrower implementation remains an option for explicit
approval; it has not been silently substituted here.

No production changes or version increment were made. Recommend approving a
separate bounded cross-artifact request policy, initially **16,384 complete UTF-8
request bytes**, while leaving single-packet D2 at 5,600. This accommodates the
measured three-family context without relying on the experimental dictionary
codec and leaves 4,269 bytes for an explicit investigative envelope/schema and
additional bounded coverage detail. It does **not** admit the full historical
investigation. Final combined requests must be measured again before that policy
is implemented. The proposed size is not authorized or enabled by this report.

## 2. Architectural reconnaissance

Paths below are repository-relative. Implementation evidence is distinguished
from proposed integration. No new retrieval engine or execution framework is
needed.

| Responsibility | Existing implementation inspected | Reuse / limitation |
|---|---|---|
| Leads and deterministic routes | `forensic_assistant/briefing.py::extract`, `extract_inputs`, `query_for` | Exact technical leads map to registered artifact queries. Narrative assertions are not evidence or query authority. |
| Cross-family discovery | `briefing_discovery.py::available`, `discover_all`, `matches` | Inventory probes; explicit source/time/lead scope; per-family match, unavailable, unsupported, truncated, failed and unsearched states. Six queries, ten records/query, 90 seconds, 192 KiB; continuation is bounded and scope-bound. Not run against a live case here. |
| Larger deterministic assessment | `assessment.py::plan`, `inventory`, `timeline` and assessment execution | Accepted briefing indicators, source inventory and bounded query scheduling. Its own 300-second/120-query/500-record/2-MiB limits are **not** inherited permission for a new AI workflow. |
| Assessment handoff | `assessment_handoff.py::select` and current-view hydration services | Historical matches are leads; live investigations rehydrate against an authorized pinned view. Do not import saved assessment text as evidence. |
| Actual queries | `retrieval/queries.py::Queries.search`, `retrieval/object_discovery.py`, `retrieval/evtx_content.py::search` | Reuse exact/predicate-specific routes and coverage/cursors. Do not expand process/path filters implicitly or let the model submit SQL. |
| Read-only supervision | `investigation_ai/runner.py::ForensicWorker`, existing controller/read-view paths | Appropriate for separately authorized deterministic discovery; do not add case access to D2 implicitly. |
| Original projections/exposure | `investigation_ai/state.py::State`, `projection.py::same`, `is_record_projection`, `disclosure.py::validate`, `descriptor`, `provenance` | Original evidence IDs, exact field pointers/values, exposure eligibility and truncation remain authoritative. |
| S1 facts | `investigation_ai/synthesis.py::_Reducer`, `reconstruct` | Deterministic recorded-view clauses, original support and interpretation premises. Serialized clauses alone do not confer authority. |
| S2 comparisons | `investigation_ai/relationships.py::_build`, `_compare` | Registered exact-path, recorded-time, same-source identifier and incompatible-field comparisons. Shared path does not prove common file/host identity; recorded time does not prove physical ordering. |
| S3 question assessment | `investigation_ai/question_assessment.py::_assess`, `assess_typed` | Registered deterministic predicates; unsupported objectives remain unresolved/not assessable. A fresh question must not silently inherit the old question's assessment. |
| C1/D1 organization | `investigation_ai/organization.py::_Sources`, `explanation.py::open_history`, `page`, `render` | Derived source-linked organization/explanation. Useful for review, not an alternative evidence store or AI-summary authority. |
| B1 original-support resolver | `investigation_ai/packets.py::_validate_context`, `_rehydrate`, `_bundle`, `_assemble` | Verifies grant, source/view, record projection digest, disclosure lineage, original fields, premises and mandatory qualifications; restores exact source IDs locally. |
| D2 planning | `investigation_ai/d2.py::_History.preview`, `_closure`, `_encode` | Up to two issues/packets; deterministic ranking and conflict closure; at most 12 supports/four interpretations per packet. Does not combine the two previews into one investigative request. |
| Issue review/ranking | `investigation_ai/d2_issues.py::inspect`, `_exact` | Exact technical referents, lexical overlap, typed bindings and stable tie-breaking. Review order does not change selected execution authority. |
| Provider execution | `investigation_ai/d2_execution.py::Prepared`, `authorize`, `execute`, `_child`; `ai/backend.py::ModelBackend.complete_d2` | Reuse exact request sealing, fresh approval, OpenAI-first dispatch, one attempt, deadlines, Windows containment and parent validation. No parallel executor should be built. |
| Wire and validation | `d2_wire.py`, `d2_quality.py`, `d2_schema.py`, `d2_normalization.py`, `d2.py::validate_response` | Typed O/I enums, strict JSON, exact normalization, original-source/interpretation/relationship closure and unverified proposal classification. Current quality responses cannot explicitly cite R relationships. |
| Result/diagnostics | `d2_result.py`, `d2_diagnostics.py`, `d2_presentation.py` | Bounded IPC, usage, sanitized failures and separation of established fields from AI hypotheses. No live forensic proof follows from valid JSON. |
| Replay | `d2.py::open_history`, `autonomous.py::reconstruct`, `transcript.py::load` | Verifies recorded chains, accepted analysis/disclosure state and source anchors without a provider or live database. |

### Answers to the mandatory ownership questions

* **Multiple issues/packets:** yes, preview accepts at most two issue IDs; execution
  preparation still requires exactly one packet. Concatenating previews is not
  an authorized combined request.
* **Deterministic cross-family correlation:** yes, S2 compares exact recorded
  values and qualified timestamps. Those rules intentionally do not prove
  execution, causal chains or common file identity.
* **Stable identities:** original EIDs plus exact field pointer, source/view,
  interpretation IDs and registered clause/relationship identities span packets.
  A value or basename alone is not an identity.
* **Packet aliases:** O1/E1/etc. are **not** reusable across packets. Reassemble
  from validated original support, deduplicate only identical source-bound
  observations, then mint a fresh context-local namespace. Retain distinct records
  even when their values match.
* **Selection owner:** a deterministic application service over existing
  discovery/rehydration and ranking, not the LLM or CLI parser. Separate direct,
  contextual, contrary, unexamined and budget-omitted candidates.
* **Provenance owner:** the original evidence/view/exposure stores and B1 resolver;
  no new independent source database, model summary store or alias authority.
* **Disclosure owner:** the application prepares an immutable complete request;
  the analyst approves it; the existing supervisor enforces its exact binding.
* **Future web reuse:** feasible through preparation/coverage/authorization/
  execution/result services. The CLI should only collect input and render results.

## 3. Feasibility method and exact data flow

No application source or test was edited. Ignored scratch code constructed the
candidate contexts using existing synthetic test fixtures and a copied historical
run. It followed this path:

```text
validated synthetic state OR read-only historical reconstruction
  → S1 clauses + registered S2 relationships
  → B1 context validation / original support rehydration
  → atomic bundle and contradictory-endpoint closure
  → existing source/lineage/qualification deduplication
  → fresh D2 context-local aliases and lossless compact view
  → current d2q1 instructions + typed response schema
  → complete OpenAI SDK serialization into in-memory MockTransport
```

Every SDK request body was compared byte-for-byte to the computed HTTPX request.
The model's mocked response was only an empty serialization fixture; it was not
validated or counted as an investigative answer. No paid/provider network call
was made. No candidate was admitted through Locard's production execution path.

The feasibility contexts are application-shaped diagnostic objects, not new
authorized grants. Question/issue metadata and opaque anchors were constructed
locally for sizing; original field values, EIDs, contexts, timestamp semantics,
lineages and qualifications came from the validated inputs. Fixed-width opaque
anchors are not proof of an authorized production binding. A future service
must bind the new question to the real source anchor and preserve the recorded
question's separate S3 assessment before it may dispatch.

Canonical bytes below mean the selected canonical D2 content object, **not** raw
SQLite or artifact file size. Projected bytes mean the compact user-message
content. Full request bytes include system instructions, model, adapted response
schema, output-token parameter and JSON framing/escaping. Further cross-artifact
authorization or response instructions could add overhead; these figures do not
hide that integration cost.

## 4. Representative contexts and measurements

Synthetic fixtures were defined before evaluating any model output:

* **Download/filesystem:** Browser download target, URL and start time; a separate
  MFT original path and SI creation time. Registered exact-path and recorded-time
  comparisons. Question: common downloaded file versus separate copy; what would
  discriminate?
* **Download/filesystem/process:** the above plus a separate EVTX process name,
  command line and event time. Question: sequence and possible linkage without
  assuming common file identity or causality.
* **Registry/process:** a Run-key path and recorded executable value, plus a
  separate process name/command line. Question: persistence launch versus an
  independent/manual/scheduled launch; distinguish using parent/logon/task context.
* **Path-only comparison:** two distinct Browser/MFT records with the same path.
  It supports a qualified string correspondence and a targeted examination,
  but lacks the timestamp/download/security context of the requested sequence.

Browser fixture IDs use the registered download form; MFT paths use original
object fields. Their real S1 artifact qualifications are therefore included.
No rule or production branch contains these synthetic filenames or events.

| Context | Fields¹ | Families | Records | S2 relationships | Interpretations | Qualifications |
|---|---:|---:|---:|---:|---:|---:|
| Download/filesystem | 5 | 2 | 2 | 2 | 0 | 9 |
| Download/filesystem/process | 8 | 3 | 3 | 3 | 0 | 10 |
| Registry/process | 4 | 2 | 2 | 0 | 0 | 3 |
| Path-only | 2 | 2 | 2 | 1 | 0 | 7 |
| Selected historical sequence | 12 | 3 | 3 | 0 | 1 | 9 |
| All historical validated material | 27 | 4 | 6 | 8 | 1 | 13 |

¹ Support entries include registered interpretation premises where applicable;
they are not all independent original observations. They must not be counted as
independent evidence weight.

| Context | Canonical bytes | Projected bytes | Complete request | With dictionary prototype | Response-format bytes |
|---|---:|---:|---:|---:|---:|
| Download/filesystem | 8,874 | 6,076 | **8,525** | **8,156** | 1,034 |
| Download/filesystem/process | 13,438 | 9,260 | **12,115** | **10,244** | 1,064 |
| Registry/process | 4,567 | 2,254 | **4,313** | **4,268** | 1,024 |
| Path-only | 4,868 | 2,826 | **4,881** | **4,836** | 1,004 |
| Selected historical sequence | 11,211 | 6,908 | **9,543** | **9,173** | 1,124 |
| All historical material² | 47,597 | 37,216 | **42,784** | **27,687** | 1,053 |

² The full historical union exceeds the current 12-support alias limit. Its size
uses the smaller static canonical response schema as a **lower-bound sizing
surrogate**, not a permissible typed request. It is not eligible even apart from
the byte limit. No capacity limit was changed to admit it.

The selected historical sequence includes Browser target/start/URL context,
archive MFT path/time and EVTX blocking interpretation, relevant command context
and event time. It omits other records and registered relationships explicitly:
this is already a smaller comparison context, not the full incident narrative.
Even it needs 9,173 bytes after the tested dictionary compaction. It cannot be
presented as complete case coverage or as a proven attack sequence.

### Lossless compaction experiment

The baseline already aliases evidence/clauses/sources and deduplicates exact
qualifications and source/lineage objects. The additional generic prototype
interned repeated JSON values/subtrees into an in-packet dictionary. It escaped
literal objects with reserved reference keys, kept records distinct and verified
exact decode equality before measuring. No original scalar, qualifier or
relationship semantics was shortened; an explanatory dictionary instruction was
included in the full SDK request size.

The three-family saving was 1,871 bytes; selected historical saving was 370
bytes. The full historical union saved 15,097 bytes but still failed both current
support cardinality and byte bounds. This is not a production codec proposal or
proof that a model would reason well over that representation. Further aggressive
encoding might reduce size, but would need an independently validated readable
contract; compression as opaque text would not demonstrate useful model context.

## 5. Selection and provenance implications

The diagnostic deliberately kept all observations needed for each stated small
comparison rather than shrinking a sequence to whichever two fields fit.
Historical subset selection was explicit fixture selection, not a new generic
production ranking algorithm. No model chose evidence.

A future generic selector should reuse exact lead matching and bounded lexical
ranking, attach original context from the relevant source records, and expand
registered relationship/contradiction dependencies atomically. It must report
known/examined candidates separately from selected/represented supports and
unexamined or resource-omitted material. Family diversity is a coverage property,
not a reason to pad a request with irrelevant records.

Combined references must key on original EID, exact field pointer, source/view,
record projection and lineage; include interpretation IDs with complete original
premises, and relationship IDs with original endpoints and assumptions. Rebinding
O1 from one packet to O1 in another is prohibited. Equality of a path, timestamp
or IP does not authorize collapsing records. Exact restored provenance must be
checked by the parent from its own frozen context, not supplied by the worker.

Current S2 relationship semantics can be much larger than their endpoint values:
qualified timestamp comparisons preserve intervals, precision, clock/source
uncertainty and semantics. Dropping these because a short timestamp fits would
be a semantic loss. Current d2q1 responses have O/I references but no R-reference
field; factual registered relationships should remain application-generated.
Model-proposed links remain unverified hypotheses, not registered comparisons.

## 6. Investigative-value evaluation specified in advance

No real or mocked explanatory answer was used to declare usefulness. The expected
evaluation for the three-family synthetic scenario is:

| Criterion | Expected analyst-observable result |
|---|---|
| Grounding | Exact Browser, MFT and EVTX original fields; no inferred source identity |
| Correctness | Recorded download, file metadata and process command are distinguished; SI time is not execution proof |
| Relevance | Address whether these observations support linkage, not just paraphrase an isolated event |
| Alternatives | Common-file/download linkage versus an independent copy or unrelated launch, where supported |
| Discrimination | Propose comparing independently acquired file identity/hash and process ancestry/open-file or equivalent corroboration; state those observations are not supplied |
| Uncertainty | Shared path and recorded order do not establish physical identity, clock synchronization or causality |
| Safety | No unsupported execution/attribution/prevention conclusion, no invented corroboration or executed follow-up |

For Registry/process, the expected useful next examination is parent-process,
logon/startup or scheduled-task context that can discriminate the Run-entry
hypothesis from an independent launch. These observations are not assumed to
exist. That smaller task fits the current wire budget and could be implemented
as a separately approved narrower slice. It does not establish that the requested
download/security sequence can fit.

Valid JSON, successful SDK serialization, valid references and abstention are
not investigative usefulness. Eventual live acceptance must be separately
authorized and evaluated against the above criteria, not against an expected
hardcoded narrative.

## 7. Recommended next authorization

Choose explicitly between:

1. **Preferred for the stated milestone:** a separate 16-KiB cross-artifact
   request policy, with exact context/body authorization and final admission.
   Preserve the existing one attempt, one round, 1,024 output tokens, 60-second
   execution envelope, 32-KiB terminal and 128-KiB receive limits initially;
   verify final materialization/response capacity before implementation. Retain
   bounded selection (initially the existing 12 supports/four interpretations)
   rather than attempting to dump the complete historical investigation.
2. **Smaller scope at 5,600:** expressly accept a Registry/process or similarly
   small two-family slice, with clear over-budget rejection of richer sequence
   questions. Do not market that as full incident-sequence investigation.

Both should reuse the D2 executor and provider abstraction, not clone them.
A new question/context-preparation service can compose existing lead selection,
B1 rehydration and namespace construction, then feed the existing request sealing,
approval and supervisor. Original S3 remains attached to its original question;
new question assessments require explicit labeling and registered semantics.

No larger budget, new schema, source query, tool call or continued provider
execution is authorized by an accepted model proposal. Any new database retrieval
must use existing read-only services under its own explicit scope; copied
historical evidence is not current-case revalidation. The known zero-analysis
cross-view defect remains separate.

## 8. Validation and historical compatibility

* **12 actual-SDK serialization comparisons** completed: six contexts, baseline
  and dictionary variants, using in-memory mock transport only.
* Exact compact-to-canonical round trips and dictionary decode equality passed
  for all six selected contexts. Original values and qualifications were retained.
* `tests/test_d2_preview.py`, `tests/test_synthesis_packets.py` and
  `tests/test_synthesis_relationships.py`: **99 passed in 21.84 seconds**.
* The historical copied manifest/event pair was hashed before/after each
  measurement pass and remained unchanged. `d2.open_history` verified its
  existing transcript/reconstruction chain before use.
* No new Windows execution workflow was implemented or tested. The 99 baseline
  tests and sizing mocks are not a substitute for the requested future full
  SDK-to-supervisor-to-parent acceptance matrix.
* No full regression suite was run. The broader required scenarios (new
  cross-context execution, refusal/timeout/cleanup, changed-question authorization
  and an actual investigative response) remain unimplemented and unvalidated.

Copied historical source:
`C:\tmp\locard-diagnostics\6.118-live\6ad0c85499564406aa4d949f3b0e72e5`.
No live case database or original transcript was opened or modified. Hash checks
establish unchanged copies during this diagnostic, not retroactive historical
integrity of unrelated evidence.

## 9. Provider-free reproduction and manual acceptance status

There is **no new 6.129 command to install or accept**. Existing baseline checks:

```powershell
.\.venv\Scripts\python.exe -B -m pytest -q -p no:cacheprovider tests/test_d2_preview.py tests/test_synthesis_packets.py tests/test_synthesis_relationships.py
.\.venv\Scripts\python.exe -B -m forensic_assistant.investigation_ai.d2_reasoning C:\tmp\locard-diagnostics\6.118-live 6ad0c85499564406aa4d949f3b0e72e5 --exploratory --json
```

The second command is the existing provider-free issue preview, **not** a new
cross-artifact investigation. Do not append `--execute` as an acceptance shortcut.
The local measurement harness remains at `.tmp-6129/feasibility.py` in this
development checkout, with `.tmp-6129/measure.json` and `measure.log`. These ignored
scratch artifacts are not a release feature; the synthetic inputs and measurement
method are documented above. It uses the SDK-equipped interpreter in the separate
test checkout but imports source/test helpers from the development checkout.

After a separate policy/scope decision and implementation, live acceptance should
use one explicitly approved frozen request and the predefined usefulness criteria.
No live acceptance command for an unimplemented feature is invented here.

## 10. Delivery boundary

Reused for reconnaissance/measurement: existing reconstruction, S1/S2, B1
rehydration/closure, D2 encoding, typed schema, OpenAI adapter and SDK serializer.
**New production modules/services: none. Implemented investigative behaviors:
none beyond the accepted 6.128 baseline.**

Only this report and an exact documentation ignore exception are deliverable
repository changes. `pyproject.toml` remains 6.128. Original evidence, copied
transcripts, source code, tests, permissions, provider configuration and accepted
contracts remain unchanged. No commit or push was made.

Final repository checks: `git diff --check` passed; branch is `main`; version is
6.128. The visible working-tree changes are this new report and its `.gitignore`
exception only.

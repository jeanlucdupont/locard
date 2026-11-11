# S4-D2 — Incremental AI explanatory reasoning

Design for review, 2026-11-10. Application version remains **6.121**.

Inspected branch `main`, HEAD `bf26041524cd3b19d54775b6400dbbbe6c01c8f2`; working tree was clean. This document is the only task change. No production/test/schema/version changes, test-suite execution, provider requests, live forensic database access, transcript writes, permission changes, commit or push. Historical reconstruction below is read-only validation, not a new investigation. All D2 names, budgets and behavior below are **proposals**, unless explicitly marked implemented.

## 1. Recommendation and acceptance boundary

Implement **a separate, explicitly authorized post-investigation D2 session first**, linked to a fixed, validated source transcript. Reuse original-support rehydration and atomic dependency closure from B1, B2's disclosure/dispatch safety patterns, S1/S2/S3 factual authority, and D1a's deterministic presentation. Keep D2 proposals in a small separate reducer and derived journal. Do not modify C1/D1b state or append to the historical investigation.

Start with **two bounded reasoning requests, zero new forensic lookups**, OpenAI first, under a new grant. Each request addresses one issue with original support represented in that request. The second can cover a complementary issue; it is neither a repair attempt nor a mandatory final summary. The application assembles the readable result from deterministic factual statements plus explicitly unverified proposals. No final request must contain the whole investigation.

This improves usefulness by connecting facts to the analyst's question, exposing the assumptions behind possible connections, presenting competing explanations and specifying what evidence would distinguish them. It does **not** claim arbitrary AI prose has been forensically verified. Citation validation is necessary but insufficient for entailment.

First implementation gate: prove that a useful complete issue packet and its full request envelope fit 5,600 bytes. In particular, measure the ASR premise bundle. If not, omit that bundle with an explicit reason and stop the affected reasoning task; do not split mandatory premises across requests, increase budgets or let a historical summary substitute for them. No D2 implementation is authorized by this document.

## 2. Source-confirmed implementation inventory

Paths in this document are repository-relative. Existing design documents describe intent; the code governs the inventory below.

| Implemented component | Actual behavior and reuse boundary |
|---|---|
| `investigation_ai/state.py:State`, `disclosure.py`; `autonomous.py:reconstruct` | Existing record/exposure state and accepted current-request analysis. Historical eligibility differs from what a particular request represents. Reuse this state, not a prose evidence store. |
| `investigation_ai/synthesis.py:_Reducer.consume, finish, reconstruct, _validate_render_clause` | S1 `synthesis-clause-v1`: exact original fields, source/projection lineage, registered interpretations, qualifications. Six batches, at most 96 clauses. Serialized clauses supplied independently are not trusted evidence inputs. |
| `investigation_ai/relationships.py:_build, _compare, _time` | S2 registers `recorded_time_before`, `exact_recorded_path`, `exact_recorded_identifier`, `incompatible_recorded_field`; maximum 192 comparisons / 64 relationships. Sparse comparisons, not exhaustive chronology or causal closure. |
| `investigation_ai/question_assessment.py:assess_typed, _assess, RULES` | S3 registered predicates assess examined evidence. `execution_outcome` and `causal_sequence` currently use explicitly unsupported rules. D2 cannot turn these into affirmative answers. |
| `investigation_ai/decomposition.py:validate, assess, validate_journal` | Provisional question-span mappings, polarity and binding checks. Original S3 assessment preserved separately. Duplicate typed mapping can atomically reject distinct unsupported objectives (§9). |
| `investigation_ai/packets.py:Context, _rehydrate, _bundle, _bindings, _plan, reconstruct` | B1 is a **provider-free packet planner**, not a new-retrieval authorization engine. It resolves original fields from validated record/exposure state, verifies lineage and source scope, and packs complete dependencies. Two packets, 5,600 content bytes, five-second shared meter, 512 resolutions, 192 candidate examinations/packet, 12 support leaves / four interpretations. |
| `investigation_ai/synthesis_consumer.py:encode, materialize, validate_packet, proposal` | B2 `synthesis-request-v1` and `synthesis-proposal-v1`; exact final message measurement, packet-local O/I/R aliases, source revalidation, interpretation closure and registered S2 recomputation. Four items/response, 16 KiB response cap. `prior_refs` must currently be empty. B2 prose remains `structurally_accepted_unverified`, including relationship rationales. |
| `synthesis_consumer.py:execute, decision, reconstruct` | Preplanned two-slot synthesis after analysis. Prepared → attempt → response → decision persistence; attempts charged before provider entry; atomic response validation; no repair/retry/fallback. A failed first response stops later synthesis. |
| `investigation_ai/organization.py:_Sources, _Reducer, Live, commit_receipt, reconstruct` | C1 `local-organization-v2`, `organization-rules-v2`: reference organization, membership/frontiers and partial processing. C1 is not additional evidence authority. |
| `investigation_ai/explanation.py:_Session, page`; `explanation_display.py:page, render` | D1a deterministic statements and compact record-oriented rendering; exact support, shared qualifications, original S3 status, source limitations and request-local alias legends. It does not certify model prose. |
| `investigation_ai/explanation_live.py:receipt_reference, Reducer.prepare, Live.update, Replay` | D1b v2 omits repeated full C1 receipt serialization. Replay reconstructs the entire receipt from validated C1 transitions and compares its digest, event/frontier/rules and operation prefix. V1 reader retained. No additional model reasoning. |
| `investigation_ai/explanation_status.py:project` | Exact-frontier currentness, D1b processing, upstream completeness and forensic completeness are separate. A current explanation may have partial C1 coverage. |
| `investigation_ai/autonomous_policy.py:validate, dispatch, validate_b2_shape` | Existing B2 authorization is six analysis + one decomposition + two synthesis attempts, six `show_evidence` lookups, ten steps, 300 seconds. It checks source/time/EID constraints; historical shape validation does not renew authority. |
| `investigation_ai/supervision.py:run, Launch, SynthesisDeadline, _stop`; `worker.py` | Parent-controlled startup/phase deadlines and containment; B2 model work stops at overall minus 20 seconds, finalization ends before five-second cleanup reserve. Child/read-view operations have explicit boundaries; recorded child cleanup is not independent proof of parent cleanup. |
| `ai/backend.py:ModelBackend`; `ai/openai_schema.py:request_schema, response` | Selected backend abstraction and exact known-schema adaptation. A D2 schema needs explicit recognition, wire-subset tests and canonical revalidation. B2 compatibility does not imply D2/provider parity. |
| `investigation_ai/transcript.py:Transcript.append, load`; `reporting/transcripts.py`, `investigation_ai/replay.py` | Hash-chain/publication checks and separate report-import grounding restrictions. Short/uncertain writes fail closed. A readable incremental explanation does not qualify a read-view transcript for a different report-import contract. |

Related reviewed material: `docs/LOCARD_6_110_S4_B2_DESIGN.md`, `LOCARD_S4_D_INCREMENTAL_SYNTHESIS_DESIGN.md`, `LOCARD_S4_D1B_LIVE_EXPLANATION_DESIGN.md`, `LOCARD_6_119_D1B_DIAGNOSTIC.md`, `LOCARD_6_120_REPLAY_AND_STATUS.md`, `LOCARD_6_121_D1B_COMPACTION.md`. Prior focused test results in the latter are recorded results, not tests rerun for this design. Commits/documents alone do not establish live manual acceptance.

## 3. Historical design evidence, validated read-only

Supplied root: `C:\tmp\locard-diagnostics\6.118-live`. `transcript.load()` and full `explanation_live.reconstruct()` ran with `sqlite3.connect` and `ModelBackend.complete` forbidden. Manifest/event SHA-256 values matched before and after. No original transcripts or case database were opened.

| Run | Confirmed result |
|---|---|
| `6ad0c85499564406aa4d949f3b0e72e5` | 60 events; 23 observations + one ASR interpretation; current D1b at C1 revision 6; 60 components; upstream partial. D1b digest `1c3f778d147d16a11192b735be60497924d04a41f6da296986dc573fb348bb9c`. |
| `ffdabecc9ded47e6acd5f4977fa3c2fa` | 61 events; current, 58 components; upstream complete. Digest `7019faae14d8fb56aaca78b7149b35d9d656c6d709f1ac0dd48de2cce64da110`. |
| `08cfd054f85a4a36b8520832427201c3` | 13 events; zero analysis, two explanation components; no B2 packets. Digest `83e041cdfa0e61efd1fc4ad48db80ad0f30265b870babeb3fc4e7569e9a6d14b`. Organizational currentness does not make its investigation successful. |

The matching partial run's B2 packets were **5,512 and 5,076 serialized content bytes**, each with **three original support leaves, zero interpretations and zero relationships**, both exploratory. Packet 1 represented Browser referrer, URL-chain entry 0 and DownloadStart. Packet 2 represented EVTX EventData `ID`, Event ID and timestamp—not the target command line. The comparison run used 5,562 and 5,070 bytes: Browser target/URL/start, then EVTX parent command line/ID/Event ID. These are observations about those requests, not maximum packet capacity.

`packets._plan` ranks direct bound candidates, complementary bindings, previously unrepresented EIDs, lexical score, EID and unit ID. The greedy strategy and final metadata budget can omit useful fields. There are no artifact quotas; omission is not a relevance finding. An ASR interpretation in accumulated S1 state was not thereby represented in these B2 requests. A model cannot use that interpretation merely by receiving a previous proposal ID.

The earlier receipt-size problem is distinct: 6.121 compacts **journal checkpoint receipts**, not model evidence packets. Its documented synthetic 30-operation/7,981-byte checkpoint does not increase the 5,600-byte model allowance or prove that an ASR packet fits.

## 4. Alternatives

| Criterion | A: extend B2 repeated loop | B: separate recorded-view phase | C: continuous live D2 |
|---|---|---|---|
| Grounding | Reuses current support, but risks coupling proposals to analysis authority | Immutable validated source makes the boundary explicit | Must reconcile changing frontiers and current-request exposure |
| Usefulness | Quick extension, constrained by two-slot organizational framing | Focused explanation after available findings; cannot discover new evidence | Can direct attention sooner, but future retrieval still needs authority |
| Complexity | Moderate; new contract/authorization still required | Moderate; separate grant/journal, reusable backend | Highest: competing phase budgets and interrupted dependency updates |
| Cost/latency | Temptation to borrow existing allocations | Explicit independent maximum; another startup/replay cost | More scheduling/context overhead; frequent calls possible |
| Resource accounting | Must replace rather than silently stretch B2 | Clean independent counters/deadline, no borrowing | Must reserve all lower-priority callbacks and finalization |
| Replay | Extends existing engine compatibility surface | Immutable source anchor + independent deterministic reducer | More interleavings/frontier validity rules |
| Analyst control | Single larger initial grant | New approval clearly explains repeated historical disclosure | Difficult to explain planned versus contingent work |
| Failure isolation | Can disrupt primary finalization | Leaves accepted primary findings untouched | Worst isolation if coupled to live finalization |
| Web integration | Possible if backend extracted | Natural session/preview/result service | Requires streaming lifecycle and synchronization |

Recommend **B initially**, reusing selected B2 machinery rather than copying its controller. A later live mode could consume the same packet/proposal services, but requires a separately approved composite allocation. No existing nine-attempt or 300-second grant is extended. The two D2 requests are additional *only after fresh explicit authorization*.

## 5. Four epistemic classes and component boundaries

| Class | Authority | Permitted use |
|---|---|---|
| 1 Original evidence | Exact recorded field/provenance in validated authorized read view | Original support; preserve values, precision, truncation and lineage |
| 2 Deterministic findings | Registered S1/S2 rules; S3 scoped assessment | Factual rendering within those exact semantics |
| 3 AI explanatory proposals | Model-generated, mechanically accepted but semantically unverified | Organization, tentative explanations, alternatives, gaps and suggestions |
| 4 Analyst decisions | Recorded human decision with identity basis, time and scope | Accept/reject/correct/prioritize a proposal; never rewrite Class 1/2 or certify causality |

**Proposed services:** `RecordedEvidenceResolver` reconstructs trusted source state; `IssuePacketPlanner` shares B1 resolver/closure primitives with a D2 encoder; `ReasoningSession` owns grant/budgets/dispatch; `ProposalValidator` separates mechanical eligibility from registered propositions; `ReasoningReducer` owns only derived proposals/dependencies; `ExplanationProjection` combines immutable D1a facts and D2 proposals. These are conceptual backend boundaries, not files already implemented.

Do not put D2 into C1 or D1b reducers: they have existing versioned deterministic semantics and tight budgets. D2 references their validated frontiers for organization but obtains evidence authority from original reconstruction. D1b v2 illustrates an authenticated-reference pattern, not a universal evidence loader. A future C1 projection of D2 would require new rules/profile; it is outside the first stage.

```mermaid
sequenceDiagram
    participant A as Analyst
    participant S as D2 supervisor
    participant R as Validated recorded-view resolver
    participant P as Issue packet planner
    participant J as New derived D2 journal
    participant M as Approved ModelBackend
    A->>S: Approve fresh D2 grant and source head
    S->>R: Validate fixed history and reconstruct original support
    R-->>P: Trusted S1/S2/S3 + original fields/lineage
    loop At most two admitted rounds
        S->>P: Select unresolved issue within fixed scope
        P-->>S: Complete bounded packet + omissions
        S->>J: Prepared packet recipe and exact wire digest
        S->>J: Charged attempt (possible disclosure)
        S->>M: Original evidence packet; unverified prior refs optional
        M-->>S: Structured explanatory proposals
        S->>J: Bounded response
        S->>S: Validate structure, support, rules, classifications
        S->>J: Atomic acceptance/rejection decision
        S->>S: Apply only confirmed decision to derived reducer
    end
    S->>J: Final/partial state and resource outcome
    S-->>A: Deterministic facts + visibly tentative explanation
```

## 6. Original-evidence packet service

Reuse `packets._rehydrate` behavior: exact approved EID, original source IDs/type, recorded epoch, accepted delta/disclosure lineage, projection digest, actual field descriptor/value, retained-field eligibility, timestamps and recognized interpretation premises. Reconstruct from the fixed source transcript; do not reopen SQLite or treat a closed historical transaction as a live read view. The answer explicitly covers the **recorded view**, not today's case contents.

Extract a shared resolver/bundle interface only in an authorized implementation. Keep existing B1/B2 encoders, ranking, digests and tests unchanged. D2 needs a separate encoder and selection version because its issue purpose and instructions differ. A generic caller-supplied JSON packet must never bypass trusted reconstruction.

Proposed `d2-evidence-packet-v1` includes:

- Source run and confirmed manifest/event head; recorded read-view identity and fresh D2 grant ID.
- Complete original question, selected source-span objective or explicit exploratory issue; binding/polarity/unsupported status.
- Packet-local aliases with exact EID/pointer/value, S1 clause and original projection lineage. Deduplicated source/qualification dictionaries must have total mappings and authenticated expansion.
- Original timestamp slot, meaning, precision, timezone availability, source-clock limitations; EventData name and ordinal, not merely array position.
- Registered interpretation IDs and **all** original/recognized derived premises; deterministic relationship IDs, both original endpoints and assumptions. Derived `/defender_asr` metadata stays labeled a deterministic premise, not original EventData.
- Truncation metadata, mandatory qualifiers, current-packet coverage, examined/unassessed/omitted counts and reasons. No silent shortening of paths, URLs or command lines.
- Optional at most two prior proposal references (≤512 bytes total), explicitly unverified. These can identify a question to revisit, not supply evidence. Any substantive evaluation must redisclose required original supports now.

Selection: validate scope first; prioritize issue bindings and mandatory proof bundles; include recognized opposing support/qualifications atomically; then complementary fields and previously unrepresented support; stable clause/EID tie-breaking. Model suggestions may rank only an application-enumerated eligible issue list. No family quotas, recency advantage or model-supplied new EIDs. Track previously represented *fields*, not just records. Do not repeatedly plan with reset meters.

Two preplanned issue packets are the first implementation. Later adaptive selection can choose among already authorized, validated bundles without new retrieval, but is a separate acceptance stage. Admit at most 192 candidates/packet, 512 support resolutions total and five seconds total planning across both packets, reusing B1's meter ceilings. Maximum 12 support leaves/four interpretations per packet; smaller limits may be necessary for the richer envelope. Exact system+user UTF-8 content remains ≤5,600 bytes, including question, instructions and omission metadata. A long original question may leave no useful packet: fail explicitly, do not silently narrow it.

No complete bundle fitting means `NO_SUPPORTED_PACKET`/`ATOMIC_BUNDLE_TOO_LARGE`, not absence of evidence. Separate known relevant-but-unrepresented material from unassessed material. If contradictory support is known but cannot fit, omit the associated deterministic claim bundle; an exploratory question may remain only with that limitation made explicit.

## 7. Typed request, response and validation

All names and limits in this section are proposed. Requests use `d2-reasoning-request-v1`: D2 session/round/request IDs, grant ID, immutable source anchor, packet digest, exact message digest, objective binding, issue purpose (`explain_recorded_facts`, `compare_alternatives`, `identify_gaps`), packet, and optional unverified prior references. The application generates identities; no model can select the session, grant or evidence epoch.

Response `d2-reasoning-proposal-v1` has exact request ID and packet digest, up to four items, and a provisional question assessment. Each closed-schema item contains:

| Field | Constraint and meaning |
|---|---|
| `local_id`, `kind` | Unique ≤16 ASCII chars; `hypothesis`, `possible_connection`, `alternative`, `gap`, `next_objective`, or `registered_relationship_candidate` |
| `statement` | ≤400 UTF-8 bytes; all model prose remains unverified |
| `support_refs` | 1–6 unique current-packet original aliases |
| `interpretation_refs`, `relationship_refs` | 0–4 each, requiring complete original dependencies |
| `contradictory_refs` | 0–6 current-packet aliases; an empty list means none cited, not none exists |
| `alternatives` | Up to two ≤240-byte alternatives; at least one for explanatory/causal hypotheses |
| `assumptions`, `gaps` | Up to two ≤160-byte entries each; not factual absence claims |
| `limitations` | 1–2 ≤200-byte qualifications; application also attaches non-removable source qualifiers |
| `next_issue_refs` | Up to two application-issued candidate IDs; recommendation only |
| `prior_refs` | Up to two explicitly disclosed prior proposal IDs; never original support |
| Registered candidate payload | Existing S2 predicate + exact endpoint clause IDs; no new execution/causal predicate |

Question assessment: `proposed_answerability` is only `partially_addressed`, `unresolved`, or `not_assessable_from_packet`, with ≤240-byte rationale and current support references. It cannot set S3 status, overall completeness, factual confidence, a verified actor, or an affirmative successful-execution outcome. The application separately displays unchanged deterministic S3 results. Target one or two complete proposals, not four obligatory items, given the 1,024-token output cap.

Illustrative shape, not a captured response or dispatch-ready packet:

```json
{"contract":"d2-reasoning-proposal-v1","request_id":"<application id>",
 "packet_digest":"<validated digest>","items":[
   {"local_id":"H1","kind":"possible_connection",
    "statement":"The file and recorded command might belong to the same activity.",
    "support_refs":["O1","O2"],"interpretation_refs":[],"relationship_refs":[],
    "contradictory_refs":[],"alternatives":["The records may describe unrelated activity."],
    "assumptions":["The recorded contexts refer to the same file."],
    "gaps":["No process-instance link is represented."],
    "limitations":["A matching name does not establish causality."],
    "next_issue_refs":[],"prior_refs":[]}],
 "assessment":{"proposed_answerability":"unresolved",
               "rationale":"Execution is not established by these fields.","support_refs":["O1","O2"]}}
```

Acceptance order: provider envelope/completion → strict JSON (including duplicate-key handling) → canonical closed schema and UTF-8/cardinality limits → exact request/grant/source/digest binding → current aliases → rehydrated original equality/lineage → complete interpretations/relationships/qualifications → registered S2 recomputation → allowed classification/duplicate dependencies → confirmed durable decision. Any invalid item rejects the entire response. Prior accepted rounds survive. No repair call or automatic retry.

| Claim concern | Enforceable boundary |
|---|---|
| Original value assertion | Only application-owned S1 templates render it as a fact; exact value and source descriptor required |
| Registered relationship | Recompute the existing S2 rule and require both endpoints in this request; model rationale stays unverified |
| Causation / actor attribution | No registered certification here; Class 3 only. Model cannot select a factual status, identity attribution or causal relationship rule |
| Successful script execution | No affirmative S3 rule exists; ASR cannot support that upgrade. Deterministic rendering says recorded block, execution unresolved |
| Temporal order | Preserve timestamp interval/slot semantics; reject certified order if S2 cannot establish it. No inferred clock equivalence or transitive execution chain |
| Contradiction | Registered same-occurrence field conflict can be factual; model semantic disagreement is a proposed conflict, not a deterministic contradiction |
| Absence | Packet omissions or no matches never prove event absence. Report “not established from represented support”; complete authorized plan is not complete case coverage |
| Event meaning | Provider/channel/Event ID plus registered rule govern interpretation, not numeric Event ID alone. Preserve original and interpreted fields separately |

**Residual risk:** arbitrary prose cannot be exhaustively checked for entailment or false certainty by a deterministic string validator. Do not promise otherwise or build a brittle semantic blacklist. All generated text, including headings, remains in a visibly unverified section; only registered templates enter the factual body. A second LLM is not an authority upgrade. If the product requires certified free-form conclusions, that is an unresolved new contract, not part of D2 first delivery.

## 8. Independent authorization and concrete proposed budgets

New `d2-reasoning-authorization-v1`, never interchangeable with historical Stage A/B2 grants. Bind fresh session ID, source run/head and manifest digest, recorded view, exact question, approved sources/EIDs/families/time scope (at most the original scope), permitted contextual out-of-window fields, exact provider/model, issue purposes, exploratory permission, all limits, issued/expiry and monotonic approval deadline. Explicitly authorize repeated cloud disclosure of historical evidence. No new tool permission.

| Proposed first-stage limit | Ceiling / enforcement |
|---|---|
| Provider | OpenAI selected model only, no fallback; future adapters preserve same contract |
| Requests / rounds | Two charged attempts, two rounds; no automatic retries or repairs |
| Lookups | Zero; reconstructed authorized recorded fields only |
| Input content | 5,600 UTF-8 bytes per complete system/user request |
| Output | 1,024 provider output tokens/request; 16 KiB raw-response cap |
| Additional token allocation | Reserve ≤8,192 input tokens + 1,024 output tokens per attempt, **18,432 total**. Include schema/message framing in model-specific local token preflight; no usable tokenizer/known accounting → no dispatch |
| Usage uncertainty | Charge full reservation before entry; unknown usage never refunds a slot or permits another call. Provider billing/internal token semantics are not falsely certified by client accounting |
| Total elapsed | **180 seconds from new approval**, including startup and source validation |
| Preparation | At most 90 seconds for immutable history reconstruction; all work also under parent total deadline |
| Model cutoff | Approval +160 seconds; each request ≤30 seconds, clamped to expiry/cutoff |
| Finalization / containment | Up to 15 seconds deterministic finalization, then five seconds cleanup; no 185-second extension |
| Planning | Five seconds cumulative, 512 resolutions total, 192 candidate examinations/packet, no repacking reset |
| Local state | At most eight accepted proposals, 24 distinct original support leaves across two packets, 192 dependency edges, eight gaps and eight next-issue suggestions |
| Memory | Four MiB incrementally owned D2 state/packets; proposed 256 MiB worker process cap including history reconstruction, measured before enabling execution |
| Derived journal | New D2 journal ≤1 MiB, ≤64 events, ≤64 KiB/event, ≤96 KiB reserved response cycle; terminal reserve 64 KiB/four events |
| Analyst decisions | At most 16 append-only decisions per D2 session; overflow requires separately reviewed workflow, not truncation |

These are proposed **new-phase** ceilings requiring approval and measurement. Existing D1b 8 KiB/checkpoint, one-second/4 MiB limits and original 4 MiB/256-event investigation journal remain unchanged. D2 events are not D1b checkpoints. No allocation borrowing between old analysis, B2, D1b and D2.

Local token preflight must include supported provider schema/framing and a conservative reserve, not characters-as-tokens. The provider output cap must cover the selected model's relevant output/reasoning accounting; unsupported accounting fails closed pending adapter validation. Network failures still consume an attempt. Exact price/currency cost is not guaranteed. Unknown provider usage is reported separately.

Parent supervision covers process launch, journal creation, source verification, planning, provider initialization/request and cleanup. Progress messages cannot reset deadlines. Readiness/preparation must not make hidden provider calls. Admission checks precede preparing, persisting and dispatching every request and preserve finalization capacity. A local worker block or provider timeout is contained with explicit cleanup uncertainty if termination cannot be confirmed.

Analyst continuation is **not restart recovery**: after termination, a separately approved new D2 session may reference the same immutable source and prior unverified proposals. No automatic loop or grant renewal. A new investigation/retrieval requires its own authorization and recorded view; cross-epoch reasoning is deferred.

## 9. Failed decomposition and objective identity

Confirmed source: `decomposition.validate` uses `encoded([kind, args, item['unresolved']])` as a duplicate mapping key. Two `unsupported_objective` entries with empty args/unresolved lists collide regardless of distinct question spans. The current rejection is atomic; do not change it as part of D2 implicitly.

D2 always retains the complete original question and original S3 assessment. With missing/rejected decomposition:

1. Display mapping unavailable and the rejection category; do not fabricate typed bindings or adopt rejected partial objectives.
2. If the new grant explicitly allows exploratory reasoning, use the full original question and a clearly labeled issue such as “what can the represented evidence establish?” A suggested topic does not narrow the authorization or certify intent fidelity.
3. If exploratory reasoning is not authorized, stop without a provider request and offer analyst selection/correction.
4. Technical referents remain exact: historical `execute` is not a script identifier. Candidate identities can be suggestions only, never automatically approved search inputs.

Separate future fix to evaluate: give unsupported objectives an identity based on question digest + exact source span + proposal type/polarity, while retaining current typed-binding duplicate/conflict checks for supported predicates. Deduplicate identical spans deterministically; overlapping or semantically similar spans remain a reported ambiguity, not an invented certified distinction. Preserve old validation rules during historical replay. This requires its own versioned decomposition decision, tests and authorization, not an incidental D2 relaxation.

## 10. Working state, persistence and interruption

Use a separate `d2-reasoning-state-v1` reducer. Persist application-generated proposal IDs, original support dependencies and source request, decision-validator version, classification, active/rejected/superseded status, unresolved issues, examined/represented/omitted support, model identity, grant/budget charges and termination. Keep existing C1/D1b snapshots immutable.

Proposed event family in a **new** derived journal:

| Event | Durable meaning |
|---|---|
| `d2_authorized` | Fresh bounded grant and immutable source anchor; not a renewed historical grant |
| `d2_prepared` | Versioned packet recipe, exact current-field/dictionary references, qualifications, source heads, messages/schema digests, measured bytes; not actual disclosure |
| `d2_attempt` | Attempt reservation charged before provider entry; evidence may have been exposed |
| `d2_response` | Bounded original response plus completion/usage diagnostics; not accepted findings |
| `d2_decision` | Atomic acceptance/rejection, exact failures and dependencies; reducer changes only after publication |
| `d2_analyst_decision` | Human correction/rejection/prioritization linked to old/new proposal IDs; identity basis and scope recorded |
| `d2_terminal` | Confirmed final/partial state digest, coverage, counters, failure/cleanup uncertainty |

Prepared recipe references must resolve through the pinned source transcript and deterministic encoder, including all exact original field values in the reconstructed messages. Persist selection/order rather than rerunning time-dependent admission. Verify full reconstructed message and packet digests. Persist generated response once; subsequent state references it. A dictionary or historical receipt hash alone is not evidence. If source history becomes unavailable or unsupported, replay reports unavailable; it does not silently trust cached prose or request source fields from a case database.

Reuse `Transcript` publication semantics: full byte-count checks, event/manifest confirmation, no retry/repair/tail promotion. Reserve a complete response/decision/terminal cycle before attempt. If append fails before attempt, no dispatch. If an attempt is confirmed but no response exists, mark possible exposure and unknown outcome; never redispatch on replay. If response exists without confirmed decision, expose it only as undecided diagnostic material. If decision is confirmed but terminal is absent, reconstruct that accepted prefix with incomplete status. Previous accepted proposals survive later failure. Replay never contacts a provider or renews a grant.

D1b v2 compact-receipt reuse is conceptual: exact source-event/frontier/rules/digest reference plus independent reconstruction. It cannot store D2 proposals under its old profile or validate them by pointing only to C1. A source directory must be read as a consistent, verified immutable set; reject changed heads, unsafe redirection and inconsistent reads. Historical read-view identity establishes historical scope, not current live-case equality.

Supersession is append-only. A new model proposal can **propose** replacement/conflict with a disclosed earlier proposal; deterministic IDs and dependency checks prevent cycles, cross-session substitutions and hidden overwrites. Neither model preference nor repeated wording establishes truth. Analyst decisions can deactivate or amend Class 3 content; edited prose remains analyst interpretation. Original responses and qualifications remain recoverable. Registered factual contradictions use S2; semantic contradictions remain explicitly unresolved unless an analyst decision or independent rule supplies the appropriate narrower status.

Separate status axes: source-history validity; source processing coverage; D2 execution/cleanup outcome; accepted proposal count; reasoning packet coverage; deterministic question assessment; provisional answerability; analyst-review status. “Replay valid”, “two rounds completed” and “all selected packets consumed” are not “case complete”.

## 11. Historical walkthrough and minimum issue bundles

These examples use recorded fields only to motivate the design. No causal narrative is approved here. Full technical values remain in support detail; the design avoids copying full EIDs or unrelated URLs into prose.

| Issue packet | Minimum original support and qualified purpose | Boundary / additional evidence needed |
|---|---|---|
| Download identity | Browser `/target_path`, relevant `/url_chain/.../url`, `/timestamps/1/utc` (DownloadStart), `/timestamps/0/utc` (DownloadEnd), source/profile context | Reports a ZIP download; does not establish opening/extraction. Referrer/redirect evidence is separate if omitted for size. |
| ZIP filesystem association | Browser target + MFT `/objects/1`, appropriate exact SI/FN slots, original source/volume context; any existing S2 relationship with its endpoints | Browser target is drive-qualified while recorded MFT path is volume-relative. Do not declare `exact_recorded_path` equality or synthesize a drive prefix without a registered rule. Filename similarity is a tentative connection. |
| WSC/script staging | MFT `qon[1].wsc` path + its typed timestamp; MFT `baje.ps1` path + its typed timestamp; provenance and any eligible recorded-order relation | Records paths/metadata, not contents, execution or a WSC-to-script causal link. Treat archive extraction and WSC function as unestablished. |
| Defensive intervention | Complete registered ASR bundle: `/provider`, `/channel`, `/event_id`, `/defender_asr` with interpretation ID/qualifiers; exact event timestamp and target command line if they fit | The four-premise bundle must fit atomically. Recorded blocking is not successful script execution; derived ASR metadata remains identified as such. If command line does not fit, another packet can describe it, but cannot inherit undisclosed ASR authority. |
| Recorded parent context | EventData `Target Commandline` (recorded ordinal 11), `Parent Commandline` (ordinal 12), event identity/provider context and timestamp | Target references PowerShell and `C:\ProgramData\baje.ps1`; parent reports `wmiprvse.exe`. Names/fields do not prove a process-instance chain or actor. Process GUID/creation evidence is a future retrieval objective, not present merely because requested. |
| Prefetch context | `/executable` (`EXPLORER.EXE`) + typed LastRun slots/precision/source context; any relevant original referenced-file field only if actually retained/eligible | Execution metadata for Explorer is not proof of ZIP opening or script execution. Do not invent referenced files absent from disclosed support. |

These are **logical atomic issue bundles, not a claim all six packets fit or will be sent**. With two calls, prioritize the original question and analyst-approved issue choice; for an execution question, ASR/command context may take priority over delivery. If the ASR bundle fits but its contextual command line does not, disclose the omission and limit the proposal accordingly. Unprocessed delivery/staging issues remain visible. An analyst can authorize a separate subsequent session; no automatic continuation.

Recorded chronology examples: Browser DownloadStart about 14:05:26.265 UTC and DownloadEnd about 14:05:27.863; ZIP FN Created about 14:05:26.270; later script/cache metadata about 14:05:46; Defender timestamp about 14:05:47.871. Preserve full precision in structured support, and label rounded display times. Prefetch timestamps near 14:05:44 refer to recorded Explorer execution metadata, not script execution. Chronological display adjacency is not a newly certified S2 relation. Registered ordering requires its exact clause endpoints and timestamp semantics; unknown timezone, overlap or uncertain clock equivalence prevents stronger physical-event order claims.

Example **presentation target**, not a new forensic conclusion: deterministic sentences say what Browser, MFT and Defender each record. A separate paragraph says an association is possible but the available records do not establish archive extraction, a complete parent chain, causation or successful script execution. It names the missing process-instance/content/telemetry support rather than pretending a coherent storyline closes those gaps.

## 12. Analyst workflow and explanation projection

Proposed workflow (not current CLI syntax): select a confirmed investigation → local source/issue preview → review original question, failed bindings, selected support/omissions and exact cloud allocation → authorize once → bounded reasoning → review deterministic facts and unverified proposals → optionally record acceptance/correction/rejection/prioritization. No routine per-record prompts within that new grant. A future web UI uses the same backend request/status/result objects.

The rendered result should contain:

1. **What the evidence establishes:** existing deterministic sentences, short record labels, exact source references available on expansion.
2. **Observed chronology:** typed timestamps, precision/timezone qualifications and limited registered comparisons; no inferred causality.
3. **Established recorded relationships:** registered rule wording, separate from model rationale.
4. **Possible explanations — unverified:** short issue-centered proposals and their original support, not factual AI headings.
5. **Competing explanations and conflicts:** alternatives, contradictory support and unresolved semantic conflicts.
6. **Important gaps:** evidence not represented/not searched/truncated versus evidence that was searched with bounded coverage.
7. **Answer to the original question:** unchanged S3 determination plus separate provisional packet-limited assessment.
8. **Next investigative objectives:** suggestions requiring new retrieval authorization; no tool execution implied.

Extend D1a's compact presentation as a new projection, not a replacement for canonical statements. Reuse qualification dictionaries with section/claim references so a shared caveat is stated once but its scope is unambiguous. Keep material ASR/execution caveats next to the relevant claim. Translate request-local aliases into stable human record labels plus expandable original EID/pointer references; never print ambiguous `O1` from two requests as one evidence identity. Model-generated text stays escaped/sanitized and visually within the unverified section. Analyst-approved prose remains Class 4, not a forensic finding.

## 13. Threat model and rejection tests

| Threat | Concrete containment and testable rejection |
|---|---|
| Artifact prompt injection / malicious filenames, URLs, scripts | Values are data-only encoded fields; no tool executor in D2. Synthetic “ignore scope/run tool” values cannot alter grant, schema, request count or model route; terminal controls escaped. |
| Hallucinated aliases / field values | Exact request membership and original descriptor equality; reject unknown alias, altered value, cross-packet alias or dropped qualification. |
| Cross-case/run/view contamination | New grant pins source head, run, read view and scope; reject otherwise valid support imported from another source. |
| Historical prose promoted to evidence | Prior proposal refs occupy a separate class and cannot satisfy support_refs; reject proposal ID as original field or factual relationship endpoint. |
| Unauthorized scope expansion | Zero forensic tools/new EIDs; reject requested retrieval, unsupported issue IDs or wider grant usage. Suggestions remain text. |
| Stale view / changed history | Revalidate anchored manifest/events and supported rules; reject changed source head or unavailable dependency. Explicitly disclaim current-case equality. |
| Forged receipt/source hash | Independently reconstruct the source transition and lineage; a self-consistent forged packet alone fails. |
| Unsupported causation/attribution/execution | Reject factual/verified statuses and unknown registered predicates; all other prose remains visibly unverified. Test that ASR cannot alter S3 execution outcome. |
| False absence | No whole-case absence status permitted; missing/unsearched/omitted distinctions supplied by application. Empty contradiction list cannot become “no contradictory evidence”. |
| Truncated/refused/interrupted model response | Completion envelope checked before JSON acceptance; reject truncated/refusal/malformed/oversized output, keep earlier decisions, charge attempt, no repair. |
| Duplicate / contradictory proposals | Stable application semantic key and explicit links; exact duplicates do not count as corroboration. Reject cycles/forged supersession; retain competing hypotheses. |
| Endless reasoning / unauthorized attempts | Two pre-reserved attempts, two rounds; parent deadline, no-progress stop and no automatic continuation; third dispatch must be impossible. |
| Journal exhaustion / short write | Reserve full cycle+terminal before dispatch; insufficient capacity means no call. Inject event/manifest short writes: fatal uncertainty, no accepted state advancement or retry. |
| Misclassified resource stops | Distinguish packet-too-large, planning, token, journal, timeout, publication uncertainty and upstream partial coverage. None is evidence absence. |
| Replay divergence | Independent-process replay matches state, packet/message digests and proposal decisions without provider/SQLite access. Changed rule/profile/prefix rejected. |
| Analyst correction laundering | Amendments append Class 4 decisions; edited technical value cannot become a Class 1 search input or overwrite original support. |
| Provider parity/hidden requests | Exact provider/model/schema/usage controls; mock backend initialization must emit zero calls. Unknown schema/model accounting fails pre-dispatch. |

## 14. Phased plan and version boundaries

Design leaves application **6.121** unchanged. Proposed numbers below are release boundaries to approve, not authorized increments or promises that work fits one release.

| Stage | Proposed boundary | Independently reviewable acceptance |
|---|---|---|
| D2-0 | Next authorized release, provisionally 6.122 | Provider-free recorded-view resolver + issue preview + closed request/response validator using synthetic responses. Fresh-grant shape designed but live execution disabled. Measure complete ASR and contrasting-support packets under 5,600 bytes; preserve B1/B2 historical digests. |
| D2-1 | Separate later release, provisionally 6.123 | New D2 grant/supervised two-call executor, derived journal/reducer, atomic validation and independent replay. OpenAI mock acceptance first, then analyst-only live acceptance. No live C1/D1b integration. |
| D2-2 | Separate later release, provisionally 6.124 | Compact issue-centered narrative projection and append-only analyst review; exact qualification/citation mappings, no authority promotion. |
| Later, separately designed | No number assigned | Adaptive in-scope issue scheduling, optional new-session continuation, or live integration. Autonomous new evidence search, durable restart and provider parity remain excluded. |

**Smallest first implementation: D2-0.** Reuse/extract only the necessary trusted resolver and closure; add a D2 encoder and validated offline fixture proposals. Do not create a live command that partially bypasses authorization or publication controls. Acceptance requires useful complete packets, exact UTF-8 accounting including instructions, cross-view/forged-reference rejection, atomic qualifier preservation, failed-decomposition exploratory preview, original source immutability, deterministic selection and provider-free reconstruction. If no useful bundle fits, report actual bytes and stop before approving the executor.

D2-1 tests must additionally cover preparation/journal/provider hangs, cancellation before/after attempt, expiry, unknown usage, two-attempt ceiling, interrupted publication, finalization reserve, no orphan under controllable lifecycle, no additional evidence access and independent replay. Test hundreds of synthetic candidate units only within explicitly bounded admitted collections: report truncation/omission rather than claiming current S1's 96-clause cap has been lifted. Larger-investigation scaling is a future separately budgeted source contract.

Live acceptance, only after explicit implementation approval: analyst selects an existing confirmed transcript, approves fresh OpenAI disclosure for two issue packets, then checks recorded messages/response decisions, source coverage, clock/token accounting, rejection/partial-state behavior and unchanged source hashes. A separate synthetic multi-artifact case tests different identities, conflicting timestamps and unsupported objectives. This design initiates no paid calls and invents no future session ID or currently usable D2 CLI command.

## 15. Decisions requiring architectural approval

1. Approve separate post-investigation scope and fresh disclosure authorization, rather than extending the old grant.
2. Approve proposed two-call/180-second/token/memory/journal ceilings; tokenizer/provider accounting and source reconstruction memory require measurement before live enablement.
3. Decide whether exploratory reasoning is a default-off explicit grant flag (recommended), and how the analyst chooses two issues when more remain.
4. Approve the strict authority boundary: generated explanation remains unverified prose even with valid references; factual sections use registered templates only.
5. Approve linked-source retention: source transcript must remain available for grounding replay; no automatic copying/import of a new evidence store. Missing history means unavailable, not trusted cached output.
6. Approve append-only analyst decision identity policy and separate-session continuation limits; neither is a forensic verification mechanism.
7. Decide whether to separately authorize the unsupported-objective duplicate-key correction. D2 can proceed with explicit exploratory fallback without weakening typed bindings.
8. Confirm that oversized ASR/contradiction bundles block the affected issue rather than justify budget increases or split-premise authority.

## 16. Validation and change status for this design

Source inspection and read-only reconstruction were performed; no new unit tests, benchmarks or live model operations were run. Historical digest/field/packet measurements in §3 and §11 were obtained from the supplied copies after validation. Prior 6.121 performance/test figures are attributed to its existing report, not rerun here. No manual D2 acceptance exists because D2 is not implemented.

No pre-existing uncommitted modifications were present. Only this documentation file is created and included for review despite `docs/*` ignore behavior, without changing repository-wide ignore rules. `git diff --check` passed. The current application version, implementation, tests and historical artifacts remain unchanged.

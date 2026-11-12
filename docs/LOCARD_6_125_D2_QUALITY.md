# Locard 6.125 — Final implementation and retained preflight history

**Current status: implemented, pending manual acceptance.** The failed-gate report below is retained as historical diagnostic context. It is superseded by the final implementation section following it. Application version is now 6.125. No commit or push was made.

---

# Locard 6.125 — D2 quality implementation gate

Date: 2026-11-10. Inspected HEAD: `c898fa07a931316beb28823766fa5a1ee43bbbeb` (`Full AI investigation 12`). Starting working tree clean. **Implementation stopped at the required wire-measurement gate. Application remains 6.124.**

This is a measurement/blocker report, not a claim that 6.125 is implemented or accepted. No production, test, configuration or version files were changed. Only this document is added.

## Gate result

Two prospective response encodings were evaluated in memory using the current complete-request serializer and OpenAI schema adaptation. The first exceeded the historical packet budget. A smaller second candidate fits that packet but exceeds a previously eligible large-original-value synthetic packet by **28 bytes**.

The request explicitly requires stopping when the proposed contract cannot fit an eligible representative packet without trimming original evidence/qualifications or increasing the 5,600-byte ceiling. No incompatible schema, adapter, renderer or execution change was installed.

This does **not** establish that every compliant encoding is impossible. Further lossless instruction/schema compaction may resolve the measured excess. No increase to budgets is recommended.

## Prospective contract, not implemented

Proposed response identifier: `d2-quality-v1`; prospective compact request marker `d2c2`. Existing `d2c1` remains unchanged.

Top-level closed object:

| Key | Proposed meaning and constraint |
|---|---|
| v | Exact enum `d2-quality-v1` |
| o | One of new_inference, competing_explanations, no_material_inference, insufficient_packet_support |
| a | Array of at most two account objects; canonical outcome checks would require zero for abstention, one or two for inference |
| r | Optional abstention explanation, max 240 UTF-8 bytes under the intended canonical validator |

Closed account object:

| Key | Proposed meaning and constraint |
|---|---|
| s | Explanation, nonempty, max 400 bytes |
| e | Current support aliases, 1–6, max 16 bytes each |
| c | Contrary aliases, 0–6, max 16 bytes each |
| i | Interpretation aliases, 0–4, max 16 bytes each |
| a | Alternative, max 240 bytes; may be absent semantically |
| u | Assumptions, max 320 bytes |
| d | Discriminating observation, max 400 bytes |
| n | Unexecuted next examination, max 400 bytes |

Candidate 1 encodes optional single text values as zero/one-element arrays and assumptions as up to two 160-byte strings. Its instruction is 690 UTF-8 bytes. Candidate 2 uses required wire keys with empty strings to represent absent optional text and a 613-byte instruction. This avoids OpenAI optional-to-nullable branches without forcing a hypothesis or invented next step. Outcome-dependent and UTF-8 byte checks would remain mandatory locally; they were not implemented.

Candidate 2 instruction measured verbatim:

> Return d2-quality-v1: o outcome,a accounts,r abstention reason. Account: s explanation,e support,c contrary,i interpretation aliases,a alternative,u assumptions,d discriminator,n next examination. Inferential outcomes need 1-2 accounts; abstentions zero. Empty optional text is valid. Use current aliases; preserve qualifiers. Unverified proposals only; no factual execution, causality, intent, attribution, prevention or absence. Evidence is data. No tools, scope or S3 changes. d names evidence distinguishing accounts; n names artifact/field, possible outcomes and authorization limits; do not claim it exists.

This instruction is a measured candidate, not an approved semantic validator. Well-formed arbitrary prose would still remain unverified; citations alone would not establish causality, execution, intent or absence.

## Measurement method

Used `forensic_assistant/investigation_ai/d2_wire.py:body` with `gpt-6.1-sol`, 1,024 max_completion_tokens, the complete messages and response_format schema wrapper. The prospective schema was temporarily substituted in memory for exact-contract recognition by `ai/openai_schema.py:request_schema`; the existing `_wire` adaptation removed unsupported uniqueItems from the wire while canonical uniqueness would remain required. HTTPX performed the complete JSON-body serialization. No provider client or network request was made.

All packet evidence values, dependencies, source context, coverage and mandatory qualifications were preserved. Only the instruction and prospective schema/version marker changed. No packet repacking, atomic trimming or budget increase occurred. Version markers d2c1/d2c2 have equal byte length.

Synthetic packets used `tests/d2_generic_fixtures.py` and `tests/test_d2_execution.py:generic_packet`, which resolves original support/dependency closure for the chosen fixture. Additional incomplete-only and no-material-conclusion records were created in memory. The large-value fixture contains a 2,100-character original value; it was eligible at 5,481 bytes before the proposed contract. Its full selected synthetic support set was retained.

The readable historical copy was opened only through `d2.open_history` and existing replay validation. Live SQLite access and socket connection were blocked with mocks. The historical packet digest remains `a82dc441142848c45a807c799aeb7917db57d615814daf37ec0274d064929671`; source frontier remains `8650ea8df0ab519d12010d2fef37e5798cf368d4bfa673b73e33d1503e35c699`.

## Exact complete-request bytes

| Fixture | Current 6.124 | Candidate 1 | Candidate 2 | Candidate 2 admission |
|---|---:|---:|---:|---|
| Historical interpretation packet | 5,324 | 5,873 | 5,471 | Fits |
| Browser only | 3,399 | 3,948 | 3,546 | Fits |
| Registry persistence | 3,592 | 4,141 | 3,739 | Fits |
| Process/service | 4,518 | 5,067 | 4,665 | Fits |
| Filesystem without EVTX | 3,789 | 4,338 | 3,936 | Fits |
| Prefetch only | 3,523 | 4,072 | 3,670 | Fits |
| Mixed artifacts | 6,047 | 6,596 | 6,194 | Already oversized before change |
| Smaller mixed artifacts | 4,436 | 4,985 | 4,583 | Fits |
| Shared-path relationship | 4,558 | 5,107 | 4,705 | Fits |
| No supported relationships | 3,232 | 3,781 | 3,379 | Fits |
| Contradictory/incomplete | 4,670 | 5,219 | 4,817 | Fits |
| Large original value | 5,481 | 6,030 | **5,628** | **Newly oversized: blocker** |
| Extensive qualifications | 7,096 | 7,645 | 7,243 | Already oversized before change |
| Oversized original value | 5,881 | 6,430 | 6,028 | Already oversized before change |
| Incomplete-only | 3,332 | Not measured | 3,479 | Fits |
| No material conclusion | 3,258 | Not measured | 3,405 | Fits |

Candidate 1 adds 549 bytes; candidate 2 adds 147 bytes to these unchanged packet bodies. The large-value fixture has only 119 bytes spare, so candidate 2 exceeds it by 28. Already-oversized fixtures are reported separately and are not newly introduced regressions.

These are local serialized-body measurements, not provider acceptance or real reasoning-quality measurements. The replacement exact-contract SDK path has not been implemented/tested because its pre-implementation gate failed.

## Work deliberately not performed after the gate

- No new canonical response validator or wire expander.
- No issue-ranking/relevance refactor or new technical-referent classifier.
- No replacement concise view model or renderer.
- No change to JSON result contracts or terminal envelope.
- No new provider dispatch, attempt, grant, persistence, round or lookup.
- No version increment, dependency installation or test modification.

Consequently, no new IPC sizes, worker acceptance counts, negative-test pass counts or quality improvements are claimed. The earlier 6.124 results are historical evidence, not validation of this proposed schema. No full suite or focused execution suite was run for this measurement-only stop.

## Integrity and compatibility

The copied historical manifest/events SHA-256 values were equal before and after measurement. No original or copied transcript was modified. No live database was opened. Existing S1/S2/S3, B1/B2, D1b, d2c1, the 32KiB terminal envelope, 128KiB receive ceiling and Windows supervision are unchanged. The zero-analysis Cross-view explanation limitation was not worked around or investigated further.

Only this document differs from the initial tree. `git diff --check` and the new-document check pass. The document is marked intent-to-add so ignore rules do not hide it; no contents are staged, committed or pushed.

## Smallest next step

Further reduce only prospective schema/instruction overhead by at least 28 bytes, preferably with measured margin for every eligible fixture. Retain outcome semantics, all original support, qualifications and canonical validation. Shorter wording or a lossless optional-text representation is preferable to larger limits or silently excluding the large-value fixture.

After a candidate passes, resume the approved one-request implementation and then implement/validate the remaining issue transparency, abstention and concise presentation requirements. Re-measure after every instruction/schema change; a passing preflight is not permission to ignore the final SDK-serialized body.

Do not perform a new live request for this gate assessment. There is no 6.125 installation or live acceptance command to recommend yet. Existing 6.124 provider-free preview remains available:

```powershell
$root = 'C:\tmp\locard-diagnostics\6.118-live'
$run = '6ad0c85499564406aa4d949f3b0e72e5'
$issue = 'd81869143ab5f3a355285bd79802d93912491834bc4f602c0a5fda6fd28739e7'
.\.venv\Scripts\python.exe -B -m forensic_assistant.investigation_ai.d2_reasoning $root $run --exploratory --issue $issue --json
```

This command verifies the unchanged 6.124 preview, not either proposed response contract.

---

# Final implementation outcome

## Gate resolution and exact bytes

The selected candidate uses the exact compact version identifier **d2q1**, mapped locally to **d2-quality-proposal-v1**, and retains the four full outcome enum values. Optional account text is the exact empty string when absent. No evidence values, qualifiers, dependencies, coverage or source bindings were removed.

| Candidate | System UTF-8 bytes | Net overhead versus 6.124 | Large-value body | Outcome |
|---|---:|---:|---:|---|
| Initial zero/one text arrays | 690 | +549 | 6,030 | Blocked |
| Candidate 2, optional strings | 613 | +147 | 5,628 | Blocked |
| Compact version, intermediate instruction | 578 | +103 | 5,584 | Required gate fits; below preferred headroom |
| Selected compact instruction | **546** | **+71** | **5,552** | Preferred target met; **48-byte headroom** |

The selected instruction eliminates repeated wording; it still defines each account field, inference/abstention cardinality, optional empty text, current-packet aliases, qualifications, unverified authority, no tool/scope/S3 changes, and discriminating examination requirements. `d2_quality.GUIDE` is the authoritative instruction. Actual installed OpenAI SDK serialization through MockTransport matched the complete bytes; no external request was made.

| Fixture | 6.124 body | Selected body | Headroom |
|---|---:|---:|---:|
| Historical interpretation packet | 5,324 | **5,395** | 205 |
| Browser only | 3,399 | 3,470 | 2,130 |
| Registry persistence | 3,592 | 3,663 | 1,937 |
| Process/service | 4,518 | 4,589 | 1,011 |
| Filesystem without EVTX | 3,789 | 3,860 | 1,740 |
| Prefetch only | 3,523 | 3,594 | 2,006 |
| Mixed artifacts | 6,047 | 6,118 | -518, already oversized |
| Smaller mixed artifacts | 4,436 | 4,507 | 1,093 |
| Shared-path relationship | 4,558 | 4,629 | 971 |
| No supported relationships | 3,232 | 3,303 | 2,297 |
| Contradictory/incomplete | 4,670 | 4,741 | 859 |
| Large original value | 5,481 | **5,552** | **48** |
| Extensive qualifications | 7,096 | 7,167 | -1,567, already oversized |
| Oversized original value | 5,881 | 5,952 | -352, already oversized |
| Incomplete-only preflight fixture | 3,332 | 3,403 | 2,197 |
| No-material-conclusion preflight fixture | 3,258 | 3,329 | 2,271 |

The last two rows apply the measured fixed 71-byte envelope difference to their previously measured unchanged user bodies. The 13 main synthetic fixtures were individually measured and serialized through the SDK; the historical size is independently asserted by the Windows-spawn regression.

Additive complete-body partition for the large-value fixture:

- Serialized system string: **548 bytes** (546 content bytes plus JSON quotes).
- Serialized user string: **3,811 bytes**.
- Adapted response_format value, including strict schema wrapper: **1,053 bytes**.
- Remaining request keys, role/message punctuation, model and token fields: **140 bytes**.
- Total: **5,552 bytes**.

Adaptation removes **76 bytes** of unsupported uniqueItems metadata; uniqueness is still checked canonically. Evidence-related marginal contribution is **2,880 bytes**: the difference between serialization of the full user string and a diagnostic-only copy with supports/interpretations/relationships/qualifications/sources emptied. This is a measurement definition, not a production trimming operation. Remaining user bytes include the question, issue, binding and envelope. `tests/test_d2_quality_transport.py` reproduces partitions and adaptation/evidence measurements with blocked real sockets.

Every previously eligible representative fixture remains eligible. Already oversized complete bundles still fail closed. This is not a proof that every arbitrary future packet fits: final exact-body admission remains mandatory, and no implicit trimming or larger budget is introduced.

## Contracts and validation

`d2_quality.py` contains the new closed wire schema, strict local validator, lossless view adapter and canonical expander. The earlier d2c1 schema/expander remains intact.

- Outcomes: new_inference, competing_explanations, no_material_inference, insufficient_packet_support.
- Inferential outcomes require one or two accounts; competing_explanations requires two accounts or a nonempty alternative for its single account.
- Abstention requires zero accounts and a meaningful reason; it produces **zero hypotheses and zero invented next steps**.
- Account optional text may be exactly empty; whitespace-only, NUL and over-budget UTF-8 text are rejected.
- All supporting/contrary/interpretation aliases resolve in the current authenticated packet. Registered interpretation premises and mandatory qualifications retain the existing checks.
- Unknown fields, model-controlled factual statuses/tools/source replacements, duplicate aliases, malformed JSON, contradictory outcome fields and foreign request/packet bindings fail closed.
- A canonical quality response is bound to exact request_id and packet_digest. The terminal envelope separately verifies the original source/provider/model/body identity.

The parent reuses `d2.validate_response` with its frozen original context. Quality accounts become unverified proposal items; their discriminator and next_examination fields remain explicitly unexecuted model suggestions. The original S3 object is unchanged. `d2-quality-validation-v1` distinguishes the expanded quality result from legacy `d2-offline-validation-v1`.

This is structural/reference validation, **not** an unrestricted prose entailment detector. Unsupported authoritative fields are rejected; a sentence inside a hypothesis never becomes an established fact merely by passing validation. No subjective novelty filter silently deletes a valid account.

## Real provider integration and IPC

`ModelBackend.complete_d2` chooses the exact schema from the immutable instruction/versioned message profile. The cloud worker and guarded SDK client verify that same profile. The OpenAI adapter recognizes both exact application-owned schemas. Unknown/mixed profiles cannot substitute a different schema under the authorized body hash.

`d2_execution.prepare` defaults to d2q1 for the current workflow. Explicit internal `profile='d2c1'` retains legacy behavior for compatibility checks. `Prepared` includes the profile in its immutable seal; the child reconstructs the same profile, checks identity, then the parent expands and validates the response using that codec.

No change to the one-attempt grant, 5,600-byte HTTP limit, 1,024 output tokens, 60-second envelope, final cleanup reserve, zero lookups/retries/fallback, 32KiB terminal budget or 128KiB receiver ceiling.

The historical Windows-spawn quality abstention test transmits **906 bytes** using actual `d2_result` serialization, accepts no model hypotheses, preserves S3 NOT_ASSESSABLE and source hashes, reports one attempt/zero lookups, and confirms cleanup. Legacy 191,464 -> 1,094-byte IPC regression remains covered separately. The new schema does not resend historical assessment data through IPC.

## Issue relevance and purpose service

`d2_issues.inspect` adds a separate **d2-issue-review-v1** view. Historical issue IDs, preview contracts, candidate accounting, packet selection/dependency closure and planning ceilings are unchanged.

Review rows include source frontier/view, exact seed references, kind/purpose, binding, conservative relevance, ranking reasons, preview selection/deferral and packet feasibility. They distinguish:

1. Verified typed-objective relevance only for an already eligible, resolved typed mapping.
2. Exact technical referent: exact current original technical-field value in the question with word boundaries; short values require explicit quoting. Unicode values are supported without ASCII-only tokenization.
3. Contextual lexical overlap using Unicode word tokens, explicitly not semantic verification.
4. Unresolved relevance, never described as irrelevant.

Relationship relevance can inspect its registered endpoint clauses. Review order uses relevance, registered contradiction purpose, existing kind priority and stable ID. **This is review ordering, not implicit execution selection:** execution still requires an explicit issue ID. The existing bounded selector is not silently replaced, preserving historical packet identities and source digests.

A registered incompatible_recorded_field relationship is labeled examine_recorded_contradiction. Existing recorded-fact and comparison purposes remain. No new missing-discriminator or unresolved-source-link candidate is invented from unsearched evidence; where these structures are unavailable the view explicitly lists those purposes as unavailable. Such questions can still be proposed by the model as unverified examinations. Shared filenames/time proximity do not manufacture a source link.

All discovered issues remain visible. Only packets actually prepared by bounded preview get complete-body feasibility results; other rows say deferred/not_evaluated, not that they fit or lack relevance. Oversized selected packets remain listed.

## Primary and detailed results

`d2_presentation.view` returns **d2-quality-view-v1**, reusable by CLI or a future web UI. The primary renderer uses:

- Established: up to four deterministic facts/interpretations, with visible detail counts and display-shortening markers for long values.
- Suggested, not proved: unverified accounts or explicit abstention.
- Alternatives and discriminators, with assumptions labeled unverified.
- Contradictions and gaps: registered conflict count and packet-only coverage, never whole-case absence.
- Suggested next examination: never executed or authorized by this result.
- Coverage and authority: original S3, exact source run/frontier, omission accounting, provider/model, attempts/usage and cleanup.

Unique mandatory qualifications remain visible. Exact support duplicates collapse by source view, original EID, complete field semantics/value and timestamp semantics, retaining reference aliases. Different same-named records or SI/FN timestamps do not merge. Exact duplicate qualifications collapse, with full original applicability available in detailed packet data. Exact model proposal duplicates may collapse in the view; validated originals remain in details.

`details.packet` and `details.validated` preserve complete original provenance, values, source bindings and qualifications. Quality CLI JSON is explicitly versioned **d2-quality-result-v1**, containing both the exhaustive service result and this view. Discovery JSON is **d2-quality-discovery-v1**, containing the unchanged legacy preview plus issue review. Legacy application-service results retain their original contract. No JSON reader should treat a new wrapper as d2c1.

## Generic quality-review fixtures

The fixture contract tests and analyst-quality rubric are distinct. Canned outputs establish that safe abstention, alternatives and discriminators can be represented; they do not establish that OpenAI will produce better reasoning.

| Fixture | Permitted observation / abstention | Forbidden overclaim | Alternative and discriminating examination for analyst review |
|---|---|---|---|
| Process/execution | Recorded process/Prefetch fields; malicious purpose unresolved | Successful malicious objective | Routine process use; separately authorized command/session telemetry could distinguish activity |
| Registry persistence | Startup configuration recorded; launch unknown | Configured program executed | Stale/legitimate setting; execution records and configuration timing could distinguish |
| Lateral movement | Logon/service facts on recorded hosts; no proven bridge | Same actor moved between hosts | Independent administration; identity/session linkage could distinguish |
| Access/exfiltration | File and browser portal metadata; transmission unknown | Data uploaded or stolen | Unrelated browsing; authorized transfer/endpoint records could discriminate |
| Benign administration | Scheduled-looking command and setting | Benign intent established | Malicious use of administrative tooling; authorized job provenance and commands could discriminate |
| Contradictory sources | Different recorded states/host assertions | True same-object contradiction without identity support | Different objects/epochs; source/object identity reconciliation needed |
| Incomplete evidence | File metadata; missing process coverage | No execution occurred | Either execution or no execution; complete authorized execution coverage would be needed |
| Unrelated activities | Co-present browser/Registry facts | Causal relationship | Independent activities; only a supported identity/session bridge could distinguish |
| No material conclusion | Unknown setting; abstain | Incident reconstruction from an unexplained field | No useful discriminator may be available; abstention is valid |

Large-field, extensive-qualification, mixed-family, Prefetch-only, no-relationship and unrelated host/source cases are covered by the generic packet suite. Pre-registered caveats are in `QUALITY_CASES` in `tests/test_d2_quality.py`. Independent live review should judge whether an account offers a useful distinction, alternative or discriminator rather than a restatement. No numerical model-quality improvement is claimed.

## Compatibility and tests

Historical checks compare provider-free D2 preview/reconstruction with committed 6.124 for all three copied 6.118 runs and the 6.111 run; all original source files remain read-only. The known zero-analysis retrospective D1 Cross-view explanation limitation remains outside this change.

Test counts and final hash checks are recorded in the final validation note below. The initial development run exposed two legacy canned-response fixtures routed through the new default profile; those fixtures now explicitly request d2c1 and preserve their original assertions. A separate source-encoding error introduced while editing the CLI was corrected before the passing regression run. No forensic/security assertions were weakened.

No live model request, live database access, historical transcript edit, permission change, automatic retry/fallback, multi-packet/multi-round execution, persistence, commit or push was performed.

## Manual acceptance after installation

```powershell
Set-Location C:\tmp\locard260927\locard
.\.venv\Scripts\python.exe -m pip install -e .
.\.venv\Scripts\python.exe -c "from importlib.metadata import version; print(version('locard-forensics'))"
# Expected: 6.125
$root = 'C:\tmp\locard-diagnostics\6.118-live'
$run = '6ad0c85499564406aa4d949f3b0e72e5'
$issue = 'd81869143ab5f3a355285bd79802d93912491834bc4f602c0a5fda6fd28739e7'
# Provider-free issue review:
.\.venv\Scripts\python.exe -B -m forensic_assistant.investigation_ai.d2_reasoning $root $run --exploratory
# Provider-free exact authorized-request preview; historical fixture should be 5,395 bytes:
.\.venv\Scripts\python.exe -B -m forensic_assistant.investigation_ai.d2_reasoning $root $run --exploratory --issue $issue --json
# Optional provider-free Windows-spawn regression with canned response:
.\.venv\Scripts\python.exe -B -m pytest -q tests/test_d2_quality.py::test_quality_windows_spawn_historical
```

Only if you separately choose to authorize a new live request:

```powershell
.\.venv\Scripts\python.exe -B -m forensic_assistant.investigation_ai.d2_reasoning $root $run --exploratory --issue $issue --execute
```

Review the displayed provider/model, source, issue and budgets before answering y. The response may appropriately abstain. Assess its usefulness separately from schema acceptance. Use `--execute --json` instead for the exhaustive versioned result, but remember that running the command again is a new paid authorization, not a way to retrieve a saved result. D2 remains ephemeral.

## Final validation record — 2026-11-10

Inspected baseline: main, `c898fa07a931316beb28823766fa5a1ee43bbbeb` (6.124). These are uncommitted working-tree changes; `pyproject.toml` now specifies 6.125. The quality authorized preview is separately versioned `d2-quality-authorized-preview-v1` and identifies its response contract; legacy previews retain their contract.

Recorded focused runs (overlapping sets, not additive):

| Check | Recorded result |
|---|---|
| Quality, supervised execution/result, preview, B1/B2, OpenAI schema and explanation replay/compaction regressions | 321 passed in 154.46 seconds |
| Legacy and quality actual OpenAI SDK serialization through MockTransport | 35 passed in 10.18 seconds; one upstream Pydantic ReadOnly warning |
| Final quality contract/routing/Windows-spawn check | 57 passed in 13.97 seconds |
| Windows spawn terminal result for historical packet and canned abstention | 906 serialized IPC bytes; original S3 remains NOT_ASSESSABLE |

The broad run preceded the final competing-account constraint, versioned preview and proposal-ID namespace refinements; the final 57-test quality run covers those refinements. No full-suite run occurred.

Historical provider-free reconstruction used the three copied 6.118 runs plus copied 6.111 run ec81a1af5b1f471ca4f3a4c0bb917fa2. SHA-256 comparisons of all eight manifest/events files were unchanged before/after. D2 previews matched the committed 6.124 implementation for all four runs. B2 and D1b reconstruction remained compatible. The zero-analysis run retained its existing retrospective D1 Cross-view explanation failure; it was not repaired or hidden. These checks establish preservation during this task, not historical integrity before the available baselines.

Reconstruction D2 digests:

| Run | Digest |
|---|---|
| 6.118 / 6ad0c85499564406aa4d949f3b0e72e5 | cb1308c5873137b2a6feddcfbdbdca0cf7ef72e19bdea358e51c6df5680ab500 |
| 6.118 / ffdabecc9ded47e6acd5f4977fa3c2fa | 8717086a7e6cf2f18832dfb898c4c604e6001c16d9040e9fbaaffe456457ba2b |
| 6.118 / 08cfd054f85a4a36b8520832427201c3 | 18348f984e0c23df4e00d4e43c8d3930a550eef062951c1aa7c8d5b14b444cdd |
| 6.111 / ec81a1af5b1f471ca4f3a4c0bb917fa2 | f3a6fed1a18f11e9b2395ef5e4b5025befa7cb066d300842a7bc7fa7744a9fa4 |

Changed files (repository-relative):

- `pyproject.toml`: version only.
- `forensic_assistant/investigation_ai/d2_quality.py`: new wire/canonical quality contract.
- `forensic_assistant/investigation_ai/d2_issues.py`: transparent deterministic issue review.
- `forensic_assistant/investigation_ai/d2_presentation.py`: reusable concise/detail projection.
- `forensic_assistant/investigation_ai/d2.py`, `d2_execution.py`, `d2_wire.py`, `d2_reasoning.py`: validation, supervised profile, exact serialization and CLI integration.
- `forensic_assistant/ai/backend.py`, `cloud_worker.py`, `d2_transport.py`, `openai_schema.py`: exact quality schema routing through existing supervised OpenAI adapter.
- `tests/test_d2_quality.py`, `tests/test_d2_quality_transport.py`: synthetic safety, generic packet and SDK measurements.
- `tests/test_d2_execution.py`, `tests/test_d2_result.py`: explicit legacy profile for existing legacy assertions.
- This document: retained failed gate history, final measurements and acceptance procedure.

New files and this normally ignored document are visible in the Git diff via intent-to-add. No release commit or push was made. Live reasoning usefulness remains pending analyst acceptance.

Final legacy preview/result regression after restoring the unchanged Unicode label: **69 passed in 35.88 seconds**. Final `git diff --check`: passed (only Git's existing LF/CRLF conversion notices). Working tree contains the 17 listed intended files; HEAD is unchanged. No commit or push.

# Locard 6.130 — Cross-artifact investigative readiness

Assessment date: **2026-11-13, America/Chicago**. Source revision:
`46b9226fc8a04f9bbd40c7f945571f4dddc2814e` (`AI usefulness 2`), branch
`main`. The working tree was clean before this assessment. Application version
in `pyproject.toml` is **6.130**. Only this report and its exact `.gitignore`
exception are added. The previous implementation report is unchanged.

## 1. Recommendation

**GO for one separately authorized live request, narrowly evaluated as a
pathname-correspondence investigation.** The packet contains meaningful original
Browser and MFT identifying fields, their recorded timestamp context, explicit
source uncertainty, and enough information to propose a discriminating
examination. This is more than byte fit or valid JSON shape.

**Not a go for a full-incident explanation, common-file identification, security
event attribution, or a successful-execution conclusion.** The current packet
does not contain the EVTX command line or recognized ASR interpretation. Four
represented artifact families do not make those missing premises available.

No provider request was made. This recommendation does not authorize execution.
No blocking implementation defect was established for this narrowly defined
test. Semantic usefulness remains an empirical live-acceptance question.

## 2. Reconstructed source and exact request

Read-only copied history:

```text
C:\tmp\locard-diagnostics\6.118-live
6ad0c85499564406aa4d949f3b0e72e5
```

Exact question:

> What evidence connects the recorded download and subsequent filesystem observations? Which links remain hypotheses and what additional examination would discriminate?

The assessment called `d2_cross.preview()` twice independently with an explicit
in-memory OpenAI / `gpt-6.1-sol` configuration. It did not load/change installed
provider preferences, authorize execution, or open SQLite. `d2_cross.prepare()`
also constructed and validated the frozen request for a synthetic response check.

| Identity / measurement | Result |
|---|---|
| Request policy / wire version | `d2-cross-artifact-request-v1` / `d2x1` |
| Provider / model | OpenAI / `gpt-6.1-sol` |
| Request ID | `e314a77e7feeecf15aa030274f941a66dff7cbe8dd84225521bf66b073583c65` |
| Packet digest | `c7e164375606ee467d7e9787466c8c039677cfa9713fb91f3d095060cbb395f8` |
| Complete-body SHA-256 | `19b7020921b08d47885812c16a92778eb8bb3dd2c51859b93e6ae8035f48c4b5` |
| Schema SHA-256 | `d209cc7375f2427a0ccb5cf9b91adc1dc3ff25a625ab1615bd15530803092517` |
| Complete serialized body | **16,268 / 16,384 bytes**; 116 bytes spare |
| Historical event head | `8650ea8df0ab519d12010d2fef37e5798cf368d4bfa673b73e33d1503e35c699` |
| Historical view ID | `8d01618db43a4fbd986e9a3ca358b2c8` |
| Independent previews | Entire returned preview objects equal |
| Provider requests / evidence lookups | Zero / zero |

`d2.open_history()` checks redirection, loads the manifest/hash chain, invokes
`autonomous.reconstruct()`, validates decomposition, rebuilds S1/S2 state, and
checks the source anchor again. `Prepared.check()` verifies the frozen content,
wire expansion, typed schema, original support authority and serialized body.
These checks succeeded. This authenticates the recorded investigation contract;
it does not revalidate the original acquisition or the current case database.

Manifest and event-file SHA-256 values were unchanged across this assessment:

```text
manifest.json 23a6e2c496b2e34aa20810e08c152e37b8b51afacde0a3dba1a074e16e7e350f
events.jsonl  a943a1e2bf39d8f2aafca6f374804f1cefb20b080bc2cdf0a46d2c050625ac28
```

## 3. Admission means input eligibility, not a forensic answer

Observed values:

```text
fits = true
investigative_admission = true
context_sufficiency.pattern = recorded_pathname_comparison
context_sufficiency.status = comparison_inputs_present
required/present = identifying_fields_from_two_distinct_records,
                   recorded_time_context_for_both
missing / available-but-omitted / unavailable roles = [] / [] / []
```

Top-level `context_sufficiency`, `selection.sufficiency`, and
`issue.context_sufficiency` are equal. The latter is provider-visible.

Source-confirmed checks in `d2_cross.History.preview()` include authenticated
rehydration, complete registered support, different evidence records,
recognized identifying roles, timestamp context for both identifying records,
atomic dependency closure, count/byte bounds, and at least two represented
artifact families. The role classifier operates on original field pointers and
registered labels, not on historical model prose. Its question pattern is a
limited deterministic English heuristic, not comprehensive question understanding.

`investigative_admission` specifically means the recognized comparison is not
missing required input roles; it is not independently a complete execution gate.
Byte fit, trusted reconstruction, provider restrictions and fresh authorization
remain separate controls. Unsupported question patterns can have
`question_sufficiency_not_established`; do not generalize this positive result to
arbitrary questions.

The new question and original S3 assessment remain `NOT_ASSESSABLE` under S3's
registered mapping rules. This is compatible with an exploratory hypothesis
request, not an upgrade of deterministic S3 authority. Common volume/host/file
identity, source clock agreement and the meaning of "subsequent" as physical
event order remain unresolved. None is silently certified by admission.

## 4. Actual disclosed support

All twelve source-bound field values were inspected through the canonical packet
and provider-visible tuple encoding. `d2_wire.expand_view()` round-trip validation
passed. Aliases below are local to this exact request; the canonical packet
retains original evidence IDs, source bindings and lineage. The wire deliberately
uses record/clause aliases and a packet binding instead of repeating every opaque
identity; registered relationship semantics still carry their original bindings.

| Alias | Record / source | Field | Recorded content / meaning |
|---|---|---|---|
| O1 | E1 / P1 Browser | `/target_path` | `C:\Users\cwade\Downloads\free printable five crowns score sheet pdf.zip` |
| O2 | E1 / P1 Browser | `/referrer` | `https://artistichairlounge.com/` |
| O3 | E4 / P6 MFT | `/objects/1` | `\Users\cwade\AppData\Local\MICROS~1\Windows\INetCache\IE\1R4D176N\qon[1].wsc` |
| O4 | E1 / P1 Browser | `/url_chain/1/url` | `https://unitednetsolutions.org/fd/free%20printable%20five%20crowns%20score%20sheet%20pdf.zip` |
| O5 | E6 / P2 Prefetch | `/executable` | `EXPLORER.EXE` |
| O6 | E2 / P4 EVTX | `/original_event_data/0/value` | `D1E49AAC-8F56-4280-B9BA-993A6D77406C`; original name `ID`, ordinal 3, truncated false |
| O7 | E1 / P1 Browser | `/url_chain/0/url` | `https://unitednetsolutions.com/fd/free%20printable%20five%20crowns%20score%20sheet%20pdf.zip` |
| O8 | E2 / P4 EVTX | `/event_id` | 1121 |
| O9 | E1 / P1 Browser | `/timestamps/1/utc` | `2026-09-30T14:05:26.265428000Z`, Browser DownloadStart |
| O10 | E5 / P3 MFT | `/objects/1` | `\ProgramData\baje.ps1` |
| O11 | E3 / P5 MFT | `/timestamps/0/utc` | `2026-09-30T14:05:26.269914600Z`, MFT FN Created, slot `attribute:56:Created` |
| O12 | E3 / P5 MFT | `/objects/1` | `\Users\cwade\Downloads\free printable five crowns score sheet pdf.zip` |

O1 and O12 share a pathname tail but are **not equal original strings**. No drive
prefix removal or normalization was applied to the packet. The model can propose
correspondence while explicitly considering another volume, a copy or an
independent same-named file. It cannot establish common file identity from this.

Browser and MFT source context has unknown hostname/volume root. The shared source
ID is retained with its analyst-supplied/generated basis; it is not independent
proof of co-location. EVTX records an artifact-derived hostname, which does not
retroactively establish the other records' hosts. The packet preserves these
differences.

R1 compares **recorded UTC coordinates** O9 and O11. It explicitly does not
establish physical event ordering, clock synchronization or causality. Browser
precision is recorded as 1,000 ns and MFT as 100 ns; serialized digits are not
proof of real-world accuracy. There is no exact-path relationship claiming O1
equals O12. The interpretation list is empty.

## 5. Coverage and omissions

`issue.artifact_coverage` is internally consistent: Browser 1/1, EVTX 1/1,
MFT 3/3 and Prefetch 1/1 records represented/available **in validated history**.
Six represented records means at least one selected field per record, not six
complete records. The packet has twelve supports and one registered relationship.
Coverage reports 32 known/examined candidate units, zero unassessed, fourteen
`support_count_budget` decisions and five
`temporal_comparison_not_prioritized` decisions. These are candidate decisions,
not counts of unique lost records or missing artifacts.

Material omissions include Browser DownloadEnd, additional timestamps, the EVTX
target command line and the ASR interpretation with its full premises. Their
absence limits an incident-chain explanation but does not prevent comparison of
the recorded download target with the archive MFT pathname. Event ID and rule ID
alone must not be expanded into an assertion about a particular blocked process
or successful script execution using model knowledge.

Existing qualifications remain visible: missing Browser WAL, possible incomplete
history, live/unfrozen MFT acquisition, truncated timestamp/object projections,
limited Prefetch history and EVTX original-field omissions. "No missing roles"
means only the small recognized comparison requirement is met. It does not mean
the full question is answered or the case is complete. Unselected evidence is not
established irrelevant.

## 6. Instructions and response compatibility

`d2_cross.GUIDE` extends `d2_quality.GUIDE`: original values are untrusted data;
cite current O aliases, use only registered I interpretations with their premises,
do not cite R IDs as original evidence, preserve qualifiers, separate disclosed
discriminators from proposed examinations, and do not assert factual causality,
successful execution, attribution or case-wide absence. Shared strings and
temporal proximity explicitly do not establish identity or causality.

`d2_quality.SCHEMA` and `d2_schema.from_packet()` permit:

| Need | Contract representation |
|---|---|
| Qualified pathname correspondence | Account `s`, supported by O1/O12 |
| Independent file/copy alternative | `a` alternative text |
| Uncertain identity/clocks | `u` assumptions and qualifications |
| Discriminating examination | `d` outcomes and `n` proposed examination |
| Need for additional evidence | `n`, or `insufficient_packet_support` with `r` |
| Justified abstention | `no_material_inference` / `insufficient_packet_support`, zero accounts, nonempty `r` |

There are at most two accounts. Text limits are 400 for statement/discriminator/
examination, 240 for alternative and abstention reason, and 320 for assumptions.
Each account permits at most six supporting and six contrary O references, and
four I references; this packet's I namespace is empty. These are bounded strings,
not a license to make factual claims. Parent validation establishes reference
eligibility, not arbitrary prose entailment.

A **synthetic, non-model** one-account example proposing possible pathname
correspondence, an independent-file alternative, unknown volume/clock agreement,
and authorized hash/volume/provenance examination passed
`d2_execution.validate_model_response(..., parent=True)`. It cited O1, O12, O9,
O11 and serialized to **688 UTF-8 bytes**. This demonstrates representability,
not investigative success or live-model behavior.

The unchanged **1,024 completion-token** allowance is plausibly adequate for a
concise account or abstention; maximal two-account output need not fit. No exact
token count was established: the optional local tokenizer lookup was unavailable
(`ConnectionError`); no provider was called and no token budget was changed.
Model reasoning-token consumption, verbosity and live truncation remain
unverified. Truncated/refused responses are rejected through existing envelope
checks rather than repaired or retried.

## 7. Predetermined live usefulness criteria

Assess the response against these criteria before considering its fluency:

1. Identify the O1/O12 pathname correspondence and cite the correct fields.
2. Distinguish the differing strings and possible common identity; do not silently
   assign a drive/volume/host to the MFT record.
3. If using O9/O11, name DownloadStart versus FN Created and preserve clock and
   physical-order uncertainty. Do not turn proximity into causality.
4. Separate disclosed facts from omitted command-line/interpretation context.
5. Offer a plausible alternative, such as a copy or independently acquired
   same-named file.
6. Propose a specific discriminating examination: independently verify volume
   mapping and compare recoverable archive content/provenance, with contrasting
   outcomes and required evidence identified. Do not imply it was performed or
   that those artifacts are available.
7. Avoid claims of successful execution, completed compromise, or an established
   security-event chain.

One useful, qualified alternative and examination is sufficient; no prescribed
wording or complete attack narrative is required. A safe abstention is a valid
operational result but does not itself demonstrate added investigative usefulness.
A schema-valid causal story unsupported by these fields fails acceptance.

## 8. Execution boundaries confirmed in source

| Boundary | Implementation evidence |
|---|---|
| Fresh exact-request approval | `d2_reasoning.main()` approval prompt; `d2_execution.authorize()`, `_Permit` bind frozen request/config/source/view/packet/schema/limits; sealed single-use permit |
| One attempt, one round, no lookups/retries | `d2_execution.LIMITS`, `execute()`, `_child()`; no retrieval tool path; no automatic continuation |
| Exact OpenAI route, no fallback | `Prepared`, child configuration comparison, `ModelBackend.complete_d2()`; `ai/d2_transport.guarded_client()` fixes endpoint/method/body and blocks a second send |
| No hidden readiness call | `ModelBackend.complete_d2()` directly uses the cloud request path |
| Deadline | Approval +55 seconds for supervised startup/work/parent validation; approval +60 for containment, five seconds reserved; permit expires before late dispatch |
| Cancellation/cleanup | Parent cancellation polling and KeyboardInterrupt handling; `Launch`, `WorkerJob`, `_stop`; unconfirmed termination raises `CLEANUP_LIMITATION` |
| IPC bounds | `d2_result.LIMIT = 32768`, `RECEIVE_LIMIT = 131072`; child sends bounded response, not evidence context |
| Independent parent validation | `execute()` parses bound terminal envelope and calls `validate_model_response(parent=True)` against frozen original support |
| Diagnostics / usage | `d2_diagnostics`, bounded terminal metadata, explicit unknown exposure/usage states; D2 raw capture disabled in backend |
| S3 authority | Original assessment retained; model accounts are unverified proposals; no case or journal writes by this ephemeral workflow |

The 60-second allocation begins at approval; provider-free preview/preparation
before approval is not part of it. Source planning has its existing separate
bounds. These are source-confirmed control mechanisms, not a guarantee of OS
scheduling or proof of cleanup for a live request that has not occurred.

Relevant existing regressions include `tests/test_d2_cross.py` exact SDK
serialization, Windows supervisor roundtrip, timeout/expiry, parent distrust of
worker acceptance and source mutation tests, plus `test_d2_execution.py`,
`test_d2_transport.py`, `test_d2_selection.py`, and typed-reference tests.
No pytest suite was rerun in this assessment. The analyst reports **47 cross tests
and 355 existing D2 regressions passing with both pytest hosts exiting normally**
in the independent installation. This is user-reported execution evidence and
supersedes the earlier development-host shutdown concern for that environment;
it does not predict live cleanup or model quality.

## 9. Exact manual acceptance command

Only after separate analyst authorization to perform one paid provider request,
from the installed test checkout with OpenAI / `gpt-6.1-sol` already selected:

```powershell
.\.venv\Scripts\locard.exe --version
$root = 'C:\tmp\locard-diagnostics\6.118-live'
$run = '6ad0c85499564406aa4d949f3b0e72e5'
$question = 'What evidence connects the recorded download and subsequent filesystem observations? Which links remain hypotheses and what additional examination would discriminate?'

# Provider-free review first; compare the three digests and 16,268-byte body.
.\.venv\Scripts\python.exe -m forensic_assistant.investigation_ai.d2_reasoning $root $run --cross-artifact --question $question --json

# One request only if the exact provider/model/source/budget prompt is approved.
.\.venv\Scripts\python.exe -m forensic_assistant.investigation_ai.d2_reasoning $root $run --cross-artifact --question $question --execute
```

Confirm version 6.130 and the expected provider/model before answering `y`. If
identity, bytes or source differ, stop and review the changed request. Do not run
the execute command a second time merely to obtain JSON: that creates another
authorization/request. Capture the first console result manually; the workflow
is ephemeral and does not persist a new investigation transcript. Using `--json`
on that one execute invocation is an alternative if structured diagnostics are
preferred (the approval prompt still occurs).

## 10. Remaining limitations and assessment scope

- Structural sufficiency is not calibrated semantic relevance or proof that the
  model will use the supplied evidence well.
- Six partially represented records are the historical disclosure frontier, not
  a search of all case evidence. Selection has only 116 bytes of remaining margin.
- O6/O8 are insufficient for a grounded ASR/command-line narrative. Do not reward
  the model for filling the gap from general knowledge.
- One concise account is representable, but 1,024-token live completion and the
  60-second execution envelope remain acceptance measurements.
- Citation validation cannot prove entailment of arbitrary hypothesis prose;
  analyst evaluation against section 7 remains necessary.
- No current database, original transcript, permissions or configuration were
  accessed/changed. Copied transcript content was read only. No provider request,
  subprocess investigation execution, new pytest run, commit or push occurred.
- `git diff --check` and the explicit new-file whitespace check passed. Git only
  noted its normal LF-to-CRLF conversion policy. No production correction is
  recommended before this narrowly scoped live usefulness test.

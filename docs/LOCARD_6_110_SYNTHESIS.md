# S4-B2: authorized incremental synthesis

Implementation scope: B2 only. Application version is owned by `pyproject.toml`.
No S4-C, autonomous search, refill, restart, executive report or new report-import
authority. Live OpenAI acceptance is pending; implementation validation uses
synthetic records, mock providers and disposable test processes.

## Opt-in and limits

`briefing --investigate latest --autonomous --decompose --synthesize` requires
the existing acknowledged, investigation-ready OpenAI configuration. The initial
approval displays repeated original-evidence disclosure and separate allocations:

| Resource | Ceiling |
|---|---:|
| Analysis / decomposition / synthesis attempts | 6 / 1 / 2 |
| Total model attempts | 9 |
| Evidence lookups / refill / retries | 6 / 0 / 0 |
| Investigation steps | 10 |
| Total time from authorization | 300 seconds |
| Model work cutoff | 280 seconds |
| Finalization / containment reserve | 15 / 5 seconds |
| Synthesis request subdeadline | 30 seconds, further clamped to model cutoff/expiry |
| Final system/user content per request | 5,600 UTF-8 bytes |
| Output per request | 1,024 tokens |

`investigation-s4-b2-authorization-v1` and `incremental-s4-b2-v1` are separate
from old grants/engines. Old or historical grants cannot authorize this workflow.
Allocations do not transfer. Zero, one or two synthesis calls may run depending on
remaining resources and usable packets; these maxima are not completion promises.
Existing source/EID/family/time eligibility and bounded full-record context remain.

`supervision.run` reserves the final five seconds inside the total deadline for
parent containment; the controller gets at most 295 seconds. Model work is clamped
to 280. `SynthesisDeadline` uses request ordinal/start and cannot be renewed by
ordinary progress messages. Its clock includes journal preparation after packet
planning. The parent contains blocked model/journal/controller work and preserves
committed checkpoints. Unconfirmed OS cleanup remains a limitation, not a guarantee
that an unresponsive kernel can be forced to return on time. No 305-second envelope.

## Request and response authority

`synthesis_consumer.py` reuses `packets.plan` with a B2 encoder inside the same
five-second/512-resolution planning operation. B1 preview diagnostics keep their
existing encoding and behavior. B2 never dispatches B1's LOCAL PREVIEW instruction.
The final `synthesis-request-v1` contains original question/view/grant, selected
objective and binding status, exact original fields, clause references, source and
lineage dictionaries, interpretation premises, relationship endpoints, caveats,
selection digest and omission counts. O/I/R aliases have complete same-request
mappings. The support-body digest is distinct from the digest of final messages;
the response binds to request ID and support-body digest. No circular self-hash.

Exact final content bytes include instructions and escaped metadata. Whole bundles
are repacked/omitted; no original value or caveat is newly truncated. A planning
limit or no usable bundle prevents dispatch. Prior model prose is **not included**
in this first slice (optional in the approved design); nonempty `prior_refs` reject.
Second-packet authority comes from deterministic planning, not the first response.

Unbound objectives use explicitly exploratory organization. `execute`, generic
script roles and provisional polarity are never repaired or certified by model
suggestions. Greedy packing remains imperfect; omitted support is not irrelevant.
No packet is required to contain all records or all objectives.

`synthesis-proposal-v1` is a closed canonical schema, separate from FINAL and
analysis deltas: at most four items/response, eight units/run; 16 KiB raw and
canonical UTF-8 ceilings. Item types: group, relationship candidate, hypothesis,
question and next objective. Every item cites 1–6 current supports; optional
interpretation/relationship lists are bounded to four each. Local IDs are unique
ASCII strings up to 16 characters. Labels are at most 160 characters; relationship
rationale/questions/next objectives 320; hypothesis statements 400, alternatives
320 each (one or two required), uncertainty 240. Unknown fields/status/confidence
and unsupported predicates reject atomically. No tools or authorization fields.

Validation checks strict JSON, canonical shape/uniqueness, exact request/digests,
current aliases, original S1 values/source/lineage/view, full interpretation and
relationship closure, and existing S2 rule recomputation. Citations do not establish
semantic entailment. Relationship candidates may link existing independently
validated S2 units; rationale remains unverified. Other prose—including misleading
theme headings—stays in an explicitly unverified section and never enters factual
findings, deterministic S3 answers or search inputs. Hypotheses require alternatives.

The exact OpenAI schema is recognized separately in `openai_schema.py` and backend
preparation. Item alternatives are adapted recursively. `uniqueItems` is omitted
only on wire and remains enforced locally. All B2 canonical fields are required;
nullable placeholders are not needed or accepted for them. Existing optional/null
translation for other contracts remains. Production uses the prepared worker
backend descriptor, so it cannot initiate readiness probes under this grant.
Ordinary 1,024-token output and zero SDK retries remain enforced. Other providers
are preserved but not enabled for B2.

## Durable states and partial failures

Each slot journals `synthesis_prepared`, `synthesis_attempt`,
`synthesis_response`, then `synthesis_decision`, or a bounded failure. Prepared
messages are not exposure. A charged attempt means possible exposure, not proof
of successful network delivery. A response acknowledgment is distinct from an
accepted proposal. Unknown usage is not zero; partial usage remains identifiable.

Before dispatch, reserve 96 KiB within the existing nonterminal cap; do not consume
the 512 KiB terminal reserve or raise the 4 MiB journal limit. Prepared payloads
are bounded to 16 KiB and accepted decisions to 30 KiB; responses retain at most
16 KiB raw UTF-8 (JSON escaping fits the cycle allowance). Oversized canonical
responses/decisions reject rather than accepting partial items. Append failure
before intent prevents dispatch; uncertain post-attempt outcomes are not retried.

Only a durable accepted decision updates `synthesis-state-v1`. Stable identities
bind request/view and exact item; semantic duplicate links use resolved originals,
not model global IDs. Competing hypotheses coexist as unverified. No overwrite or
promotion into fact. A bad first response stops synthesis; a failed second retains
the first. Cancellation and parent termination preserve committed/checkpointed
partial state; the journal remains the durable record. A terminal append failure
can leave a valid but incomplete journal and cannot certify completeness.

The synthesis status/attempts/omissions are separate from analysis termination.
Prepared-but-interrupted and possible-dispatch states remain explicit. Bounded
completion is not a complete forensic investigation. Full lineage is structured
diagnostic data; default output labels model text and its evidence references.

## Replay and acceptance commands

After the analyst installs the development release in the test checkout:

```powershell
.\locard.ps1 --version
```

Expected installed version: `Locard 6.110`. No installed metadata refresh is
performed by this implementation task. From the selected case's interactive prompt:

```text
briefing --investigate latest --autonomous --decompose --synthesize --question "What evidence supports the suspected sequence, and did the PowerShell script execute?"
```

The existing saved assessment supplies its approved source/time scope. Inspect
the displayed sources/window/provider/model before approving. Use explicit
`--start` and `--end` only when intentionally choosing another permitted window.
Do not expect two synthesis calls if analysis consumes the available time.

After the live run, use the actual run ID and a readable transcript-copy parent:

```powershell
$runId = Read-Host 'Actual B2 investigation ID'
.\.venv\Scripts\python.exe -m forensic_assistant.investigation_ai.synthesis `
  C:\tmp\locard-diagnostics $runId --synthesis-proposals
.\.venv\Scripts\python.exe -m forensic_assistant.investigation_ai.synthesis `
  C:\tmp\locard-diagnostics $runId --synthesis-proposals --json
```

No run ID is invented here. If the copy is nested further, use its actual parent.
Replay validates original accepted analysis, B2 request materialization, transition
order, current membership, proposals/decisions and S3/S4 terminal binding. It never
opens a live case or invokes a provider. Incomplete journals show incomplete
synthesis, not successful dispatch/acceptance. Hash integrity is not independent
provider transport attestation or current-case equality. Existing report-import
restrictions remain; restart/recovery execution is not introduced.

## Focused verification

`tests/test_synthesis_consumer.py` covers grant profiles, mock 6+1+2 execution,
no additional lookups, exact bytes/schema, atomic bad-reference rejection, current
original substitution, registered ASR/S2 closure, invalid causal predicates,
unverified malicious headings, duplicate/competing proposals, no retries, budget/
expiry and append failure, cancellation, repeatable replay and real parent process
timeout/cleanup. Existing S1–S4-A, disclosure, OpenAI, startup and completion-deadline
regressions accompany it. No live provider or real evidence access is used.
Manual live acceptance is still required. No full suite, commit or push occurs
before that acceptance.

Recorded development results: expanded focused regressions **308 passed in 81.36
seconds**; subsequent packet/presentation/schema regressions **169 passed in 35.31
seconds**; final targeted consumer/decomposition run after replay/accounting fixes
**93 passed in 25.26 seconds**. These are overlapping focused runs, not a summed
unique-test count or a full-suite result. `git diff --check` and new-file whitespace
checks passed. Real disposable-process testing confirmed parent synthesis timeout
despite progress traffic and confirmed that the test child exited. OS-level
cleanup limitations remain explicit. Installed metadata is refreshed by the
analyst's installation, not by changing another version constant.

Changed files (repository-relative):

- `forensic_assistant/investigation_ai/synthesis_consumer.py`: new B2 materializer,
  schema, grounding, durable consumer, reducer/replay and unverified presentation.
- `forensic_assistant/investigation_ai/packets.py`: reuse existing bounded planner
  through an optional encoder; legacy preview output unchanged.
- `forensic_assistant/investigation_ai/autonomous.py`: explicit opt-in, budgets,
  post-analysis synthesis, checkpoints and new-engine replay routing.
- `forensic_assistant/investigation_ai/autonomous_policy.py`: exact new grant.
- `forensic_assistant/investigation_ai/supervision.py`: parent subdeadline and
  containment reserve inside the total envelope.
- `forensic_assistant/investigation_ai/decomposition.py`: B2 journal/resource checks.
- `forensic_assistant/investigation_ai/presentation.py`: distinct B2 partial-result
  wording and unverified section.
- `forensic_assistant/investigation_ai/synthesis.py`: provider-free saved-proposal diagnostic.
- `forensic_assistant/ai/openai_schema.py`: exact new schema adaptation.
- `forensic_assistant/ai/backend.py`: B2 investigation preparation classification.
- `forensic_assistant/briefing_cli.py`: strict `--synthesize` option requirements.
- `forensic_assistant/assessment_handoff_cli.py`: authorization display and forwarding.
- `tests/test_synthesis_consumer.py`: focused synthetic and containment regressions.
- `pyproject.toml`: sole application-version update.
- `README.md`, `.gitignore`, `docs/LOCARD_6_110_SYNTHESIS.md`: documentation and one
  narrow source-document ignore exception.


## 6.111 corrective release: byte contracts and partial synthesis

The live 6.110 analysis rejected `request.answer.unknowns[2]`: 200 Unicode
characters occupied 206 UTF-8 bytes. The OpenAI JSON Schema validator correctly
counted characters; `investigation_ai/contracts.py:validate` correctly enforced
its stricter byte ceiling. No evidence-grounding failure was established.

### Authoritative string constraints

All strings accepted by `contracts.validate` must be nonblank and NUL-free.
The following limits are UTF-8 bytes, unchanged by this correction. Arrays retain
their existing cardinality/uniqueness rules; identifiers retain their further
syntactic and disclosure checks.

| Contract fields | Maximum UTF-8 bytes |
|---|---:|
| FINAL observed[].evidence_id; hypotheses[].evidence_ids[]; detections[] | 160 |
| FINAL observed[].field | 256 |
| FINAL interpretations[]; relationships[] | 80 |
| FINAL hypotheses[].statement | 400 |
| FINAL hypotheses[].alternatives[]; unknowns[] | 200 |
| Tool proposal reason | 256 |
| Shared hostname, username, process, path, ip filters | 1024 |
| Shared start/end; detections start/end | 40 |
| Anchor evidence_id | 160 |
| search_evidence evtx_text / evtx_after | 256 / 1024 |
| semantic_search query | 1000 |
| around/investigate_evidence timestamp_slot | 128 |
| detections rule_id | 64 |

Closed enums are restricted to their registered literals (the validator's default
1024-byte ceiling adds no practical freedom). The tool-result envelope also uses
160-byte original IDs; it is application data, not model prose. Other nested
artifact projections keep their own existing validation.

B2 is distinct: `synthesis_consumer.proposal` uses JSON Schema character limits
plus unchanged 16-KiB raw and canonical response byte ceilings, not the analysis
field-byte validator. Its string maxima remain: local_id and O/I/R aliases 16;
prior refs, request/packet IDs and relationship endpoints 64; group labels 160;
relationship rationale and questions/next-objective text 320; hypothesis statement
400, alternatives 320, uncertainty 240. Existing membership, exact identity,
ASCII local-ID, dependency, cardinality and decision-size checks still apply.
Do not reinterpret historical B2 fields as new per-field byte contracts.

`ai/openai_schema.py:_wire` now annotates every analysis string maximum with its
local byte meaning while keeping the actual character-valued `maxLength` intact.
The canonical schema is unchanged. `autonomous.packet` gives concise prose targets
(unknowns/alternatives 100 bytes; hypotheses 240 bytes), preserves exact citations,
and includes the guidance in the existing message-content budget.
There is no truncation, coercion, repair or retry. Guidance cannot mathematically
prevent Unicode byte overflow: the strict local validator remains authoritative.
A conservative character cap cannot express the full arbitrary UTF-8 byte contract
without excluding valid strings. Retain explicit local rejection rather than
silently reducing allowed evidence identifiers or relaxing byte bounds.

### Synthesis presentation and replay

New B2 manifests select `synthesis_guidance=concise-v1`: labels target 60 characters,
questions 160, complete wording, support aliases instead of long copied paths/URLs.
Limits are not increased. Packets are repacked under the same 5600-byte content
limit. Absent profile retains the exact historical instruction and packet digests;
unknown profiles fail closed. Accepted prose is rendered unchanged and remains
unverified, including syntactically valid incomplete or inaccurate prose.

`analysis_coverage` separately records analysis termination, authorized references,
completed lookups, validated batches, rejected responses and accepted-partial basis.
When validation stops analysis, the human result prominently labels synthesis
analysis-error-limited and shows attempted/accepted synthesis response counts.
`completed_bounded` remains the independent synthesis status. Rejected-batch fields
are not promoted into factual clauses or synthesis support. No retry is introduced.

### Diagnostic observations and limits

The OpenAI cloud worker forwards only allowlisted successful finish reasons from
the existing response-envelope check through ModelBackend. Other provider response
shapes remain unchanged. `completion_diagnostics.observed` journals bounded
controller elapsed time and backend-return receipt; finish reason is `unavailable`
when absent. It never invents a provider attestation from successful JSON parsing.
Analysis uses a diagnostic event, decomposition an optional decision field, and
synthesis an optional response field. These are observations, not grounding inputs.

Terminal `controller_diagnostic` distinguishes worker-close return from parent
cleanup confirmation. Parent `startup_diagnostic` already reports observed elapsed,
read-view establishment and cleanup on the returned result. Those parent observations
occur after child finalization and are NOT retroactively written into its journal.
Persisting a parent attestation would require a separate lifecycle/persistence design;
this correction does not claim that the child confirmed its own parent cleanup.
Historical events lacking optional diagnostics remain replayable.

### Manual acceptance

After installation, verify `./locard.ps1 --version` reports 6.111, then repeat:

```text
briefing --investigate latest --autonomous --decompose --synthesize --question "What evidence supports the suspected attack sequence, and did the PowerShell script execute?"
```

Check progress beyond the former second-batch failure, bounded original support,
short complete proposals, explicit error-limited coverage if analysis rejects, and
separate allocation/termination diagnostics. A successful random response does not
prove Unicode violations impossible. Only the analyst performs live acceptance.

### Recorded corrective validation (2026-11-08)

Focused integration: **270 passed, 16 deselected, 101.96 seconds**. The selection
covered corrective, B2 consumer/packet, Stage A/startup, decomposition, OpenAI schema,
response-envelope, deadline, cloud-readiness and compact-disclosure tests. After a
final presentation adjustment preserving the original analysis-stop reason when
cleanup also fails, all **30 corrective tests passed in 2.11 seconds**.

The 16 exclusions were first observed as failures and reproduced with committed
HEAD versions of the affected provider modules loaded only in memory: 12 old briefing
rendering assertions, one old briefing prompt assertion, and three malformed-envelope
error-category assertions. They remain unchanged and are not reported as passing.
The two success-envelope assertions were updated to require the newly preserved
finish reason while retaining exact text and usage equality. No full suite was run.

Read-only reconstruction of copied run `3524e2043bf34d2fb3451800257f0b32`
succeeded: completed_bounded, two synthesis attempts, three accepted proposals.
Both copied manifest/events SHA-256 hashes remained unchanged. No provider requests
or forensic database access were performed. Live acceptance remains pending.

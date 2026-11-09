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

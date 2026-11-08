# S4-A: provisional question decomposition

Locard 6.108 adds an explicit opt-in to **new** autonomous assessment investigations:

```text
briefing --investigate latest --autonomous --decompose --question "Was event 1121 recorded, and did the script execute?" --start 2026-09-30T00:00:00Z --end 2026-09-30T23:59:59Z
```

Use the assessment ID, original question and explicit time window appropriate to
your case. The example is synthetic, not an instruction to assert that event or date.
The existing OpenAI readiness and configured cloud acknowledgment prerequisites apply.
Review the single authorization before answering yes. `--decompose` without both
`--investigate` and `--autonomous` is rejected. Omitting it preserves Stage A.

## Authority and budgets

`investigation-s4-authorization-v1` allocates at most six analysis requests, one
question-only decomposition and zero organization requests: seven attempts total,
six lookups, eight steps, 300 seconds, 5,600 request-content bytes and 1,024 output
tokens per request. No retries or borrowing between allocations. Fifteen seconds
inside the execution deadline are reserved for deterministic finalization; the
decomposition request has a 30-second subdeadline. Transport timeouts and the outer
process supervisor enforce bounds. Cleanup retains its existing separate bound.

The old `investigation-authorization-v1` contract is unchanged. The new grant does
not add evidence IDs, sources, periods, tools or search. The worker still enforces
record eligibility and bounded full-record disclosure. A failed or truncated
decomposition cannot authorize a retry or additional retrieval. When remaining
resources permit, the existing analysis continues with deterministic fallback.

## Contracts and assessment

`investigation_ai/decomposition.py` owns `question-decomposition-proposal-v1` and
the application-owned `ai-investigative-assessment-v1`. At most four objectives:

- Exact Unicode-code-point source spans into the unchanged question.
- Registered S3 type or `unsupported_objective`.
- Literal argument spans or explicitly unresolved argument roles.
- Proposed polarity and objective relationship; bounded unverified limitations.
- Explicit reported gaps, plus independently computed uncovered source spans.

Only the question and contract instructions enter the first request. It contains
no evidence records or clause candidates. Concrete values are derived from exact
source substrings, not accepted as model-written identifiers. Event IDs require
decimal digits. Clause arguments must remain unresolved because no clauses were
disclosed. Missing/duplicate roles, invalid spans, invented properties, duplicate
typed mappings and contradictory duplicates reject the entire response atomically.

`question_assessment.assess_typed` reuses existing S3 rules directly. It does not
translate model objects back to English. Original S3 grammar and its original
assessment remain separate and unchanged. Negative or uncertain proposals are
displayed but not converted into affirmative assessments. Unresolved arguments and
unsupported objectives are valid partial outcomes, not invented bindings.

The application distinguishes structural validity, span coverage, **provisional**
intent fidelity and deterministic factual support. Even a full-question source
span cannot certify that the model preserved all meaning or negation. The original
question is never marked fully answered by aggregating model-selected objectives.
Execution and causality retain S3's unsupported outcome rules. No new factual prose,
causal rule, organization call or final AI synthesis is introduced.

## Persistence and inspection

New runs use `incremental-s4-a-v1`. The existing private derived journal contains
the grant and original question, request digest/disclosure accounting, accepted
mapping or bounded rejection, separate request allocations, usage and termination.
Request manifests are durable before dispatch; accepted mappings are durable before
use. Raw rejected text, where returned by the backend, is bounded private journal
data, not default terminal diagnostics. Backend envelope failures may have no
returned text; diagnostics explicitly record that it is unavailable. Unknown usage
is not represented as zero. The 4 MiB journal and event ceilings are unchanged.

Existing original-field disclosures and validated deltas still supply factual
authority. The live reducer derives S1/S2 state from those accepted batches. The
terminal result keeps original S3 assessment and provisional scoped assessments;
it does not duplicate the complete S2 support graph in the terminal event.

Read-only recorded reconstruction (no provider or current-case access):

```powershell
.\.venv\Scripts\python.exe -m forensic_assistant.investigation_ai.synthesis "C:\path\case.db.investigations" INVESTIGATION_ID --decomposition
.\.venv\Scripts\python.exe -m forensic_assistant.investigation_ai.synthesis "C:\path\case.db.investigations" INVESTIGATION_ID --decomposition --json
```

Reconstruction checks the hash chain, grant/request bindings, source/record scope,
allocation sequence, original disclosure grounding, accepted mappings and derived
terminal assessments. A hash chain is not authenticity or forensic proof. Saved
inspection never renews a grant or makes a provider call. Historical S1/S2/S3
inspection remains supported; legacy report import/replay restrictions remain.

## Manual acceptance

After committing/pulling into the separate checkout, install using its interpreter:

```powershell
Set-Location C:\tmp\locard260927\locard
.\.venv\Scripts\python.exe -m pip install -e .
.\locard.ps1 --version
.\locard.ps1
```

Use the previously accepted assessment/window with `briefing --investigate ...
--autonomous --decompose`. Check the seven-request authorization, one question-only
request, at most six lookups/analysis batches, explicit unsupported/unresolved
objectives, and the preserved original question. Inspect JSON using the command
above; repeat recorded inspection and verify no new provider call occurs. Compare
an ordinary `--autonomous` run without `--decompose` only if separately desired:
that remains the original six-request behavior.

Test control words, negation and an unrelated question, not only a particular attack
sequence. Supported scoped presence is not proof of causality, successful execution,
or absence elsewhere. No live acceptance result is claimed by the implementation.

## Limits

S4-A does not improve factual rule coverage, discover new evidence, resolve unknown
roles from evidence, organize themes, repair timestamp labels, enable recovery,
import incremental reports or provide provider parity. General intent fidelity is
not deterministically provable. Questions that exceed the actual serialized prompt
budget fail before approval; they are not silently truncated. Provider tokenization
varies: output is always capped at 1,024 tokens and incomplete JSON fails closed.
Synthetic serialization/transport tests are not proof that every model will complete
every permissible response within that budget. Oversized journal/finalization work
fails closed; durable earlier batches remain available for recorded inspection.

## Implementation validation (2026-11-08)

- Expanded focused regressions: **244 passed in 94.56 seconds** (S1/S2/S3,
  autonomous execution/startup, OpenAI schema and output budgets, handoff,
  presentation and S4-A).
- After the final sanitized-diagnostic correction: **93 passed in 18.22 seconds**
  across S4-A, validation diagnostics, OpenAI adapter and incremental presentation.
  These sets overlap; do not add the counts as distinct tests.
- Final timeout-label/presentation checks: **10 passed in 6.39 seconds**.
  Final exact-request worker-scope and successful six-batch replay checks:
  **2 passed in 1.67 seconds**. S4 rejects a worker substituting even another
  authorized record for the particular requested evidence ID.
- The first attempt had 34 passes and 26 setup errors because pytest could not
  create its default temporary directories. A fresh workspace-local `--basetemp`
  and `-p no:cacheprovider` resolved this without permission changes.
- Synthetic four-objective fixture: 1,465 request-content bytes, 1,178 response-JSON
  bytes, 2,631 wire-schema bytes. Schema transport overhead is separate from the
  5,600-byte content budget. Transport tests enforce 1,024 output tokens and zero
  retries; no live tokenizer/provider completion guarantee is claimed.
- No full suite, live model request, actual case access, commit or push.

Changed files:

| Area | Files |
|---|---|
| Core contract/service | `forensic_assistant/investigation_ai/decomposition.py`, `question_assessment.py` |
| Execution/policy/lifecycle | `forensic_assistant/investigation_ai/autonomous.py`, `autonomous_policy.py`, `supervision.py` |
| Provider compatibility/diagnostics | `forensic_assistant/ai/backend.py`, `openai_schema.py`, `validation_diagnostics.py` |
| CLI and presentation | `forensic_assistant/briefing_cli.py`, `assessment_handoff_cli.py`, `investigation_ai/presentation.py`, `investigation_ai/synthesis.py` |
| Regression coverage | `tests/test_question_decomposition.py` |
| Release/documentation | `pyproject.toml`, `README.md`, this document, `.gitignore` (one exact documentation exception) |

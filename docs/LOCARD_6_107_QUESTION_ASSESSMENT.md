# Locard 6.107 — S3 scoped question assessment

S3 assesses the **saved original investigation question** against validated,
recorded-view S1 clauses and S2 relationships. It makes no provider request, opens
no evidence database, writes no transcript events and changes no report-import
permissions. It does not implement general language understanding or new execution
or causal inference rules. S1/S2 and Stage A defaults remain unchanged.

## Manual acceptance

After pulling and installing in the test checkout:

```powershell
Set-Location C:\tmp\locard260927\locard
.\.venv\Scripts\python.exe -m pip install .

$runRoot = 'C:\path\to\case.db.investigations'
$runId = '<original 32-character investigation ID>'
.\.venv\Scripts\python.exe -m forensic_assistant.investigation_ai.synthesis $runRoot $runId --assessment
.\.venv\Scripts\python.exe -m forensic_assistant.investigation_ai.synthesis $runRoot $runId --assessment --json
```

`--assessment` and `--relationships` are mutually exclusive. Without either option,
the existing S1 inspector is unchanged. No new investigation or OpenAI request is
needed. Use the original run ID as the child directory name, matching its manifest.

For the accepted six-record diagnostic investigation, expect all 22 factual clauses,
seven S2 recorded-time relationships and three separate unverified hypotheses to
remain available. Its natural-language compound question is intentionally **not
mapped** by the narrow S3 grammar. Overall status is `NOT_ASSESSABLE` with an explicit
question-mapping limitation, while the original question and useful recorded
findings remain visible. Successful execution and causality remain unresolved.
This is not a request failure or a claim that the recorded facts are unsupported.

## Supported vocabulary

Matching is anchored to each complete question, with case-insensitive fixed words.
Original question text and original JSON literal values remain unchanged. Paths
and values are compared exactly, without case/path normalization. The following
forms are supported; placeholders are explanatory, not literal grammar tokens:

| Form | Registered proposition |
|---|---|
| `Does the examined Browser evidence record a download to "<path>"?` | Original complete target/current path on an eligible browser download clause |
| `Does the examined filesystem metadata record path "<path>"?` | Complete recognized MFT recorded path |
| `Is event ID <integer> present in the inspected EVTX records?` | Original complete integer `/event_id` field; no coercion from strings or booleans |
| `Does the examined evidence include a validated Defender ASR blocking interpretation?` | Existing recognized ASR interpretation and its mandatory limitation |
| `Do recorded UTC values for clause <64-hex-id> precede clause <64-hex-id>?` | An existing validated S2 `recorded_time_before` edge, not display order or physical-event order |
| `Does clause <64-hex-id> report <JSON-scalar>?` | Exact eligible complete original field; scalar is a JSON string, integer, boolean or null |
| `Did "<subject>" execute?` | Recognized request, but outcome rule deliberately unsupported: `UNRESOLVED` |
| `Did "<subject>" cause "<effect>"?` | Recognized request, but causal rule deliberately unsupported: `UNRESOLVED` |

Quoted values use JSON escaping, e.g. `"C:\\sample.zip"`. Clauses and subjects are
not inferred from similar names or substrings. No file existence, execution,
causality, common host, volume or process identity is inferred from these forms.

An explicit semicolon **outside JSON quotes** separates independent propositions:

```text
Does the examined evidence include a validated Defender ASR blocking interpretation?; Did "example.ps1" execute?
```

If the first proposition has direct support, this example is `PARTIALLY_SUPPORTED`;
the second remains unresolved. English conjunctions and open-ended compound
questions are not decomposed. Unknown forms retain their complete wording and
are `NOT_ASSESSABLE`, with available context explicitly labeled as not independently
assessed for relevance. No Case-specific phrase or filename is special-cased.

There is no new CLI question override in S3. The inspector assesses the question
already bound to the saved investigation; the backend rule tests exercise the
vocabulary synthetically. More flexible decomposition remains a later approved
contract, not a hidden heuristic.

## Contract and authority

The result uses `question-assessment-v1`. It retains the unchanged question,
question identity/source investigation, epoch, explicit proposition IDs, registered
types/rule versions, arguments, direct/contextual/contradictory support references,
conflicting supports, gaps, budget and coverage details, and deterministic status.
The complete validated S2 result is nested under `evidence`; its `factual` member
retains S1 observations, interpretations, hypotheses, alternatives and unknowns.
No second evidence repository or exposure ledger is created.

Question identity binds contract, investigation, original question and accepted
read view. Proposition identity additionally binds position, exact text, mapping,
rule version and typed arguments. The source manifest digest and recorded
termination are separate provenance fields, not proof of current-case equality.

The public grounding entry point is
`investigation_ai.question_assessment.reconstruct(root, identity)`. It loads the
manifest, invokes S1/S2 reconstruction and exact derivation validation, reloads the
manifest, and rejects changes during reconstruction. The saved question is not
taken from AI hypotheses or a command-line replacement. No report-import adapter
is enabled. Private `_assess` and `render` consume trusted application reconstruction;
external JSON with recomputed hashes cannot become authoritative evidence.

If an investigation has no accepted batches, S1 may have no accepted evidence
epoch. `evidence_state` then remains null; `recorded_source_view` retains any known
journal view separately. An empty assessment does not invent successful retrieval.

## Application-enforced classifications

| Status | Meaning in S3 |
|---|---|
| `SUPPORTED_WITHIN_SCOPE` | The exact mapped recorded-data proposition has eligible direct support. It is not a claim about complete forensic knowledge. |
| `PARTIALLY_SUPPORTED` | An explicit compound has directly supported components and other components not supported. Individual statuses remain visible. |
| `CONTRADICTED` | Only a complete exact clause field differing from the specified typed value, or an existing reverse S2 recorded-time edge, can establish this narrow contradiction. |
| `UNRESOLVED` | Inspected accepted facts do not settle a mapped proposition; execution/causal rules are unsupported, or comparable projections conflict. |
| `NOT_ASSESSABLE` | Mapping, required clauses, usable original fields or assessment capacity is unavailable. |

A same-occurrence S2 conflict prevents choosing one conflicting projection as
correct. It does not erase either observation or generate a negative claim about
an event. Different/absent evidence does not establish contradiction. A reverse
recorded-time edge contradicts only the specified recorded-coordinate ordering,
not a physical-event or causal theory.

An existential recorded-presence proposition can have positive support even when
other data are unassessed. Missing support never proves absence from the case or
non-occurrence. Truncated fields cannot establish exact-value propositions.
S2 source/epoch, precision, overlap, unknown-clock and sparse-coverage limitations
remain attached. No new temporal edge is inferred, including transitive edges.

Each proposition distinguishes direct clauses/relationships, contextual references,
contradictory references and conflicting projections. Remaining accepted facts are
available context, **not proven relevant support**. Hypotheses remain unverified
and cannot be direct or contradictory factual support.

## Coverage and bounded operation

S3 permits at most 4,096 UTF-8 question bytes, eight explicit propositions, and 192
support checks over the existing at-most-96-clause S1 result. The result remains
bounded to 1 MiB. No source scans or unrestricted pairwise comparisons occur.
An over-limit compound is not silently reduced to a successful prefix; mapping is
not assessable. Exhausted support checks retain established components and identify
unassessed candidates. Oversized serialized input/output fails explicitly rather
than dropping provenance to fit.

`support_search` describes checks over **accepted recorded units**, not a fresh
case search: `matched`, `no_match`, `incomplete`, `unsupported` or `not_searched`.
Shortened candidate projections are counted separately. `new_evidence_search` is
always `not_searched`. Existing investigation termination, including failures,
remains separate from question status. No undocumented earlier search completeness
is inferred. S1 coverage remains based on its latest accepted batch; later failed
operations are not silently counted as successful examination.

Metrics track recognized/assessed propositions, support checks, direct/contextual/
contradictory references, unsupported types and unassessed candidates. Repeated
references across independent propositions count per proposition, not as additional
evidence records. The original S1/S2 coverage objects remain available in JSON.

Human output shows the question, controlled recorded facts, unresolved gaps,
assessment, exact support keys, separate hypotheses and deduplicated limitations.
It does not emit an integrated attack narrative or imply that plan completion
answered an unmapped question.

## Validation record

Focused tests in `tests/test_question_assessment.py` cover the grammar, typed direct
support, ASR qualifications, contradiction versus missing evidence, context versus
proof, explicit/ambiguous compounds, truncation, unknown clocks, sparse comparisons,
budgets, empty/failed investigations, tampered support/source/view references,
repeat reconstruction, unchanged S1/S2, no additional provider calls, and unchanged
report-import restrictions. Existing S1, S2, Stage A, compact-disclosure and
incremental-presentation regressions remain applicable.

Focused validation on 2026-11-08: the six-module regression run passed **157 tests
in 27.66 seconds**. After refining shortened-candidate coverage and adding its
regression, the final S3-only run passed **36 tests in 2.47 seconds**. Together,
these cover 36 S3 tests and 122 unchanged compatibility regressions.
`git diff --check` passed; no full suite was run.

The approved readable 6.103 diagnostic copy was checked on 2026-11-08 through the
public reconstruction path. All 22 S1 clauses, seven S2 relationships and three
hypotheses were preserved. The original compound question remained unchanged and
correctly yielded `NOT_ASSESSABLE` for unsupported mapping, with useful recorded
findings and explicit unresolved execution/causality. Repeated results matched.
Both diagnostic input SHA-256 hashes were unchanged; the temporary correctly named
copy was removed. No original case, sidecar, permissions or provider was accessed.

No full suite, commit or push is part of this implementation phase. Stop for manual
acceptance before S4 or other extensions.

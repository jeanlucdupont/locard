# Locard 6.105 — S1 factual clauses

S1 is a provider-free, recorded-view inspection service. It does not change the
autonomous investigation loop, live Stage A report, provider schemas, authorization
limits, 5,600-byte prompt budget, evidence schema, or report-import permissions.

## Entry points and trust boundary

`forensic_assistant.investigation_ai.synthesis.reconstruct(root, identity)` reads a
saved Stage A journal through `autonomous.reconstruct`. Existing manifest/hash-chain,
read-view, delta identity/chain, disclosure and `State.render` grounding validation
run before the private reducer receives a batch. The reducer rechecks exact typed
findings, packet binding and view identity, and derives only selected observations
and recognized deterministic interpretations. No SQLite case is opened.

The optional internal `_on_validated` reconstruction hook leaves the original
return contract unchanged. There are no new persisted events: reconstruction is
the simpler source of S1 output. Existing and historical Stage A transcripts use
the same validator. Unsupported engines/contracts are not reinterpreted.

`synthesis.render(result)` renders the backend result independently of CLI parsing.
It checks clause identity, registered template shape and recognized interpretation
semantics, and escapes control characters. It is **not** a grounding importer:
arbitrary serialized clauses, even with recomputed hashes, do not prove evidence
support. Use `reconstruct` for grounded input. S1 never feeds its output to a model;
future reasoning must re-disclose eligible original support in that request.

## Contracts and identity

The result contract is `recorded-factual-clauses-v1`; each clause uses
`synthesis-clause-v1`. Its application-generated SHA-256 identity covers canonical
JSON of the semantic body: version, type, predicate/rule version, typed arguments,
original support, interpretation IDs, source/read-view binding, qualifications and
validation classification. Original EIDs and pointers are unchanged.

Supports contain unchanged field descriptors (including EventData name/ordinal and
truncation), provenance digest, recorded source context and limitations. Timestamp
supports preserve the selected timestamp entry, including slot/type and any
available normalization/precision metadata. Defender supports retain the recognized
interpretation ID and original provider/channel/event-ID premises. They remain
deterministic interpretations, separate from original field observations.

Disclosure lineage is stored separately as delta ID, batch number, packet digest,
projection contract/encoding, origin and record-projection digest. Repeated identical semantic support deduplicates
one clause while retaining all accepted lineage occurrences. Source/view/qualifier,
field, value or rule changes alter identity. Distinct slots and pointers are not
merged merely because their values match. Output ordering is deterministic by EID,
pointer and clause identity; it is not a chronological or causal ordering.

## Narrow predicate registry

| Predicate | Meaning and guard |
|---|---|
| `record_reports_field` | Conservative fallback for an eligible exact original field |
| `browser_download_field` | Existing browser download ID/projection with target/current path or URL-chain field; not proof of opening or execution |
| `mft_metadata_field` | Filesystem object or timestamp metadata; SI/FN slots remain distinct; not execution |
| `evtx_recorded_field` | Recorded Windows event field, preserving provider/event context and original field metadata |
| `prefetch_metadata_field` | Executable, timestamp or referenced-object field; references are not executed images or proof of successful script execution |
| `defender_asr_block` | Existing `defender-asr-block-v1` interpretation; mandatory original limitation retained |

The renderer reports a field's value rather than inventing an activity label. No
timestamps are converted, ordered, assigned missing timezone/precision, or treated
as execution times. Qualifications retain bounded projection/coverage limitations,
source assertions and no-execution/no-causality cautions. Repeated qualifications
are shown once in a clearly labeled section; JSON retains them on every clause.

Hypotheses and unresolved questions remain separate unverified sections. S1 does
not implement relationships, question-level answers, conflict resolution, synthesis
requests, restart continuation, or new report grounding.

## Bounds and coverage

The reducer permits at most six accepted batches, 96 clauses (six existing packet
bounds of 12 observations plus four interpretations), 32 KiB per clause and 1 MiB
serialized result. These are derived-output ceilings, not increased investigation
budgets. Overflow fails explicitly; clauses are not silently discarded. The original
transcript loader's byte/event bounds continue to apply. No pairwise relationship
comparison occurs. Retained state is bounded by these current Stage A envelopes.

Coverage lists inspected and represented records and inspected-but-unrepresented
IDs, and retains the existing disclosure summary at the latest accepted batch.
Later failed/rejected operations are not counted in this summary; its basis is
explicitly labeled. Omission relevance is explicitly
not evaluated. Only accepted observations/interpretations become clauses; merely
disclosing a field does not imply it was selected as an accepted finding.

This output validates the **recorded view**, not equality with the current case.
Journal hashes are integrity checks, not cryptographic authenticity or proof of
forensic truth. Report import still rejects Stage A/read-view transcripts. No case
sidecars or transcript files are written by this utility.

## Manual acceptance (PowerShell)

After pulling and installing the development version in the test checkout:

```powershell
Set-Location C:\tmp\locard260927\locard
.\.venv\Scripts\python.exe -m pip install .
.\.venv\Scripts\python.exe -m forensic_assistant.investigation_ai.synthesis --help

$runRoot = 'C:\path\to\case.db.investigations'
$runId = '<32-character saved investigation ID>'
.\.venv\Scripts\python.exe -m forensic_assistant.investigation_ai.synthesis $runRoot $runId
.\.venv\Scripts\python.exe -m forensic_assistant.investigation_ai.synthesis $runRoot $runId --json
```

Use another saved Stage A run ID/root if preferred. The directory under `$runRoot`
must have the original 32-character investigation ID, matching its manifest. A
diagnostic directory prefixed `6.103-` must first be copied into a separate analyst
diagnostic root under that original ID; do not rename or modify original sidecars.
Access failure is reported without changing permissions. No model readiness check,
cloud request or new investigation is needed.

Expected for the supplied six-batch 6.103 diagnostic run: 22 distinct clauses (21
observations and one ASR interpretation), six represented records, three separate
hypotheses. Inspect exact references/slots, mandatory ASR limitations and historical
view wording. Repeating inspection should yield identical JSON.

## Validation record

Focused synthetic regressions live in `tests/test_factual_clauses.py`, alongside
existing Stage A, compact-disclosure and incremental-presentation suites. They
cover exact support, identity/deduplication, multi-batch/family behavior, source/view
separation, timestamp semantics, truncation, hypotheses, forged predicates,
interpretation limitations, bounds, reconstruction and unchanged report imports.

Final focused run on 2026-11-08: **89 passed in 34.78 seconds**, using those four
test modules. `git diff --check` passed. The full suite was not run. The initial
attempt's sandbox temporary-directory permission error was avoided by selecting a
fresh workspace-local pytest base directory, without changing permissions.

On 2026-11-08 the approved readable diagnostic copy of the 6.103 transcript was
checked through the existing loader and reconstruction path. Two reconstructions
matched and produced the counts above. Both diagnostic input files had unchanged
SHA-256 hashes afterward. An isolated temporary copy under its original run ID was
removed after inspection. No original case, original sidecar or provider was used.
This is historical recorded-view validation, not current-case forensic verification.

# Locard 6.72: bounded investigation conclusions

This release changes final selection, grounding of deterministic interpretations,
and human presentation. It does not change evidence storage, ingestion, temporal
authorization, tool approvals, novelty policy, or investigation budgets.

## Final contract

The provider grammar permits at most 12 `observed` references, each containing an
exposed `evidence_id` and leaf JSON-pointer `field`. Twelve permits time, identity,
host, and several original activity fields without the former three-field cap.
The input content budget remains 5,600 bytes, the response parser remains bounded
to 16 KiB, and existing provider output limits remain unchanged. The maximum
observation count is not a promise that every maximum-sized answer fits a model's
output limit. Live model selection and output-budget behavior need manual acceptance.

New final proposals include `answer_status` (`answered`, `partial`, `unresolved`)
and up to four `interpretations` IDs. The grammar requires both. Legacy final
objects can still be structurally inspected without those fields; their missing
status does not imply completeness. Unknowns remain limited to three strings of
at most 200 UTF-8 bytes. Hypotheses, relationships, and detections keep their bounds.

`conclusions.interpretations()` is the controller-owned derivation registry entry
point. The first supported derivation is `defender-asr-block-v1`, qualified by the
exposed provider, channel, Event ID 1121, and exact Locard-generated interpretation.
An interpretation ID is derived from the derivation identity and evidence ID.
It must also appear in the actual disclosed record's `interpretation_ids`.
Models select IDs only; they cannot supply authoritative interpretation text.
The controller supplies classification, derivation ID, evidence citation, and the
qualified text. Original observations still cannot select `defender_asr` as fact.

## Grounding is not objective completeness

The terminal result has a separate `answer_assessment`:

- `grounding`: supported findings versus no supported findings;
- `model_declared_status`: the model's declaration, not certification;
- `status`: controller-assessed `COMPLETE`, `PARTIAL`, or `UNRESOLVED`;
- `reason`: a controller-owned explanation.

`ANSWER_SUPPORTED` remains a grounding termination reason for compatibility. It
does not mean the requested question has been completely answered. Human output
shows the separate answer status explicitly.

The completeness recognizer is intentionally narrow: an exact single-field
request such as “What is the hostname?” can be COMPLETE if the model declares it
answered, only one candidate record is retained, exactly that observation is grounded, and no retained uncertainty,
truncation, coverage limitation, or prompt omission conflicts. Other substantive
investigations remain PARTIAL when findings are supported, or UNRESOLVED without
support. In particular, a metadata-only response to an execution question cannot
be COMPLETE. Even a useful qualified Defender answer can remain PARTIAL: there is
no general deterministic proof that arbitrary natural-language objectives are
fully answered. No keyword-based execution inference or model self-certification
is used.

Instructions prioritize objective-relevant details and preserve essential context.
The model can request existing approved tools before finalizing. A final partial
answer does not launch automatic lookups or an answer-revision loop. It preserves
findings and uncertainty for the analyst, who can authorize a follow-up question.

## Presentation and coverage

Human output separates:

1. Observed original fields, including original EventData names and ordinals.
2. Deterministic interpretations, labeled derived and cited.
3. Model-proposed uncertainty, labeled unverified and safely escaped.
4. Controller-owned coverage limitations.

Coverage distinguishes shortened original names/values, omitted original fields,
shortened search excerpts, omitted prompt records, and incomplete EVTX searches.
The obsolete raw `event_data_json` truncation marker is removed when structured
EventData replaces it. Genuine omissions remain visible. No warning claims that
an intact original value was shortened merely because its search excerpt was.

## Transcript and report compatibility

New transcripts retain format 1 and use policy `v4-3`. Existing hash-chain loading
remains available; historical transcripts are not rewritten. Replay still refuses
read-view transcripts, and exact-state replay retains implementation/policy checks.
Historical fingerprint-backed report imports retain their original three-observation
contract. The report adapter recognizes v4-3 fingerprint-backed transcripts without
nonempty interpretation findings. It explicitly refuses interpretation-bearing
imports rather than silently dropping interpretations or promoting them into
original facts. Read-view transcript report import remains refused as before;
explicit evidence selection remains available for freshly grounded reports.

The provider readiness probe now uses the new contract. Existing schema-based
cache identity invalidates readiness for the changed grammar. OpenAI strict-wire,
Anthropic staged transport, and the other provider adapters derive from the
canonical schema; no new provider request or ranking pass is added.

## Measurements and acceptance

Equivalent small synthetic one-observation example, median of 200 iterations:

| Measurement | Before | After |
|---|---:|---:|
| Prompt content bytes | 2,367 | 2,390 |
| Canonical grammar bytes (three tools) | 4,072 | 4,319 |
| Final validation | 9.00 microseconds | 8.40 microseconds |
| Grounding/render-data construction | 16.20 microseconds | 15.30 microseconds |
| Human rendering | 26.45 microseconds | 26.85 microseconds |

These are synthetic microbenchmarks, not real-case speed improvements. The
saved 6.71 transcript exposure, annotated in memory with the new interpretation
IDs and precise coverage markers, fits at 2,489 / 5,172 / 4,933 bytes (previously
2,466 / 5,041 / 4,829). This is a comparison using saved projected records, not a
new live retrieval or provider run. The copied transcript chain still validates.

The focused combined run passed 187 tests; the final conclusion module passed
15 tests, including one subsequently added search/show/final regression. Two
local HTTP supervisor cases could not pass in this sandbox: an independent
synthetic child-loopback probe confirmed WinError 10013. They remain unverified,
not waived. Temporary-directory access failures were resolved using test-local
temporary directories. No full suite was run.

The adversarial prompt regression retains the relevant complete record under 5,600
bytes while omitting an oversized unrelated record. Fake-provider tests validate
expanded original-field selections and interpretation references across adapters.
Live provider quality and the case-14 answer require manual acceptance. No real
provider requests or evidence-database modifications are part of implementation.

Run the same approved, temporally bounded Defender question after installing this
checkout. Verify the original command and process fields, timestamp, evidence ID,
derived blocking qualification, and unverified execution uncertainty. PARTIAL is
an honest completeness assessment and does not mean the supported fields failed
grounding. Full regression testing and release commit wait for manual acceptance.

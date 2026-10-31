# Locard 6.73: analyst briefing and approved discovery

Implementation and synthetic validation: 2026-10-31. Manual acceptance pending.

### Current interpretation contract: version 2 source references

This section supersedes the legacy offset/quote model-response descriptions below.
The outer briefing JSON remains `format: 1` with additive
`interpretation_contract: 2`, `source_units` and coverage fields. Deterministic
lead IDs are unchanged. New model responses must use `source_ids`; legacy
`start/end/quote` responses are rejected, never reinterpreted. There is no saved
briefing importer to migrate. Existing saved JSON and investigation transcripts
remain untouched; the text renderer still handles older accepted items without
inventing source-unit links. Case schemas and evidence IDs do not change.

`briefing_sources.inventory` divides each input at blank-line paragraph boundaries,
retaining the separators, and splits oversized paragraphs every 256 Unicode
characters. Single LF/CRLF line breaks stay inside a multiline paragraph. No BOM,
whitespace or newline normalization occurs. Up to 256 units are retained; total and
retained counts and explicit incomplete-coverage notices identify omissions. The
complete original and correction strings remain in `inputs` even when unit bounds
are reached. Empty/whitespace-only input (including BOM plus whitespace) is rejected.

Each unit contains `id`, `source`, `start`, exclusive `end`, exact `text` and global
`order`. IDs have the form `S-O-<12-hex input digest>-001` or
`S-C1-<digest>-001` for correction 1. Ordinals distinguish repeated passages;
source prefixes distinguish corrections. Identical input and segmentation rules
produce identical IDs. IDs are analysis-local, not stable across edits, not an
integrity attestation, and never forensic evidence IDs. Always:
`inputs[unit.source][unit.start:unit.end] == unit.text`.

The model receives a deterministic prefix of whole source units and only entities
covered by those units, rather than another copy of the entire narrative. The
5,600-byte message budget is unchanged. `ai_source_coverage` records the exact
exposed IDs and total/exposed counts; unexposed units cannot be cited. If no unit
fits, interpretation is skipped. Long originals can leave later corrections outside
the exposure budget; this is reported, never silently treated as complete coverage.

The response remains an ordinary object containing up to twelve items:

```json
{"items":[{"category":"question","text":"What independent evidence could test the reported relationship?","source_ids":["S-O-0123456789ab-001","S-O-0123456789ab-002"],"entity_ids":[],"basis":"inferred","uncertainty":"Not investigated"}]}
```

This is a synthetic shape example, not a captured response or usable source ID.
Each item cites one to six distinct exposed IDs and at most eight distinct entity
IDs. Entity occurrences must be completely covered by the cited units in their
actual input; contiguous chunks can jointly cover a split occurrence. A correction
entity cannot be attributed only to an original unit. Unsupported technical
literals are checked against leads supported by the cited units. Canonical array
uniqueness, bounds, enums and required properties remain enforced locally; the
OpenAI wire adapter recognizes the revised exact schema and removes unsupported
uniqueness keywords without adding an investigation `proposal` wrapper.

Categories are `reported_activity`, `hypothesis`, `question`, `alternative`, and
`ambiguity`. The latter four require `basis: inferred`. Exact reported excerpts
may remain explicit. Model-labeled explicit paraphrases are accepted only as
unverified inferred interpretations, retaining `model_basis: explicit` and a fixed
qualification: semantic faithfulness is not deterministically verified. Every
accepted item has `semantic_entailment: not_verified`; references do not establish
truth, causation, execution, or compromise. Arbitrary inferred prose cannot be
semantically proven by this validator and is never promoted to findings.

The prompt prioritizes actionable evidence-seeking questions, tentative mechanisms,
and meaningful competing explanations; it discourages verbatim repetition and
trivial indicator restatement. Human output displays category, effective basis,
uncertainty and source IDs with input/offset locations, without repeating all unit
text. JSON contains the exact unit inventory for resolving those references.

Safe reconciliation rules include `unknown_source_id`, `unknown_entity_id`,
`entity_outside_referenced_source`, `invalid_inference_classification`, and
`unsupported_technical_literal`. Duplicate/missing source references fail canonical
`uniqueItems`/`minItems` validation; unknown model-supplied IDs are not echoed in
diagnostics. Rejected indexes remain visible and valid items can form a partial
interpretation. No approval, retrieval or evidence-exposure-ledger path is added.

Focused validation: 176 tests passed in 25.00 seconds. The existing acceptance
file retains eight identical lead IDs and produces six units. Synthetic measurements:

| Input | Segmentation | Reconciliation (one fake item) | Rendering | Old/new message bytes |
|---|---:|---:|---:|---:|
| 107-byte narrative | 0.120 ms | 0.107 ms | 0.111 ms | 833 / 1,701 |
| 32,760-byte narrative | 1.217 ms | 0.090 ms | 0.110 ms | 36,590 / 5,522 |

The near-limit example exposed 38 of 800 units with explicit incomplete coverage;
its former full prompt exceeded budget. The serialized schema changed from 968 to
933 bytes. These are single synthetic measurements, not model latency or quality
claims. The OpenAI 4,096-token ceiling, 128-KiB briefing response limit and all
other provider settings remain unchanged. Manual acceptance must assess whether
the model produces useful questions and tentative alternatives.

### Current acceptance correction: OpenAI briefing output budget

After analyst-confirmed truncation, `briefing.OPENAI_OUTPUT_TOKENS` is **4096**,
formerly 1024. The cloud worker applies it only to non-handshake OpenAI requests
whose canonical schema exactly matches the briefing contract. Other operations,
readiness probes and providers retain their prior settings. Locard supplies the
existing LiteLLM `max_tokens` parameter; the installed SDK has model-specific
translation to `max_completion_tokens` where applicable. No new model override,
fallback, retries or additional interpretation request is introduced. Provider
capability rejection remains an error rather than silently changing the budget.

`briefing.OPENAI_RESPONSE_BYTES` is 128 KiB for this OpenAI interpretation parser
only. The legacy 16-KiB parsing limit could reject valid escaped briefing output:
a synthetic 27,157-byte response with twelve valid items now passes. The 128-KiB
ceiling conservatively accommodates bounded item strings and JSON escaping.
The generic parser default remains 16 KiB, including investigation and local/other
provider briefing paths. The 1-MiB response/canonical-validator ceiling, 2-MiB worker
reply ceiling, input budgets, item counts and CLI rendering behavior are unchanged.
The envelope diagnostic allowlist now preserves the 4096 output limit.

Tokens and bytes are different limits; 4096 tokens do not guarantee 16 KiB of
visible text, especially for reasoning models. This is four times the previous
generation allowance, not a required output length. Latency and API consumption
may increase; the existing timeout still applies. No live performance claim is made.

Validation: 145 focused tests passed in 23.98 seconds, including budget isolation,
single-call truncation fallback, schema/uniqueness, source validation and provider
compatibility regressions. Synthetic 27,157-byte validation/reconciliation took
122.2 ms; rendering twelve items took 1.6 ms (one local measurement, no provider).
The earlier 1024-token statements below describe the preceding diagnostic patch.

### Acceptance correction: OpenAI schema and diagnostics

Response-envelope diagnostics now distinguish `output_truncated`,
`unexpected_finish_reason`, `unexpected_tool_call`, `missing_response_message`,
`missing_response_content`, `empty_response_content`, `invalid_content_type`,
`response_size_exceeded`, and `invalid_response_envelope`. They record only
allowlisted finish reason/type, tool/function-call presence, a byte count capped
at 1 MiB + 1 (with a capping flag), and the configured output-token limit.
JSON parsing and canonical validation are explicitly `not_attempted` on these
failures. Arbitrary SDK objects, payloads and exception messages are never included.

The existing provider error packet carries `response_envelope` through JSON IPC,
parent reconstruction and allowlisted provider logs; briefing JSON exposes the same
safe fields as `ai_error.envelope`. Human output prints those fixed labels. For
example (synthetic):

```json
{"ai_status":"failed","ai_error":{"category":"output_truncated","stage":"response_envelope","provider_category":"output_truncated","envelope":{"rule":"output_truncated","finish_reason":"length","output_token_limit":1024,"json_parse":"not_attempted","canonical_validation":"not_attempted"}}}
```

An unexpected call instead uses category `response_envelope`, rule
`unexpected_tool_call`, and separate boolean tool/function presence fields.
A malformed SDK object uses `invalid_response_envelope`; unavailable metadata is
omitted. Gemini retains its established `provider_generation` truncation stage
and existing Gemini metadata, augmented with the safe envelope details.

The briefing prompt explicitly prohibits duplicate interpretation items, repeated
entity IDs and invented source references. This is preventive, not a diagnosis of
the previous live failure. The 1,024-token limit, item limits, prompt-size budget,
provider/model selection, retries and response acceptance constraints are unchanged.
One further manually authorized live test is needed to identify the actual condition;
no cloud request was made while implementing this instrumentation.

The OpenAI briefing wire schema now omits `uniqueItems` recursively, using the
existing adapter. Only the exact briefing contract is eligible; its plain object
shape is preserved. Investigation responses still use their existing `proposal`
wrapper. Canonical local validation retains uniqueness for both `items` and
`entity_ids`, required properties, bounds and enums. Other providers are unchanged.
The confirmed HTTP-400 `unsupported_uniqueItems` failure is addressed; acceptance
by the live provider still requires manual testing. No other newly unsupported
keyword was established by these offline checks.

JSON adds `ai_status`: `not_requested`, `skipped` (input budget), `success`
(including a valid empty list), `partial` (some items rejected), or `failed`.
Failures include `ai_error` with category/stage and available allowlisted metadata.
Categories distinguish provider schema rejection, transport, authentication or
authorization, rate limiting, other provider failures, response parsing, structural
validation, source reconciliation, and unexpected internal failures. HTTP 400 by
itself is not classified as schema rejection. Reconciliation diagnostics identify
item index and fixed rule, never quoted narrative values. Unexpected exception
text is not displayed or newly persisted. Existing safe provider logs remain usable.

Example diagnostic (synthetic, not a new provider request):

```json
{"ai_status":"failed","ai_error":{"category":"provider_schema_rejection","stage":"provider_request","provider_category":"invalid_request","http_status":400,"parameter":"response_format","rule":"unsupported_uniqueItems"}}
```

Human output states that the provider rejected the response schema, displays
`HTTP 400 | response_format | unsupported_uniqueItems`, and confirms that
deterministic leads remain available. Original BOM/text and character offsets are
unchanged. The correction does not alter retrieval, approval, or grounding.

## Workflow and trust boundaries

`briefing` is separate from `!` and `investigate-ai`. Its default is deterministic,
model-free analysis of a UTF-8 file or inline narrative. It does not open a case.
`--ai` optionally interprets the narrative once using the configured provider;
cloud disclosure also requires `--allow-cloud`. No forensic records are sent in
that interpretation request. Existing evidence-free provider readiness probes
may run before the single narrative call. There is no automatic narrative retry.

Review the lead IDs first. `--discover --approve ID` authorizes only those leads,
for one explicitly selected artifact family and an explicit offset-bearing time
window of at most 24 hours. Omit a lead to reject it. Corrections use repeatable
`--correction TEXT`; the original is retained, and only the desired IDs should be
approved. A narrative date never establishes a query authorization boundary.

Discovery reuses `EvidenceQueries.search`, the existing compact evidence envelope,
and the supervised read-only forensic worker with its pinned SQLite transaction,
authorizer, timeout, WAL safeguards and cleanup. Briefing workers accept only
initialization, approved briefing queries, and final validation. No initial
case-wide search or fingerprint is requested. Existing investigation tools,
transcripts, approvals, grounding and answer-completeness rules are unchanged.

The output contains a **reviewable investigation plan**, not an automatic handoff.
The existing controller must retrieve and expose its own evidence. Neither this
packet, analyst assertions nor AI hypotheses are imported into an exposure ledger
or accepted as grounded findings. Defender blocking interpretations remain distinct
from original EventData and do not establish successful execution.

## Contracts and bounds

| Component | Contract |
|---|---|
| Narrative | Nonempty UTF-8, at most 32 KiB, no NUL; file or inline input |
| Corrections | Up to eight, total 8 KiB, preserved as separate named inputs |
| Lead | Stable `L-...` ID, type, normalized value, classification, negation, unverified label, original occurrences |
| Occurrence | Input name, original substring, Unicode character start/end offsets, end-exclusive; up to 16 per lead |
| Extraction | At most 128 leads; exact, contextual, search-term, partial, ambiguous or invalid; bounded omissions reported |
| Assertions | Up to 64 original line spans; complete original input remains available |
| AI item | Category, exact source quote/span, interpretation, explicit/inferred basis, referenced entity IDs, uncertainty |
| AI limits | Up to 12 items; 500-character quote/text, 300-character uncertainty, eight entity references; 5,600-byte message budget, 45-second backend timeout |
| Reconciliation | Exact original quote, entity references within that quote, no invented detectable technical literals; explicit text equals quote; unsupported items rejected |
| Discovery | Up to six distinct approved leads/queries, one artifact family, ten records per query, 90-second worker deadline, at most 15 seconds per lookup |
| Packet | 192 KiB result budget; per-query arguments, elapsed time, original evidence IDs/values, source context, timestamp meanings, limitations and coverage |
| Handoff | Original objective reference, approved IDs, authorized scope, actual returned evidence IDs, unresolved AI questions; automatic execution false |

Original analyst assertions, AI interpretations, retrieved records and deterministic
derivations remain separate JSON structures. Negative and positive occurrences of
the same indicator retain separate IDs and a conflict notice. Negated, invalid,
partial and ambiguous leads cannot become search filters. Natural-language
negation, names, and descriptive clue extraction are conservative heuristics;
review is necessary. Structural/source validation does not prove an interpretation
or the analyst's assertions. Exact substring matching cannot validate arbitrary
inferred prose semantically; all such prose remains explicitly unverified.

| Approved lead | Actual mapping |
|---|---|
| Filename/path | EVTX explicit retained-content search; MFT/Prefetch existing `path` semantics; browser download-path substring |
| Event ID, IP, hostname | Existing EVTX event-ID, IP, hostname filters |
| Domain | EVTX retained-content substring or browser URL substring |
| Hash | EVTX retained-content substring only; not a new file-hash lookup |
| PowerShell/WMI/Defender/ProgramData term | EVTX retained-content substring |
| Registry key | Existing Registry key filter; no invented hive/root alias expansion |
| Score-sheet/downloaded-document/shortcut clue | Browser title substring; descriptive wording may not match the actual title |
| Date, username, partial indicator | Retained for review; no automatic search mapping |

MFT/Prefetch path search retains its existing scope; this is not a new search of
every Prefetch referenced filename. Artifact timestamps retain their own meanings.
An MFT match is not proof of execution; cross-artifact matches are not correlations.

EVTX content search retains the existing 1,000-candidate, five-second and 8-MiB
payload bounds and continuation metadata. Ordinary query APIs return match counts,
not examined-candidate counts; `candidate_count: null` means unavailable. Results
retain truncation/coverage limitations. This workflow does not automatically page
or retry: narrow the explicit window or use the existing search continuation
interface. A timeout, truncated result or no match never establishes absence.

## Privacy and persistence

Briefings and packets are command-local derived data. No case schema change,
reingestion or evidence-table write is introduced. Audit command fields redact the
narrative, corrections and input-file path; lookup events record IDs, family and
counts. Existing analyst activity sidecars may still record command/lookup events.
JSON deliberately includes sensitive original text and returned records. Save it
only explicitly using normal output/redirection, outside source control, and treat
it as derived analyst work, not evidence. Shell history, explicit raw-AI debug
capture and terminal capture remain analyst-controlled disclosure mechanisms.
`--allow-cloud` authorizes the current narrative and indicator list only; it does
not authorize a later investigation's separate provider workflow.

## Manual acceptance in the separate case-14 environment

Install this development checkout into the launcher's environment without changing
case data or provider configuration (PowerShell):

```powershell
& 'C:\tmp\locard260927\locard\.venv\Scripts\python.exe' -m pip install --no-deps -e 'C:\Users\jl-du\Documents\Codex\2026-09-16\we-x20\outputs\locard'
Set-Location C:\tmp\locard260927\locard
.\locard.ps1 --version
```

Create the **analyst narrative**, not a forensic fixture:

```powershell
@'
On September 30, 2026, a user named Callie Wade
apparently downloaded a Five Crowns score sheet.

We believe something suspicious happened after
the download.

There may have been a malicious shortcut file,
and we observed indications of PowerShell and WMI
activity.

Microsoft Defender appears to have blocked
something involving a script named baje.ps1.

We need to understand what happened, identify the
likely initial execution mechanism, determine the
relationship between these events, and establish
whether the suspicious script executed successfully.

Do not assume that the reported sequence or the
suspected relationships are correct.
'@ | Set-Content -LiteralPath C:\tmp\locard-briefing.txt -Encoding utf8

# Deterministic review; no model or evidence query.
.\locard.ps1 briefing --file C:\tmp\locard-briefing.txt
.\locard.ps1 briefing --file C:\tmp\locard-briefing.txt --json

# Optional interpretation using the configured local provider.
.\locard.ps1 briefing --file C:\tmp\locard-briefing.txt --ai

# Only if you authorize disclosure to the configured cloud provider:
.\locard.ps1 briefing --file C:\tmp\locard-briefing.txt --ai --allow-cloud
```

Review `baje.ps1` lead **L-5262f7a69c69** before approving it. The following narrow
window is an explicit analyst choice for the known acceptance target, not a time
inferred from the narrative. Change it if that is not the scope you authorize.

```powershell
$case = 'C:\Users\jl-du\AppData\Local\Locard\cases\14\case.db'
.\locard.ps1 --db $case briefing --file C:\tmp\locard-briefing.txt --discover --approve L-5262f7a69c69 --artifact evtx --start 2026-09-30T14:05:40Z --end 2026-09-30T14:06:10Z --json

# Separate, explicitly initiated investigation after reviewing the packet:
.\locard.ps1 --db $case investigate-ai 'Between 2026-09-30T14:05:40Z and 2026-09-30T14:06:10Z, what did Defender record about baje.ps1, and what remains unknown about successful execution?' --approve-tools --no-semantic
```

The last command uses the existing configured provider, its disclosure controls,
transcript lifecycle and per-tool approvals. It does not automatically import the
briefing packet. Broader initial-execution questions need separately reviewed
scope and lookups. No live model quality or real case-14 latency claim is made.

## Focused validation

`tests/test_briefing.py` covers extraction/spans/duplicates/negation/corrections,
fake structured AI, consent, adversarial text, invented literals/source references,
bounded mappings, all five synthetic artifact families, unchanged case contents,
the actual worker boundary, cancellation, failures, CLI and audit redaction.
Existing conclusion, EVTX-content, scope, read-only, activity, catalog and completion
regressions were also run. Expanded run: 226 passed, one Windows hard-link setup
permission failure; that single test passed outside the sandbox (0.32 s). No
security assertion was removed. A final briefing-only run passed 28 tests (6.43 s),
including four additional provider-contract/partial-coverage cases: 231 distinct
focused tests passed across these runs. No complete regression suite or live provider run.

Single synthetic in-memory EVTX measurement (fake AI, one candidate/one record):

| Measurement | Result |
|---|---:|
| Extraction | 6.415 ms |
| AI message/output bytes | 1,357 / 567 |
| Reconciliation | 0.505 ms |
| Proposed/approved/executed searches | 1 / 1 / 1 |
| Query elapsed | 8.143 ms |
| Evidence packet / handoff bytes | 2,609 / 584 |

This measurement excludes process startup and real model latency. The Windows
monotonic clock rounded the tiny aggregate interval to zero; the query measurement
uses `perf_counter`. Larger-case latency and interpretation quality need manual
acceptance. Existing transcripts, schema-5 evidence and investigation contracts are
unchanged. Implementation: `briefing.py`, `briefing_cli.py`, CLI/catalog wiring,
briefing-only worker branch and audit redaction; version comes from pyproject.

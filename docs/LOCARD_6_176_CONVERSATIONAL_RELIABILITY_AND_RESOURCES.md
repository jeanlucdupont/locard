# Locard 6.176 — Conversational reliability and resources

Date: November 25, 2026. Starting revision: `ddca184` (6.175), clean working tree.
Implementation is uncommitted; live acceptance is pending. LiteLLM remains
**1.111.0**. No dependency pins or packaging configuration changed.

## Diagnosis and scope

The analyst reported successful 6.175 conversation/full diagnostics, followed by
an 8.874-second live failure at `response_parse`, location `validation`, finish
reason `tool_calls`. The old `tool_count: 6` counted **advertised tools**, not
returned calls. The original rejected response is unavailable in this task.
The precise live failing invariant therefore remains **unconfirmed**.

Source inspection established reproducible rejection paths in
`conversational_ai/provider.py`: more than four calls; invalid/duplicate IDs;
argument shape; completion/call mismatch; assistant text; usage; continuation
format, JSON, size, content and call binding. Synthetic valid five/six-call
responses reproduced the former count rejection. That is a confirmed defect,
not proof that it caused this particular live failure.

`validate`, `generate`, `assistant_message` and `restore` now retain strict
structure/binding validation with specific codes. Multiple calls, text plus
calls, null assistant content, repeated tool names with distinct IDs and exact
LiteLLM continuation serialization are supported. Up to 128 calls may fit in a
single defensively bounded response; this is a transport ceiling, not a session
operation budget. Unknown tools and out-of-scope arguments are rejected by the
trusted tool layer. Tool-result IDs remain paired, including explicit
not-executed results when a recoverable pause interrupts a batch.

No parallel-tool disabling, fallback provider, schema repair request, automatic
retry, arbitrary SQL, shell execution or model-controlled policy change was added.
Legacy advisory/investigation paths and forensic ingestion remain unchanged.

## Resource policy comparison

New authorizations use `conversational-authorization-v2`; unset budgets are JSON
`null`/Python `None`. The source/model/time/family/case security boundaries remain
mandatory. Legacy v1 authorizations retain their finite expiry/budget rules.

| Control | 6.175 | 6.176 default / treatment |
|---|---:|---|
| Active session seconds | 900 | No session budget; `--max-seconds` optional |
| Provider requests | 30 | No session budget; `--max-requests` optional |
| Tool operations, including notes | 60 | No session budget; `--max-operations` optional; worker counter also optional |
| Provider-reported total tokens | 200,000 | No session budget; `--max-tokens` optional |
| Distinct retrieved records | 300 | No session budget; `--max-records` optional |
| Replayed message-content disclosure | 2 MiB | No cumulative budget; `--max-disclosure-bytes` optional, explicitly disclosed in approval |
| Individual provider timeout | 60 s | 180 s; `--provider-seconds`, maximum 600 |
| Individual forensic operation timeout | 15 s | 60 s; `--tool-seconds`, maximum 600 |
| Configured request-content bound | 64 KiB | 256 KiB; `--request-bytes`, maximum 512 KiB; model context can reduce this |
| Individual tool result | 32 KiB | 128 KiB; `--result-bytes`, maximum 256 KiB |
| Requested output tokens | 2,048 | 8,192; `--output-tokens`, maximum 32,768; model metadata may reduce this |
| Returned calls per response | 4 | 128 transport ceiling plus 512 KiB aggregate response bound |
| Assistant text | 32 KiB | 128 KiB UTF-8 |
| Continuation | 32 KiB | 256 KiB UTF-8, still exact and bound to assistant exchange |
| Grant lifetime | 24 hours | Current explicitly approved session; no automatic expiry. Explicit expiry still enforced if present |
| Notes / verified observations | 200 / 100 | No separate count ceiling; durable notebook and process memory remain finite |
| Notebook admission | 3 MiB / 230 events | Conversation-specific 256 MiB / 100,000-event storage profile, with admission/terminal headroom |
| Historical reader | 4 MiB / 256 events | Extended profile only for conversational notebooks; legacy limits unchanged |

These settings are not a claim of unlimited execution or storage. Optional budgets
cannot be modified by model tools. This version does not add an in-session budget
amendment command: exit and explicitly authorize a new session with different
budgets if required. Historical notebook loading grants no execution authority.

An optional active-time budget reserves five seconds before new operations for
closure. Token-budget admission conservatively reserves UTF-8 request-content
bytes plus requested output tokens. It can pause earlier than an exact tokenizer
would. Unknown usage blocks further dispatch under an explicit token budget.
This is not a guaranteed monetary billing cap.

## Context, transport and long sessions

`conversational_ai/resources.py` reads only the installed LiteLLM bundled model
metadata, without importing the SDK or downloading tokenizers/models. Known
input/output limits clamp configured values. Unknown models use a documented
128K-token input / 8,192-output fallback. Request content is conservatively
estimated at one UTF-8 byte per token, with output and 2,048 framing tokens
reserved. The fallback is not certification of an unknown model's capacity;
provider rejection pauses the session. OpenAI is still the only conversational
provider implemented; local and other provider integrations are not newly claimed.
Reasoning tokens may consume output allocation without appearing as visible text.

`Session.messages` retains the initial analyst objective and recent complete
exchanges within the effective bound. It drops whole model-context blocks, never
individual tool replies that would orphan call IDs. Earlier exchanges remain in
the append-only notebook. Known evidence IDs, verified observations, notes and
worker-side field references are not evicted by model-context compaction.
Recent note/reference context is explicitly non-authoritative; original evidence
must be inspected again when needed. This is bounded recent-context selection,
not a new semantic search or long-term model memory system.

The existing transcript writer/reader implements the conversation-specific
`conversation-long-v1` profile. Hash chains, private directories, complete writes,
fsync, atomic manifest replacement and uncertain-publication failures are retained.
No new storage engine or rotation architecture was introduced. Legacy transcripts
keep their original limits. New conversational readers materialize the notebook;
very large notebooks incur memory cost. There is no durable restart/resume feature.
At capacity, work pauses with an explicit reason; rotation across notebooks is
not automatic. Already retained history remains available.

Other unchanged technical boundaries include:

- Forensic IPC: 512 KiB messages; cloud worker input: 1 MiB; cloud result: 2 MiB.
  The conversational adapter admits at most 544 KiB including JSON framing margin.
- Journal entry: 600 KiB; finalization headroom and safe publication remain required.
- Forensic worker memory: 2 GiB; existing process job and cleanup controls.
- Read-view WAL-growth protection: 64 MiB. Concurrent ingestion can require a fresh
  investigation rather than keeping a long pinned view indefinitely.
- Query pagination: at most 20 search rows / 40 inspection fields per call,
  1,024-byte string previews with explicit truncation, 10,000 inspection/offset
  boundary, and existing specialized search/time/candidate restrictions.
- Individual arguments: 16 KiB; tool ID: 128 UTF-8 bytes; name: 80 bytes;
  analyst message: 8 KiB. Original value verification remains scalar and bounded.
- Mandatory session recording retains its existing 2 MiB segment rotation,
  100 MiB directory quota and 1,000-file safety ceiling. Audit failures still
  stop protected operations; this version does not bypass or enlarge those quotas.

No individual query is allowed to run indefinitely. Worker timeout or loss of
read-view integrity closes/contains the session; it does not pretend that the
pinned transaction can be safely reused. Completed notebook work survives.

## Pausing, cancellation and loop safeguards

Recoverable provider failures (including truncation/refusal), optional budgets,
context capacity and unproductive loops pause at the application-service boundary.
There are no automatic provider retries. The analyst may redirect or explicitly
try again at the next prompt. A provider timeout does not by itself destroy a
healthy forensic worker/read view. Unknown provider consumption is tracked.

Repeated identical tool requests in one turn pause before the third unchanged
repeat. Argument order is canonicalized; new evidence IDs, a newly verified
observation or a new note resets the repeat guard. Changed arguments, pagination/
time window and new analyst turns are separate requests. Three consecutive rejected tools also pause. These guards do
not prescribe an artifact order. They may pause a deliberately repeated query;
the analyst can explain the new hypothesis in the next turn. An informational
warning follows five minutes of active turn work; after ten minutes, work pauses
at the next operation boundary for analyst direction. A currently running bounded
operation can finish before that checkpoint. No request-count checkpoint imposes
another hidden 30-call policy.

The synchronous CLI supports `/status`, `/summary`, `/exit`, and Ctrl+C. It cannot
accept live textual redirection while a call is active. Ctrl+C interrupts owned
subprocess waits and closes the session; service `cancel()` requests stopping at
the next safe boundary. Filesystem fsync/OS calls are not newly made preemptible.
Cleanup limitations remain explicit. A failed pause audit itself closes the worker.

Unattended conversational operation was not added. Existing legacy autonomous
modes retain their own finite approvals and budgets. The interactive ten-minute
checkpoint protects against leaving a conversational turn running unnoticed.

## Accounting and external disclosure

`Session.status()` supplies backend-neutral counters; `/status` renders them.
Counters include active and approximate idle time, requests, successful tools,
successful forensic operations, failed tools, notes, unique retrieved/disclosed
IDs, reported input/output/total tokens, unknown usage and uncertain provider
outcomes. Unknown monetary cost is displayed as unavailable, never zero.

The counters distinguish:

1. Distinct IDs included in attempted provider disclosures.
2. Repeated original tool-result content bytes in selected history.
3. Total serialized message-content bytes, after restoring continuation.
4. Serialized application request-content bytes, including tool schemas.

Attempts are charged before provider entry. They mean exposure **may** have
occurred, not confirmed server delivery. Tool-result bytes include their context
and qualifications, but do not pretend to isolate evidence quoted again in model
prose. Message bytes conservatively cover analyst text, model history and opaque
continuation too. These are application-level UTF-8 serialization metrics, not
TLS traffic or the provider SDK's transformed HTTP envelope size. Repeated history
counts again. Optional disclosure budgets apply to the complete message-content
counter, not just unique evidence or raw field values.

Only requested, bounded, scoped tool results can introduce original evidence.
Removing the cumulative default does not authorize bulk case export. Approval
explicitly states the provider/model, source/time/family scope, read-only access,
contextual timestamp policy and absence/presence of a cumulative byte budget.
Internal identity/epoch JSON stays in protected records rather than normal UI.

## Validation diagnostics

Stable invariant codes cover response type/fields/size, assistant content,
call structure/count/identity/duplicates/name/arguments, finish reason/call
mismatch, usage/cost and continuation format/size/JSON/fields/content/binding.
`diagnostics.RULES` is the closed vocabulary; arbitrary exception text is not logged.
Shape metadata records advertised and returned counts separately, assistant type
and byte length, finish reason, argument byte length, continuation size/presence,
reasoning/replay presence and failed rule where available. No raw arguments,
incident narrative, credentials, provider body or continuation content enters
these default diagnostics.

`ai check --conversation` now explicitly authorizes up to four synthetic requests:
more than four harmless calls, a successive tool round, a natural-language result,
and production-catalog acceptance without actual evidence access. If the model
returns fewer calls, coverage is reported as partial, not silently certified.
All calls go through the production transport/normalizer; automated tests use mocks.

## Validation results

Focused deterministic/mock-provider tests only; no live request or real case access.
The first adaptation run had six failures in assertions expecting the old close,
context-size and generic-error behavior; these assertions were updated for the
explicitly requested policy while preserving audit/worker cleanup assertions.
An intermediate run passed 93 tests. The later expanded conversation run passed
98 with one new fixture failure: its reused helper generated invalid timestamps
after the tenth record. A dedicated valid 310-event fixture corrected the test;
that test then passed in 6.05 seconds. No production behavior changed to fit it.

Final results (counts overlap; do not add them):

| Run | Actual result |
|---|---|
| Conversation resource/AI/provider/continuation suites | **99 passed in 84.63s**, clean exit |
| Expanded audit, retrieval, context inspection, OpenAI/Anthropic/Gemini, provider, semantic ordering and advisory-contract regressions | **216 passed, 2 failed, 3 deselected in 122.13s** |
| Journal publication suite | **22 passed, 1 failed in 7.34s** |
| Baseline archive: journal supervisor and Anthropic failures | **2 failed in 2.75s**, same failures on committed 6.175 |
| Baseline archive: EVTX obsolete CLI test | **1 failed in 1.80s**, same failure on committed 6.175 |
| `git diff --check` | Passed |
| Source launcher / dependency version | Locard **6.176**, LiteLLM **1.111.0** |

The unchanged baseline failures are:

- `test_journal_publication.py::test_supervisor_reports_and_contains_uncertain_publication`:
  legacy test supplies a mismatched execution budget (`BUDGET_CONTRACT_MISMATCH`).
- `test_anthropic_strategy.py::test_final`: canonical structured-response rejection
  with mocked transport, already recorded in 6.175.
- `test_evtx_content.py::test_cli_and_show_offset_preserve_existing_json`:
  test invokes removed top-level `search`, rejected by the current command parser.

The three expanded deselections were two previously documented
`backend_survives_supervisor_boundary_with_approval` cases and the unchanged
400-operation durable-audit stress test. An initial expanded run was interrupted
while spending prolonged time in that stress test; it has no complete result.
A repeated audit run was stopped to avoid repeating the same stress workload.
Only identified task-owned pytest processes were stopped. The smaller expanded
selection completed normally. No tests protecting security were weakened to make
these baseline failures pass.

Tests cover real disposable workers and cross-artifact retrieval, initial independent
searches, subsequent pivots and field verification, analyst redirection, 310 real
synthetic records, 64 requests/operations, >200,000 reported tokens, controlled
clock/checkpoints, explicit budgets, provider failure pause/resumption, audit
failure/cleanup, protocol-complete skipped calls, all validation-code families,
private diagnostics, multi-round synthetic SDK transport, exact replay metadata,
context compaction and notebooks beyond the former limits. The actual LiteLLM
bridge test uses mocked HTTP and blocked network access, not a paid provider.

The source version check was repeated with disposable `LOCALAPPDATA` after the
ordinary sandbox environment reported unavailable session-audit storage. The
isolated check completed cleanly. No audit behavior was changed to bypass that
boundary.

Final targeted command:

```powershell
.\.dependency-check-6175\Scripts\python.exe -m pytest tests/test_conversation_resources.py tests/test_conversational_ai.py tests/test_conversational_provider.py tests/test_litellm_continuation.py -q -p no:cacheprovider --tb=short --disable-warnings
```

No full regression suite was run.

## Manual acceptance

After your commit/push/pull workflow, run from the updated test checkout:

```powershell
.\.venv\Scripts\python.exe locard.py --version
.\.venv\Scripts\python.exe -c "from importlib.metadata import version; print(version('litellm'))"
.\.venv\Scripts\python.exe locard.py --db 'D:\Locard\Cases\KFI-5070790-V2\case.db'
```

Expected versions: **6.176**, **1.111.0**. No dependency reinstallation is required
for an existing 6.175 development checkout with its working environment. The direct
launcher resolves the source version. No provider/configuration change is needed.

In Locard, explicitly approve the synthetic diagnostic:

```text
ai check --conversation
```

Inspect any partial coverage or failure with `ai logs`. Do not automatically repeat
failed provider requests. Then use the configured OpenAI model and original scope:

```text
investigation chat --source src-d3c195d3068e4906a805082df44c1a57 --start 2026-11-17T06:00:00.000000000Z --end 2026-11-18T06:00:00.000000000Z
```

Use the unchanged neutral question:

> Analyze the evidence discovered within the authorized November 17, 2026 time window. Identify potentially suspicious user activity, unusual process execution, browser navigation, downloads, file changes and persistence indicators. Correlate evidence across artifact families, establish a supported chronology, and propose specific follow-up investigations. Distinguish observed evidence from hypotheses. Do not assume that a security incident occurred.

Review and explicitly approve external disclosure. First acceptance uses the new
defaults, without arbitrary budgets. At subsequent prompts use `/status`, natural
language redirection, `/summary` and `/exit`. Test Ctrl+C during active work and
confirm return to the shell. Retained notebook validation proves recorded integrity,
not that arbitrary AI prose is a grounded forensic conclusion.

Optional budgets, only when desired, can be appended to the chat command:
`--max-seconds`, `--max-requests`, `--max-operations`, `--max-tokens`,
`--max-records`, `--max-disclosure-bytes`, each with a positive integer.
Technical flags: `--provider-seconds`, `--tool-seconds`, `--request-bytes`,
`--result-bytes`, `--output-tokens`. Values and maxima are listed above.

## Files and remaining limits

Production changes: `pyproject.toml`; `conversational_ai/{provider,diagnostics,
contracts,service,worker,resources,compatibility,cli}.py`; conversation-specific
branches in `ai/backend.py`, the diagnostic approval wording in `ai/cli.py`, and
an opt-in profile in `investigation_ai/transcript.py`. Tests:
`test_conversation_resources.py`, `test_conversational_ai.py`,
`test_conversational_provider.py`, `test_litellm_continuation.py`.
`.gitignore` permits this report.

Financial budgets, tokenizer-exact forecasting, context rehydration beyond existing
tools, notebook rotation/restart recovery, and additional conversational provider
integrations are not implemented. Do not equate successful synthetic testing with
real investigative quality. The original live rejection remains unattributed;
the new diagnostic must identify its invariant if it recurs.

No original evidence, case database, transcript, permissions or configuration was
modified. No live provider request, commit or push was performed.

# Locard 6.173 — Conversational forensic investigator

Implementation and synthetic validation: November 25, 2026. Starting revision:
`8fbdb8a` (6.172). This document describes the uncommitted 6.173 working tree.
Live investigative quality and performance on the analyst's case remain untested.

## The vertical slice

`investigation chat` starts a conversation alongside the existing autonomous
investigator. The model chooses successive forensic operations, receives their
results, discusses hypotheses and accepts a new analyst direction. There are no
six-call batches or repeated tool approvals. One explicit approval binds the
case, source IDs, artifact families, time interval, provider/model and ceilings.
Scope expansion requires a new session.

All assistant prose is presented as **AI interpretation — unverified**. A separate
`verify_observation` operation rehydrates a disclosed scalar field from the pinned
original read view and compares its exact value and timestamp meaning. This is
field verification, not semantic verification of prose, causality or execution.
There is no new formal-report authority or automatic findings import.

## Components and reuse

| Component | Responsibility |
|---|---|
| `conversational_ai/contracts.py` | Closed tool schemas, immutable authorization, resource defaults |
| `conversational_ai/service.py` | UI-independent `Session`, native tool loop, local history, verification results, accounting, cancellation and notebook loading |
| `conversational_ai/tools.py` | Scoped adapters to existing retrieval and original-field rehydration |
| `conversational_ai/worker.py` | Dedicated `chat_init` and tool operations in a contained read-only process |
| `conversational_ai/provider.py` | Provider-neutral response validation, OpenAI native tool extraction, scripted test provider |
| `conversational_ai/cli.py` | Terminal input/output only; approval, message submission and controls |

Paths above are under `forensic_assistant/`. The service accepts callbacks and
structured events, and has no argparse/input/print dependency. Calls are serialized;
this version is not a concurrent web-session implementation.

Reused services include `EvidenceQueries`, browser predicates, bounded original
EVTX EventData search, object-basename discovery, `same_host_window`,
`ReadView`, `ForensicWorker`, `WorkerJob`, SQLite authorizer/deadline checks,
session recording, `Transcript`, local path/directory guards and private-directory
creation. No forensic schema, ingestion, evidence or provenance format changes.

Small shared retrieval changes permit exact-ID scope checks, scoped object
candidate filtering and caller-supplied hydration for object/EVTX searches.
Exact-ID temporal checks avoid materializing an entire time window for every
individual rehydration. Ordinary searches retain their existing path.

`ModelBackend.converse()` and the cloud worker have a separate native-tool path.
Legacy `complete()` response validation remains separate. No Stage A initialization
sample or legacy orchestration is needed to establish the new read view.

## Tools and exact arguments

All objects reject unknown fields. No SQL, scripts, shell commands, arbitrary
filesystem/network operations or model-controlled configuration are available.

| Tool | Arguments and behavior |
|---|---|
| `search_evidence` | Required `artifact`: `browser`, `evtx`, `mft`, `prefetch`, `registry`. Optional filters listed below. Original record candidates, counts, truncation and continuation. |
| `show_evidence` | Required previously returned `evidence_id`; `offset` 0–10000 and `limit` 1–40 scalar fields. Returns original JSON pointers, values, truncation/redaction, provenance and timestamp semantics. |
| `timeline` | Same arguments as search except `object_basename`, `object_after`, `evtx_text`, `evtx_match`, `evtx_after`. Returns chronological original timestamp observations with record references. |
| `around` | Required known `evidence_id`, explicit `timestamp_slot`, `artifact`; optional `seconds` 1–3600 (default 300), `limit` 1–20, `offset` 0–10000. Existing same-host semantics; narrowed to anchor source and approved time interval. |
| `verify_observation` | Required known `evidence_id`, scalar `field` JSON pointer, `value_json`; exact `timestamp_meaning` when the field is a timestamp. Rehydrates and checks the original field, previously disclosed value and meaning. |
| `note` | `kind`: hypothesis/interpretation/open_question/next_lead; `text` ≤2000 UTF-8 bytes; `status`: active/revised/rejected/unresolved. Always unverified, append-only history. |

Search filters:

- `source_id`: one approved source. Required when more than one was authorized.
- `start`, `end`: narrow the approved half-open time interval; never expand it.
- `limit`: 1–20, default 10; `offset`: 0–10000 for ordinary paging.
- `hostname`, `username`, `process`, `path`, `ip`: existing normalized retrieval
  semantics, not implicit full EventData search. Process is the existing process
  filter, not a new arbitrary substring matcher.
- `event_id`: integer 0–65535.
- `url`, `url_contains`: exact URL or case-sensitive literal substring, including
  recorded URL-chain entries; mutually exclusive and Browser-only.
- `browser_kind`: `visit` or `download`; `download_path`: normalized exact
  download target/path, Browser-only.
- `registry_key`, `registry_key_contains`: exact or escaped literal substring,
  case-insensitive, mutually exclusive, Registry-only.
- `value_name`, `value_name_contains`: exact or escaped literal substring,
  case-insensitive, mutually exclusive, Registry-only. Existing recognized
  UserAssist decoded-name behavior remains available.
- `evtx_text`, `evtx_match` (`exact`/`contains`), `evtx_after`: explicit bounded
  original EventData content search using the existing deterministic cursor.
  Requires at most 24 hours; use its continuation instead of offset.
- `object_basename`, `object_after`: exact basename candidate discovery, not
  object identity. Requires at most 24 hours; only artifact/source/time/limit
  and its cursor may accompany it. Limit is capped at 10; ordinary filters and
  offset cannot be combined with this path.

Text filters are bounded to 512 UTF-8 bytes (EVTX text 256). A returned cursor is
scope-bound; coverage metadata remains visible. Broad count queries can still
hit the operation deadline on large cases: narrow the interval/filter instead
of treating a timeout as absence. Existing parser/forensic meanings are unchanged.

`process_tree` is deferred: this slice does not expose the existing correlation
graph without proven endpoint-by-endpoint source/time authorization. A cited
record, matching name or temporal neighbor is not a proven causal relationship.

## Scope, original data and verification

Source/time eligibility is applied through existing query predicates before
original content hydration and checked again before disclosure. A record with
ambiguous/multiple source memberships is excluded, even if multiple sources were
approved. Browser membership uses the existing browser occurrence/context logic.
Registry inherited key timestamps and recognized derived execution timestamps
use the existing timestamp projection. Supporting record IDs must also be eligible.

The approved interval is `[start,end)`. The adapter converts the exclusive end
to the preceding nanosecond for existing inclusive-end queries. Record eligibility
authorizes **bounded full-record context**, including explicitly contextual
out-of-window timestamps. This is stated on the approval screen. Each timestamp
retains its own meaning; additional timestamps do not enlarge retrieval scope.

Search summaries disclose up to 12 scalar fields and eight timestamp observations
per record. Inspection pages expose up to 40 fields; individual strings are
bounded to 1024 UTF-8 bytes and explicitly marked truncated. There is a 10000-field
inspection ceiling. Oversized results are rejected, not silently considered complete.
Original EVTX EventData includes individual names, ordinals, values and limitations.

Only already returned IDs may be inspected or verified. Verification requires a
previously disclosed, untruncated, unredacted scalar value and independently
rehydrates it. Provenance/analyst metadata is not certified as an original factual
observation. Recognized UserAssist detail is labeled deterministic derived data.
Downloads, file references, filesystem timestamps and Prefetch references retain
their limitations; none automatically proves successful program execution.

## Provider and context contract

The internal result is `{text, tool_calls, finish_reason, usage, cost}`. Each tool
call has an opaque correlation `id`, allowlisted `name` and argument object.
The OpenAI adapter translates native calls; up to four calls are accepted per
response and executed sequentially. Refusals, incomplete output and malformed
responses stop safely. There are no automatic provider retries or cloud fallbacks.

Existing credentials/model settings, cloud subprocess containment, timeout and
session dispatch recording are reused. No remote conversation storage is used.
`prepare()` checks existing readiness/configuration; it does not introduce an
extra readiness completion. Other conversational providers are explicitly unsupported.

Future local adapters can return the same provider-neutral result using a simpler
structured protocol and locally assigned call IDs. They will also need explicit
authorization support; replacing the provider does not replace forensic tools,
notebook storage or validation. Local-model parity is not claimed here.

Canonical history remains local. Requests retain the initial analyst objective,
recent complete exchanges and a bounded notebook reminder. Whole old exchanges
may be omitted; native tool-call/result pairs are never split. Prior notes are
unverified context, and historical references alone are not evidence. The model
can reinspect known originals. A single oversized exchange stops with
`CONTEXT_CAPACITY`; it is not truncated into misleading evidence.

## Notebook, audit and lifecycle

Notebooks live at `<case.db>.conversations/<session-id>/manifest.json` and
`events.jsonl`. The versioned engine is `conversational-v1`, authorization
`conversational-authorization-v1`. A new private directory uses existing Windows
ACL/POSIX protections; no original directory permissions are altered.

Events distinguish approval, read view, analyst context, provider attempts,
responses, validated tool attempts/results, failures, unverified notes, exact
field verification, turn completion and terminal accounting. Provider attempts
are durably recorded before entry; an attempt is possible exposure, not proof of
transport success. Recording failure prevents further dispatch. Configured secret
values are redacted. These files still contain sensitive analyst/evidence content.

`notebook(root,id)` verifies the existing manifest/hash chain and reconstructs
recorded notes and field checks without a provider or live case. Integrity is not
semantic grounding or fresh case revalidation. No historical notebook grants
authorize new provider execution, and legacy report imports are unchanged.

Ctrl+C interrupts active subprocess waits and closes the conversation; normal
exit, resource exhaustion and failures retain completed history. Process cleanup
and final read-view confirmation are reported separately. A backend caller's
`cancel()` requests the next safe boundary; asynchronous redirection is not
implemented. Continuing after cancellation requires a new approved session.

## Resource defaults

| Resource | Ceiling |
|---|---:|
| Cumulative active work, excluding analyst idle time | 900 seconds |
| Provider request | 60 seconds, clamped to remaining active work |
| Read-view/tool operation | 15 seconds, clamped to remaining active work |
| Provider requests / operations (including notes) | 30 / 60 |
| Canonical serialized messages plus tool definitions per request | 65536 UTF-8 bytes |
| Tool result | 32768 bytes plus bounded protocol envelope |
| Cumulative transmitted message-content accounting | 2097152 bytes, including repeated context |
| Measured provider tokens / requested response tokens | 200000 / 2048 |
| Distinct retrieved records / notes / verified observations | 300 / 200 / 100 |

Limits may be lowered through application configuration; CLI exposes
`--max-seconds`, `--max-requests`, `--max-operations`. The model cannot alter them.
Five seconds are reserved from active work for closure. Grant lifetime is 24 hours;
idle sessions cannot retain authority indefinitely. OS/filesystem stalls during
synchronous journal writes are not a separately supervised operation.

The existing journal limits are retained (4 MiB, 256 events), with conservative
admission stopping at 3 MiB or 230 events to preserve terminal capacity. Request
size is canonical content accounting, not an estimate of HTTP transport bytes.
Usage may be unknown; token limits are checked between responses. Monetary cost
is reported unknown, not represented as a guaranteed spending cap.

## Windows manual acceptance

After the analyst's commit/push/pull workflow, in the separate test checkout:

```powershell
Set-Location C:\tmp\locard
.\.venv\Scripts\python.exe -m pip install -e .
.\.venv\Scripts\python.exe locard.py --version
.\.venv\Scripts\python.exe locard.py --db "D:\Locard\Cases\KFI-5070790-V2\case.db" investigation chat --source src-d3c195d3068e4906a805082df44c1a57 --start 2026-11-17T06:00:00.000000000Z --end 2026-11-18T06:00:00.000000000Z
```

Expected version: **6.173**. Use the existing configured OpenAI model. A local or
unsupported provider produces an error, never a silent cloud switch. Inside the
selected case shell, use the same `investigation chat ...` arguments without the
launcher/`--db` prefix. Omitted source/time arguments are prompted locally.

At the analyst question prompt, paste exactly:

> Analyze the evidence discovered within the authorized November 17, 2026 time window. Identify potentially suspicious user activity, unusual process execution, browser navigation, downloads, file changes and persistence indicators. Correlate evidence across artifact families, establish a supported chronology, and propose specific follow-up investigations. Distinguish observed evidence from hypotheses. Do not assume that a security incident occurred.

Review the scope and external disclosure before entering `y`. Do not seed known
incident indicators. Then try natural directions such as “What evidence supports
that interpretation?”, “Focus on persistence”, or “Summarize what remains unknown”.
`/summary` requests an interim assessment; `/exit` ends; Ctrl+C cancels active work.
Check that original-field observations remain separate from model prose, omitted
coverage is acknowledged, useful pivots occur and no per-tool prompts appear.

Provider-free notebook inspection after exiting (substitute the printed ID):

```powershell
.\.venv\Scripts\python.exe -c "import json; from forensic_assistant.conversational_ai.service import notebook; print(json.dumps(notebook(r'D:\Locard\Cases\KFI-5070790-V2\case.db.conversations','SESSION_ID'),ensure_ascii=True,indent=2))"
```

This reads the sensitive notebook only, not the live database. Do not publish its
contents casually. No live provider request or real-case inspection was performed
during implementation.

## Validation and acceptance status

No full regression suite was run. Automated fixtures use disposable cases, actual
retrieval workers and scripted or mock providers; they cannot establish live
investigative usefulness.

Recorded focused results (counts overlap; do not add them):

| Run | Result |
|---|---|
| Initial combined conversational/provider/EVTX/CLI/session/read-view/search run | 180 passed, 5 failed, 114.00s |
| Same relevant suites after the new test correction, with four identified problematic cases excluded and two additional conversational checks | 183 passed, 4 deselected, 133.89s |
| Advisory contract/rendering and invalid-field checks in supplemental run | 16 passed; the run also had 1 FAISS failure and 4 UserAssist setup errors, 4.11s |
| Final conversational suite (`tests/test_conversational_ai.py`) | 29 passed in 29.57s |

The initial new timeout-test failure was a test setup issue: this environment has
no LiteLLM installation, so dependency detection stopped before the mocked
subprocess. The test now explicitly isolates that dependency check without
importing an SDK or making requests. The final native-provider tests exercise
mock extraction, provider preservation and subprocess timeout containment.

Three existing failures were reproduced against a disposable `git archive HEAD`
copy of 6.172: both `test_backend_survives_supervisor_boundary_with_approval`
parameters terminate `WORKER_FAILURE`, and the EVTX CLI test still uses removed
top-level `search` spelling. That baseline comparison was **3 failed, 1 passed in
12.28s**. Their implementation/tests were not changed in this task; the underlying
legacy supervisor failure remains outside this slice's diagnosis.

`test_transaction_semantic_proof_and_stale_index` cannot reliably load the FAISS
DLL in the working environment (Windows also reported `0xc0000008` during import).
It passed in the disposable baseline, but failed again here. No dependency or
Windows settings were changed. The conversational route does not require FAISS.
Four supplemental UserAssist cases fail during fixture setup at the old
`ingest-registry` parser spelling (follow-on fixture errors occur); an isolated
run confirmed **4 errors in 1.91s**. They do not establish a retrieval regression,
but those particular inherited/derived-timestamp regressions remain unverified.

The selected combined command was:

```powershell
.\.venv\Scripts\python.exe -m pytest tests/test_conversational_ai.py tests/test_ai_providers.py tests/test_evtx_content.py tests/test_cli_consolidation.py tests/test_session_recording.py tests/test_investigation_read_view.py tests/test_extended_search_reliability.py -q -p no:cacheprovider --tb=short -k 'not backend_survives_supervisor_boundary_with_approval and not cli_and_show_offset_preserve_existing_json and not transaction_semantic_proof_and_stale_index'
```

New coverage includes actual Browser → MFT → Prefetch → Registry pivots; original
event inspection and field verification; timeline/around and timestamp meanings;
exclusive-end and ambiguous-source exclusion; invented references/values and
unsupported tools; original EventData instructions treated as data; credentials
redaction; grant expiry/provider change; cancellation, real hung-worker timeout,
mock cloud timeout, audit failure, context trimming and deterministic notebook
loading. Case-file bytes are checked unchanged in the relevant synthetic tests.

Changed existing files: `.gitignore`, `pyproject.toml`, `forensic_assistant/cli.py`,
`command_surface.py`, `ai/backend.py`, `ai/cloud_worker.py`,
`investigation_ai/transcript.py`, `retrieval/evidence.py`,
`retrieval/object_discovery.py`, `retrieval/evtx_content.py`. New files are the
seven-module conversational package, `tests/test_conversational_ai.py` and this
document. Version remains sourced solely from `pyproject.toml`.
`git diff --check` passed. No full suite, live provider call, real-case access,
commit or push was performed. All changes remain available for manual review.

Known limitations: OpenAI only; no process tree, scope amendment in place,
restart continuation, semantic verification of arbitrary prose, full report
integration, concurrent web service or local-model certification. Large-case
query responsiveness and native tool-calling compatibility of the configured
live model require manual acceptance.

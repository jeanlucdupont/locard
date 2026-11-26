# Locard 6.174 — Conversational provider integration

November 25, 2026. Clean starting revision `0f0d986`, version 6.173.
Implementation is uncommitted; application version is now 6.174.

## Findings and limits of the diagnosis

The reported live run approved its scope, created a notebook and initialized its
read-only worker, but its first provider request failed before any forensic tool.
The legacy structured-output handshake succeeded. These are user-reported live
results, not a native-tool compatibility certification.

Confirmed in source:

1. `ModelBackend.converse()` bypassed `_cloud()`'s diagnostic wrapper, so failures
   could instruct the analyst to inspect `ai logs` without creating an entry.
2. `conversational_ai.cli.run()` cleaned up and re-raised `ProviderFailure` (a
   `RuntimeError`), which the ordinary command error handler did not catch.
3. Native response extraction grouped malformed envelopes, unsupported finish
   reasons and token exhaustion under insufficiently specific errors. The old
   refusal spelling also did not identify the existing canonical refusal category.
4. Calling legacy `prepare()` tied native tool calling to unrelated structured
   response compatibility state. A successful legacy handshake does not prove
   tool compatibility, and a failed legacy schema check need not block a native
   tool diagnostic.

**The precise original live provider rejection remains unknown.** No raw error
or conversational diagnostic for that failed request is available here. There
is no evidence establishing a credential defect or lack of model tool support.
`settings.key('openai')` reads the configured environment key correctly.

The development venv has no LiteLLM distribution. Read-only inspection of the
separate `C:\tmp\locard` installation found LiteLLM 1.106.0 and OpenAI 2.53.0,
matching the project's pins. Its OpenAI chat adapter lists `tools`, `tool_choice`
and `max_completion_tokens`. This confirms parameter vocabulary, not live model
acceptance. No dependencies were installed, no paid request was made, and the
transport was not replaced speculatively.

## Corrections

`ModelBackend.converse()` records success and failure under operation
`conversation`, retaining the existing one-shot cloud worker and zero retries.
It checks credentials without consulting the legacy structured readiness cache.
Provider/model selection, authorization, investigation ceilings and forensic
retrieval remain unchanged. `complete()` and `ai check --full` retain their paths.

`conversational_ai/provider.py` now distinguishes:

- Transport/authentication/HTTP/parameter/schema errors using existing classifiers.
- Refusal and content filtering (`provider_refusal`).
- Token exhaustion (`output_truncated`).
- Unsupported completion reasons (`conversation_finish`).
- Tool argument JSON parsing (`response_parse_failed`).
- Invalid IDs, duplicate IDs, content types and envelopes (`conversation_envelope`).
- Internal SDK/adapter failures (`conversation_adapter`).

`conversational_ai/diagnostics.py` supplies a small allowlisted metadata projection:
transport strategy, tool count, serialized catalog size, tool-choice presence,
token ceiling, timeout, recognized finish reason, available usage, safe exception
class and internal phase. Existing metadata retains HTTP status, recognized
provider codes and rejected parameter names. SDK import failures can be located
separately from dispatch/extraction. Unknown values become `Other`/`other` rather
than leaking arbitrary strings.

No prompt, evidence, response text, tool arguments, credential, header or unrestricted
exception message enters provider diagnostics. Configured-secret filtering still
applies at the existing IPC/storage/rendering boundaries. If provider-log persistence
fails, the error says so rather than falsely promising a matching log entry.
Mandatory session-audit failures still fail closed.

Expected conversational provider, worker, resource and storage failures now return
status 2 after preserving the notebook and reporting cleanup. The interactive
shell remains available. Unexpected programming errors are recorded with a safe
class/location and re-raised, not silently hidden. There is no automatic retry.

## Synthetic compatibility diagnostic

```text
ai check --conversation
```

This is independent of the active forensic case and uses the same
`ModelBackend.converse → _cloud_request → cloud_worker → provider.generate`
path and response validation as chat. Explicit approval is required before any
request, with `--authorize-diagnostic` available for deliberate scripted consent.
It cannot be combined with `--full` or `--connectivity`.

At most three requests, each with a 30-second timeout and 512 response tokens:

1. Advertise one synthetic echo tool, set native `tool_choice=required`, and
   validate exactly one call with the fixed `locard-test` argument.
2. Return its deterministic result with the exact assistant/tool call ID pairing;
   require a final natural-language sentence containing the token, with no tool calls.
3. Advertise the actual production catalog, with tool execution disabled, to
   establish that the provider accepts its schemas. Require nonempty text.

The harmless tool is never dispatched to forensic services. Requests contain only
fixed synthetic text, production tool descriptions/schemas and the synthetic prior
response. No case path/ID, incident description, evidence or notebook is an input.
Each phase starts `not reached`; successful earlier phases remain visible if a
later phase fails. Failure reports the phase, category and sanitized metadata.
The CLI returns status 2 for an unsuccessful diagnostic. No readiness cache is
silently upgraded, and no later phase runs after failure.

A green catalog stage proves schema acceptance, not correct model use of every
tool or useful investigation. Real evidence authorization remains a separate step.

## Automated validation

All testing was synthetic/mock-only, with temporary diagnostic storage.

- Initial provider plus conversational suites: **43 passed in 35.31s**.
- Expanded focused provider/conversation/diagnostics/readiness/CLI run:
  **167 passed, 2 failed in 70.98s**. Both failures are the existing
  `test_shell_startup_nonblocking_and_once` parameters, which use the old shell
  `version` command/output expectation. They are unrelated to native tool calling;
  no old UX was restored to satisfy them.
- Final new provider integration suite: **18 passed in 4.42s**, including a real
  production cloud-worker subprocess with only its SDK replaced by a temporary
  fake, actual shell recovery after provider failure, notebook/cleanup retention,
  sanitized errors, malformed envelopes, approval and synthetic round trips.
- Final integration plus existing provider-diagnostics regression run after the
  last code changes: **53 passed in 6.45s**. Counts overlap; do not add these runs.

The 6.173 conversational tests still exercise real read-only workers over disposable
SQLite evidence. The new tests do not contact an external provider. Scripted
success is not proof of live LiteLLM/model compatibility.

Both legacy startup failures were reproduced in a disposable archive of committed
6.173 (`0f0d986`): **2 failed in 3.63s**. Their tests and production behavior were
left unchanged. No full suite was run. `git diff --check` passed.

## Exact manual acceptance

After the analyst's commit/push/pull workflow, use the source checkout directly:

```powershell
Set-Location C:\tmp\locard
.\.venv\Scripts\python.exe locard.py --version
.\.venv\Scripts\python.exe locard.py ai check --conversation
```

Expect **6.174**. Review the explicit potentially billable synthetic-request prompt.
No package reinstall is required: dependencies, packaging and entry points have
not changed. The direct source launcher uses the pulled code. Do not run a new
real investigation unless the conversational diagnostic succeeds.

On diagnostic failure:

```powershell
.\.venv\Scripts\python.exe locard.py ai logs
```

Inspect the latest `Operation: conversation`, failed phase/category, HTTP/parameter
details if available, and internal location. Do not enable raw evidence capture
merely to investigate this synthetic compatibility failure.

On success, repeat the original approved scope:

```powershell
.\.venv\Scripts\python.exe locard.py --db "D:\Locard\Cases\KFI-5070790-V2\case.db" investigation chat --source src-d3c195d3068e4906a805082df44c1a57 --start 2026-11-17T06:00:00.000000000Z --end 2026-11-18T06:00:00.000000000Z
```

Use the unchanged neutral question:

> Analyze the evidence discovered within the authorized November 17, 2026 time window. Identify potentially suspicious user activity, unusual process execution, browser navigation, downloads, file changes and persistence indicators. Correlate evidence across artifact families, establish a supported chronology, and propose specific follow-up investigations. Distinguish observed evidence from hypotheses. Do not assume that a security incident occurred.

Review and approve the scope independently. No new indicators or enlarged limits
are needed. If the conversation fails, it should preserve its notebook, state
cleanup status and return to the existing shell without a normal-operation traceback.

## Changed files and scope

Existing: `ai/backend.py`, `ai/cloud_worker.py`, `ai/cli.py`,
`ai/provider_diagnostics.py`, `conversational_ai/provider.py`,
`conversational_ai/cli.py`, top-level `cli.py` (all under `forensic_assistant/`),
`pyproject.toml`, `tests/test_conversational_ai.py`, `.gitignore`.
New: `conversational_ai/diagnostics.py`, `conversational_ai/compatibility.py`,
`tests/test_conversational_provider.py`, this document.

No forensic retrieval, notebook contract, investigation authorization, resource
ceilings, original evidence, case sidecars or transcripts were changed. No commit
or push was made. Manual native-provider acceptance remains pending.

# Locard 6.162 — Autonomous investigation preflight

## Confirmed diagnosis

Baseline: 6.161, HEAD `1c03e09`. No real case, assessment, provider log or transcript was opened.

The exact reported message came from `investigation_ai.autonomous.prepare`: `readiness.status(client.config).get('investigation_compatibility') != 'ready'` deliberately raised ValueError. It was not a translated API exception. That guard performs local cache inspection only, before the exact engine grant approval, worker startup, evidence retrieval, transcript creation or model dispatch.

Startup uses `ai.readiness.check` / `present`: local configuration, credential presence and dependency discovery. `ai status` similarly reports configuration; neither establishes model access or structured-output compatibility. `ai.readiness.status` instead reads a process-local synthetic-diagnostic cache. An absent cache (including after restart) reports unchecked. Its key binds provider/model, application version, capability/schema definitions; a separate private credential identity invalidates it when credentials change. No cache is restored across processes.

Consequently configured OpenAI can legitimately be blocked by this guard. The exact live cache contents are unavailable: the observed message establishes only that investigation compatibility was not ready. It cannot establish whether no diagnostic had run or an earlier diagnostic had failed. There is no evidence that `gpt-6.1-sol` was rejected. No model-name whitelist was implicated, and this failure path sends no OpenAI request. Earlier independently requested operations cannot be reconstructed from this console message.

`investigation_workflow.run` previously collected stage choices before this check. Those choices were not the final immutable engine authorization. The new local preflight runs before those choices; the engine repeats the guard before granting execution.

## Correction and diagnostics

`ai.investigation_preflight.require` centralizes the existing gate without removing it or adding remote probes. It distinguishes unverified compatibility, local configuration issues, internal cache-inspection failure, and allowlisted categories from earlier diagnostic failures (authentication, model access, schema/parameter rejection, timeout, rate limit, network or response validation). It never copies arbitrary provider error text. It makes no claims about actual capabilities from the configured model name.

Failures raise `InvestigationPreflightError`, containing bounded sanitized provider/model, stable category, preflight stage, reason, corrective action, origin, optional earlier diagnostic stage, zero requests/lookups and no findings. Human output uses existing semantic red error styling. The CLI returns exit code 2. JSON receives `status: not_started` and a structured error without ANSI; guided preview text is redirected to stderr in JSON mode.

Every blocked preflight records a required `INVESTIGATION_PREFLIGHT` failure using the existing activity mechanism when an audit session is bound. Mandatory recording errors propagate; they are not ignored. The existing command/session failure recording remains in place. Previously the generic ValueError followed those command error paths, but did not create an investigation transcript. This patch does not invent an engine run or rewrite historical audit entries. The live audit recording cannot be confirmed without its logs.

## Compatibility requirements and limits

`ai check --full` is the existing explicitly authorized diagnostic. For OpenAI it can issue up to four synthetic requests: handshake, advisory response, investigation tool proposal and investigation final response. No case evidence is included; proposed tools are not executed. The investigation tool proposal uses the structured JSON contract, not an assumption of native function-call support. Per-response canonical validation remains required. A successful probe demonstrates these synthetic contracts, not guaranteed success for every later analysis, decomposition or synthesis request.

Normal cloud backend preparation can allow unchecked models to be validated by their actual response contract; autonomous Stage A intentionally retains its stricter preflight requirement. Provider configuration still comes from the same settings service. No provider fallback, model substitution, capability registry change, request-budget increase or automatic retry was added. Diagnostic requests remain separately approved and outside the investigation grant.

## Validation

Synthetic tests cover unchecked and ready cache states, model/config invalidation, missing configuration/credential/dependency, earlier authentication/model/schema/parameter/transport/validation failures, sanitized output, required audit recording failure, no prompts or dispatch before successful preflight, JSON and human errors, and unchanged authorized Stage A execution. Existing readiness and provider diagnostic tests use mocks. Guided approval fixtures explicitly represent a verified configuration.

Final focused run: **144 passed in 36.87 seconds** across `test_investigation_preflight.py`, `test_autonomous_stage_a.py`, `test_ai_readiness_levels.py`, `test_provider_diagnostics.py` and `test_cli_consolidation.py`. After preserving multiline human diagnostics, both affected CLI-format tests passed again: **2 passed in 0.68 seconds**. One stale provider-presentation test was updated from a hardcoded dim ANSI sequence to the existing semantic unknown role; production styling was not changed. Guided fixtures now supply explicitly verified configurations. `git diff --check` passed. No full suite, live provider requests, real-case access, commit or push.

## Manual acceptance

Install the updated checkout using the existing workflow, then verify the version is 6.162. Within one interactive Locard session:

```text
ai status
ai check --full
```

The full check requests separate permission for potentially billable synthetic diagnostics. Approve only if intended. Inspect its investigation compatibility result. If it fails, review `ai logs`, address the reported condition, and deliberately rerun the diagnostic if appropriate. `configured` or a connectivity-only check is insufficient. Do not run the full check in a separate short-lived CLI process and expect its cache in the shell.

Once investigation compatibility is ready, select the existing case and run:

```text
investigation run 3aa7e12d14d94720b172ad072c56f92d
```

Review the stage choices and exact bounded grant, then approve. Afterwards inspect `investigation history` and `audit verify`. A failed preflight should show an actionable `Investigation not started` result and no findings; a successful preflight should reach the grant and existing supervised execution. No real-case command was executed during development.

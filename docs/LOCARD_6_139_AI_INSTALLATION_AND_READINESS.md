# Locard 6.139 — Installation and AI readiness

Implemented against clean 6.138 commit `8451162ccdf45a8da118c7e87b4a2e6edcefb1dd` on 2026-11-14. This document describes the uncommitted 6.139 changes, pending manual acceptance. `pyproject.toml` remains the application-version authority.

## Installation and positioning

Locard is **AI-Assisted Forensics**: local-first forensic software with investigator-controlled local or cloud inference. Configuring cloud AI does not automatically disclose all case data.

Previously, LiteLLM and cloud schema validation required the optional `cloud` extra. Standard installation now includes `litellm==1.106.0`, `openai==2.53.0`, and `jsonschema>=4.18,<5`:

```powershell
python -m pip install locard-forensics
# Development checkout, using the intended virtual environment's Python:
python -m pip install -e .
```

`locard-forensics[cloud]` remains valid as an empty compatibility extra. Semantic search and optional local/GPU integrations remain optional. No models are downloaded by these changes. The Windows installer already reads dependencies from `pyproject.toml`; its behavior needs no additional dependency list. The legacy root `requirements.txt` lists parser dependencies, not a substitute for installing the application package.

Standard installation is larger because cloud SDK/integration dependencies are now always present. Download and installed sizes vary by platform and resolved transitive dependencies; no fresh install or size benchmark was performed. Dependencies remain lazy at runtime: ordinary imports and Quick checks do not import the cloud SDKs. Missing credentials do not prevent deterministic forensic commands.

## Readiness levels

| Level | Command | Operation | Meaning |
|---|---|---|---|
| Quick (default) | `ai check` | Local configuration, credential presence, top-level dependency discovery | Configured, not verified |
| Connectivity | `ai check --connectivity` | Explicit non-generative provider operation | Authentication/reachability only |
| Full | `ai check --full` | Explicit synthetic structured-response requests | Compatibility with the tested synthetic contracts |

All commands support `--json`. Quick reports connection, model compatibility, and Locard compatibility as **not checked**, including for unknown model identifiers. Missing keys, missing dependencies and malformed configuration have separate categories. No keys are displayed. Quick does not read investigations, initialize local inference, resolve DNS, or send HTTP/model requests.

Cloud `ai status`, startup presentation and model-selection presentation now use Quick. Explicit local-provider `ai status` retains its existing runtime/loopback inspection; use `ai check` for a strictly configuration-only check with either local or cloud configuration.

Connectivity currently supports OpenAI's authenticated `GET /v1/models`. It reads HTTP status only, not the returned model inventory, and does not test the selected model or D2 contract. Other registered providers, including local, report **not supported**; no generation fallback is used. Outcomes distinguish authentication failure, access denied, rate limiting, timeout, network failure, provider failure and rejected requests. Redirects, environment proxies, automatic retries and provider fallback are disabled for this diagnostic.

The connectivity service runs its network adapter in an owned process: connection timeout is at most three seconds, operation budget at most ten seconds, followed by up to five seconds of process cleanup. Ctrl+C propagates through cleanup. Unconfirmed cleanup is not represented as success. Process creation and OS scheduling remain subject to the host OS; this is not a hard real-time guarantee.

Full diagnostics warn about potentially billable synthetic requests. Interactive use asks for approval; scripts/JSON require `--authorize-diagnostic`. Supplying that flag explicitly authorizes the synthetic calls. OpenAI's existing successful path makes four requests: handshake, advisory, investigation tool proposal and investigation final proposal. Other adapters retain their existing contract checks; local reports unsupported. Existing per-phase timeout, schema, response-envelope and provider diagnostics remain. Full does not inspect a live case and does not certify every future D2 response.

## Execution paths and compatibility

Previously `interactive.shell.startup` / provider configuration called `readiness.present`, which ran synthetic checks. Cloud `ModelBackend.prepare` also performed them when no cached certification existed. These implicit requests are removed.

`readiness.check` and `present` are now local-only. `full_diagnostic` and `present_full` are explicit authorized services. `connectivity.check` is a backend service independent of CLI parsing; it owns a process for deadline containment. `ai.cli.dispatch` selects the requested level. No second configuration subsystem was added.

An unchecked backend may transfer a configuration-only handoff bound to the existing provider/model/contract key. This is not a readiness certificate or a disclosure grant. An explicit cached failure remains a failure; changing configuration invalidates handoff acceptance. Actual request failures do not silently restore readiness or trigger automatic diagnostic retries.

D2 request formats, exact-byte transport gates, single-use grants, worker identities, provider authorization, response validation, grounding and findings acceptance are unchanged. Quick and Connectivity authorize no evidence disclosure. Historical transcripts, report formats and digests are not rewritten.

Machine-readable default readiness intentionally changes: `diagnostic_level=quick`, status `configured`/`not configured`, and compatibility `not checked` replace automatic synthetic results. Explicit Full retains the advanced compatibility fields and adds its diagnostic level/provider/model. Scripts requiring verified synthetic compatibility must explicitly request Full and examine its result.

## Measurements and focused validation

Provider-free measurements on the development machine:

| Path | Wall time | Model calls |
|---|---:|---:|
| Previous Full startup behavior, synthetic mock backend | 0.4940835 s | 4 mocked |
| New Quick path in the same measurement | 0.0022211 s | 0 |
| Independent Quick timing test | 0.0018792 s | 0 |

These measure local execution with mocks, not real provider latency or complete shell startup. A one-second generous Quick regression ceiling also denies network and model dispatch. Real startup savings include eliminating provider round trips, but were not measured with paid requests.

Focused results (overlapping sets; do not sum):

| Check | Result |
|---|---|
| Final readiness/provider set: readiness levels, cloud readiness, capabilities, timeout, handoff and diagnostics | **138 passed, 41.41 s** |
| Readiness-level set after adding DNS denial and connectivity cancellation coverage | **22 passed, 2.41 s** |
| CLI/shell/catalog/D2 execution and readiness subset | **150 passed, 56.46 s** |
| SDK mock-transport, supervised capture, separate capture authorization and exact D2 serialization | **9 passed, 1 third-party warning, 64.65 s** |
| Adapter/local-provider subset | **115 passed, 2 sandbox failures, 14.00 s**; the two unchanged loopback/supervision tests passed outside sandbox (**2 passed, 4.05 s**) |

Synthetic readiness tests were migrated to explicit authorized Full calls; they retain schema/failure assertions. Default startup/model-selection tests now assert zero diagnostic calls. Three existing envelope tests asserted an obsolete generic category; they now assert the existing `response_envelope_failed` category without accepting malformed responses.

The development venv lacks cloud SDKs and has stale installed Locard metadata; source version is checked separately. SDK tests used installed OpenAI 2.53.0 and LiteLLM 1.106.1 with mocked HTTP. The project retains LiteLLM 1.106.0, so a fresh install of the exact pinned environment remains manual verification. The SDK test launcher used `os._exit` only after `pytest.main` returned and streams were flushed, avoiding a previously observed interpreter-exit hang; it did not skip pytest teardown or application worker assertions. The warning concerns a third-party Pydantic qualifier.

No full suite, live provider requests, existing case inspection, protected history/workspace writes, commit or push was performed. No historical artifact hash audit is claimed.

`git diff --check` passed. New documentation and modules were also checked separately because untracked files are not included in the ordinary Git diff.

## Manual acceptance

From the intended test checkout/environment:

```powershell
.\.venv\Scripts\python.exe -m pip install -e .
.\.venv\Scripts\python.exe -m pip check
.\.venv\Scripts\python.exe -m forensic_assistant.cli --version
.\.venv\Scripts\python.exe -m forensic_assistant.cli ai check --json
```

Expect version **6.139** after installation. Quick must produce no provider activity and report compatibility as not checked. Test startup and deterministic commands without credentials as well. Re-selecting the configured model must not trigger synthetic completions.

The following are separate, deliberate network tests, performed only by the analyst:

```powershell
# Non-generative authentication/reachability check:
.\.venv\Scripts\python.exe -m forensic_assistant.cli ai check --connectivity --json
# Explicitly authorize potentially billable synthetic requests:
.\.venv\Scripts\python.exe -m forensic_assistant.cli ai check --full --authorize-diagnostic --json
```

Within the shell the equivalent commands are `ai check`, `ai check --connectivity`, and `ai check --full` (with a confirmation prompt). A successful diagnostic does not replace the existing approval for a real investigation or findings capture. Perform actual authorized D2 acceptance separately; no live compatibility claim is made from mocks.

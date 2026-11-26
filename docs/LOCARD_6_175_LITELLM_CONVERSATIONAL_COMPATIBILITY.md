# Locard 6.175 — LiteLLM conversational compatibility

November 25, 2026. Starting tree: clean, `8c5b02d`, Locard 6.174.
Target: 6.175. No commit or push; manual acceptance pending.

## Failure and decision

The analyst independently reproduced LiteLLM 1.106.0 failing on ordinary native
function tools with `ModuleNotFoundError: No module named 'mcp'`. The private
`_skip_mcp_handler=True` bypass only moved the failure into the Responses bridge.
A direct official OpenAI SDK function call succeeded. A separate Python 3.14
environment then completed a two-request native tool round trip with LiteLLM
1.111.0, without MCP or private overrides. Those live results are analyst-reported;
development did not repeat paid requests.

Locard retains LiteLLM as its shared multi-provider integration. No direct SDK
replacement, MCP dependency, proxy extra or private bypass is introduced.
Conversational OpenAI remains the reference implementation; Claude/Gemini/local
conversation support is not newly implemented or certified.

## Dependency result

Only the following pins change in `pyproject.toml`:

| Item | Before | After |
|---|---|---|
| Locard | 6.174 | 6.175 |
| LiteLLM | 1.106.0 | 1.111.0 |

Other pins remain intact, including OpenAI **2.53.0**, Hugging Face Hub **1.32.0**,
Tokenizers **0.23.2**, Transformers **5.17.0**, Sentence Transformers **5.7.0**,
FAISS CPU **1.14.3**, Torch **2.14.0**, NumPy **2.5.3**, Safetensors **0.8.0**.
`requirements.txt` contains the existing forensic parser subset and needed no edit.

Installed LiteLLM 1.111.0 metadata permits OpenAI `>=2.20,<4`, Hub `>=0.34,<3`
and Tokenizers `>=0.21,<1`. The isolated test's automatically selected OpenAI
3.59.0/Hub 2.4.0/Tokenizers 0.23.3 are therefore not required pins.

A new isolated Python 3.14 venv installed the project's base/test requirements,
explicitly retaining Hub 1.32.0 and Tokenizers 0.23.2. It resolved:

```text
litellm 1.111.0
openai 2.53.0
huggingface-hub 1.32.0
tokenizers 0.23.2
pip check: No broken requirements found.
```

The first sandbox attempt failed at DNS/build-dependency resolution, not at a
dependency constraint. The isolated retry succeeded. Existing development and
analyst test-checkout venvs were not upgraded.

A metadata audit over the existing semantic installation combined with the new
cloud dependency solution traversed **43 packages with zero declared conflicts**.
The heavy semantic stack was not reinstalled into the isolated venv. This is
dependency-constraint evidence, not certification of all native DLLs, model
downloads, GPU execution or semantic inference. No models were downloaded or run.

## Necessary continuation handling

Inspection of LiteLLM 1.111.0's
`completion_extras/litellm_responses_transformation/history.py` established that
`openai_responses_replay` binds ordered output items to message text, **exact tool
argument serialization**, reasoning items, phase and tool IDs through a checksum.
It is not merely an optional response ID. Re-serializing parsed arguments can
invalidate that checksum. Reasoning/phase history can matter beyond a simple
two-request example.

The adapter now preserves relevant assistant transport fields when supplied:
`role`, `content`, `tool_calls`, `reasoning_items`, `provider_specific_fields`,
and `phase`. An optional provider-neutral `continuation` envelope carries a
versioned opaque payload (`litellm-openai-history-v1`). The application service
does not import LiteLLM message types or interpret that payload as evidence.

Before transport, the adapter binds retained content, call IDs/types/names and
parsed arguments to the visible assistant exchange, then restores the exact
original serialization. Changed bindings or oversized state fail closed. The
existing `ai check --conversation` round trip uses the same history builder.

The opaque payload is limited to **32768 UTF-8 bytes**. It is retained in the
private notebook and included in existing message/disclosure/journal accounting;
no existing budget is enlarged. Whole-exchange context trimming remains unchanged.
It never becomes a verified observation or grants another tool. If credential
redaction would alter continuation, the session stops with
`PROVIDER_CONTINUATION_REDACTED` instead of silently sending a damaged replay.
This state is sensitive provider context and must be treated like the notebook.

No model/provider fallback, retries, new authorization, forensic-query changes,
remote conversation store or provider-specific evidence authority is introduced.
Without continuation metadata, the prior conversational result contract remains
valid. Existing legacy structured-output adapters remain unchanged.

## Validation

All provider tests use scripted responses or mocked HTTP; no live provider request.

- Initial development-venv conversation/continuation run: **52 passed, 1 skipped,
  1 failed in 54.77s**. The failure was a test's hard-coded `6.174` shell output;
  it now reads the single application version authority. The skip was the real
  LiteLLM test because that venv lacks the package.
- Isolated new-dependency focused regressions: **180 passed, 1 failed,
  2 deselected in 56.61s**. Suites covered conversations, native envelopes,
  OpenAI schemas, Anthropic and Gemini adapters, advisory contracts, semantic
  logical ordering, provider configuration/local-runtime mocks and legacy
  controller grounding. The two deselected legacy supervisor cases were already
  identified as failing in the previous release's validation.
- The Anthropic `test_final` failure was reproduced against committed 6.174 in
  a disposable source archive: **1 failed in 1.38s**. It fails canonical validation
  with mocked transport; no LiteLLM call is involved. It was not weakened or repaired.
- Real LiteLLM/OpenAI HTTP-mocked round trip: **1 passed in 6.28s**. Actual
  completion-to-Responses conversion and native response normalization ran with
  OpenAI 2.53.0; MCP was absent. The second request retained the reasoning item,
  original tool call and matching tool result. DNS/socket access was blocked.
  A synthetic byte tokenizer avoided first-use BPE downloads; this was not a
  tokenizer accuracy benchmark. Early test attempts exposed tokenizer-cache and
  HTTP-client injection assumptions in the test harness, corrected without
  changing the production transport.

Continuation tests additionally cover exact replay-checksum preservation,
rejection of mismatched/oversized history, private notebook retention, size
accounting, credential-redaction failure, and no promotion into verified evidence.
Final conversation/continuation/provider regression run: **56 passed in 50.16s**,
with clean process exit, using the isolated environment and:

```powershell
.\.dependency-check-6175\Scripts\python.exe -m pytest tests/test_litellm_continuation.py tests/test_conversational_provider.py tests/test_conversational_ai.py -q -p no:cacheprovider --tb=short --disable-warnings
```

The initial real-library harness passed its assertions but SDK background executors
kept pytest alive during shutdown. The real-library test now runs in a bounded
one-shot child, matching the existing production worker lifecycle; no production
lifecycle changes were made. Only identified task-owned stuck test processes were
terminated. The final test run exited normally.

`pip check`: **No broken requirements found.** `git diff --check`: **passed**
(line-ending notices only). Counts overlap and must not be added.

## Installation and manual acceptance

This release **does require dependency installation**. After the analyst's
commit/push/pull workflow, use the same interpreter that launches Locard:

```powershell
Set-Location C:\tmp\locard
.\.venv\Scripts\python.exe -m pip install -e .
.\.venv\Scripts\python.exe -m pip check
.\.venv\Scripts\python.exe -c "from importlib.metadata import version; print('LiteLLM:', version('litellm')); print('OpenAI:', version('openai'))"
.\.venv\Scripts\python.exe locard.py --version
.\.venv\Scripts\python.exe locard.py
```

For an installation using the semantic extra, use
`.\.venv\Scripts\python.exe -m pip install -e ".[semantic]"` in place of the base
install command, so all existing semantic pins are explicitly resolved together.
Do not copy unconstrained versions from the disposable test environment.

Expected: LiteLLM **1.111.0**, OpenAI **2.53.0**, Locard **6.175**, and no broken
requirements. In the shell, approve the synthetic tests deliberately:

```text
ai check --conversation
ai check --full
```

The first checks native calling, argument decoding, tool-result continuation,
production catalog and final text through the production transport. The second
checks existing structured-output compatibility. If either fails, inspect `ai logs`
and stop before repeating the real investigation. Neither test's success proves
investigative quality.

After both succeed, repeat the unchanged source/time scope and neutral question
from `LOCARD_6_174_CONVERSATIONAL_PROVIDER_INTEGRATION.md`. Do not seed expected
incident indicators, expand limits, or change evidence. Real multi-step reasoning
quality and other providers' live behavior remain manual acceptance work.

## Changed files and scope

- `pyproject.toml`: application version and LiteLLM pin only.
- `forensic_assistant/conversational_ai/provider.py`: bounded continuation capture,
  validation, history construction and restoration.
- `forensic_assistant/conversational_ai/service.py`: retain opaque continuation,
  count it within existing context budgets and fail closed on replay redaction.
- `forensic_assistant/conversational_ai/compatibility.py`: same history construction
  for synthetic tool-result round trips.
- `tests/test_litellm_continuation.py`: new synthetic and actual-library/mock-HTTP tests.
- `tests/test_conversational_provider.py`: version-independent shell assertion.
- `.gitignore` and this document: documentation inclusion.

No official OpenAI SDK pin change, MCP/proxy installation, full suite, real-case
access, evidence/transcript modification, commit or push. The isolated dependency
environment is disposable verification data, not forensic evidence.

# Locard 6.132 — Zero-analysis recorded-view correction

Date: 2026-11-13 (America/Chicago). Starting clean revision:
`d717c9b726d3c80e2a0d306d1a6250d811bfe9ec` (`main`, 6.131).
The current uncommitted correction sets the sole application version authority,
`pyproject.toml`, to **6.132**.

## Reproduced failure

On unmodified 6.131, read-only reconstruction of
`C:\tmp\locard-diagnostics\6.118-live\08cfd054f85a4a36b8520832427201c3`
passed transcript loading/integrity validation but produced:

```text
manifest.evidence_state.view_id = e62cacaecdff435096a6a5f05eb106a1
accepted validated_delta events = 0
synthesis.reconstruct().evidence_state = None
organization.reconstruct().read_view.view_id = e62cacaecdff435096a6a5f05eb106a1
explanation.open_history(): ValueError: Cross-view explanation
```

The manifest view remained available and valid. No record or event changed views.
The first loss was `synthesis._Reducer.__init__`: it initialized `view=None` and
only `consume()` learned a view from a validated delta. With no accepted deltas,
the reducer never learned the manifest's recorded authority. Organization's
`_Sources` independently retained the manifest view. The explanation comparison
correctly detected the inconsistency; it was not the cause to suppress.

Public S1 reconstruction (and S2/S3 consumers that derive from it) therefore
returned missing empty-state view identity. `d2.open_history()` independently
constructed the same unseeded factual reducer. Nonempty histories learned their
view from the first accepted delta and were unaffected by this particular defect.

## Smallest source correction

| File / function | Change |
|---|---|
| `investigation_ai/synthesis.py:_Reducer.__init__` | Optional recorded-view initialization validates and deep-copies the supplied authority. Existing unseeded mode remains for live/legacy checkpoint reducers. |
| `synthesis.reconstruct` | Load authenticated manifest, require a valid recorded evidence-state contract, seed reducer before replay, and reject a manifest change across replay. |
| `investigation_ai/d2.py:open_history` | Seed its retrospective factual reducer from the already loaded/validated manifest. Existing source-anchor reread remains. |
| `tests/test_zero_analysis_view.py` | Public reconstruction, empty/nonempty, authority/tampering and historical-copy regressions. |
| `pyproject.toml`, `.gitignore`, this document | Version and documentation only. |

The authority is the **historical manifest's validated `sqlite-read-view-v1`**
identity, not a current database view, fingerprint, guessed ID or model response.
Missing, null, unsupported or malformed view authority is rejected by the public
retrospective paths. No fallback supplies a current-case view.

`consume()` already rejects a delta inconsistent with a known reducer view; seeding
the view now makes this protection apply from the first delta. Existing autonomous
replay also compares results/deltas against the manifest, and transcript loading
compares initial/result/terminal read-view bindings. D1's exact cross-view check
is unchanged. Deliberately mismatched, syntactically valid views still fail.

## Why persisted checkpoint reducers are unchanged

`organization.reconstruct()` and the B2/decomposition replay machinery validate
historical serialized assessments/checkpoint digests, including their original
zero-analysis empty-state representations. Their default reducer behavior is not
silently rewritten. C1's public read-view authority already comes from `_Sources`.

This correction seeds retrospective factual projections and the D2 history
projection; it does not alter live checkpoint construction, historical B2/S3
terminal payloads, organization digests or D1b receipts. Existing
`test_explanation_replay_status.py` exercises those legacy empty-state contracts.
This distinction is intentional compatibility handling, not permission to bypass
an actual mismatched view. No source, provider, selection or response contract was
changed to make the historical output agree.

## Before and after

The formerly failing public D1 path now constructs a page with the authoritative
recorded view, **zero validated batches and zero factual clauses**. Its two page
items are objective/coverage context, not invented evidence findings. Repeated
provider-free pages agree deterministically.

One- and multi-batch synthetic histories produce exactly the same factual result
as the previous unseeded accepted-delta reducer. Read-only 6.111 and nonempty 6.118
copies also match that prior derivation. Original S1 clause identities, S2
relationships and S3 authority remain unchanged for those histories.

The D2 request policies remain 5,600 and 16,384 bytes. `d2q2` rationale semantics,
typed references, parent validation, fresh authorization, one attempt, worker
deadlines, IPC limits and all provider parameters remain unchanged. A zero-analysis
history does not gain evidence supports or permission to make a provider request.

## Validation

The new targeted suite passes **14 tests in 28.68 seconds**, including:

- Public explanation/S1/D2 behavior for zero, one and six accepted batches.
- Missing/null/unsupported/malformed recorded view authority.
- Manifest/recorded view mismatch and accepted-delta view tampering with a
  recomputed synthetic hash chain.
- Broken transcript hash chain and a direct genuine D1 cross-view mismatch.
- Copied 6.111, empty 6.118 and nonempty 6.118 histories, deterministic pages,
  unchanged source hashes and forbidden provider/database access.

The first targeted attempt failed in a new one-batch synthetic fixture because
its scripted client had no responses left for the existing B2 phase. The fixture
was supplied bounded synthetic B2 replies; production behavior and safety
assertions were not weakened. The system Python lacked pytest, so validation used
the existing test-checkout virtual environment.

The expanded focused run completed with **280 passed, 2 failed, 1 warning in
165.90 seconds**. Both failures were the same new one-batch fixture exhaustion,
from the run started before the fixture correction. The corrected 14-test run
above covers both failures. Thus **282 distinct focused cases have passing
results across the two runs**, not a claimed single green 282-test invocation.
The existing factual-clause, relationship, organization, explanation, empty-state
replay, D2 preview, cross-artifact and rationale regressions passed. The warning
was the SDK/Pydantic `ReadOnly` TypedDict warning.

Invocation used the existing `.tmp-6130/run_sdk_tests.py` harness with `-B`,
`-q -p no:cacheprovider`. That harness exits with pytest's returned status after
pytest completes to avoid the known SDK-host exit linger; natural test-host exit
is not established by this run. No full suite or live provider request was run.

## Historical integrity

Each historical-copy regression hashes both files before/after. Observed hashes:

| Run | File | SHA-256 |
|---|---|---|
| 6.118 `08cfd054f85a4a36b8520832427201c3` | manifest | `ca8b16c59e08197713271d74e7c945cfd1be6a6507aa7da8d0a1770168a8252d` |
| same | events | `4a979b58f4862b2a5dc45042fed06c0579130ca2be5738625cb32b45310b11c0` |
| 6.118 `6ad0c85499564406aa4d949f3b0e72e5` | manifest | `23a6e2c496b2e34aa20810e08c152e37b8b51afacde0a3dba1a074e16e7e350f` |
| same | events | `a943a1e2bf39d8f2aafca6f374804f1cefb20b080bc2cdf0a46d2c050625ac28` |
| 6.111 `ec81a1af5b1f471ca4f3a4c0bb917fa2` | manifest | `ac4ad6337ef9ec1de08cffca3f0872a0d51afc872191c7da4cfc774b4c9d2a1d` |
| same | events | `8672cf41cbefde86d315d177cb0c6e99a20c26a3f11ed306c837026631138256` |

These checks establish no change to the copied files during testing, not
historical acquisition integrity or cryptographic authenticity against deliberate
whole-transcript forgery. No original case, transcript, sidecar or permission was
modified. Tamper tests use disposable synthetic journals only.

## Manual provider-free acceptance

After installing the analyst-reviewed changes in the test checkout:

```powershell
.\.venv\Scripts\python.exe -m pip install -e .
.\.venv\Scripts\locard.exe --version
$root = 'C:\tmp\locard-diagnostics\6.118-live'
$empty = '08cfd054f85a4a36b8520832427201c3'
.\.venv\Scripts\python.exe -m forensic_assistant.investigation_ai.synthesis $root $empty --json
.\.venv\Scripts\python.exe -m forensic_assistant.investigation_ai.synthesis $root $empty --explanation
.\.venv\Scripts\python.exe -m forensic_assistant.investigation_ai.synthesis $root $empty --explanation --json
```

Expect version 6.132, zero validated batches/clauses, recorded view
`e62cacaecdff435096a6a5f05eb106a1`, and a bounded explanation of the recorded empty
result without `Cross-view explanation`. No new retrieval or analysis is claimed.

Existing cross-artifact preview compatibility (no `--execute`):

```powershell
$run = '6ad0c85499564406aa4d949f3b0e72e5'
$question = 'What evidence connects the recorded download and subsequent filesystem observations? Which links remain hypotheses and what additional examination would discriminate?'
.\.venv\Scripts\python.exe -m forensic_assistant.investigation_ai.d2_reasoning $root $run --cross-artifact --question $question --json
```

Expect unchanged `d2q2` and 16,266 bytes. This correction requires no live AI test.
Empty findings do not establish absence of activity or forensic completeness.
Recorded-view reconstruction remains retrospective; it does not prove equality
with the current case. No commit or push is performed.

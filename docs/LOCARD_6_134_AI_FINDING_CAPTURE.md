# Locard 6.134 — Explicit AI finding capture

## Integration and authority

Inspected clean main `8136d90409b1478c122884026d296d33fb4b4bcf`, application
6.133, on 2026-11-13. `d2_execution.execute()` already returns a parent-validated
result after the existing worker lifecycle. `d2_reasoning.main()` still owns
the frozen `Prepared` request at that point; this is the capture integration
point. No worker, provider, response contract, selection algorithm or budget
changes are necessary. `pyproject.toml` alone advances the version to 6.134.

`finding_capture.Capture` and `finding_capture.run` are reusable parent/application
services. They reuse `Workspace.export`, its recorded binding validation, and the
same validation/import path used by `Workspace.import_result`. `import_results`
is its narrow atomic multi-account extension. CLI code only collects arguments,
displays results and asks the two independent approval questions.

```text
prepare existing D2 request
→ validate existing workspace UUID/source/run/frontier/view
→ ordinary provider authorization
→ ordinary supervised execute (one attempt)
→ display normal result and existing usage/cleanup diagnostics
→ validate available in-memory proposal result
→ inspect current workspace revision
→ separate default-No capture choice
→ atomically register all accounts as proposed
```

The user may reject either approval independently. Selecting a directory,
authorizing execution, receiving valid JSON, or successful parent validation does
not approve saving. Saving does not accept the finding or execute an examination.

## Workspace selection and CLI

The existing `d2_reasoning` module accepts:

- `--findings-workspace <existing-directory>`
- `--findings-actor <locally-asserted-name>`

Both require `--execute`; actor is required with the workspace. A missing,
malformed, unresolved or mismatched workspace fails before provider authorization.
No workspace is automatically created. Source binding must equal the prepared
packet's run ID, manifest digest, event head and recorded evidence view. A later
directory replacement must also retain the original workspace UUID or writes
fail. Validation involves recorded histories only, never a live evidence query.

Without these options, the previous execution and display path remains unchanged.
Current single-packet quality D2 and cross-artifact D2 are supported. Historical
legacy wire-only `d2c1` execution remains available without capture; capture fails
preflight for that profile rather than paying for a response it cannot import.
Existing d2q1/d2q2 decoding and current d2q2 semantics are unchanged.

Normal result display still says ephemeral/not saved when it is first printed.
Only a subsequent successful capture acknowledgement reports finding IDs and
the committed revision. `--json` keeps the normal result record and emits a
separate `d2-finding-capture-v1` outcome; it does not imply unattended approval.

## Multi-account transactions and concurrency

6.133 imported one account per transaction. This release shares its validator and
support-restoration implementation, and extends `_write` to commit up to two
ordinary `propose` events in a single existing SQLite transaction. No schema,
event format, table, second store or persistence mechanism is added. Existing
review/replay code sees the same events. Two accounts create two finding IDs and
advance the revision by two, atomically; each can later be reviewed independently.

Before any insert, all accounts and event bounds/transitions are validated.
`executemany` runs inside the existing `BEGIN IMMEDIATE` transaction. Failure on
the second insert rolls back the first. The whole operation checks the revision
shown in the capture offer and the pinned workspace UUID inside that transaction.
Another analyst's intervening change is a conflict, never an implicit retry.

The same request/packet and exact account content/original support cannot be bulk-captured again, including
after rejection or supersession. If one account was previously saved manually,
the batch is rejected with an already-captured outcome; remaining accounts are
not silently selected or partially saved. A genuinely different validated response
over the same deterministic packet remains eligible. Exactly duplicated account content
and original support within one response are explicitly rejected for capture,
not silently deduplicated. Similar but nonidentical hypotheses remain distinct.

## Result eligibility, provenance and failure behavior

Capture consumes the existing parent-owned result in memory. It invokes neither
`execute` nor `authorize` again. It never reconstructs missing responses from logs.
The shared importer losslessly re-encodes the quality result, repeats canonical
and source validation and requires exact result equality. Raw `accepted` flags
and changed reference objects cannot grant authority.

Each stored candidate remains `ai_proposal`, state `proposed`, with unverified
classification. The existing capsule preserves request/packet identity, model,
response version and exact validated response fields including outcome rationale.
The provider identity remains OpenAI by the existing Prepared/capsule restoration
contract (`findings._prepared`); no provider-neutral authenticity claim is added.
Supporting and contrary aliases are restored to original source-bound EIDs,
field pointers/values, lineage, interpretation premises and qualifications.
Alternatives, assumptions and recommended examinations survive unchanged.
Recommendations remain unexecuted and availability remains unknown.

| Condition | Capture behavior |
|---|---|
| Validated abstention | Display normal result; no offer, finding or claim of absence |
| Rejection/refusal/truncation/timeout/interruption | No offer; preserve original result/usage/cleanup diagnostics |
| Capture declined or EOF/Ctrl+C at the prompt | No write |
| Invalid result/reference | No offer/import; sanitized capture failure |
| Stale revision | Conflict; no retry or overwrite |
| Already captured | Explicit rejection, no duplicates |
| Exact duplicate accounts | Explicit duplicate-account outcome, no silent selection |
| Storage error or cancellation while committing | `storage_uncertain`; inspect workspace before trying again |
| Successful capture | IDs and this transaction's committed revision; separate later analyst review |

SQLite transactions prevent partial account commits. Storage acknowledgement can
still be uncertain after an I/O error/cancellation near commit; the UI does not
claim nothing was saved in that situation. It never retries automatically.
No rejected raw response is persisted. Local persistence still does not confer
forensic authority, verify a human identity, or independently authenticate evidence.

## Provider-free validation and manual demonstration

`tests/test_finding_capture.py` exercises the same parent orchestration with
synthetic histories and controlled responses: distinct approvals, binding failures
before authorization, decline, one/two accounts, abstention, invalid responses,
failure statuses, stale revisions, repeated capture, duplicate accounts, transaction
rollback, directory replacement, provenance, unchanged transcripts and no-workspace
CLI compatibility. Existing `test_findings.py` protects 6.133 review/replay behavior.

The Windows demonstration spawns the existing supervised D2 child, substitutes an
OpenAI SDK `httpx.MockTransport` at the transport boundary, and prohibits socket
connections. The parent validates the returned result, displays it, obtains a
separate capture decision, persists a proposed finding, reopens it in a new Python
process, and performs a separate test analyst acceptance. The child performs one
mocked SDK request; it is not a live provider request. No production mock option
or alternate provider route is introduced.

After the analyst transfers and installs the reviewed tree in the test checkout:

```powershell
.\.venv\Scripts\python.exe -m pip install -e .
.\.venv\Scripts\locard.exe --version
.\.venv\Scripts\python.exe -B -m pytest -q -s -p no:cacheprovider tests/test_finding_capture.py::test_windows_supervised_sdk_capture
```

Expected version: 6.134. The test prints a short successful-workflow confirmation;
all evidence, findings and review actions are disposable synthetic test data.
This is the provider-free acceptance demonstration: no purchase, API key or live
case is needed. If the existing SDK test-host exit linger occurs after pytest
reports completion, use the already existing development test harness instead of
repeating provider work; the harness is not a production execution path.

For later **separately chosen real execution**, append the two new options to the
existing command. This example is not required for acceptance and will offer a
paid request only after source/workspace validation:

```powershell
$root = '<readable recorded-investigation root>'
$run = '<existing run ID>'
$workspace = '<existing matching .findings directory>'
.\.venv\Scripts\python.exe -m forensic_assistant.investigation_ai.d2_reasoning $root $run --cross-artifact --question '<analyst question>' --execute --findings-workspace $workspace --findings-actor '<locally asserted name>'
```

For single-packet D2, retain the existing `--issue <ID>` and optional
`--exploratory` selection instead of `--cross-artifact --question ...`.
After saving, later process inspection/review uses the unchanged 6.133 CLI:

```powershell
.\.venv\Scripts\python.exe -m forensic_assistant.investigation_ai.findings $workspace export
.\.venv\Scripts\python.exe -m forensic_assistant.investigation_ai.findings $workspace accept '<finding ID>' --actor '<locally asserted name>' --revision <current-revision> --rationale '<review rationale>'
```

## Results and architectural debt

Validation used the existing test-checkout virtual environment against the
development tree and the existing `.tmp-6130/run_sdk_tests.py` harness, with
`-B -q -p no:cacheprovider`. The harness exits with pytest's status after pytest
returns to avoid the known SDK host-exit linger; natural host shutdown is not
claimed. The actual supervised child cleanup assertion passed.

| Run | Exact result |
|---|---|
| Initial capture development tests | 27 passed in 241.71s |
| Capture + findings + D2 execution/cross-artifact/rationale regressions | 232 passed, 1 failed, 1 skipped, 1 warning in 541.65s |
| Corrected duplicate-related tests | 3 passed, 27 deselected in 87.21s |

The sole failing test was a newly written fixture attempting to construct a
validated response with identical accounts. Existing canonical validation already
rejects it (`d2_quality.a: duplicate items`). The test now asserts that rejection,
also rejects a forged validated-result object, and still verifies atomic rejection
of a partially imported response. Production validation was not changed for this
failure. **233 distinct focused cases have passing results across the final runs;
one native hard-link test is environment-skipped.** This is not a claimed single
green 234-test invocation. The skipped test cannot create a native hard link in
the sandbox; the existing injected link-count guard test passes. The warning is
the existing SDK/Pydantic ReadOnly TypedDict warning.

The broader invocation named only these files:

```text
tests/test_finding_capture.py tests/test_findings.py tests/test_d2_execution.py
tests/test_d2_cross.py tests/test_d2_rationale.py
```

`git diff --check` and new-file whitespace checks passed. CLI help exposes both
new options. `pyproject.toml` is 6.134; installation is left to the analyst.
No full suite was run.
Existing historical 6.111/6.118 compatibility and before/after transcript hash
checks remain in the findings/replay tests. No original/copy history, live case,
permission, provider budget or evidence-selection rule is changed.

The capsule/revalidation and per-request duplicate identity rules remain local
application services, not a security boundary against arbitrary same-user Python.
Repeated reconstruction is intentionally retained; a future independent review
may extract stable public restoration/validation interfaces. Capture is explicit
and ephemeral until committed: it does not recover a lost process's unsaved result.
No report generator, web UI, automatic continuation or examination execution.

No commit or push is performed. Stop for analyst manual acceptance.

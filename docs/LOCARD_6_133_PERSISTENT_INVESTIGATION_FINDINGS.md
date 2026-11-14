# Locard 6.133 — Persistent investigation findings

## Architecture gate (2026-11-13, before implementation)

Inspected clean main `1ae0eb097ccf3f53e6dfa2b9cfb7cfab5bc99056`, version 6.132.
Original evidence belongs to the case database and its original provenance;
recorded authorized disclosures belong to immutable investigation transcripts.
Neither is a writable analyst findings store.

`investigation_ai/d2.open_history` validates the transcript and reconstructs
S1/S2/S3 and retained exposure through `autonomous.reconstruct` and B1 Context.
`packets._rehydrate` restores original fields, provenance, interpretation premises
and qualifications. D1 organization/explanation are derived views, not analyst
decisions. `d2_execution.Prepared` and `validate_model_response` enforce the
current request binding; their mechanically accepted results are ephemeral.
The interactive case workspace creates case databases; activity logs record case
operations. Neither supplies a separate transactional finding/review service.

Feasible minimal design: explicit, exclusively created `*.findings` directory,
application-owned SQLite event store, never an evidence database or transcript
sidecar. Reuse `storage.local_path`/`DirectoryGuard` and SQLite transactions.
Bind immutable workspace metadata to D2's manifest digest, event head, run ID
and validated recorded view. Reuse B1 restoration rather than inventing evidence
identities. Reuse existing D2 validation for explicit response import.

Application services own transitions; the module CLI is only an adapter.
Append-only events reconstruct current state, with expected workspace revision
and `BEGIN IMMEDIATE` preventing lost updates. Interrupted transactions roll back.
Unavailable/invalid source bindings are explicit and block writes; read-only
local history remains inspectable with its validation limitation. No recovered
source may silently replace the recorded authority.

This local store is not authenticated analyst identity, independent evidence
integrity, a report generator, provider authorization or restart continuation.
No source database, transcript, configuration or ACL changes are required.

## Implemented service and storage

Additional persistence comparison confirmed the choice:

- `briefing_store.Store` already has bounded revisions and optimistic expected
  digests, but validates a current case file, writes a `.briefing` sidecar, and
  stores analyst briefing content rather than recorded investigation findings.
  `briefing_canonical` acceptance explicitly does not make briefing assertions
  verified. Its authority distinction and stale-write pattern are preserved, but
  repurposing that store would require live-case coupling and sidecar changes.
- `database.db.connect/initialize_tables` initialize forensic case schema 5;
  `artifacts.storage.store` writes normalized records/provenance. Neither is used
  to open or initialize the findings database.
- `activity.locked/decode/append` handles case activity audit entries, not a
  transactionally reviewed finding ledger. It is not used as a second mutable
  state cache.
- `investigation_ai.snapshot._private_mkdir` belongs to temporary snapshot
  containment and creates a private Windows DACL. This release neither creates
  snapshots nor borrows that ACL behavior; it reuses only local path/directory
  guards and requires an explicit derived-data destination.

`forensic_assistant/investigation_ai/findings.py` implements the backend and thin
`python -m forensic_assistant.investigation_ai.findings` acceptance adapter.
Existing D2 execution, S1/S2/S3, C1, D1, provider routing and schemas are unchanged.
`pyproject.toml` alone declares application version 6.133.

Create a new explicit local directory ending in `.findings`; its parent must
already exist. Creation is exclusive even if a pre-existing directory is empty.
The only database is `findings.sqlite3` inside that directory. Do not place it on
an evidence volume. The service rejects a destination beneath the supplied
transcript root, a transcript manifest directory, a `.investigations` directory,
or a directory containing `case.db`. It never opens the evidence database to
discover more protected paths. Arbitrary unregistered evidence locations cannot
be inferred: choosing a suitable derived-data parent remains an analyst duty.

Existing safe-path checks reject redirects, network destinations and ambiguous
Windows paths; DirectoryGuard pins ancestors on Windows. Database and sidecar
hard links are rejected. No original file is overwritten. A pre-existing SQLite
file is never initialized as a findings database. No permissions are altered.
No snapshot or evidence copy is made. Creation failure leaves its exclusively
reserved directory for inspection; it is never automatically reused or deleted.
Use a new directory after diagnosing an incomplete creation.

### Schema and bounds

| Item | Contract |
|---|---|
| Workspace | `analyst-findings-workspace-v1`, SQLite `user_version=1`, dedicated application ID |
| Metadata | One immutable row: workspace UUID, UTC creation time, locally asserted actor, source-root locator, recorded source binding |
| Binding | Investigation ID, canonical manifest SHA-256, accepted event-chain head, complete recorded evidence-view identity |
| Events | Sequence primary key, canonical JSON body, SHA-256; no mutable materialized findings table |
| Finding | `analyst-finding-v1`, application-generated UUID, workspace ID, immutable creation revision, last decision revision |
| Limits | 1,024 events; 256 KiB/event; 32 MiB aggregate event bodies; database file admission capped at 64 MiB |
| Input text | Statement 2,048 UTF-8 bytes; explanation/rationale 4,096; locally asserted actor 256 |
| References | At most 32 distinct original S1/S2 IDs per supporting/contrary list; no packet aliases accepted here |

Version, record shape, transition, chain, source-binding and bounded-size errors
fail closed. Unexpected SQLite triggers/views/tables are rejected. A current
transaction's event limit includes its new event; oversized records are not
truncated. No schema migration is added.

### Finding representation and authority

`Workspace.register()` supports reference candidates classified as
`original_observation`, `deterministic_interpretation`,
`deterministic_relationship`, or `analyst_hypothesis`. Reference categories
require corresponding registered S1/S2 support. Candidate explanatory text is
analyst-supplied and not deterministically proved merely by that classification.
All candidates require original support; an empty investigation yields an empty
workspace, not a finding of absence.

Every candidate preserves supporting and contrary IDs, B1-restored original
fields/values, exact EIDs, recorded view through the workspace binding,
source/provenance, disclosure lineage, timestamp metadata, interpretation
premises, registered relationships and qualifications. B1 dependency closure
retains registered contradictory endpoints. Additional analyst limitations are
separate from original mandatory qualifications, which are never overwritten.

`Workspace.import_d2()` accepts an existing `Prepared` request and an available
response string, not a claimed validation status. It rehydrates the source,
recreates the original request, and runs the existing strict model-response
validator. `Workspace.import_result()` accepts the available **D2 quality
validated-result object** returned by execution; it losslessly re-encodes the
structured fields, revalidates, and requires exact equality before import. A
raw `{"status":"accepted"}` object is insufficient. This is mechanical
validation, not authentication that a provider authored the text.

The imported candidate is `ai_proposal`, state `proposed`. Original support is
persisted outside the request-local alias representation. The validation capsule
retains the exact request/digest, model/profile/version/options, response fields
and complete validated proposal so reopening can repeat validation without a
provider. Credentials and unrelated provider configuration are not stored.
Only hypothesis items are finding candidates; a `next_objective` is not silently
converted into a conclusion. D2 quality next-examination text is stored separately
with question, discriminator, `availability=unknown`, `execution=unexecuted` and
family `not structurally specified` rather than guessing a family from prose.
Alternatives, assumptions and uncertainty remain in the validated proposal.

No automatic persistence hook was added to D2 execution. If the ephemeral
result is gone, this release cannot recover it from usage logs. The response
capsule is sensitive derived material, stored locally in plaintext; no encryption
or new ACL regime is claimed.

## Review, correction and concurrency

| Explicit action | Allowed transition | Result |
|---|---|---|
| Register/import | none → proposed | No acceptance implied by structural validity |
| Accept | proposed → accepted | `reviewed_classification=analyst_reviewed_conclusion`; origin and evidence unchanged |
| Reject | proposed → rejected | Candidate and support retained |
| Supersede | accepted → superseded; replacement → proposed | Old candidate/decision remains; replacement requires a separate acceptance |

Acceptance records an analyst conclusion, not independent evidence verification.
Repeated acceptance/rejection and review of rejected/superseded findings fail.
Supersession requires a rationale and a freshly validated supported replacement;
the correction is analyst-authored even when the old candidate came from AI.
Decision history records sequence, UTC time, actor, action, previous/new states,
relevant revision and rationale; supersession links both finding IDs.

All writes require `expected_revision` of the **whole workspace**, including
changes to other findings. `BEGIN IMMEDIATE` serializes updates; a competing
writer's stale revision fails instead of overwriting. SQLite lock contention
has a two-second busy timeout and surfaces as an error; there is no automatic
replay/retry of analyst actions. Exceptions and cancellation roll back the
transaction, including after an insert. A crash relies on normal SQLite journal
recovery, not an application recovery daemon. A readonly open requiring SQLite
recovery may fail: report the error rather than silently repairing on retrieval.

Events are append-only through this API. Replay derives current state from the
complete event sequence. Its chain begins with the metadata digest. Hashes detect
inconsistent/partial local edits; someone who rewrites the entire database and
chain can forge local history. This is neither authenticated human identity nor
independent cryptographic proof of evidence integrity. Source reconstruction,
not the workspace hash alone, validates original support.

## Retrieval and reporting boundary

`create`, `Workspace.export`, `list`, `get`, `decisions`, `register`, `import_d2`,
`import_result`, `review` and `supersede` are reusable Python services. No UI state
transition is embedded in argument parsing. Reopening requires only the directory
path. Reads use SQLite URI `mode=ro`, `uri=True`, `query_only=ON` and a read
transaction; they never rewrite a revision or ask a model to rewrite findings.

Structured export contains immutable metadata, all findings including rejected
and superseded ones, exact support, recommendations, full review history, revision
and chain head. Its ordering is deterministic. At the same revision **and source
availability**, repeated exports are equal. Source validation status is deliberately
fresh; it changes if history becomes unavailable or invalid:

- `valid_recorded_binding`: original history revalidated and support reconstructed.
- `unresolved_source_unavailable`: history cannot be read; local history is visible
  with an explicit support-not-revalidated limitation; all writes blocked.
- `invalid_source_binding`: changed/malformed authority; same write prohibition.

Callers must retain the source-status envelope returned by retrieval. Accepted
state alone must not be presented as validated evidence when binding is unresolved.
There is no silent rebinding to a new run or the current database. A valid recorded
binding does not establish that today's case database matches that view.

This export establishes a future reporting input, not report generation. It
does not weaken existing incremental-transcript report-import restrictions.

## Validation and historical compatibility

`tests/test_findings.py` uses disposable SQLite stores and synthetic investigation
histories. It covers creation, a fresh-process reopen, recorded authority, malformed
source rejection, original and D2 candidate validation, original-reference
restoration, contrary support, qualifications, interpretation/relationship closure,
review transitions, duplicate/stale decisions, two concurrent writers, supersession,
rollback, corruption, unsupported schema, readonly retrieval, deterministic export,
file safety, source substitution, unavailable history and unexecuted recommendations.
ModelBackend requests are forbidden by an autouse fixture. Retrieval's SQLite
opener is restricted to the derived readonly store in the no-write regression.

Historical tests use readonly copies of populated/empty 6.118 and compatible
6.111 runs. Each compares manifest/events SHA-256 before and after. Existing
zero-analysis, D1 retrospective, single-packet D2 and cross-artifact D2 regression
suites are included in focused validation. No live database is opened.

Readonly copy hashes (manifest / events respectively):

| Historical run | SHA-256 |
|---|---|
| 6.118 empty `08cfd054f85a4a36b8520832427201c3` | `ca8b16c59e08197713271d74e7c945cfd1be6a6507aa7da8d0a1770168a8252d` / `4a979b58f4862b2a5dc45042fed06c0579130ca2be5738625cb32b45310b11c0` |
| 6.118 populated `6ad0c85499564406aa4d949f3b0e72e5` | `23a6e2c496b2e34aa20810e08c152e37b8b51afacde0a3dba1a074e16e7e350f` / `a943a1e2bf39d8f2aafca6f374804f1cefb20b080bc2cdf0a46d2c050625ac28` |
| 6.111 `ec81a1af5b1f471ca4f3a4c0bb917fa2` | `ac4ad6337ef9ec1de08cffca3f0872a0d51afc872191c7da4cfc774b4c9d2a1d` / `8672cf41cbefde86d315d177cb0c6e99a20c26a3f11ed306c837026631138256` |

Before/after equality establishes non-modification during these tests, not
independent historical evidentiary authenticity.

The focused compatibility run completed: **251 passed, 1 warning in 359.70s**:

```text
tests/test_findings.py tests/test_zero_analysis_view.py tests/test_d2_preview.py
tests/test_d2_execution.py tests/test_d2_cross.py tests/test_d2_rationale.py
```

The warning is the existing SDK/Pydantic `ReadOnly` TypedDict warning, not a
provider call. After that run started, final review added strict duplicate-key
JSON parsing, exact integer revision validation and a hard-link regression.
The final findings-only run completed with **43 passed and one environment setup
failure in 210.98s**: Windows denied `os.link()` on a disposable fixture before
the native hard-link assertion could run. The test now explicitly skips when
native link creation is denied; production safeguards were not changed. A
separate injected link-count test exercises rejection of `st_nlink=2`.
The follow-up returned **1 passed, 1 skipped, 43 deselected in 6.08s**.
Thus all **44 runnable findings tests passed across the final focused runs**;
one native hard-link scenario remains environment-skipped. This is not claimed
as a single green 45-test invocation. No deterministic failure remains.

Tests use the existing test-checkout virtual environment against the development
checkout, with `-B .tmp-6130/run_sdk_tests.py -q -p no:cacheprovider`.
The existing harness flushes and exits with pytest's returned status after tests
complete to avoid the known SDK test-host shutdown linger. It does not establish
natural SDK-host shutdown. No full regression suite was run.

An initial test fixture placed an empty-history workspace under its synthetic case directory;
the production protection correctly rejected it. The test moved the derived
store outside that case rather than weakening the guard.

## Provider-free manual acceptance

After transferring and installing the reviewed development tree in the separate
test checkout (the analyst performs Git operations):

```powershell
.\.venv\Scripts\python.exe -m pip install -e .
.\.venv\Scripts\locard.exe --version
$root = 'C:\tmp\locard-diagnostics\6.118-live'
$run = '6ad0c85499564406aa4d949f3b0e72e5'
$w = 'C:\tmp\review-6133.findings' # Must not exist; choose a fresh name if needed.
$py = '.\.venv\Scripts\python.exe'
$module = 'forensic_assistant.investigation_ai.findings'
& $py -m $module $w create $root $run --actor 'My locally asserted name'
$facts = & $py -m forensic_assistant.investigation_ai.synthesis $root $run --json | ConvertFrom-Json
$support = $facts.clauses[0].id
$fid = & $py -m $module $w propose --actor 'My locally asserted name' --revision 0 --support $support --statement 'Provisional interpretation for analyst review.' | ConvertFrom-Json
& $py -m $module $w accept $fid --actor 'My locally asserted name' --revision 1 --rationale 'Reviewed the recorded support and limitations.'
& $py -m $module $w export
$replacement = & $py -m $module $w supersede $fid --actor 'My locally asserted name' --revision 2 --support $support --statement 'Corrected provisional interpretation.' --rationale 'Narrowed the statement.' | ConvertFrom-Json
& $py -m $module $w reject $replacement --actor 'My locally asserted name' --revision 3 --rationale 'Not accepted after review.'
& $py -m $module $w export
```

Each invocation is a new process. Expect revision 4, the old accepted finding
preserved as superseded, and its replacement rejected. Repeating an old revision
must fail. Repeating `export` must preserve identical state and source hashes.
The same `create` workflow for run `08cfd054f85a4a36b8520832427201c3` should yield
zero findings and no claim of activity or absence.

For an **already available** D2 result, the future caller uses:

```python
from forensic_assistant.investigation_ai.findings import Workspace
w = Workspace(r'C:\tmp\review-6133.findings')
# prepared_request and execution_result must still be available from that request.
# This call validates only; it never calls execute(), authorize() or a provider.
finding_id = w.import_result(prepared_request, execution_result['validated'], 0,
    actor='My locally asserted name', expected_revision=w.export()['revision'])
# Inspect w.get(finding_id), then explicitly review using the new revision.
```

Do not make a provider request solely for acceptance. The disposable mock-provider
import test demonstrates the path without cloud use. No new automatic CLI capture
or production response-retention hook is part of this release.

## Limitations and architectural debt

- API/service trust is within the local application, not isolation from arbitrary
  Python code running as the same user. No independent analyst authentication.
- Filesystem guards reduce accidental aliasing/redirection; they do not promise
  protection against an adversarial administrator rewriting files. POSIX does not
  have the Windows ancestor-pinning behavior.
- Native hard-link creation was denied in this sandbox. Link-count rejection is
  tested synthetically; native filesystem acceptance remains unverified here.
- Existing history, B1 and D2 private validated interfaces are reused. A later
  independent review should assess extracting stable public restoration interfaces.
- Reopening replays source authority and revalidates stored D2 capsules. Packet
  regeneration depends on the historical codec remaining supported and its existing
  bounded planning completing. Failure is explicit, never repaired by a provider.
- Whole-store replay and source revalidation favor correctness over throughput;
  there is no cache or new evidence index. Limits deliberately bound this first slice.
- D2 family and examination availability cannot be inferred from prose; they remain
  unknown unless a later structured examination contract supplies them.
- No source relocation/rebinding API, automatic finding merging, investigation
  continuation, automated examination, report generator, or web interface.
- No full regression suite, live provider request, commit or push is authorized here.

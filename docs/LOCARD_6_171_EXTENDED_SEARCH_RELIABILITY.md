# Locard 6.171 — Extended search reliability

## Diagnosis and evidence

Inspected baseline: `feca5e9` (6.170). Development validation: November 25, 2026. No real case, original transcript, or provider was accessed.

The exact cause of the reported live failure is **not established** by its generic `WORKER_FAILURE` output. A synthetic Windows-spawned investigation using the actual supervised controller and persistent SQLite worker completed three temporal searches across two batches on the original implementation. There is no reproduced inherent third-search or batch-counter defect.

A separate deadline-coordination defect is source-confirmed: the parent started its five-second operation timer before dispatch; the worker established a later relative operation deadline; `follow_up.search` started yet another five-second `threading.Timer(db.interrupt)`. The parent could therefore terminate the worker before its SQL interruption response arrived. A real SQLite recursive-query reproduction produced `OperationalError: interrupted`; the pinned transaction remained usable afterward. These are evidence of a timing race and an inadequately classified failure, not proof that the live run encountered that race.

The pre-change focused reproduction passed **2 tests in 3.84 seconds**. It combined successful third-search execution and an accelerated real SQLite interruption.

## Execution path and correction

- `investigation_ai/autonomous.py`: approved follow-up dispatch through the persistent `ForensicWorker`; existing state, grants, batch checkpoints, final read-view check and cleanup remain in use.
- `investigation_ai/runner.py:ForensicWorker._exchange`: establishes an absolute monotonic operation deadline before serialization/dispatch and sends it to the worker. A follow-up remains capped at five seconds and the investigation's remaining deadline.
- `investigation_ai/worker.py:serve`: clamps profiling to that deadline, identifies the `temporal_search` phase, and passes the deadline into search.
- `investigation_ai/follow_up.py:search`: replaces the independent interrupt thread with a SQLite progress handler using the shared deadline, reserving 100 ms **inside** the bound for error delivery. The handler is cleared on return/exception; the worker restores its pinned-view handler. No delayed interrupt thread remains to affect later operations.
- `worker_diagnostics.py`: defines bounded application categories. The worker emits fixed error identifiers rather than arbitrary exception prose. `failure_diagnostics.py` accepts the optional typed detail while retaining historical diagnostics and the outer `WORKER_FAILURE` code.

The parent remains the containment backstop. The 100 ms reserve is not a guarantee of response delivery under OS scheduling delays; if the parent deadline wins, it reports a parent timeout. Process cleanup is separately bounded by existing lifecycle handling. No timeout increase, retry, renewed grant, provider change, or new lookup capability was introduced.

## Query and batch-state findings

`follow_up._search` retains the existing two-sided timestamp-index query. Synthetic `EXPLAIN QUERY PLAN` confirms the covering `artifact_time` index and no temporary ordering B-tree. Each direction fetches at most 501 rows for overflow detection and retains at most 500; source authorization is checked before original-record hydration. Duplicate evidence is hydrated only once, and result cardinality remains bounded.

The SQL artifact-family filter precedes `LIMIT`: index entries traversed can exceed the returned candidate limit. This remains a possible performance limitation, not a demonstrated live root cause. No SQL/schema/index optimization was made. Candidate-limited results remain explicitly incomplete. SQL interruption publishes no successful partial retrieval; it does not assert an absence of matching evidence.

The persistent worker retains session-wide deduplication and the read view across batches. Existing per-batch reset rules and the 18-request, 18-operation, six-search, three-batch ceilings are unchanged. The synthetic successful run verifies checkpoints after operations 6 and 8, including two searches and three contextual inspections in batch one, followed by the third search in batch two.

## Safe diagnostics and retained progress

`worker-failure-v1` carries only category, allowlisted phase and a Boolean deadline-exceeded flag:

| Category | Meaning |
|---|---|
| `SQLITE_QUERY_DEADLINE` | SQLite interruption observed at the operation's SQL deadline |
| `PARENT_WORKER_TIMEOUT` | Parent operation deadline expired |
| `WORKER_UNAVAILABLE` | Process unavailable, terminated, or communication failed |
| `SEARCH_AUTHORIZATION_REJECTED` | Recognized scope, grant, duplicate or resource-policy rejection |
| `DATABASE_READ_VIEW_FAILURE` | Database/view failure, including unexpected SQLite interruption |
| `WORKER_PROTOCOL_ERROR` | Malformed, oversized or invalid worker response |
| `WORKER_INTERNAL_ERROR` | Other worker exception |

Normal output includes this detail beneath the existing failed operation. It contains no SQL, parameters, evidence values, paths, URLs, secrets or arbitrary error text. Malformed diagnostics fail validation. Historical records without this extension remain accepted.

Injected third-search failures preserve earlier validated findings and the completed first checkpoint. Attempted searches and successfully returned records remain separate. A surviving worker can perform the existing final integrity check. A terminated/unavailable worker cannot confirm that check: the result retains the primary worker failure and explicitly reports `INTEGRITY_UNCONFIRMED`. Cleanup confirmation is independent of read-view integrity. No failed retrieval becomes accepted evidence.

## Focused validation

`tests/test_extended_search_reliability.py` uses disposable SQLite cases and scripted providers, with the real supervised controller and persistent worker. Coverage includes dense neighborhoods, duplicate candidates, third-search success, actual SQL interruption, parent timeout, process exit, internal exception, cancellation, accepted-state preservation, checkpoint reconstruction, malformed protocol messages, absolute deadline clamping and unchanged database bytes. Two independent provider-free reconstructions must agree. Existing focused suites cover source/time rejection, duplicate refusal, grants, startup and context budgets.

Recorded expanded focused run: **120 passed in 141.38 seconds**, covering extended investigation, follow-up discovery, contextual inspection, startup, supervised budgets, worker, packet capacity and investigation progress. Final targeted run after protocol/deadline additions: **40 passed in 39.20 seconds** (`test_extended_search_reliability.py`, `test_post_retrieval_packet.py`, `test_v4_worker.py`). These sets overlap and are not additive unique-test counts. `git diff --check` passed. No full suite or live acceptance was run.

## Manual acceptance

After installing this checkout in the test environment:

```powershell
.\.venv\Scripts\python.exe locard.py --version
.\.venv\Scripts\python.exe locard.py
```

Expect `Locard 6.171`. Select the intended existing case, then repeat the previously approved extended investigation using its saved assessment identifier:

```text
investigation run <assessment-id> --follow-up --extended
```

Review the question, source/time scope and authorization before approval. Verify progression beyond the third temporal search, retained findings and checkpoints, and the separately reported completion/integrity/cleanup states. If it fails, retain the sanitized worker category, phase and deadline flag; those distinguish the next diagnostic step. Retrieval success alone does not establish incident-reconstruction quality.

The original live exception, real-case query latency and live acceptance remain unresolved. No original evidence, case sidecar, configuration or transcript was modified. No commit or push was performed.

# Locard 6.120 — Empty-state replay and D1b status diagnostics

Implementation and focused validation: 2026-11-10.

Starting HEAD: `f15c1ea26c46a43de3fc60efbee91cf2bdcc8e85`, branch `main`.
The working tree already contained the 6.119 generic AI activity-label correction and its tests. Those changes are preserved. `pyproject.toml` now declares **6.120**; it remains the sole application-version authority. No commit or push was performed.

## Scope and correction

`organization.reconstruct()` previously passed `sources.related=None` into S3 assessment when no analysis batch had been accepted. Live finalization instead builds a registered S2 state from the accepted S1 reducer. The replay path now uses `relationships._build(facts.finish())` when the relationship snapshot is absent. It does not substitute an arbitrary dictionary or invent observations, interpretations or relationships. Nonempty histories retain their existing path.

An additional empty-history edge case surfaced in the new tests: without a terminal record, B2's retrospective preview supplies omission metadata even though live zero-batch execution never enters B2 planning. For zero accepted batches and no terminal only, C1 finalization now uses the live empty omission list. It still recomputes and checks the recorded C1/D1b digests. This does not change B2 execution, planning, authority or nonempty history semantics.

Before the correction, both the copied zero-batch run and a synthetic invalid-first-response run raised `AttributeError: 'NoneType' object has no attribute 'get'`. Afterward, normal reconstruction reproduces the recorded derived state. `VALIDATION_FAILURE` remains an unsuccessful investigation outcome; organizational completion is not investigation success or forensic completeness.

Modified implementation:

| File / functions | Change |
|---|---|
| `forensic_assistant/investigation_ai/organization.py:reconstruct` | Registered empty relationship-state derivation and empty-history/no-terminal omission handling |
| `forensic_assistant/investigation_ai/explanation_live.py:Live.update/summary`, `Replay`, `page/render` | Bounded numerical diagnostics, exact-frontier currentness, independent statuses and recorded execution outcome |
| `forensic_assistant/investigation_ai/explanation_status.py` (new) | Diagnostic contract, unchanged admission predicates with distinct reasons, bounded validation and shared status projection/rendering |
| `forensic_assistant/investigation_ai/presentation.py:render` | Independent currentness/processing/upstream statuses and separate publication outcome counts |
| `pyproject.toml` | 6.119 → 6.120 in the existing working tree |

No parser, evidence, authorization, provider, decomposition, checkpoint selection, checkpoint serialization, journal publication or resource-limit redesign is included.

## Diagnostic compatibility and publication outcomes

New terminal summaries have a separate optional `diagnostics` object:

```
contract: explanation-diagnostics-v1
attempts: at most 9 bounded entries
omitted_attempts: bounded overflow count
time_limit_exceeded: boolean (the existing cumulative processing limit was exceeded)
```

Existing checkpoint contracts, profiles, reducer state, prefix stop codes and digests are unchanged. Existing aggregate `stops` retain their historical meaning. In particular, historical `journal_reservation` is not rewritten to a more specific reason, and historical prefix `event_byte_limit` is not reclassified as a failed write.

Each new diagnostic entry distinguishes:

| Outcome | Meaning |
|---|---|
| `admission_rejected` | No checkpoint publication was attempted for this prepared update |
| `committed_prefix` | A valid bounded prefix was published and committed; some candidate work stopped |
| `committed_complete` | This checkpoint's candidate processing completed and its publication/commit succeeded |
| `publication_uncertain` | Publication or commit failed; existing fatal publication handling remains in force |

New admission reasons distinguish `event_byte_limit`, `local_journal_allocation_limit`, `global_journal_reservation` and `journal_event_slot_limit`. Prefix/preparation diagnostics expose `operation_limit`, `dependency_visit_limit`, `processing_time_limit`, and existing memory, admission, checkpoint, dependency and index-edge limits without changing the reducer's recorded codes.

Available numerical details include actual encoded event bytes including the JSONL newline, event ceiling, consumed D1b bytes, remaining applicable D1b allocation, global journal bytes/ceiling, future reserved bytes/slots, remaining event slots, examined candidate count, prepared operations and committed operations. `candidate_operations_considered` is the reducer's examined-candidate count, which may include an unchanged candidate or the candidate at which selection stopped; it is not necessarily the number of new operations.

If no complete event has been encoded, size is `unavailable` and numerical event details are absent. No estimated number is labeled measured. Diagnostics contain no original field values, evidence IDs, paths or model prose. The optional diagnostic object is schema/size checked during replay, capped at 8,192 encoded bytes, and never used as evidence authority or to reconstruct operations. Historical summaries without it remain accepted.

On publication uncertainty the diagnostic is available in memory before the existing fatal exception propagates. Locard does **not** attempt another journal write to persist it after uncertainty. The existing publication exception/containment path remains authoritative; a missing terminal cannot be presented as confirmed durable diagnostics.

All bounds remain unchanged: 8,192 bytes/checkpoint, 65,536 D1b journal bytes, 4 MiB global journal, 256 events, primary/B2/C1 reservations, operation/visit ceilings, 300-second investigation envelope, lookup/request limits, and no retries. Diagnostic overhead participates in the existing live owned-memory measurement. No new journal event is added.

## Currentness and completeness

Currentness compares the committed receipt's run, read view, C1 revision, C1 state digest, C1 checkpoint event identity and source frontier with the latest committed C1 receipt. It never compares the D1b revision counter to the C1 revision counter.

| Status | Meaning |
|---|---|
| Currentness `current` | Exact committed C1 identities match |
| Currentness `stale` | A committed explanation is bound to a different C1 frontier |
| Currentness `unavailable` | A necessary committed receipt is absent |
| Processing `complete` | Admitted D1b component work is complete, with finalization available |
| Processing `partial` / `pending` / `resource_limited` | Missing finalization, unavailable/currentness gap, or outstanding bounded component work, respectively; pending/omitted counts remain explicit |
| Upstream `complete` / `partial` / `unavailable` | Separate C1 processing/finalization state |

The existing aggregate `incomplete` flag remains conservative for compatibility. New human output separates these statuses. Persisted explanation output also shows the recorded investigation termination, or that no terminal record is available. S3 statuses and qualifications are unchanged. Parent cleanup remains explicitly unconfirmed by explanation persistence.

For the original partial run, output now includes:

```
Explanation: current at C1 revision 6.
Explanation components: 60 accepted; 0 pending; 0 omitted.
Explanation processing: complete within admitted component scope.
Upstream organization: partial.
Final assessment: available.
Forensic completeness: not established.
Recorded investigation outcome: AUTHORIZED_PLAN_EXHAUSTED.
```

For the zero-batch run, the two accepted explanation components are assessment/coverage material, **not two accepted forensic findings**. Output retains `VALIDATION_FAILURE`, zero original clauses, and original S3 `NOT_ASSESSABLE`.

## Copied-run acceptance results

Copies were read only under `C:\tmp\locard-diagnostics\6.118-live`. Manifest/hash-chain validation preceded reconstruction. Each run was reconstructed in two fresh Python processes with SQLite connections and `ModelBackend.complete` forbidden. Outputs were deterministically equal; before/after file hashes matched. The original case and transcript locations were not accessed.

| Run | D1b digest | Result |
|---|---|---|
| `08cfd054f85a4a36b8520832427201c3` | `83e041cdfa0e61efd1fc4ad48db80ad0f30265b870babeb3fc4e7569e9a6d14b` | Exact recorded state; 0 observations/interpretations; C1 1/D1b 1; current; execution remains `VALIDATION_FAILURE` |
| `ffdabecc9ded47e6acd5f4977fa3c2fa` | `7019faae14d8fb56aaca78b7149b35d9d656c6d709f1ac0dd48de2cce64da110` | Exact recorded state; 23 observations + 1 interpretation; C1 6/D1b 6; current; upstream complete |
| `6ad0c85499564406aa4d949f3b0e72e5` | `1c3f778d147d16a11192b735be60497924d04a41f6da296986dc573fb348bb9c` | Exact recorded state; 23 observations + 1 interpretation; C1 6/D1b 5; current; upstream partial |

Their C1 state digests, respectively, remain:

- `82e9a4bd2b3472589e8f9e86cb6a6ae91a5f2f74f273a9fbb1f77e6fa516b951`
- `0f339bd80f8dcd852c5a1fc9fd385e08f40659e344a141602b4a5f83aac0a651`
- `48b043237cf3c9f5d8182f99beeb06516d8a17d32295de6211832ec384a498d2`

All original S1 clause IDs equal the explanations' retained clause sets. Historical checkpoint prefixes, source/read-view bindings, current/historical relationship classifications and original S3 results are validated by the existing reconstruction path. The new display/diagnostic wrapper is intentionally not part of those old state digests.

Historical fixture `C:\tmp\locard-diagnostics\6.111-b2\ec81a1af5b1f471ca4f3a4c0bb917fa2` retains:

- 61 canonical statements: `0a449bb4cde578094d5f6145769ca0a0c5cf34eb984299eccdb4c1441b62ca5a`.
- Seven compact pages: `79bb708cbcca853cd8d4c3b168150353d5ad0cdd32c4ead34fc427af911297da`.

File hashing confirms unchanged bytes during these checks, not integrity before the supplied copies existed.

## Focused tests and environment

New `tests/test_explanation_replay_status.py` covers invalid first responses, rejected first deltas, interrupted zero-batch execution, registered empty S2 construction, no fabricated findings, final anchors/checkpoints after failed analysis, missing final assessment/terminal, fresh-process determinism, each admission predicate, operation/visit/time diagnostics, committed byte-limited prefixes, complete publication, fatal uncertain publication, bounded telemetry and exact frontier currentness.

Only these three existing provider expectations changed in `tests/test_ai_providers.py`:

1. OpenAI adapter response expects `finish_reason='stop'`, preserving exact text/usage comparison.
2. Native-tool rejection asserts `ProviderFailure.category='response_envelope_failed'`, stage `response_envelope`, rule `unexpected_finish_reason`, `tool_calls_present=true` and `json_parse='not_attempted'`.
3. Cloud-worker completion expects the established finish reason; timeout, successful process exit and stderr checks remain intact.

Both local-supervisor approval tests are unchanged. They need permitted loopback TCP sockets for their synthetic local HTTP fixture; restricted Windows sandbox execution can produce WinError 10013 before any response. No real local model or paid provider is needed.

Recorded executions (sets overlap; counts must not be added as unique tests):

| Selection | Result |
|---|---|
| New replay/status tests, after correcting new test assumptions and missing-terminal edge case | 18 passed in 7.25s |
| New tests + live explanation/resource, organization/finalization, journal publication/short-write suites | **140 passed in 119.36s** |
| Provider + terminal activity + three advisory integration cases outside sandbox | 47 passed, 3 environment-dependent failures in 14.23s |
| Those three advisory integration cases with an in-memory local default configuration | **3 passed in 3.00s** |
| Final changed-helper/render subset: new tests + persisted display/provider-free regression | **19 passed in 12.98s** |
| Later expanded subset including oversized-envelope regression | 19 passed, 1 timing-dependent display failure in 30.19s |
| Unchanged display/provider-free regression rerun alone | **1 passed in 44.00s** |
| Final replay/status diagnostics subset, including oversized envelope and processing-overrun coverage | **20 passed in 8.91s** |

The three environment-dependent advisory cases assume a local provider but read the machine's saved OpenAI selection outside the sandbox. They timed out waiting for their local-specific label. No production routing or saved configuration was changed. An in-memory default configuration resolved them. The provider suite, including the three corrected expectations and two unchanged local-supervisor cases, passed in that broader run.

The timing-dependent display failure was diagnosed from its disposable synthetic journal: D1b spent 1.094 seconds appending checkpoints, exceeded its unchanged one-second cumulative allowance (1.156 seconds total), and correctly stopped further updates. Its older explanation consequently differed from the final retrospective state expected by the test. The test and limit were not weakened. An isolated rerun passed. The new diagnostic contract also explicitly records this processing overrun, without changing whether updates are admitted.

No full suite, live model/provider request, live forensic access or installation was performed. The development interpreter's installed package metadata still reports 6.94; direct source tests used the working tree. `pyproject.toml` is 6.120. The analyst's installation step must refresh metadata before acceptance; no duplicate version constant was introduced.

## Provider-free manual acceptance

After pulling and installing the reviewed checkout in the test environment, verify installed metadata:

```powershell
.\.venv\Scripts\python.exe -c "from importlib.metadata import version; print(version('locard-forensics'))"
```

Expected: `6.120`. Use the existing independent reconstruction utility, **not** `ai-history replay`, which can inspect the current case:

```powershell
$root = 'C:\tmp\locard-diagnostics\6.118-live'
$py = '.\.venv\Scripts\python.exe'

# Failed zero-batch investigation: now reconstructs; outcome stays VALIDATION_FAILURE.
& $py -B -m forensic_assistant.investigation_ai.synthesis $root 08cfd054f85a4a36b8520832427201c3 --live-explanation

# Current explanation with partial upstream organization.
& $py -B -m forensic_assistant.investigation_ai.synthesis $root 6ad0c85499564406aa4d949f3b0e72e5 --live-explanation

# Successful comparison run.
& $py -B -m forensic_assistant.investigation_ai.synthesis $root ffdabecc9ded47e6acd5f4977fa3c2fa --live-explanation

# Compact structured status only; no case database argument is used.
& $py -B -m forensic_assistant.investigation_ai.synthesis $root 6ad0c85499564406aa4d949f3b0e72e5 --live-explanation --json |
    ConvertFrom-Json | Select-Object -ExpandProperty live_status
```

For exact state digests and new numerical diagnostics, run this read-only backend inspection (old transcripts correctly return `diagnostics: null`):

```powershell
$inspect = @'
import json, sys
from pathlib import Path
from unittest.mock import patch
from forensic_assistant.investigation_ai.explanation_live import reconstruct
from forensic_assistant.investigation_ai.transcript import digest
with patch('sqlite3.connect', side_effect=AssertionError('No database access')), patch('forensic_assistant.ai.backend.ModelBackend.complete', side_effect=AssertionError('No provider access')):
    result = reconstruct(Path(sys.argv[1]), sys.argv[2])
    print(json.dumps({'state_digest': digest(result['state']), 'status': result['status'], 'execution_outcome': result['execution_outcome'], 'diagnostics': result['diagnostics']}, indent=2))
'@
& $py -B -c $inspect $root 08cfd054f85a4a36b8520832427201c3
& $py -B -c $inspect $root 6ad0c85499564406aa4d949f3b0e72e5
```

These commands perform no provider execution, grant renewal, case retrieval or journal migration. Repeating them should reproduce the same derived output.

## Remaining limitations and D2 prerequisites

- The 8,290-byte empty checkpoint envelope remains too large. This release identifies the event-size failure accurately; it does not compact receipts or admit oversized events.
- The existing conservative C1 view-size admission can still omit an organizational link. Partial upstream status remains visible.
- Successful bounded prefixes remain successful, but their pending work can outlive a resource stop. Zero pending only describes the committed admitted scope.
- Two unsupported decomposition objectives can still collide on the existing deterministic duplicate key. Rejection remains atomic, original S3 remains intact and authorized exploratory B2 fallback remains available. D2 must handle unavailable objective bindings explicitly; no rule relaxation is included.
- Currentness and replay validity do not attest live-case equality, whole-case coverage, causal entailment, successful execution or parent cleanup.
- Publication-uncertain diagnostics cannot be made durably certain by attempting another append. The prior confirmed state and existing fatal containment handling remain the boundary.
- D2 should require deterministic replay of successful, failed, empty and interrupted histories, explicit partial coverage, and separate evidence/interpretation/hypothesis authority. D2 implementation is not included.

## Change-set handling

The new documentation is explicitly included with Git intent-to-add despite the existing `docs/*` ignore rule. No repository ignore rules were changed. The new source/test files are also included for review. Intent-to-add does not create a commit or stage a final reviewed content snapshot; the analyst retains Git review/commit control.

Pre-existing 6.119 changes to `terminal_activity.py`, `test_terminal_activity.py` and the previously added provider-label tests are preserved. This release modifies only the files listed above, the three provider expectations, the new test file, and this document.

`git diff --check` passed, including the intent-to-add files. No checkpoint reducer/serialization changes were found by AST comparison against HEAD; both parametrized local-supervisor test bodies are unchanged.

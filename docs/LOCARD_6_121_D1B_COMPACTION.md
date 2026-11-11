# Locard 6.121 — Lossless D1b checkpoint receipt compaction

Date: 2026-11-10. Starting revision: `9cd9dfcb72cf9c1e77f57d4306002166f81143d9`, branch `main`, clean starting tree, application 6.120. Inspected/implemented working version: **6.121**. No commit or push. Version authority remains `pyproject.toml`.

## Original limitation and measured duplication

The authenticated copied 6.118 run `6ad0c85499564406aa4d949f3b0e72e5` contains no first D1b checkpoint: its reconstructed zero-operation event is 8,290 bytes, above the unchanged 8,192-byte ceiling. It ultimately reached the final C1 frontier through five later checkpoints, using 30,309 journal bytes. This is an efficiency correction, not recovery of lost historical evidence.

Re-measurement from the validated C1 transition (read-only, no case/provider access):

| Component | Canonical UTF-8 bytes |
|---|---:|
| Complete logical C1 receipt | 7,575 |
| Changed-key object, 42 entities / 60 links | 6,858 |
| Entity-ID array alone | 2,815 |
| Link-ID array alone | 4,021 |
| Run/read-view object | 210 |
| Source frontier + checkpoint event/revision/state-digest object | 296 |
| Empty D1b operation array | 2 |
| Checkpoint excluding receipt and operation-array values | 505 |
| Complete checkpoint data | 8,082 |
| Event envelope/hash-chain/newline overhead | 208 |
| Complete reconstructed event | **8,290** |
| New receipt-reference object for the same receipt | **691** |

Subobject sizes include their own keys/braces; the breakdown is explanatory, not a set of disjoint additive columns. The full receipt and operations plus the fixed checkpoint remainder and event overhead are additive. The previously measured event remains a reconstruction, not a persisted event. Full receipt references are 6,884 bytes smaller in this example. Run/view and exact source/checkpoint identities are intentionally retained.

## Changed files and contracts

| File | Scope |
|---|---|
| `forensic_assistant/investigation_ai/explanation_live.py` | Profile-selected receipt serialization, exact prospective event sizing, compact binding validation, replay and display binding |
| `forensic_assistant/investigation_ai/autonomous.py` | New opt-in live explanation runs declare the compact profile |
| `pyproject.toml` | Version 6.120 → 6.121 |
| `tests/test_explanation_compact.py` | Synthetic serialization, tampering, safety, equivalence and measurement tests |
| `docs/LOCARD_6_121_D1B_COMPACTION.md` | This report and acceptance commands |

New manifest profile: `local-explanation-v2`. New checkpoint wire contract: `explanation-checkpoint-v2`. Existing logical `explanation-revision-v1`, `explanation-frontier-v1`, statement rules and candidate ordering remain unchanged; the logical state's profile records which wire rules apply. Old manifests retain `local-explanation-v1` / `explanation-checkpoint-v1` and the original conservative packing algorithm. Unknown profiles fail closed.

The v2 checkpoint's `receipt` field contains an exact reference:

```
contract, profile, rules                 supported C1 receipt/profile/rules
run_id, read_view                        exact original identities
event.sequence, event.hash              committed C1 checkpoint
revision, digest                        C1 revision and state digest
source_frontier                         exact upstream frontier
receipt_digest                          digest of the FULL canonical receipt
```

It omits repeated serialization of `changed`, `previous_digest` and `final`; these remain in the complete receipt reconstructed from the original C1 transition. The complete receipt is retained in the logical D1b state and is available through reconstruction for diagnostics. There is no second source store, migration, additional lookup or provider call.

`receipt_reference()` validates registered C1 contract/profile/rules before producing a binding. `Live.update()` still requires the exact current organizer receipt, recomputed C1 state digest, current journal frontier, confirmed publication, run and read view. New runs declare v2 but publish no checkpoint until all existing source/resource/publication gates pass. There is no silent downgrade on failure.

## Replay and authority boundary

1. `transcript.load()` validates manifest, sequence and hash chain.
2. `organization.reconstruct()` validates B2 history, original S1 sources, S2 dependencies and each supported C1 transition.
3. `organization.commit_receipt()` recomputes changed entity/link keys and the complete logical receipt from before/after C1 state.
4. `Replay.source()` receives that reconstructed receipt, not a wire-supplied receipt claim.
5. `Replay.consume()` recomputes its compact reference and compares canonical digests, preserving exact JSON types. It checks immediate C1 event sequence/hash adjacency, one use per revision and resource limits.
6. `Reducer.prepare(..., replay=...)` recomputes candidates, original-support/dependency resolution and exactly the recorded examined prefix. It ignores replay wall-clock speed, not operation/visit/admission budgets. It checks the complete generated checkpoint against the recorded checkpoint, including candidate, predecessor and resulting-state digests.
7. Terminal and presentation bindings use the actual profile and confirmed state. Failed/empty/interrupted histories retain the 6.120 behavior.

A matching event hash or supplied receipt digest alone grants no authority. Changed-key forgery, incompatible rules, missing source checkpoint, cross-run/view bindings and stale receipt identities fail before acceptance. S1 qualifications, S2 assumptions and B2 unverified classifications still come from the unchanged source adapter. Valid hash chains are not substitutes for semantic source validation.

Historical event files are never rewritten. Report-import permissions, provider authority, grants, decomposition rules and restart behavior are unchanged.

## Exact bounded operation packing

V2 prepares one candidate operation atomically, recomputes the prospective logical state's counters, pending keys, coverage and digest, builds the full checkpoint and then measures the complete canonical event including hash-chain overhead and newline. It tests the explicit byte-limited-prefix form (`stop=event_byte_limit`), so a usable prefix is not admitted based on the shorter standalone operation encoding. An operation that does not fit is rolled back while its already incurred dependency visits remain charged.

The final event is measured again by the unchanged live admission gate. Other stop reasons can change a few bytes; final admission remains authoritative. The implementation does not promise maximum packing density. It preserves deterministic candidate order and never drops qualifications or dependencies to fit an operation. The v1 estimator is retained exclusively for old-profile behavior.

Preparation remains cooperative: the deadline/slice check occurs before each candidate; exact serialization is bounded work within that candidate. If time expires, the examined prefix is retained subject to the existing overall time/admission checks. No additional replay operations are admitted because replay is faster. Publication advances reducer state only after confirmed append. Fatal or uncertain publication still stops, without append retries, manifest repair or tail promotion.

Unchanged limits: 8,192 event bytes; 65,536 D1b journal bytes; nine checkpoints; 32 operations per checkpoint / 288 total; 2,048 visits; 192 lifetime statement admissions; 128 KiB reference state; 4 MiB owned heap; one second cumulative work / 100 ms cooperative slice; 4 MiB / 256-event journal; existing primary/B2/C1/final reservations; 300-second investigation deadline. C1 view admission is untouched.

## Synthetic performance comparison

`test_compact_measurement_and_exact_prefix` uses the same synthetic original-support adapter and mocked C1 receipt with 42 changed entities and 60 changed links. Receipt size is 7,539 bytes (36 fewer than the historical receipt because identity envelopes differ). Its compact reference is 655 bytes. This fixture reproduces the size/semantic shape; it is not a claim about a counterfactual historical run.

| First update | Legacy v1 | Compact v2 |
|---|---:|---:|
| Full logical receipt | 7,539 | 7,539 |
| Zero-operation wire cost, like-for-like sizing only | 8,253 | 1,369 |
| Receipt serialization savings | — | **6,884 bytes** |
| Actual prepared event | 8,253 | **7,981** |
| Complete operations admitted within 8 KiB | 0 | **30** |
| Preparation time | 1.990 ms | 19.689 ms |
| Prefix replay time | 1.934 ms | 19.073 ms |
| Counted peak owned heap | 97,735 | 145,184 |
| Eligible committed revisions | 0 | 1 |
| Additional journal bytes if admitted | 0 | 7,981 |
| Prepared pending / omitted | 40 / 0 | 10 / 0 |

The zero-operation v2 cost is a wire-only comparison with equal-width state hashes, not a publication of a rewritten v1 checkpoint. Actual compact preparation and exact replay are tested separately. Legacy pending counts above describe the rejected prepared state; no legacy revision is committed for this first update.

A separate nine-update in-memory reducer comparison, with later receipts containing no newly changed keys, produced:

| Metric | Legacy v1 | Compact v2 |
|---|---:|---:|
| Total preparation time | 24.964 ms | 44.564 ms |
| Counted peak owned heap | 114,887 | 154,317 |
| Committed in-memory revisions | 8 | 9 |
| Admitted journal-byte cost | 20,119 | 21,060 |
| Total operations | 40 | 40 |
| Final pending / omitted | 0 / 0 | 0 / 0 |

All resulting canonical statements are exactly equal. This measures serialization/reducer work, not disk fsync or a real investigation. Total journal cost increases by 941 bytes because one previously skipped intermediate update now fits. Compaction is not a promise that every run's total journal shrinks. The tests also run complete synthetic autonomous investigations with existing elapsed, heap, journal and no-extra-request assertions. Timings are single-machine observations, not a guarantee against OS scheduling/fsync delays; owned heap is the application's reference-graph accounting, not process RSS.

## Historical acceptance

Read-only validation ran twice in independent Python processes with `sqlite3.connect` and `ModelBackend.complete` forbidden. Full reconstruction outputs matched. SHA-256 checks of each copied `manifest.json` and `events.jsonl` matched before/after.

| 6.118 run | Preserved D1b state digest | Status |
|---|---|---|
| `6ad0c85499564406aa4d949f3b0e72e5` | `1c3f778d147d16a11192b735be60497924d04a41f6da296986dc573fb348bb9c` | Current at C1 6, D1b 5, 60 components; upstream partial |
| `ffdabecc9ded47e6acd5f4977fa3c2fa` | `7019faae14d8fb56aaca78b7149b35d9d656c6d709f1ac0dd48de2cce64da110` | Current, 58 components; upstream complete |
| `08cfd054f85a4a36b8520832427201c3` | `83e041cdfa0e61efd1fc4ad48db80ad0f30265b870babeb3fc4e7569e9a6d14b` | Zero analysis, two components; unsuccessful investigation remains unsuccessful |

The 6.111 copy `ec81a1af5b1f471ca4f3a4c0bb917fa2` retains 61 canonical statements, digest `0a449bb4cde578094d5f6145769ca0a0c5cf34eb984299eccdb4c1441b62ca5a`, and seven display pages, digest `79bb708cbcca853cd8d4c3b168150353d5ad0cdd32c4ead34fc427af911297da`.

No separate transcript for every intervening release was supplied. Compatibility is supported by preserved v1 decoding, these supplied histories and synthetic old/new-profile tests; it is not a claim of having executed every historical release.

## Focused validation

Normal invocation: `.\.venv\Scripts\python.exe -B -m pytest -q -p no:cacheprovider --basetemp=<disposable-directory> ...`.

| Focused selection | Recorded result |
|---|---|
| Existing live explanation + 6.120 replay/status tests | **60 passed in 71.58s** |
| Initial compact tests | **24 passed in 40.43s** |
| Expanded compact + live resource + journal short-write/publication + organization finalization tests | **83 passed in 74.51s** |
| Final exact canonical-type binding, tampering and reconstruction subset | **20 passed, 12 deselected in 40.14s** |
| Explicit B2 classification/qualification reconstruction assertion | **1 passed in 2.83s** |

Sets overlap; do not add them as unique coverage. The exact-type check rejects a Boolean revision even where Python's ordinary equality would consider it equal to integer 1.

Coverage includes compact profile creation, complete reconstructed receipts, forged bindings/C1 candidate digests, missing checkpoints, atomic prefixes and byte limits, original-support equivalence, resource/final reservations, publication uncertainty, short writes, zero analysis, cancellation/interrupted histories, independent-process deterministic replay, and unchanged model/lookup counts. Production source limits were not increased and no existing test expectations were weakened.

## Provider-free manual acceptance

After installing the reviewed checkout:

```powershell
.\.venv\Scripts\python.exe -c "from importlib.metadata import version; print(version('locard-forensics'))"
# Expected: 6.121

.\.venv\Scripts\python.exe -B -m pytest -q -p no:cacheprovider tests/test_explanation_compact.py tests/test_explanation_replay_status.py

$root = 'C:\tmp\locard-diagnostics\6.118-live'
$py = '.\.venv\Scripts\python.exe'
& $py -B -m forensic_assistant.investigation_ai.synthesis $root 6ad0c85499564406aa4d949f3b0e72e5 --live-explanation
& $py -B -m forensic_assistant.investigation_ai.synthesis $root ffdabecc9ded47e6acd5f4977fa3c2fa --live-explanation
& $py -B -m forensic_assistant.investigation_ai.synthesis $root 08cfd054f85a4a36b8520832427201c3 --live-explanation
```

These historical commands do not open the case database or call a provider. Historical copies remain v1. The synthetic test invocation creates disposable journals, including v2 journals, and proves compact dispatch integration without provider requests. A future analyst-run investigation with the existing `--live-explanation` opt-in will declare v2; no new command surface or additional AI request was introduced.

## Remaining limits and review boundary

- A large reference state, expensive source resolution, slow serialization or fsync can still exhaust existing budgets. No time, memory or journal ceiling has been raised.
- Exact packing is more CPU-intensive; measured additional cost is acceptable in the supplied synthetic cases, not a guarantee for all cases.
- C1's unprocessed organizational `duplicate_of` link remains an upstream partial-processing limitation. D1b currentness does not establish C1 completeness, forensic completeness or cleanup confirmation.
- No historical run is claimed to have behaved differently; no historical receipt/checkpoint is migrated.
- No D2, decomposition, report-import, restart, provider, evidence or permission changes.
- No full test suite, live provider calls, live forensic database access, installation, commit or push. Changes remain for analyst review and manual acceptance.

The new documentation and test file are included with intent-to-add despite ignore rules, without changing repository-wide ignores or creating a commit. `git diff --check` passed. No reviewed content snapshot is staged; the analyst retains commit control.

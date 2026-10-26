# Bounded investigation identity and content verification

2026-10-25. Application version 6.70. Working-tree patch based on `6a670f5`;
manual acceptance pending. No case-14 access or real-model execution.

## Diagnosis and scope

Observed in code: `controller._run -> worker.serve -> fingerprint` previously
hashed before `tools.initial` and again at completion. `semantic/documents.py::fingerprint`
traverses every non-internal table, ordered by declared logical key, and every
column value, including raw BLOB/text bytes in 64 KiB chunks. Large cells require
additional substring queries. Removing the earlier physical copy did not remove
these scans. This implementation has not changed the fingerprint algorithm.

User-reported: the real 18 GB case timed out with the fingerprint phase displayed,
without the prior cleanup error. This supports the bottleneck hypothesis; no
measurement here establishes the exact real-case duration or sole cause.

The normal path now pins a single transaction and skips both mandatory content
hashes. Actual semantic retrieval can still demand a full hash. Initial retrieval
also performs searches, counts, and evidence hydration; this patch does not promise
constant-time startup or change those queries.

## Fingerprint dependency map

Paths below are under `forensic_assistant/`.

| Consumer | Purpose / invariant | Transaction alone sufficient? | Decision |
|---|---|---|---|
| `investigation_ai/worker.py::serve`, initial | Stable evidence view and initial content identity | Yes for consistency; no for cryptographic identity | Remove mandatory hash; explicit run-local identity replaces only consistency tracking |
| Same, completion | Live-case equality with initial digest | No | Remove equality claim; check active transaction and unchanged file identity instead |
| `investigation_ai/case.py::ReadViewFingerprint.value` | Exact semantic index freshness against pinned contents | No | Compute lazily once when semantic search actually requests it, only within that active view |
| `semantic/index.py::build`, `status`, `search` | Index generation/freshness, stale rejection | No | Retain unchanged exact digest comparisons; standalone search still hashes |
| `investigation_ai/controller.py::_run` | Response continuity, manifest/terminal identity | Yes for same-view continuity | Compare explicit `evidence_state`; legacy `evidence_fingerprint` stays null for new runs |
| `investigation_ai/transcript.py::digest`, `load` | Event-chain integrity, consistent recorded identities | No; concerns transcript bytes | Retain payload hashes and chain validation; validate new state structure and cross-event agreement |
| `transcript.py::implementation` | Producer source-code identity | No; not a database operation | Retain code SHA and existing policy/application metadata |
| `investigation_ai/cli.py`, history show | Current case versus recorded digest | No | New contract reports equality unavailable without scanning; historical digest path unchanged |
| `investigation_ai/replay.py::replay` and legacy worker path | Exact original-state replay | No | Keep digest and implementation/policy gates; explicitly refuse new hashless transcripts |
| `reporting/transcripts.py::load`, `collect.py::build` | Same-state investigation inputs, exposure/grounding | No | Keep old digest checks; explicitly refuse new hashless transcript import |
| `reporting/worker.py`, `bundle.py::validate` | Report current-case compatibility plus independent grounding | No | Unchanged full hashes and grounding validation, including explicit-ID reports |
| `investigation_ai/state.py` | Exposed evidence, allowed anchors, grounded facts | Same connection supplies stable values; hashes do not establish grounding | Unchanged; no database fingerprint computation here |

Evidence source hashes and evidence IDs remain unchanged. They identify source
bytes/record locations, not a cryptographic digest of all normalized case tables.
The schema has no universal immutable case UUID establishing content identity.
Workspace names and CASE_CREATE activity labels are analyst metadata, not such a
proof (`interactive/workspace.py::case_label`). No schema migration or new persistent
case identifier was introduced.

## Execution and guarantees

`controller.run -> worker.serve -> ReadView`: resolve the case, retain OS device/file
identity, open `mode=ro`, set existing query-only/trusted-schema/extension restrictions,
BEGIN and read immediately. Every investigative query, including the final view
check, uses that connection. COMMIT/ROLLBACK remain denied during the active view.
`ReadView.check_identity` checks the active transaction plus the file identity before
and after each operation. Cleanup rolls back/closes or terminates the contained worker.

The IPC/manifest/terminal state has this shape (synthetic example):

```json
{
  "evidence_fingerprint": null,
  "evidence_state": {
    "contract": "sqlite-read-view-v1",
    "view_id": "11111111111111111111111111111111",
    "file_identity": {"device": 1, "inode": 42}
  }
}
```

The token is randomly generated for this worker/view. It is not a digest, portable
case identifier, signature, or reusable cross-run compatibility token. Existing
fingerprint fields never contain it. The outer transcript format/hash chain remains
format 1; the evidence-state contract is separately versioned. New transcript
inspection checks this structure and identity agreement across initial/tool/terminal
records. Older readers cannot safely treat a null digest as matching content.

| Guarantee / event | Previous two-hash design | Current design |
|---|---|---|
| Stable evidence across tool calls | Pinned transaction | Same |
| AI cannot modify case, execute SQL/files/shell, bypass approval | Existing controls | Same |
| Final observed facts grounded in exposed fields | Existing ledger/validators | Same |
| Live case equals original content at final check | Exact logical digest comparison | **Not established**; `live_case_matches` is null |
| Concurrent SQLite insert/update in WAL | Stable old view, reject final digest mismatch | Stable old view, permitted; findings explicitly scoped to that view |
| WAL checkpoint state change | Reader retention possible | Same; checkpoint changes do not themselves invalidate logical view |
| Rollback-journal writer | May block on commit | Same; writer receives busy/locked until reader releases |
| File replacement/deletion | OS may prevent; identity checks | Same; otherwise identity mismatch/path disappearance fails closed |
| Raw overwrite/corruption outside SQLite | SQLite guarantees insufficient | Still not guaranteed; no claim to detect every filesystem modification |
| Transcript byte integrity | Hash chain, not proof against forgery | Same; not proof of unchanged case contents |

No mtime, size, data_version, schema version or page-count check masquerades as a
content hash. There is no live-content equality check in normal completion. The
64 MiB WAL growth guard remains an exchange-time safety check, not continuous
monitoring during model/approval waits. No journal defaults, ingestion, parsers,
evidence schema, budgets or tool permissions changed.

## Compatibility tradeoff

New investigations remain useful for grounded findings and transcript inspection,
but cannot be imported into existing exact-state replay or investigation-based
reports. Those operations fail explicitly before interpreting a view token as a
digest. This is a deliberate functional restriction preserving their security
contract, not equivalent compatibility. A future adapter would need an explicitly
approved grounding/state contract; none was silently added here.

Existing fingerprint-backed transcripts/reports keep their checks. Replay still
requires its existing exact producer implementation/policy match, so not every old
transcript is replayable after code changes. Report import retains its existing
format/policy/schema rules. Tests generate genuine historical-format digests with
a test-only legacy worker adapter; no fixed fake hashes replace security checks.

Explicit evidence-ID report generation still works with current case fingerprints
and independent grounding. Such a report covers that explicit selection/current
state; it does not retroactively certify the hashless investigation's whole-case state.

## Synthetic measurements

Single before/after measurements with real workers, scripted model, semantic search
disabled, 128 KiB synthetic retained text per event. Times in seconds; phase times
may overlap and must not be summed. High-resolution phase timings are used for the
short completion check (the coarse execution clock rounded it to zero).

| Metric | 128 records before | 128 after | 512 records before | 512 after |
|---|---:|---:|---:|---:|
| Database bytes | 17,731,584 | 17,731,584 | 69,709,824 | 69,709,824 |
| Worker startup | 0.352356 | 0.309269 | 0.434344 | 0.313781 |
| Investigation initialization (worker initial operation) | 1.144651 | 1.146326 | 5.218548 | 6.558764 |
| Database open | 0.001341 | 0.001326 | 0.001592 | 0.001355 |
| Read transaction establishment | 0.000623 | 0.000886 | 0.000858 | 0.000962 |
| Initial fingerprint | 0.086982 | 0 (not called) | 0.370097 | 0 (not called) |
| Initial retrieval | 1.036428 | 1.126523 | 4.820195 | 6.532007 |
| Until first model request | 1.679215 | 1.591558 | 5.821301 | 7.022716 |
| Final fingerprint | 0.103977 | 0 (not called) | 0.344337 | 0 (not called) |
| Final verification (hash before; view check after) | 0.113377 | 0.000730 | 0.352910 | 0.000731 |
| Cleanup | 0.028092 | 0.031858 | 0.031071 | 0.040878 |

Full hashes fell from two to zero. Hash time roughly scaled with fixture size in
these samples. **The larger revised run was slower overall**, with increased retrieval
time despite removed scans. No retrieval code changed; these single measurements
cannot establish the cause of that variation or an end-to-end improvement. They do
not reliably extrapolate to an 18 GB, 2.59-million-record mixed-artifact case.

Reproduce on a new disposable directory with:
`python -B tests/investigation_read_view_profile.py NEW_DIRECTORY 128`
(or 512). Never point the harness at an existing case. Actual semantic search still
performs full exact index verification; reports and legacy replay still scan as
required. Remaining retrieval/count costs may dominate and are not optimized here.

## Validation status

Final focused run: **121 passed, 4 deselected in 113.63 seconds**. The four
deselected cases were independently executed and failed as described below.
Coverage includes no-fingerprint
startup/completion, consistent reads across writes/inserts, WAL/rollback behavior,
replacement/deletion where permitted, cleanup, authorizer/grounding, explicit
transcript contracts, semantic freshness and historical report/replay validation.

Four pre-existing cases in `test_investigation_startup.py` fail because their 6.63
rowid oracle/fixtures have no declared logical keys. The fingerprint implementation
and those failing function bodies were verified identical to HEAD and failures
reproduced independently. Their assertions and the production fingerprint algorithm
were not weakened or repaired as part of this task. No full suite was run.

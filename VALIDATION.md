# Interactive CLI 0.7.0 validation - 2026-09-26

Application version 0.7.0; evidence schema 3 and report format 1 unchanged.
Apache-2.0 and dependency requirements are unchanged. The interactive shell reuses
one parser/dispatcher with the scripted CLI. No MiniCPM service is required for
ordinary tests; controller/report integration uses scripted local clients and
synthetic evidence only.

| Major stage | Complete accumulated suite |
|---|---|
| Baseline | 266 passed |
| Shared parser/dispatcher | 266 passed |
| Existing-case validation and analyst UI state | 279 passed |
| Shell routing, selection, switching and help | 305 passed |
| Approval, parser containment and interrupted ingestion | 314 passed |
| Case isolation and Windows console validation | 320 passed |
| Final 0.7.0, documentation and startup-flow verification | 320 passed in 135.84 seconds |
| Final isolated core-only environment | 320 passed in 134.59 seconds |

The isolated environment has no sentence-transformers, FAISS, torch, transformers,
NumPy, huggingface-hub, tokenizers, or safetensors installed. Final suites were run
concurrently with separate temporary directories, so timings are not benchmarks.
An editable 0.7.0 installation succeeded without dependency installation or build
isolation. The installed entry point reports `Locard 0.7.0`.

## Interactive implementation gates

- Approval input uses synchronous, deadline-polled console input. Timeout and
  cancellation leave no background stdin reader; following input remains readable.
- Windows input uses explicit key events, avoiding ambiguous Unicode/special-key
  prefixes. Input-mode restoration is mandatory. Oversized lines are discarded,
  not executed as silently truncated commands.
- Parser children wait for parent-owned containment before parsing. Real Windows
  worker and descendant processes terminate on cancellation/timeout; parent death
  releases the kill-on-close job. Startup cancellation closes the permission pipe
  and waits for the launcher to reap its unpermitted child. Unconfirmed cleanup
  fails visibly rather than returning to the shell as if cleanup succeeded.
- Interrupted EVTX and artifact runs record `interrupted`, finish time, errors,
  and whether current-file publication committed. Tests cover cancellation before
  and after publication, earlier completed files, WAL and rollback databases,
  detached staging databases, and released handles. Hard termination cannot always
  finalize a run; `running` is never interpreted as successful completion.
- Real command integration switches between two synthetic cases, performs evidence
  retrieval and independent investigations, generates reports, and verifies both
  reports against their respective cases. Original database bytes remain unchanged
  for these read/derived-output operations. Model objects and command overrides
  are not retained; history clears at selection/switch/exit.
- Selection rejects missing, invalid, legacy, structurally incomplete, redirected,
  or locked targets without creating/upgrading them. Invalid remembered cases go
  directly to selection, without a reuse confirmation. Paths with spaces, Unicode,
  relative paths and local paths longer than 260 characters are tested.
- UI state tests cover ten-entry ordering/deduplication, bounded strict JSON,
  corruption preservation, atomic-replacement failure and redirection refusal.
  Preferences live outside forensic databases; scripted commands do not update them.

A live Windows terminal session verified remembered-case startup, status, in-memory
up-arrow history, accented input, Ctrl+C while editing, EOF and exit. Test artifacts,
synthetic databases, transcripts, UI-state files and reports are outside the source
repository. No actual evidence or analyst profile state was used.

Limits: live UNC-share access was not validated; existing SQLite/read-only path
restrictions apply. Console display width and supplementary-character delivery can
vary by terminal. Read-only structural checks are not a full integrity scan or
forensic-grounding validation. SQLite work has bounded validation deadlines, but
filesystem/device access can still incur operating-system latency. Abrupt process
or power loss may leave incomplete derived staging or ingestion/transcript state;
those outputs must not be represented as completed work.

---

# V4 validation — 2026-09-20

V4 application version is 0.5.0. Evidence schema remains 3; no migration was added.
The manually updated GitHub README was fetched before implementation and preserved.
No new runtime dependencies or third-party license changes were introduced.

The complete accumulated suite progressed from 169 baseline tests to 170 after the
context-bundle regression/fix, 193 after the read-only worker stage, 208 after the
controller, 212 after CLI/replay, and 225 after resource/evaluation tests. Final:
**236 passed in 58.34 seconds** after closed-output, stale-index availability,
rejected-request accounting and explicit model-action/continuation prompt checks.
The complete suite with semantic imports blocked also passed: **236 in 61.69 seconds**.
Ordinary tests use scripted models, synthetic
fixtures and, for HTTP deadline validation, a local synthetic HTTP server; they do
not require MiniCPM. Editable installation succeeded without network/dependency
resolution, `locard --version` reports `Locard V4 (0.5.0)`, and `pip check` is clean.

The original context-bundle regression was demonstrated failing before the fix.
It checks that attaching semantic selection reasons cannot replace original anchor
IDs or deterministic relationship objects through loop-variable shadowing.

## Snapshot and trust-boundary gates

The long-lived snapshot gate was rejected: 102,254,312 bytes of WAL retained during
24 writer commits while two readers held the original snapshot; only 3 of 24,819
frames checkpointed. Rollback-journal readers blocked writer commits. Forced reader
termination released locks and allowed a writer-owned checkpoint to truncate WAL.
The approved per-operation fingerprint alternative and tradeoff are documented in
[V4.md](V4.md). Reproduce the rejected-design experiment explicitly with
`python tests/v4_snapshot_validation.py NEW_OUTPUT_DIRECTORY`.

V4 tests cover concurrent WAL and rollback readers, writer progress between
operations, state changes during model waits, interrupted large-table fingerprinting,
worker death and cleanup, WAL-pressure watchdog behavior, authorizer write/attachment
denial, deadlines, missing-case behavior, transcript isolation and replay refusal.
The ordinary watchdog threshold test simulates measured WAL growth; the separate
snapshot experiment performs actual concurrent writes and measures retained bytes.

Other tests cover malformed/duplicate JSON, excessive bounds, forbidden operations,
out-of-case/unexposed anchors, omitted-field citations, invented findings/detections,
unchanged engine statuses, mandatory Registry key support, hypothesis alternatives,
semantic labels, loops/no novelty, approval refusal, dry-run without iterative
execution, model failure and a slow HTTP response body. A Windows transient manifest
replacement failure was observed and addressed with bounded retries of the same
atomic replacement; a regression test injects that sharing violation. Persistent
I/O failure still fails rather than silently rewriting the manifest in place.

## Synthetic V3 versus V4 path exercise

These are small labeled scenarios using scripted model proposals. The baseline is
the deterministic branch of V3's hybrid planner; V4 starts with that same retrieval.
Counts describe retrieved original evidence IDs, not model reasoning quality.

| Scenario | V3 relevant | V4 relevant | V4 other | Calls / turns | Termination |
|---|---:|---:|---:|---:|---|
| Office/PowerShell, later executable and Prefetch | 2 | 4 | 0 | 3 / 4 | ANSWER_SUPPORTED |
| Process, Run value/key, later user-directory executable | 2 | 5 | 0 | 2 / 3 | ANSWER_SUPPORTED |
| Failed logons, later logon and session process | 5 | 7 | 0 | 2 / 3 | ANSWER_SUPPORTED |
| Insufficient causation; overclaim rejected, labeled hypothesis accepted | 2 | 2 | 0 | 0 / 2 | ANSWER_SUPPORTED |
| Registry prompt injection requesting forbidden shell operation | 9 | 9 | 0 | 0 / 3 | TOO_MANY_REJECTIONS |

All accepted factual references matched disclosed original IDs. No unrestricted
observed-fact prose was accepted. Hypotheses remain unverified; the fourth case does
not establish causation. Scripted results are not evidence that a real model will
choose the same useful operations. Tests are in `test_v4_evaluation.py`.

Measured full duration was 0.313–0.422 seconds per small scripted investigation;
worker operation totals were 0.031–0.077 seconds. The remaining 0.281–0.360 seconds
includes process startup, controller/serialization and transcript I/O, not purely
algorithmic controller overhead. Prompts were 5,034–5,554 bytes; transcripts
14,881–27,965 bytes. In the first three cases, 8/7/8 cumulative returned records
deduplicated to 4/5/7 unique IDs respectively. This is not a large-case throughput
benchmark; full fingerprints can dominate large cases and cause a bounded timeout.

## Real optional semantic integration

`tests/v4_semantic_validation.py` exercised installed local BGE-small-en-v1.5 and
FAISS with all five generated cases. Each run performed initial hybrid retrieval,
one additional requested semantic search with deterministic expansion, a scripted
final selection, and replay without an LLM. All five completed with structurally
validated findings; all five replays matched. No setup/download was performed.

| Scenario | V3 hybrid relevant / other | V4 relevant / other | V4 total seconds |
|---|---:|---:|---:|
| 1 | 4 / 1 | 4 / 1 | 13.656 |
| 2 | 5 / 7 | 5 / 7 | 12.000 |
| 3 | 5 / 0 | 7 / 1 | 12.797 |
| 4 | 2 / 1 | 2 / 1 | 12.500 |
| 5 | 9 / 0 | 9 / 0 | 13.156 |

The scripted semantic query was intentionally the same in all five cases; these
results demonstrate integration/replay and expose irrelevant retrieval rather than
establishing retrieval accuracy. The fifth case uses a safe scripted final here;
forbidden-request rejection is measured separately above. Worker totals, including
loading embeddings, were 11.735–13.313 seconds; the 2 GiB worker ceiling remained in
force. After the live-model prompt refinements, all five semantic checks and replays
passed again. Prompts were 5,063–5,537 bytes and transcripts 42,417–82,161 bytes. Existing
V3 validation below documents offline socket/DNS blocking and model-selection gates.

## Live MiniCPM status and public-file review

**Live V4 MiniCPM integration passed twice** after the operator started the loopback
server. It reported `MiniCPM5-2B-Q4_K_M.gguf`. Both runs requested `process_tree`,
executed one validated read-only operation, and then selected the disclosed
`/process_name` field of the original EVTX record. Both terminated
`ANSWER_SUPPORTED` with no rejected requests. The final value and citation were
rendered by Locard, not accepted as model-authored fact prose. Replay of the second
live transcript matched initial retrieval and the tool result without calling the
model. Total durations were 6.344 and 2.672 seconds (server caching may affect the
second); model time was 6.000 and 2.344 seconds. The two prompts were 5,155 and 5,398
bytes. The server reported 1,335/1,376 input tokens and 72–73/63 output tokens.

Earlier live attempts stopped safely with an empty/early final or `TOOL_LOOP`.
The original test question also lacked the anchor required by the existing
deterministic process-tree planner. The harness now supplies that explicit anchor.
Locard's prompt now includes action-format examples, tool argument names, completed
operations and an explicit continuation notice. The server's JSON grammar alone
was insufficient instruction for this small model. The 5,600-byte budget, strict
validator and loop controls remain unchanged. The successful harness explicitly
requests a first tool action; this is a basic protocol/continuation check, not proof
that MiniCPM will autonomously choose useful steps for arbitrary questions.

`tests/v4_model_validation.py` requires an operator-started server, at least one
accepted operation and a validated final selection. It exits unsuccessfully if
that gate fails. All supplied evidence is synthetic. These limited live checks do
not establish forensic accuracy, completeness or prompt-injection immunity.

The V4 Git-visible change review contained source, tests and documentation only;
no new binary artifacts, credentials/token-pattern matches or actual local-user
paths were found. Ignore probes cover EVTX, SQLite journals, model weights and
transcript directories/files. All new fixtures are synthetic; generated databases,
models, semantic indexes and transcripts remain outside Git. This is a review of
the V4 changes, not a new attestation of every historical commit. No commit or push
was performed as part of V4 implementation.

# V3 validation — 2026-09-19

V3 retains schema 3 and stable V0/V1/V2 evidence IDs. Baseline: 147 tests passed.
Stage totals progressed through 150 (representations), 153 (sidecar/hybrid),
160 (planner/security), 163 (privacy/cache), 165 (filters), and 169 tests after
invalid-vector rejection checks. Final code suite: 169 passed in 46.15 seconds.
Full suite with semantic imports blocked: 169 passed in 37.31 seconds.
The full accumulated
suite is also executed with imports of torch, NumPy, FAISS, Sentence Transformers,
Transformers and Hugging Face Hub explicitly blocked.

The real-model offline integration program blocks socket connections and DNS
resolution before model loading. CPU load, build, search, rebuild, SQL host filters
and duplicate suppression passed. Same-count content changes and model identity
mismatches were rejected. Explicit CLI setup downloaded the pinned model and model
card successfully. Editable package installation reports Locard V3 (0.4.0), and
pip check reports no broken requirements. MiniCPM was not needed for these tests.

Both BGE-small-en-v1.5 and all-MiniLM-L6-v2 installed on Windows x64 / Python 3.12.
Both initially retrieved all six simple labeled examples within the top three.
The broader mixed-artifact fixture includes MFT, Prefetch, Registry, relevant
EVTX records, and forty repetitive distractor processes. BGE achieved mean
semantic recall@10 of 1.0; MiniLM achieved 0.667 and missed the Office-interpreter
and user-directory executable labels. BGE was selected. Precision uses a fixed
K=10 denominator and is low because each question has only one or two labeled
positives; these small synthetic labels are not a forensic-accuracy benchmark.
The evaluation script reports SQL-only, semantic and hybrid results separately,
including artifact diversity and duplicate IDs. No claim of production recall,
maliciousness classification, or prompt-injection immunity follows from these tests.

## Scale and resource measurements

- 100,000 mapped representations from 100,000 synthetic evidence records.
- Duplicate-heavy corpus: 1,000 unique texts, 99,000 exact embedding-cache hits.
- Complete build: 141.7 seconds on the repeated run; first run 167.7 seconds.
- Peak process working set: 665,874,432 bytes (approximately 635 MiB), measured
  with the Windows process-memory API through the completed build/search run.
- Active generation: approximately 246.2 MB decimal (235 MiB), including
  153,600,000 bytes of vectors. Previous generations are retained separately.
- Three end-to-end searches: 11.28, 11.18 and 10.84 seconds. These include full
  content fingerprinting, integrity checks and SQL filtering; the model was
  already loaded. Fresh CLI model-load latency is additional.
- Repeated builds produced identical vector-file and mapping-file SHA-256 hashes
  on this environment. Build timestamps differ. Cross-platform bit identity is
  not guaranteed.
- A separate unique-text run reached 6,000 vectors in 386.7 seconds before being
  intentionally stopped to evaluate exact-text caching. It was not a completed
  100,000-unique-text benchmark. The observed rate is about 15.5 vectors/second;
  a large unique corpus should be expected to take substantially longer than the
  duplicate-heavy build. Do not report cache throughput as embedding throughput.

All scale/evaluation databases, generated binary fixtures, downloaded weights and
indexes are outside Git. Source-only generators are provided in tests/v3_scale.py,
tests/v3_evaluation.py and tests/v3_integration.py. Each takes explicit local paths;
use an output directory outside the source repository. Incremental indexing is
not implemented or benchmarked in V3. No original examiner evidence was used.

## Release limitations

Locard source is Apache-2.0; dependencies retain their licenses. Existing AGPL/LGPL
redistribution obligations remain documented in THIRD_PARTY_NOTICES.md. Semantic
retrieval is optional, CPU-only, and derived. Long values, collections, chunks,
candidate pools and MiniCPM bundles have explicit limits. Hybrid hydration rejects
rows above 2 MiB. Citation validation checks references, not the truth of prose.
Public release still requires reviewing all staged files/history and excluding
sensitive local sidecars; V3 does not erase the earlier privacy-audit findings or
make ignored case directories safe to publish as an archive.

---

# Locard validation

## V2 validation (package 0.3.0, schema 3)

Validated on Windows AMD64, CPython 3.12.14. V1 baseline: **105 passed**.
The complete accumulated suite was run after each major implementation stage:

| V2 stage | Full-suite result |
|---|---|
| Additive schema-3 migration | 107 passed |
| Timestamp/path/context normalization | 110 passed |
| MFT ingestion | 114 passed |
| Prefetch and Registry ingestion | 120 passed |
| Unified retrieval and CLI | 122 passed |
| Cross-artifact correlations and four rules | 127 passed |
| Investigation assembly | 127 passed |
| Mixed model bundles and citations | 134 passed |
| Parser/context/resource boundary regressions | 145 passed |
| Final provenance and correlation-coverage checks | **147 passed** |

Final accumulated acceptance run: **147 passed in 32.80 seconds**. A fresh public
EVTX re-ingestion also verified parser provenance `python-evtx` / `0.8.1` on all
2,261 newly inserted records, with zero errors. Historical unknown parser versions
are left unknown, and duplicate ingestion never overwrites first-ingestion provenance.

Original V0 tests remain unchanged. Existing V1 expectations were adjusted only
for schema version 3 and twelve discovered rules; evidence-preservation assertions
remain intact. New tests cover native synthetic binary parsing, all new ID
namespaces, duplicate/path provenance, source-change rejection, migration rollback,
allocated/deleted MFT records, multiple filenames, SI/FN precision, near-end attribute
terminators, parent reuse/cycles, Prefetch formats/run counts, dirty/truncated hives,
key/value timestamps and binary data, parser worker failures, all four new rules,
host/path/time ambiguity, mixed CLI/JSON, context omissions, malicious Registry text,
and citation validation. Tests do not require MiniCPM or Internet access.

### Parser gate and substitution

Before adopting adapters, installed binary packages were inspected and exercised
against public artifacts. `mft==0.7.0` was rejected because its Python binding did
not expose reliable physical record offsets and skipped zero slots. Counting yielded
records or trusting declared header record numbers would weaken provenance.
`dissect.ntfs==3.16` replaced it, using its binary structures and record fixup decoder.
The rejected package was removed from the environment and requirements.

Accepted dependencies: Dissect NTFS 3.16 (AGPL-3.0-or-later), Dissect cstruct 4.7 and
util 3.24 (Apache-2.0), libscca-python 20260527 and libregf-python 20260526
(LGPL-3.0-or-later). License expressions were checked in installed distribution
metadata. These are not all permissive dependencies; no existing repository license
prohibited the selected local use. Distribution must account for their licenses.
The libyal bindings are upstream alpha software; tested versions are pinned.

The gate verified raw integer FILETIMEs, multiple SI/FN attributes, deleted records,
Prefetch format differences, Registry key/value fields and absolute offsets against
actual `nk`/`vk` source signatures. Source hashes matched before and after checks.
MFT gate counts: 13,068 records, 1,229 unallocated, 5,446 with multiple filenames,
13,064 SI attributes and 18,506 FN attributes. Registry gate counts matched the
end-to-end record counts below. Malformed inputs generated explicit errors.

During full-adapter validation, 112 valid MFT records initially raised EOFError:
the four-byte attribute end marker lay too near the record boundary for a full
attribute header. Checking the marker before asking Dissect to decode a header
fixed this framing error. A synthetic regression preserves this case; no parser
validation was disabled or bypassed.

### Public-artifact integration

All downloaded artifacts and resulting databases stay in workspace scratch storage,
outside the Git repository. Samples came from the
[pymft-rs MFT fixture](https://github.com/omerbenamram/pymft-rs/tree/master/samples)
and [Plaso test data](https://github.com/log2timeline/plaso/tree/main/test_data).
The EVTX fixture is the same one identified in the V0/V1 validation below.
Hashes identify the exact inputs independently of changing upstream branches.

| Source | SHA-256 | Inserted records | Seconds |
|---|---|---:|---:|
| MFT | `c78f4968345b70783fbf6573d86c4bf300295ae26ddde4033dd1037b802e13c1` | 13,068 | 20.56 |
| NTUSER.DAT | `4a3232850f9677de96774b4de0020ac7f5e2efeb5e4576a200bb751d9e1c9d1d` | 6,729 | 1.40 |
| SYSTEM | `96dc1f1cc3c0b44ef9af72d1c18a8e6a4338c67988f303d05693ca4be6bf7eb9` | 104,211 | 22.96 |
| SOFTWARE | `c2e1a391d6be9740e79da7944e012ad9ac878902db38ec7fc225a2a68d262a1b` | 311,358 | 185.22 |
| security.evtx | `5f29a03cf8c1b4bfbd82c4074ccc81ecfe85d7ee15375afc352ed5025c9a4d8d` | 2,261 | 9.76 |

Every listed ingestion completed with **zero errors**, and every source SHA-256
remained unchanged. Registry counts combine keys and values. The SOFTWARE fixture
used a 600-second worker timeout. Measurements include competing validation work
and are not isolated throughput guarantees.

Seven public Prefetch inputs each ingested completely with unchanged hashes:

| Filename | Format | Run count | SHA-256 |
|---|---:|---:|---|
| CMD.EXE-087B4001.pf | 17 | 2 | `93ec53e941b285d1d2a11e1224ab2d5c7a1b8ac493ab8dec407f518c5655ae75` |
| PING.EXE-B29F6629.pf | 23 | 14 | `cdb6e2de2b02808755aa2591708ebe155ee3483947e230f5fdd6870390fafd26` |
| WUAUCLT.EXE-830BCC14.pf | 23 | 25 | `fc20953fefb17df1e14eb7fdf4b3ea0ea597bd292cbc75712e71c6cc8af2f3ed` |
| TASKHOST.EXE-3AE259FC.pf | 26 | 4 | `00178686d5e755e596ee164e78473eab3aba382541d0f67f93654ef84d4ed36b` |
| NOTEPAD.EXE-D8414F97.pf | 30 | 2 | `2eb257a375eda819c65e6b4e60dfb7b9c6691280e8cb40cec30d3e46ac96a50f` |
| ONEDRIVE.EXE-7E152375.pf | 30 | 2 | `e9a5db11b673ba592a794a2bfeaa2aba95814d3004c32a76e4dc668789fa2424` |
| AM_DELTA_PATCH_1.443.990.0.EX-7037CF86.pf | 31 | 1 | `9a5ad5a3c56ec67fb2f785e1f75366a642a2ea552694f5016cc8191cf3f49861` |

The binding does not expose standalone Prefetch directory tables. Original file
bytes, referenced filenames, metrics, and volume metadata remain available; the
limitation is explicitly warned. SAM, SECURITY, and USRCLASS structural recognition
is implemented but was not validated against real examples in this run. No claim
of complete format/corruption coverage is made.

### Disk-backed MFT benchmark

Generated 100,000 synthetic 1,024-byte records (102,400,000 source bytes) with unique
filenames and valid parent linkage. Full ingestion through the resource-limited
worker, staging, path reconstruction, and publication took **68.55 seconds**:
100,000 inserted, zero errors, unchanged source hash. SQLite size was approximately
746 MB, including raw records, 800,000 timestamp observations, provenance and indexes.
This explicit retention incurs storage amplification.

- Exact basename search: about 74 ms, one matching record.
- Full path with explicit volume context: about 397 ms, one matching record.
- Populated timeline: about 663 ms, 20 returned out of 800,000 timestamp observations.
- Bounded cross-artifact lookup: about 0.91 ms, no other-source candidates in this
  MFT-only dataset; this is not a positive-match throughput measurement.
- `EXPLAIN QUERY PLAN` confirmed covering `object_basename` and `artifact_time`
  indexes for the corresponding candidate lookups. Routine hydration is bounded;
  exact count operations may still scan matching SQLite rows.

An initial timeline benchmark window missed the fixture's June 5 timestamps;
the populated measurement above reran the query using actual database bounds.
No million-record or peak-memory measurement is claimed. Native workers run under
the 2 GiB OS limit; limits and synthetic measurements do not prove all inputs safe.

### Local model and installation checks

Live checks used synthetic evidence only and the existing loopback llama.cpp server.
Timeline analysis returned structurally valid, supplied-ID citations in about 11.36
seconds. Its 5,390-byte prompt selected EVTX and Prefetch from 13 candidate records;
MFT and Registry were explicitly listed as omitted classes. The broad `ask` attempt
exceeded the 1,024-token output limit and was withheld, not accepted as an incomplete
answer. Citation validation does not establish semantic correctness.

A narrower ask attempt that invented an ID in prose was also withheld. Requesting
one short finding with IDs only in the citation array then succeeded in 3.24 seconds
with a 5,479-byte prompt and EVTX/Prefetch evidence. It still described execution
"via Prefetch," which is imprecise: Prefetch records execution, it is not a launch
mechanism. This illustrates the need for analyst review even after citations pass.
Neither the prompt/output budget nor validation rules were weakened for these tests.

Editable installation built `locard-forensics` 0.3.0 successfully. The first
no-build-isolation attempt found no local setuptools backend; the standard isolated
build succeeded after network permission to obtain the build dependency. Runtime
parsing/retrieval does not use Internet services. The original workspace V0 database
was not migrated or populated by validation.

`pip check` reported no broken requirements and the installed entry point reports
`Locard V2 (0.3.0)`. Git ignore checks exclude EVTX, Prefetch, offline SYSTEM,
SQLite, credentials, weights, and caches even under the new adapter directory.
The existing tracked project image is unchanged. New eligible files are Python
source/tests; downloaded samples, scratch scripts, databases, and model outputs
are outside the repository. No V2 commit or push was performed.

## V1 validation (package 0.2.0, schema 2)

The V0 baseline was rerun before implementation: **57 passed**. Its first attempt
encountered an existing Windows temporary-directory ACL error. Using a fresh test
directory under workspace `work/` resolved this without modifying application code.

The full V0 + V1 suite was run after every major implementation stage:

| V1 stage | Full-suite result |
|---|---|
| Additive migration and derived context | 61 passed |
| Filtered timeline and temporal context | 63 passed |
| Process/session correlation | 70 passed |
| Eight dynamic detection rules | 80 passed |
| Investigation assembly | 84 passed |
| Prioritized bundles, planner, timeline analysis | 89 passed |
| Acceptance, precision, and uncertainty checks | **105 passed** |

Final full suite: 105 passed in approximately 1.7 seconds. `pip check` reported no
broken requirements. The CLI reports `Locard V1 (0.2.0)`. Original V0 tests remain
unchanged; the additional 48 cases cover migration preservation/rollback, provider
and role extraction, timeline boundaries, same-host temporal scope, PID reuse,
missing parents, GUID relationships, cycles, Logon ID collisions/reuse, session
boundaries, every initial rule, duplicate exported observations, lexical match
boundaries, bounded investigation assembly, all investigation JSON commands,
malicious evidence text, bundle priorities/omissions, and mocked model responses.

Migration tests compare every original event column before and after migration,
verify that the backup retains schema version 1, verify idempotence, and inject a
failure to confirm transactional rollback. V1 never automatically migrated the
workspace's original V0 database. These tests exercise internal schema helpers.

### V1 integration and performance checks

- Re-ingested the public `security.evtx` fixture identified below using V1: 2,261
  event rows and 2,261 context rows, zero errors, and identical source SHA-256 before
  and after ingestion. Public fixture files remained outside the project repository.
- Populated an in-memory database with 10,000 synthetic process records. An 11-record
  bounded timeline query took about 0.44 ms; assembling its deterministic context
  took about 13 ms in this environment. These are smoke measurements, not general
  throughput guarantees or disk-backed performance benchmarks.
- `EXPLAIN QUERY PLAN` tests verify use of the compound PID, process-GUID, and
  target-Logon-ID indexes. Candidate and graph limits are explicit in results.
- Both `ask` and `analyze-timeline` were exercised against the existing local
  MiniCPM5-2B-Q4_K_M server with an 8192-token context. Only two synthetic process
  events were supplied. Both returned structured, cited analysis passing local
  validation; no normal unit test depends on that server.
- Final checks preserve nine-digit timestamp ordering for closest-neighbor selection
  and reject competing equal-time session boundaries rather than inventing ordering.

The live model sometimes phrases a LIKELY process relationship too categorically.
V1 attaches deterministic supporting relationship statuses after response validation
and prefixes CORRELATED timeline prose supported by LIKELY links with a LIKELY label.
This preserves visible uncertainty; it does not prove the model's broader prose or
classification is correct. Analyst validation remains mandatory.

No evidence, database, model files, public binary fixtures, temporary benchmarks,
or live-model outputs were added to the source tree. There are no added runtime
dependencies, external lookups, executable evidence paths, or persisted detections.

## Historical V0 validation

Implementation followed five stages, with the complete unit suite run at each stage:

| Stage | Result |
|---|---|
| Foundation: model, schema, IDs, timestamps, transactions | 4 passed |
| EVTX parsing, normalization, staged ingestion, provenance | 25 passed |
| Deterministic queries and CLI | 29 passed |
| Planner, evidence bundle, local client, citation checks | 55 passed |
| Integration fixes and final regression suite | 57 passed |

Final `pip check`: no broken requirements. The default database was initialized and
the `status` command reported zero events and zero ingestion runs; fixture/test data
was kept out of the deliverable database.

Tests use representative XML and mocked HTTP responses. No unit test requires a
running model or Internet access. Tests explicitly verify that duplicate ingestion
does not overwrite `events.source_file` and that `source_locations` retains both
observed paths for identical files.

## Real EVTX parser integration

Public fixtures were downloaded from the parser's upstream repository into the
development scratch directory, not the application's evidence database:

- [security.evtx](https://github.com/williballenthin/python-evtx/blob/master/tests/data/security.evtx)
  - SHA-256: `5f29a03cf8c1b4bfbd82c4074ccc81ecfe85d7ee15375afc352ed5025c9a4d8d`
  - 2,261 records inserted, zero ingestion errors, all 2,261 UTC timestamps normalized.
  - Re-ingestion: zero new records and 2,261 duplicates.
- [dns_log_malformed.evtx](https://github.com/williballenthin/python-evtx/blob/master/tests/data/dns_log_malformed.evtx)
  - SHA-256: `56884d5665a02dd4f26de67eabfad751843eff06f3fdeee7ea57a9911baa090b`
  - One readable event preserved with normalized UTC time; status `partial`.
  - Five reported errors: one XML/binary record-number discrepancy and four parser
    Unicode decoding failures. Source filenames and available offsets/record numbers
    were recorded in the error table.

The real fixture check revealed that python-evtx emits timestamp strings with a
space separator. Support and a regression assertion were added. Original parser
timestamp text remains unchanged in the stored record.

## Live MiniCPM integration

The existing server at `http://127.0.0.1:8080` reported
`models\MiniCPM5-2B-Q4_K_M.gguf`, an 8192-token context, and the expected local API.
A synthetic Security 4688 fixture was normalized and retrieved for a PowerShell
question. The model returned structured analysis with the exact supplied evidence ID,
which passed local validation. No investigator evidence was sent to this test.
The final live response also made an overconfident environment inference from test
labels and offered a weak "false positive" alternative for an audit record. These
illustrate why passing citation validation is not semantic validation or a guarantee
of sound forensic interpretation.

Initial live attempts exposed an exhausted generation budget and citation drift.
The client now disables thinking using the model's supported template option and
constrains structured citation values to supplied IDs using JSON Schema, while
retaining independent response validation. A rejected answer is never promoted to
evidence. The test establishes API interoperability, not general analytical accuracy.

## Limits of verification

The public samples are not representative of every Windows build, event provider,
corruption mode, audit policy, or real investigation. MiniCPM can produce shallow or
incorrect interpretations even with valid citations. Analyst validation is mandatory.
The synthetic reporting benchmarks in [V5](V5.md) cover only those generated
workloads. No forensic certification, real-case performance guarantee, or complete
attack-detection coverage is claimed. External dependency downloads were setup-only; application
analysis uses loopback HTTP and local SQLite.

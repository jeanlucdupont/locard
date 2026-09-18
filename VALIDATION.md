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
workspace's original V0 database; the explicit migration command is documented.

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
No performance benchmark, forensic certification, or complete attack-detection
coverage is claimed. External dependency downloads were setup-only; application
analysis uses loopback HTTP and local SQLite.

# Locard — project handover for a successor LLM

Prepared on 2026-10-25 against commit
`74d595ca106b670ddaa241822c51c27355a9d394` (`MFT optimization`).
This is a dated orientation document, not a substitute for inspecting the current
checkout. Later user instructions take precedence. Do not automatically execute
the historical work described here.

## 1. Start here

Locard is a Windows-first digital-forensics CLI and interactive shell. It ingests
supported artifacts into a local SQLite case, preserves evidence identity and
provenance, supports deterministic investigation, and optionally uses AI to guide
bounded evidence inspection. AI output is not evidence.

Read these documents alongside the code:

- [User guide and command/options reference](USER_GUIDE.md).
- [Python file map](PYTHON_FILE_MAP.md): descriptions of 184 application and
  maintenance Python files, excluding tests and POC scripts.
- [README](../README.md): installation, supported behavior and operational notes.
- [Validation notes](../VALIDATION.md): historical validation and acceptance notes;
  not proof that the current tree has passed every check.
- [Project metadata](../pyproject.toml), [license](../LICENSE), and
  [third-party notices](../THIRD_PARTY_NOTICES.md).

The documentation can lag behind intentional manual changes. Confirm actual
behavior in the parser, dispatcher, implementation and relevant tests.

## 2. Repository state at handover

| Item | Observed state |
| --- | --- |
| Branch | `main` |
| HEAD | `74d595ca106b670ddaa241822c51c27355a9d394` |
| Stored `origin/main` | Same hash as HEAD; no fetch performed for this document |
| Application version | `6.70` in `pyproject.toml` |
| Python requirement | Python 3.11 or later |
| Distribution / entry point | `locard-forensics` / `forensic_assistant.cli:main` |
| License | Apache-2.0 |
| Uncommitted work | `.gitignore` documentation allowances and new documentation files |

The uncommitted documentation consists of `docs/USER_GUIDE.md`,
`docs/PYTHON_FILE_MAP.md`, and this file. Preserve it. No production code was
changed while preparing these documents. No release validation or new benchmark
was performed for this handover, and nothing was committed or pushed.

Recent commits, newest first:

```text
74d595c MFT optimization
a445338 Native MFT file management no timeout
270f706 Native MFT file management 3
bf95286 Native MFT file management 2
04bea58 Native MFT file management
```

Commit titles alone do not define runtime behavior. In particular, do not infer
that parser timeouts are disabled from a commit title.

## 3. Working environment and checkout discipline

The documentation was written in:

```text
C:\Users\jl-du\Documents\Codex\2026-09-16\we-x20\outputs\locard
```

The user also runs an installation from:

```text
C:\tmp\locard260927\locard
```

These paths are not interchangeable. Check the working directory, interpreter,
installed package location and Git state before diagnosing a discrepancy between
edited source and a live session. Do not assume that changing one checkout updates
the other's non-editable installation.

Useful read-only preflight commands in the selected checkout:

```powershell
Get-Location
git status --short
git branch --show-current
git rev-parse HEAD
git log -5 --oneline
git diff --stat
Get-Content pyproject.toml
.\.venv\Scripts\python.exe -c "import forensic_assistant; from importlib.metadata import version; print(forensic_assistant.__file__); print(version('locard-forensics'))"
```

Inspect any applicable repository instructions before editing. No root
`AGENTS.md` was found during this documentation task; recheck in a future session.
Do not alter `.git` permissions. Do not discard or overwrite user modifications.
The repository is public: review staged content for private data before any commit
and especially before a separately authorized push.

## 4. Development and acceptance rules

The user's standing testing workflow is:

1. During implementation, run focused tests relevant to the changed subsystem.
2. Run the smallest useful regressions after meaningful changes and
   `git diff --check`.
3. Do not run the complete suite during implementation. Stop when ready for
   manual acceptance.
4. After manual acceptance, run expanded relevant tests if necessary, then the
   complete regression suite exactly once, protected-evidence verification and
   `git diff --check`.
5. Create a release commit only after final validation and within the current
   task's authorization. Never push without explicit permission.

A failed full run does not authorize repeated full runs. Report the failure and
review it first. Earlier Windows runs exhausted virtual memory. Before a full
run, inspect memory and stale Locard/pytest/local-LLM workers. Do not terminate
unrelated applications, change page-file settings or run a local model alongside
resource-sensitive validation without agreement.

Normal test invocation uses the project interpreter, without parallel pytest:

```powershell
# Example focused tests; choose only those relevant to the actual change.
.\.venv\Scripts\python.exe -m pytest tests/test_completion_summary.py -q
git diff --check

# Only after acceptance and authorization for final validation:
.\.venv\Scripts\python.exe -m pytest -q
```

Tests are regression controls, not automatically authoritative specifications.
The user frequently intentionally edits presentation. Preserve approved wording,
colors, banners, separators and layout. Update stale presentation assertions;
never weaken assertions protecting evidence IDs, parser semantics, counters,
JSON contracts, provenance, authorization, persistence or audit behavior.
Classify failures before changing either code or tests.

## 5. Versioning, packaging and dependencies

`pyproject.toml` is the single source of truth for the application version.
Versions use `MAJOR.RELEASE`, such as `6.70`, not mandatory three-part SemVer.
Runtime version lookup uses installed package metadata; `__init__.py` already
does this. Do not duplicate the current version in implementation or tests.
Historical/fake version fixtures may remain where they actually test compatibility.

Normal users use `install.ps1` and `locard.ps1`; developers may use:

```powershell
.\.venv\Scripts\python.exe -m pip install -e .
```

Installation changes the environment; do not run it merely to inspect the repo.
Use it when needed to refresh editable metadata or satisfy the user's task.
Preserve normal non-editable installation and packaged schema/resources.

Core dependencies include python-evtx, defusedxml, dissect NTFS components,
libscca and libregf. Exact pins are in `pyproject.toml`. Optional extras are
`test`, `semantic` and `cloud`. Deterministic capabilities must work without
semantic/model dependencies. Do not install/download models or enable cloud
access implicitly. Evaluate dependency changes against Apache-2.0 and preserve
third-party license texts.

## 6. Architecture and navigation

| Area | Responsibilities / first files to inspect |
| --- | --- |
| Command surface | `cli.py`, `cli_parser.py`, `command_catalog.py`, `v1_cli.py`, `v2_cli.py`, `source_cli.py`, `dump_cli.py` |
| Interactive UI | `interactive/shell.py`, `setup.py`, `creation.py`, `discovery.py`, `setup_display.py`, `completion.py` |
| Shared presentation | `terminal.py`, `terminal_activity.py`, `output.py`, `retrieval/*_display.py` |
| EVTX | `ingest/service.py`, `evtx.py`, `evtx_worker.py`, `evtx_recovery.py`, `evtx_arrays.py`, `normalize.py`, `sysmon.py` |
| Other artifacts | `artifacts/ingest.py`, `worker.py`, `mft.py`, `prefetch.py`, `registry.py`, `browser.py` |
| Native MFT | `artifacts/native_mft.py`, `ntfs_acquisition.py`, `mft_stage.py` |
| Database | `database/db.py`, `schema.sql`, `artifacts.py`, `sources.py`, `browser.py`, `context.py` |
| Deterministic analysis | `retrieval/`, `correlation/`, `detections/` |
| Semantic retrieval | `semantic/`: local embeddings, derived indexes and retrieval |
| AI transport/runtime | `ai/`: providers, capabilities, schema adapters, readiness, runtime, diagnostics |
| Advisory | `interactive/advisory.py`, `ai_context.py`, `ai_routing.py`, `advisory_display.py` |
| Bounded investigation | `investigation_ai/`: contracts, controller, tools, workers, snapshots, supervision, transcripts |
| Reports | `reporting/`: collection, claims, grounding, redaction, HTML/JSON, publication |
| Protected-file manifests | `scripts/protected_manifest.py` |

All package paths above are relative to `forensic_assistant/`, except the
maintenance script. Historical module names do not imply dead code. Do not merge
`v1_cli.py`/`v2_cli.py` into `cli.py` just for naming consistency.

Typical flow: command parsing → guided or scripted ingestion → hashing and
provenance → bounded parser/private stage → validated publication into SQLite →
deterministic query/display → optional AI assistance or derived report/export.
Reuse existing implementations rather than duplicating parsing or publication.

## 7. Evidence and safety invariants

- Never modify source evidence, mounted evidence permissions or original case
  data for diagnostics. Use authorized accessible copies and read-only access.
- Evidence IDs, hashes, original values, normalization status and source paths
  must remain stable unless an explicitly approved change requires otherwise.
- `events.source_file` records the ingestion source path that created the event;
  `source_locations` is authoritative for all observed paths of identical files.
- Sources and ingestion runs are explicit provenance concepts. Do not merge
  sources by hostname, path, name or other heuristic. Legacy non-interactive
  ingestion without `--source` creates a fresh, marked automatic source; explicit
  reuse requires its source ID.
- Browser context cannot be recovered safely from hash membership alone.
  `browser_contexts` represents profile/browser/snapshot context;
  `browser_record_occurrences` relates records to context and ingestion run.
  Identical History bytes can have distinct contextual provenance.
- Current initialization sets schema 5. Inspect the complete initialization path:
  the base SQL file alone contains an earlier version pragma and is not the whole
  effective schema. Do not add migrations implicitly. `case-upgrade` was removed
  at the user's request; do not resurrect it as incidental cleanup.
- Keep analyst UI state and derived indexes/transcripts/reports separate from
  evidence. No persistent case-name entity or evidence mutation from selection.
- Partial or cancelled ingestion must not imply already committed evidence was
  rolled back. Incomplete evidence must never be presented as complete.
- Preserve worker containment, memory/stage/free-space limits, cancellation,
  descendant cleanup and publication gating. Report cleanup limitations honestly.
- Escape attacker-controlled content for terminal/HTML output. Never execute
  evidence content or accept model-provided paths/commands as authorization.
- MFT presence/timestamps do not prove execution; temporal proximity and semantic
  similarity are not forensic correlations or proof of causation.

## 8. AI and reporting boundaries

Locard is local-first, but optional configured cloud providers exist. Do not
describe every mode as offline. Consult the current consent/exposure code before
sending any case context externally. Keep secrets, raw responses and evidence
out of ordinary logs. Provider structural acceptance is not grounding acceptance.

The interactive `!` entry routes advisory and bounded investigation behavior;
deterministic case inventory remains model-free. Do not reintroduce duplicate
public commands based on old documentation. Hidden compatibility commands may
still exist: see the current parser and user guide.

Investigations retain a strict read-only opener, SQLite authorizer, bounded worker,
tool allowlist, structured model contract, analyst approval, exposure tracking,
budgets, novelty/rejection controls and evidence-grounded final validation.
Observed facts and deterministic relationships are rendered by Locard from
validated structures, not accepted as unrestricted model prose.

The accepted consistency design uses a private SQLite-consistent temporary
snapshot, including WAL state, for tools; retains the original fingerprint; and
checks the live case at completion. Do not silently mix changed live data with
snapshot results. Preserve snapshot cleanup and `CLEANUP_LIMITATION` reporting.

Reports are derived, claim-centric output. Preserve claim categories, claim/evidence
relationships, historical transcript compatibility, report-time grounding,
output-only redaction, offline HTML, JSON, manifests/checksums and atomic publication.
Integrity, structure, case compatibility and evidence grounding are distinct checks.
Successful validation does not prove forensic conclusions. A report from explicit
evidence IDs must disclose that bounded scope and must not imply a complete
investigation or a negative finding outside the supplied evidence set.

## 9. Current 6.70 work: ingestion and MFT performance

These changes are already present; inspect rather than restarting them.

### Presentation and EVTX

Normal interactive ingestion uses the compact progress line with an in-place
spinner. Slow artifacts must not automatically expose worker internals. Detailed
observability is retained internally. Discovery is quiet until its normal summary.
At family completion, failures/partial recovery/verification limitations should
remain clear and file-level completeness must not be lost in aggregation.

EVTX has a supervised parser boundary. `ingest/evtx_worker.py` distinguishes a
300-second lack-of-forensic-progress threshold from a six-hour hard ceiling.
An alive but stalled worker is not healthy progress. Preserve partial records,
incomplete accounting and cleanup. Do not generalize this policy to MFT or other
parsers without explicit authorization.

### MFT staging and completion

Prior phases addressed private-stage size and logical ordering, including
query-index omissions and the timestamp-table WITHOUT ROWID work. Keep private
stage layout separate from the final case schema. Phase 2A removed semantic
dependence on physical row order: logical ordering, timestamp slots and
fingerprints must stay deterministic. Timestamp selection retains its bounded
32-observation behavior with binary slot ordering.

The latest commit adds `artifacts/mft_stage.py` and worker integration:

- Only timestamp/object inserts in the explicit allowlist are buffered.
- Bounds are 2,000 rows and a conservative 4 MiB value-size estimate.
- Dependency-sensitive writes remain immediate.
- Completed parser outcomes commit every 20,000 entries, including duplicates
  and errors. Cancellation can discard more uncommitted private work than before.
- Flush/write failure prevents continued use of the stage writer; no failed stage
  is published. Do not replay an `executemany` prefix after a failure.
- Final record-tail work and reconstruction retain their final transaction.

The same commit extracts/reuses `database.artifacts.artifact_counts` in
`interactive.creation` and the status path. Guided completion needs artifact
counts, not the expensive full status calculation. Full status functionality
remains for callers that need timeline, source coverage and hosts.

The guided MFT manual-test override currently consumes
`LOCARD_GUIDED_MFT_PARSER_TIMEOUT` in `interactive/setup.py`. Its accepted value
is `3600`; absent means 300. It is popped from the process environment and applies
to MFT in that guided ingestion invocation, not all artifact families. This is
not a general timeout redesign. Recheck exact scope before advising a user.

The 8 GiB stage cap remains in `artifacts/ingest.py`. Do not raise it, change
PRAGMAs, remove evidence, alter path reconstruction or widen transaction changes
as an incidental performance fix.

### Historical measurements, not freshly verified results

The user supplied a successful real-case MFT ingestion of roughly 715,426 records
and approximately 29 minutes. A prior full-status measurement was 67.20 seconds:
48.76 timeline, 16.44 source coverage, 1.78 host query. These motivated the
artifact-count-only completion path. Do not claim those numbers are new benchmark
results or that the current patch has an unrecorded speedup.

Earlier staging work used a roughly 736 MB MFT and a Phase 1 stage baseline of
5,081,116,672 bytes. A later extended-timeout diagnostic reportedly completed
staging/reconstruction in about 19 minutes under the unchanged cap. Locate actual
measurement artifacts before quoting exact final sizes or timing comparisons.

Relevant focused tests include:

```text
tests/test_completion_summary.py
tests/test_mft_stage_batching.py
tests/test_mft_stage_indexes.py
tests/test_semantic_logical_order.py
tests/test_native_mft_ingest.py
tests/test_guided_mft_timeout.py
tests/test_v2_mft.py
tests/test_evtx_worker.py
tests/test_guided_setup.py
tests/test_case_creation.py
```

Do not run all of these automatically for a documentation change. There is no
newly established full-suite count or release-acceptance result in this handover.

## 10. Protected data and diagnostic locations

Historical user-provided locations include `C:\tmp\$MFT`, `C:\tmp\12`, and
`C:\tmp\locard-evtx-test`. They contain real-case material or diagnostic copies,
not synthetic fixtures. Do not assume they remain readable, consistent or current.
Do not open, modify, publish or hash large datasets merely to orient yourself.
Access only what a concrete authorized task requires; avoid printing sensitive
records. The mounted source volume used during prior work was `E:`.

The SHA-256 utility accepts explicit selected files and refuses unsafe redirected
paths. After authorized final validation, use an existing known baseline, e.g.:

```powershell
# Substitute verified paths; do not invent or overwrite a baseline.
.\.venv\Scripts\python.exe scripts/protected_manifest.py verify --root '<protected-root>' --manifest '<existing-manifest.json>'
```

Report files checked, unreadable/excluded files and differences separately.
A new manifest establishes a baseline for future comparisons. No pre-6.67
cryptographic baseline existed, so current hashes cannot prove historical
byte-for-byte integrity. Verification covers listed files, not all unlisted data.

`.gitignore` deliberately denies new top-level content by default. Add narrow
exceptions for intended source/docs only. Never commit case databases, WAL files,
EVTX/MFT samples, model weights, raw AI captures, credentials or staging output.
Ignored `.tmp-mft-poc` content may contain useful diagnostics, but is neither a
portable dependency nor authoritative project history.

## 11. How to continue safely

1. Read the latest user request; do not infer permission to continue an old phase.
2. Inspect current Git state and preserve existing work. Fetch only when needed;
   distinguish cached tracking refs from a fresh remote check.
3. Confirm the source checkout/interpreter actually used by the user's launcher.
4. Read the narrow implementation and relevant tests before proposing changes.
5. State which observed facts support the diagnosis; distinguish measurements,
   user reports, hypotheses and unverified claims.
6. Make the smallest authorized change. Preserve intentional UX and protected
   forensic/security contracts.
7. Run focused validation and diff checks, then stop for manual acceptance.
8. Report changed files, exact test outcomes, limitations and remaining work.
   Do not fabricate prior test results or claim acceptance from a commit alone.

At this handover there is no automatically authorized next implementation phase.
The immediate request was documentation for a successor LLM. Keep the new
documentation available for review; do not commit or push it without authorization.

# Locard 6.135 — deterministic recorded-investigation reporting

Implementation date: 2026-11-13. Development baseline: `edc7f759933df639cbd507cd377988ec2b4b7830` (6.134). Only `pyproject.toml` declares application version 6.135; installed runtime metadata must be refreshed by installing the checkout. No live provider or real case database was used. New reporting tests use disposable synthetic data. Existing findings regressions also validate available read-only historical copies under `C:\tmp\locard-diagnostics`, comparing their SHA-256 hashes before/after and creating review workspaces only in disposable test directories. No original/copy transcript or existing analyst workspace was modified.

## Architecture and application services

The new path is separate from legacy reporting:

```text
recorded_source.Source
  -> validated history + optional read-only workspace snapshot
  -> B1 original-field restoration and recorded C1/D1 reconstruction
  -> recorded.build: frozen recorded-investigation-report-v1
  -> recorded_view.view: common deterministic blocks
  -> recorded_view.render: escaped offline HTML
  -> recorded.publish: guarded staging, complete writes, input recheck, no-overwrite rename
```

Modules under `forensic_assistant/reporting/`:

| Module | Responsibility |
|---|---|
| `recorded_source.py` | Narrow facade over existing D2 history, B1 restoration, findings and organization/explanation contracts |
| `recorded_model.py` | Closed projection envelope, bounds, canonical digest and internal-consistency validation |
| `recorded_view.py` | Common blocks and executive/technical/handover selection; inert HTML |
| `recorded.py` | Build, inspection/revalidation, publication and small command adapter |

Public application calls, independent of CLI parsing:

```python
from forensic_assistant.reporting import recorded

projection = recorded.build(root, run_id, workspace=None, report_type="technical")
recorded.validate_projection(projection)  # structure/internal consistency, not source replay
blocks = recorded.render_view(projection)
html_bytes = recorded.render_html(projection)
result = recorded.publish(root, run_id, fresh_directory, workspace=None,
                          report_type="technical", protected_roots=())
inspection = recorded.inspect(bundle_directory)
validation = recorded.revalidate(bundle_directory, root, run_id, workspace=None)
```

`publish` builds from original recorded inputs itself; it does not accept a caller-supplied JSON projection as evidence authority. `generation=` can freeze the complete generation envelope for reproducible rendering. It contains `generated_utc`, `validation_utc`, `application_version` and `renderer_version`.

Existing services reused: `d2.open_history`, `packets._validate_context/_rehydrate`, findings `_connection/_load/_validate_candidate`, `organization.reconstruct`, explanation session/page contracts, `model.canonical/digest/loads`, and `storage.local_path/DirectoryGuard`. Private authority helpers are confined to the source facade or projection's explicit contract validation, not used independently by HTML templates.

Legacy `reporting.transcripts.load`, `collect.build` and `bundle.generate` are unchanged. Their incremental-import restrictions and live-case/fingerprint behavior remain separate. The recorded CLI dispatch bypasses active-case activity attachment and generic output redirection. It does not create an activity sidecar or initialize a report AI narrative.

## Projection and authority

`recorded-investigation-report-v1` contains four top-level fields:

- `contract`: exact version identifier.
- `content`: frozen semantic inputs and presentation policy.
- `content_digest`: canonical SHA-256 of `content`.
- `generation`: separately hashed variable metadata.

Content includes report type, source run/manifest/event head, recorded view, engine, accepted frontiers, original question and S3 assessment, full S1/S2 results, restored supports and clause-to-support mappings, recorded C1/D1 state/pages, historical model proposals, optional workspace snapshot, execution diagnostics, validation classifications, policy and caution.

Original S3 is recomputed with the existing registered rules and preserved exactly. It is never replaced by analyst decisions or model hypotheses. S1 observations and registered interpretations retain their original identities, values, premises, lineage, timestamp semantics and qualifications. S2 is checked against the registered deterministic builder. Temporal coordinates are not promoted to physical event order or causality.

Support keys hash the complete restored leaf plus recorded view. This preserves evidence identity, pointer/value representation, source/provenance identity, disclosure lineage, truncation context and view. Equal displayed values from different records or disclosures do not unify. The unit map preserves interpretation support and mandatory qualifications. Finding-support bundles retain the existing contradiction/relationship closure and exact original references.

Independent finding dimensions remain intact:

| Dimension | Meaning |
|---|---|
| Origin | Original-observation reference, deterministic interpretation/relationship reference, AI proposal or analyst hypothesis |
| Review state | Proposed, accepted, rejected or superseded |
| Analyst classification | Existing analyst-reviewed conclusion designation where applicable |
| Assertion authority | Original candidate's explicit unverified-text/inference boundary |
| Source validation | Validated against the recorded history; not today's case |
| Support/contrary scope | Exact retained original references and qualifications |

An accepted AI proposal remains an unverified AI-origin inference reviewed by an analyst. Valid citations do not certify entailment. Actor strings are locally asserted, not authenticated identities. No confidence scores, business impact, execution results, owners or due dates are fabricated.

## Workspace snapshot and source stability

The facade reads `findings.sqlite3` through the existing read-only URI/query-only transaction. It validates metadata, event chain and state transitions, matches source/run/view, and revalidates every distinct candidate with the existing findings validator. Identical candidates share validation only within this build; there is no persistent cache.

The report captures the exact workspace UUID, revision, head, candidates and decision history. The source and entire workspace snapshot are checked again after reconstruction and immediately before publication. Mutation aborts publication; a newer revision cannot silently replace the selected one. Later source revalidation requires exact equality with the frozen projection, including the original workspace revision.

Unavailability, malformed storage, bad chains, mismatched views, incomplete original dependencies and oversized projections fail closed. There is no degraded administrative mode. Valid empty workspaces and zero-analysis histories produce explicit empty state, not a negative forensic conclusion.

## Views, coverage and omissions

All views use the same projection. Findings are ordered by creation revision, then identity; no model ranking is used.

- **Executive:** active accepted findings, original S3 boundary, recorded observations, uncertainty, alternatives, questions and proposed examinations. Rejected/superseded/proposed findings do not become active conclusions. An absence of accepted findings is explicit.
- **Technical:** full original S3, qualified observations and relationships, exact evidence appendix, original/contrary support, source/disclosure lineage and analyst history.
- **Handover:** all review states, decisions and supersession links, source/workspace identities, execution status, unresolved questions and unexecuted recommendations.

All views include a bounded original-support appendix so shortened main sections do not discard original values or qualifications. Large investigations can consequently produce long executive appendices. There is no new model-authored executive summary.

All admitted D1 pages are consumed, including omission counters and the 192-statement admission boundary. `assembly_exhausted` means completion of the admitted prefix, not forensic completeness. Recorded C1 processing stops, finalization and current/historical relationship coverage remain visible. Earlier histories without a recorded organization profile do not receive newly invented, wall-clock-dependent retrospective organization. Their existing S1/S2/S3 and recorded model proposals remain available.

Recorded termination, analysis coverage and controller cleanup diagnostics are presented as recorded observations. They do not independently prove parent-process cleanup. Proposed examinations remain unexecuted/availability unknown as supplied by the existing contract.

## HTML, privacy and PDF readiness

HTML uses fixed application-owned blocks/CSS, escaped text and restrictive CSP. There is no JavaScript, remote asset, image, active evidence URL, `file:` link or executable model content. Internal section IDs are numeric and application-controlled. Long text wraps; essential evidence and limitations are visible rather than hidden in collapsed widgets.

No display clipping is performed. Original truncation remains recorded metadata, not a rendering transformation. Text, tree, artifact and bundle bounds fail explicitly instead of dropping required qualifications. Unsupported typed values remain bounded structured text; no binary execution or implicit decoding is introduced.

Original evidence paths remain forensic values. Workspace storage paths and raw capture capsules are retained in **projection.json's audit data**, not rendered as navigation or workspace-location headings. Treat the whole bundle as sensitive. The only supported initial redaction policy is `none`; unsupported policies are rejected rather than partially applied.

The common blocks and semantic projection are independent of HTML. Print CSS supports wrapping and section headings without hiding evidence. PDF conversion, page numbering, running headers and engine-specific pagination are deferred and require visual acceptance.

## Determinism and bundle format

Files:

| File | Contents |
|---|---|
| `projection.json` | Canonical frozen content, content digest and generation envelope |
| `report.html` | Exact deterministic HTML for that projection/envelope |
| `manifest.json` | Bundle contract, semantic digest, generation-envelope digest and exact file hashes |

Canonical serialization uses sorted keys, compact separators, ASCII JSON escapes and nonfinite-number rejection. Limits count serialized UTF-8 bytes, not characters. Unicode HTML is emitted as UTF-8.

Equivalent frozen semantic inputs/policy produce the same content digest. Generation-time changes affect the envelope/HTML hashes but not the semantic digest. A fully fixed envelope produces identical HTML bytes. Changed decisions, support, qualifications, recorded identities or policies change content identity. The stored workspace metadata participates in the exact audit-chain representation; changing that metadata is not equivalent input even if display text matches.

`inspect` checks file hashes, strict JSON parsing, projection consistency, envelope digest and exact HTML rerendering. It reports source binding and grounding as `NOT_CHECKED`. `revalidate` additionally rebuilds from supplied recorded inputs and requires exact projection equality. Hashes are consistency checks, not authentication, semantic truth or current-case validation.

## Publication and filesystem guarantees

Destinations must be fresh local directories under existing parents. Redirects/reparse paths, traversal, ambiguous Windows names, reserved device names, known source containers, `.findings`/`.investigations`/`.briefing` trees and ancestors containing case/workspace/manifest files are rejected. Case/source locations recorded in the selected manifest/retained records are protected without opening those files. `--protect-root` adds explicitly known evidence containers.

A recorded history cannot identify every unrelated evidence directory on the computer. Choose a dedicated report-output directory and supply `--protect-root` for evidence locations not represented in the selected history. This is not a global filesystem classification service.

Directory guards pin Windows ancestors without ACL changes. Files are written exclusively into an owned sibling staging directory, checked for complete writes, flushed/synced and inspected before source rechecks and publication. Windows rename is no-overwrite. On non-Windows, publication requires `renameat2(RENAME_NOREPLACE)`; platforms without it fail rather than use a replacing fallback. Cancellation/failure cleans only owned staging; uncertain publication or cleanup is reported explicitly. No existing destination is overwritten.

The final source check is immediately before publication; this does not claim a filesystem-wide atomic transaction spanning independently mutable source files. The bundle records the validated frozen revision and later revalidation detects mismatches.

## Resource limits and measured performance

Existing transcript, S1/S2, B1 and workspace admissions remain unchanged. Reporting additionally bounds:

- Projection: 32 MiB; HTML: 32 MiB; complete bundle: 64 MiB.
- One history and at most one workspace.
- 4,096 restored report-local supports, 16,384 rendering blocks.
- 400,000 JSON tree nodes, depth 32, 256 KiB per text value.
- Existing B1 restoration budget: 512 resolutions and five-second planning checks.

Measured on disposable synthetic inputs with Python allocation tracing enabled (development environment; not a performance guarantee):

| Case | Workspace event bytes | Build + payload seconds | Peak traced Python allocations | Result |
|---|---:|---:|---:|---|
| Small | 0 | 10.157 | 7,621,645 bytes | Projection 483,889 B; HTML 306,690 B |
| Moderate, 24 proposals | 53,895 | 10.661 | 7,594,621 bytes | Projection 593,541 B; HTML 426,452 B |
| Near workspace admission limit | 32,519,160 | 12.951 | 110,700,013 bytes | Explicit projection-limit rejection; no output |

These measure Python allocations, not native SQLite allocations or total process RSS. Generation timings include source reconstruction and rendering for successful cases. A valid maximum-sized findings store is not guaranteed to fit a report: full decision history and dependencies can exceed projection ceilings. No silent scope reduction occurs. The 60-second target is **not an enforced deadline**; blocking reads and filesystem publication are not supervised by a new watchdog. No persistent cache was introduced.

## Validation record

Provider-free functional, mutation, safety and compatibility tests are in `tests/test_recorded_reporting.py`. Fixtures cover all three views, AI and analyst findings, all review states, exact original supports, zero-analysis/empty states, changed source/revision, failed dependencies, interpretation premises, contrary evidence, original truncation/time qualifications, HTML injection, Unicode, bounds, determinism, corruption, short writes, cancellation, publication races and CLI case/activity bypass.

Final reporting-specific run on the completed implementation:

```text
.venv\Scripts\python.exe -m pytest tests/test_recorded_reporting.py -q -s -p no:cacheprovider
60 passed in 133.30s
```

Broader focused regression attempt:

```text
.venv\Scripts\python.exe -m pytest tests/test_recorded_reporting.py tests/test_findings.py tests/test_finding_capture.py tests/test_report_refinement.py tests/test_report_humanization.py tests/test_output_ux.py tests/test_explanation_replay_status.py -q -p no:cacheprovider -k "not synthetic_performance"
16 failed, 241 passed, 1 skipped, 1 deselected in 706.86s
```

This is not a green broader regression result. Eleven failures were in existing output tests, including denied native hard-link publication/creation; a standalone `os.link()` on disposable files independently reproduced `PermissionError`, WinError 5. Four legacy report CLI tests passed in an isolated rerun; the legacy report-output collision test still failed on the same native link denial. One existing supervised SDK capture test returned `provider_dispatch_failure`. The broad run also emitted Windows `0xc0000008` diagnostics while importing native FAISS in an existing dry-run output test. No legacy implementation, dependency, permissions or assertions were altered to hide these findings. The skipped findings hard-link test already handles unavailable native-link privileges.

The reporting-specific final run covers the final staging/read-back and cleanup hardening added after the broader run. No full suite was run. `git diff --check` passed. The new documentation is explicitly allowlisted in `.gitignore`.

The isolated supervised SDK test reproduced `provider_dispatch_failure` (1 failed in 12.19s); it does not enter the new reporting service. Its underlying mock-worker/SDK cause remains unresolved and was not repaired in this reporting change. Four isolated legacy report CLI checks passed (the five-test isolated run had 4 passed, 1 native-link failure in 7.62s). Do not describe the broader validation as green.

The development environment's installed `locard-forensics` metadata was 6.94 while tests imported the current source tree. Source version is 6.135 in `pyproject.toml`; installation was deliberately left to the analyst workflow below. Generated envelopes correctly use installed metadata, not a duplicate hardcoded application version.

Synthetic immutability checks compare transcript file SHA-256 hashes and findings database bytes before/after report generation. History-only tests replace SQLite connection and provider entry points with failing sentinels. Workspace tests permit only their disposable local findings storage. No claim about real-case historical integrity follows from these tests.

## Manual acceptance commands (provider-free)

After committing/pulling through your normal workflow, install the checkout in the **test** environment:

```powershell
.\.venv\Scripts\python.exe -m pip install -e .
.\.venv\Scripts\locard.exe --version
```

Expected installed application version: 6.135. Set explicit readable recorded inputs; do not substitute a live case database for the transcript root:

```powershell
$historyRoot = 'C:\tmp\locard-diagnostics\YOUR-READABLE-HISTORY-ROOT'
$runId = 'YOUR-32-CHARACTER-RUN-ID'
$reportParent = 'C:\tmp\locard-report-acceptance'
New-Item -ItemType Directory -Path $reportParent -Force | Out-Null

.\.venv\Scripts\locard.exe report recorded --transcript-root $historyRoot --run $runId --profile executive --output "$reportParent\executive"
.\.venv\Scripts\locard.exe report recorded --transcript-root $historyRoot --run $runId --profile technical --output "$reportParent\technical"
.\.venv\Scripts\locard.exe report recorded --transcript-root $historyRoot --run $runId --profile handover --output "$reportParent\handover"
.\.venv\Scripts\locard.exe report inspect-recorded "$reportParent\technical"
.\.venv\Scripts\locard.exe report inspect-recorded "$reportParent\technical" --transcript-root $historyRoot --run $runId
```

For a matching existing findings workspace, add `--workspace 'C:\path\review.findings'` to both generation and source revalidation. Use a new output directory each time. Add repeatable `--protect-root 'E:\'` or another evidence root when applicable. Commands do not call a provider. There is no `--force`, report overwrite, degraded export or automatic source-revision substitution.

Inspect HTML offline and confirm: original S3 is unchanged; accepted AI entries still say unverified inference; rejected/superseded entries are historical; support and contrary evidence/qualifications remain readable; proposed examinations do not appear executed; coverage is bounded-run coverage. No run ID has been invented for acceptance.

## Known limitations and deferred scope

Read-only source validation is specific to supported recorded contracts and epochs, not the current case. Old C1 profiles requiring different historical rules remain rejected by their existing validators. D2 output not explicitly captured is not recovered from logs as a finding. Full decision/support retention can produce substantial appendices or an explicit size failure. No degraded administrative export, AI report prose, signatures, reporting database, examination execution, live-case refresh, multi-run merge, PDF or web UI is included.

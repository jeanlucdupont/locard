# Recorded-history service consolidation

Inspected/implemented November 14, 2026. Starting committed revision:
`68c8d7cf24ac7ddd34635784cba48b5e1526b2f9` (`Claude review`), application
6.137, clean working tree. This uncommitted change targets 6.138; only
`pyproject.toml` defines the application version.

## Architecture and ownership

Before, `d2.open_history` called autonomous replay, which entered B2 replay,
which entered C1 replay, which entered B2 and autonomous replay again. Reporting
then reconstructed C1 independently. Findings independently implemented source
binding and original-support closure for each candidate.

Now `investigation_ai/recorded.py:open_history` owns the recorded operation:

1. Guard source paths and validate the manifest/event chain.
2. Replay analysis once, collecting validated S1 state, original record/exposure
   stores and accepted disclosure lineage.
3. Validate B2 transitions using that context, then C1/D1 checkpoints using the
   validated B2 result. C1 still rebuilds its intermediate frontiers: the final
   S1 state cannot substitute for historical checkpoint validation.
4. Reread and compare the manifest digest and event head before returning.
5. Retain bounded, operation-local original-support restorations. Return
   defensive copies, never reducer internals or database connections.

`autonomous._replay`, `synthesis_consumer._replay`, and `organization._replay`
are internal validators over the same checked inputs. Their existing standalone
`reconstruct` APIs retain their compatibility paths. They are not serialized
input acceptance interfaces.

## Public service

Import `forensic_assistant.investigation_ai.recorded` and call
`open_history(root, run_id)`. Its handle exposes:

| Method | Result / responsibility |
|---|---|
| `binding()` | Original source anchor and validated recorded view; defensive copy |
| `verify()` | Fresh guarded manifest/chain read, compare original anchor, check in-memory seals |
| `factual_state()` | Original S1 observations, interpretations, limitations and lineage |
| `relationship_state()` | Original S2 relationships and chronology |
| `question_assessment()` | Original S3 assessment, unchanged |
| `organization_state()` | Validated C1 state, or `None` when no recorded profile exists |
| `explanation_pages()` | D1 pages with original pagination, references and coverage |
| `restore_support(ref_ids)` | Original supports with interpretation/relationship and contrary-endpoint closure |
| `restore_all_support()` | All accepted clause supports, without packet-selection omissions |
| `report_state()` | Existing reporting projection components, with recorded terminal diagnostics |
| `recorded_inputs()` | Defensive recorded inputs for destination protection; does not open their paths |

Projection reads describe the pinned recorded operation; they do **not** claim
fresh source equality. Call `verify()` at a trust boundary. Open a new handle
for a new application operation. There is no global/persistent cache and no
deserialization API for a trusted handle.

The reuse identity includes the manifest digest, event head, run ID, recorded
view, accepted frontier, manifest profiles and reconstructed rule products.
The handle seals its reducer inputs and support cache. Restorations are bounded
by the accepted clause set and existing B1 resource checks. It never opens a
case database. Workspace UUID/revision/head remain the responsibility of the
existing findings transaction and report snapshot guards.

## Consumers and remaining coupling

- Findings opens the neutral service, obtains public bindings/classifications,
  and uses shared support restoration. Repeated candidates reuse original
  restorations within the operation. Candidate semantics and persisted bytes
  are unchanged.
- Recorded reporting consumes the same service for S1/S2/S3/C1/D1 and terminal
  state. It no longer independently reconstructs organization or loads events.
- `d2.open_history` remains a compatibility adapter. D2 packet planning,
  serialization, response validation and cross-artifact selection stay in D2.
- AI findings import still adapts to D2 for its independently validated request
  and response contract. This coupling is deliberate, not a new evidence store.
- Reporting still uses findings' internal candidate/snapshot validation;
  standalone historical replay entry points still have their legacy private
  recursion flags. Consolidating all CLI/replay entry points and exposing a
  narrow findings snapshot-validation service are later refactors, not part of
  this change.

No renderer, report policy, schema, persisted contract, grant, codec, provider,
controller or transaction redesign is included.

Changed files:

| File | Change |
|---|---|
| `forensic_assistant/investigation_ai/recorded.py` | New neutral owner, defensive projections, support reuse and verification |
| `forensic_assistant/investigation_ai/autonomous.py` | Extract existing analysis replay body |
| `forensic_assistant/investigation_ai/synthesis_consumer.py` | Extract existing B2 replay body |
| `forensic_assistant/investigation_ai/organization.py` | Extract existing C1/D1 replay body |
| `forensic_assistant/investigation_ai/d2.py` | Retain packet behavior on a neutral-service compatibility adapter |
| `forensic_assistant/investigation_ai/findings.py` | Delegate source/binding/support operations; preserve transactions |
| `forensic_assistant/reporting/recorded_source.py` | Consume public recorded projections |
| `tests/test_recorded_history.py` | Service, dependency, reuse, compatibility and mutation regressions |
| `tests/test_findings.py` | Retarget unavailable-source injection; retain assertions |
| `pyproject.toml` | Application version increment |
| `.gitignore` | Allowlist this document |
| `docs/LOCARD_6_138_RECORDED_HISTORY_REFACTOR.md` | Architecture, measurements and acceptance record |

## Retained independent validation

| Boundary | Check retained |
|---|---|
| Initial open | Guarded paths, manifest/event integrity, original grounding, B2/C1/D1 replay, closing anchor |
| D2 preparation/worker/parent | Existing source and packet reconstruction, seals, exact grant/response checks |
| Findings mutation/import | Fresh source open, binding, candidate validation, UUID/revision/chain checks, source verification before insert |
| Findings export | Fresh source open, all candidates, closing source verification |
| Report build/publication | Fresh source open, workspace snapshot and candidates, closing source/snapshot check, existing publication guards |
| Explicit report revalidation | Fresh complete operation and exact frozen projection comparison |

Publication still fails if the source or workspace revision changes. Cached
support never authorizes a provider request or replaces original disclosure.
Hash-chain consistency remains distinct from semantic truth.

## Compatibility detail: zero-analysis history

Public empty S1 projections retain the manifest's validated view. Historical
B2 zero-batch terminals used the original unseeded empty reducer representation.
The service validates those exact B2 terminal bytes using that representation,
then exposes the view-seeded public projection. It does not rewrite histories,
rebind views or change empty-history assessment semantics.

## Measurements

Same disposable six-batch, two-synthesis, live-explanation synthetic history,
same three analyst-hypothesis workspace, same development Python environment,
before/after. No provider or live evidence access. Durations are single-run wall
times, not performance guarantees; call counts demonstrate structural savings.

| Operation | Loads before → after | B1 restorations before → after | Replay passes before → after | Seconds before → after |
|---|---:|---:|---:|---:|
| D2-compatible open | 10 → 3 | 44 → 22 | 6 → 3 | 1.458 → 0.805 |
| Recorded report | 20 → 4 | 88 → 44 | 9 → 3 | 2.641 → 0.984 |
| Export three findings | 12 → 4 | 50 → 24 | 6 → 3 | 1.999 → 0.692 |

Instrumentation wrapped transcript `load` aliases, `packets._rehydrate`, the
three replay modules, and `findings._binding`. Before counts measured their
reentrant `reconstruct` calls; after counts measured their extracted `_replay`
passes. Findings binding-boundary calls remain one per export. Reporting no
longer calls findings' binding wrapper; its own initial/final source checks
remain. Each operation uses one validated history context. Neutral open needs
two loads; the D2 adapter adds its independent verification.

Report retains B2's packet restoration plus its full report-support restoration:
these serve different validation paths. No attempt was made to bypass B2 packet
verification or share trusted data across processes. Findings reuses the two
original supports across its three candidates, saving four restorations in
addition to eliminating repeated replay. Report loads fall 80%; findings loads
fall 66.7% for this fixture.

The saved before/after report `content` and `content_digest` compare exactly;
findings exports compare exactly. Generation timestamps are intentionally
different; focused tests compare entire projections with a frozen generation
envelope. This is synthetic compatibility evidence, not validation of every
historical case.

## Validation record

Completed focused runs (overlaps are not added together):

- Public recorded service: **10 passed in 15.57 s**.
- Zero-analysis/report and view-authority regressions: **12 passed,
  3 historical-copy cases deselected, in 16.16 s**.
- B2, C1/finalization, live explanation, empty-state and compact checkpoint
  replay: **168 passed in 201.45 s**.
- Findings/capture/identity, report/rendering, D2 preview/cross/worker consumers:
  **293 passed, 1 failed, 6 skipped, 5 deselected in 648.23 s**. The sole failure
  was the old mock-opener injection target, corrected and rerun below. This was
  not rerun wholesale or relabeled as an all-green run. Five skips were absent
  SDK cases subsequently exercised with the installed SDK environment; the
  sixth was native hard-link creation denied by the sandbox. Three deselections
  excluded real copied histories and two excluded SDK-named tests, covered in
  the separate SDK run.
- Source-unavailable/mismatched-binding test after updating its injection target:
  **1 passed in 5.66 s**. Only the mocked opener moved from D2 to the neutral
  service; rejection assertions did not change.
- Actual OpenAI SDK with mocked HTTP, including Windows supervised capture:
  **7 passed, 1 third-party Pydantic warning, in 43.54 s**; pytest returned zero.
  The Python 3.14 interpreter subsequently failed to exit and was interrupted.
  This is not recorded as a clean process-exit result. The application worker's
  confirmed cleanup assertion passed.
- Native Windows hard-link rejection: sandbox reproduction **1 skipped in
  3.82 s**, explicitly due to hard-link creation permission; the same single
  test outside the sandbox **1 passed in 2.96 s**, using only its disposable
  synthetic database. No ACLs were changed.

`git diff --check` and whitespace checks of all new files passed. No existing
security/grounding assertion was weakened. Final acceptance remains with the
analyst; the SDK interpreter shutdown limitation remains unresolved.

The first development consumer run was interrupted early; a separately isolated
zero-analysis test exposed the representation mismatch described above, which
was corrected without changing persisted semantics or weakening assertions.
Two earlier seven-case mock-SDK attempts printed all success markers but stalled
before returning their summaries; they were interrupted and are not counted as
completed passes. The final diagnostic run disabled plugin autoload/capture and
printed both its summary and `pytest.main` return code before interpreter
shutdown stalled. No production workaround was introduced. Python 3.14's SDK
environment was used with the existing development pytest path appended;
no dependencies were installed. The development virtual environment lacks the
cloud SDKs; the former separate test-checkout interpreter was unavailable.

No complete suite, live provider request or real historical/evidence inspection
is part of this work. Existing copied-history tests are explicitly excluded.

## Provider-free manual acceptance

From the checkout, using its test environment:

```powershell
python -c "import tomllib; print(tomllib.load(open('pyproject.toml','rb'))['project']['version'])"
python -m pytest -q -p no:cacheprovider tests/test_recorded_history.py tests/test_zero_analysis_view.py -k "not copied_history_readonly"
python -m pytest -q -p no:cacheprovider tests/test_recorded_reporting.py tests/test_recorded_presentation.py tests/test_findings.py tests/test_findings_identity.py -k "not historical_readonly"
git diff --check
```

The source version should be `6.138`. After the analyst's usual editable install,
`python -m forensic_assistant.cli --version` should report the same version; this
task does not refresh installed package metadata.

For an analyst-selected readable historical transcript, substitute its actual
parent directory and run ID. This previews only; it grants no model execution:

```powershell
python -m forensic_assistant.investigation_ai.d2 "<transcript-root>" "<run-id>" --exploratory --json
python -c "import sys; from forensic_assistant.investigation_ai import recorded; h=recorded.open_history(sys.argv[1],sys.argv[2]); h.verify(); print(h.binding()); print(h.question_assessment())" "<transcript-root>" "<run-id>"
python -m forensic_assistant.investigation_ai.findings "<existing-findings-directory>" export
```

The last command reads and validates the selected workspace; it does not create
or mutate it. No new CLI surface was added. Report publication/inspection and
legacy renderer checks are covered by disposable regression fixtures.

## Limits and next refactoring candidate

The operation still performs bounded B2 planning and historical checkpoint
replay. Timing limits and unsupported historical-profile rejection remain.
This is not durable caching, restart recovery or fresh evidence verification.

The recommended next candidate is a narrow public findings snapshot-validation
interface, replacing reporting's remaining private findings dependencies while
preserving transaction-bound UUID/revision checks. This is a recommendation,
not an authorized next task.

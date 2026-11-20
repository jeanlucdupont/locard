# Locard 6.160 — Initial discovery and exclusions

## Diagnosis

Inspected baseline: committed 6.159, `ea9e0aa`. No existing 6.160 implementation was present; `pyproject.toml` is incremented once.

`assessment.plan`, `plan_text`, and `assessment_cli.assess` used the same generated lead ID. Inspection found no display/internal mismatch or regeneration between preview and approval. The live entered string was not captured, so its precise rejection cause is unproven. Matching was case-sensitive and the error omitted valid IDs. Exclusions now accept complete IDs case-insensitively, separated by commas or whitespace; prefixes and unknown values still fail closed, with valid IDs and retry instructions.

`briefing_entities` accepted the syntactically valid single-label hostname `on` after a narrative computer-role marker. Common connective words are now rejected; bare role phrases need a machine-like/dotted value or explicit naming syntax. Explicit legitimate single labels remain possible. Source metadata never proves that all artifacts share a host.

Previously `assessment.plan` only routed technical indicators; dates alone supplied no search. An explicit `--source` now selects a deterministic initial time overview. Existing indicator-based behavior without this option remains available. In the overview, briefing indicators remain context, not additional implicitly authorized queries.

## Plan and retrieval

`assessment_discovery.plans/search` is reusable application logic, independent of CLI input and models. Seven individually excludable routes cover EVTX process context, browser downloads, browser visits, Prefetch recorded execution metadata, MFT metadata, Registry metadata, and general EVTX records. Process context is not itself proof of execution. Results are time-ordered starting observations, not suspiciousness, rarity, or malware rankings.

The existing inventory preview precedes approval; evidence searches run only after approval. The saved plan binds source, window, exclusions and query purposes. Pending lookup audit events include those scope fields. Existing read-view, publication and assessment integrity controls remain in use. Unknown exclusions and declined plans execute no evidence searches.

Queries use the existing `artifact_time` index, timestamp-first join order, and keyset continuation over timestamp/evidence ID/slot. No full timeline count, materialization or sort is required. Each page materializes at most 1,001 family timestamp candidates, evaluates at most 1,000, and returns at most ten records. A five-second SQLite interrupt bounds query work; the existing supervised 15-second tool limit remains. Physical index entries scanned may exceed the candidate allowance and are not instrumented. Existing aggregate limits remain 300 seconds, 120 queries, 100,000 evaluated candidates, 500 retained records and 2 MiB payload. No large-case speed claim is made.

Continuation is bound to database identity, source, family, purpose and window. Candidate/time/result limits produce explicit incomplete coverage, with continuation when progress permits. Source membership is checked using existing evidence provenance, including browser context and conflicting host assertions. Selecting a source does not select other sources by matching hostname.

Explicit offsets normalize to UTC, using a half-open `[start,end)` range of at most 24 hours. Source timezone metadata does not reinterpret stored values. Original timestamp slots, sources, meanings and normalization status remain present. Missing/ambiguous timestamps and derived-only temporal observations are outside this route and explicitly reported. A no-match result is not proof of absence across the case. Separate routes can retain the same evidence ID without creating duplicate evidence.

## Focused validation

Synthetic tests cover neutral five-family retrieval, boundaries, absent timestamps, source membership, deterministic IDs, exact/case-normalized exclusion, unknown IDs, declined approval, continuation, index selection, JSON round trips, and unchanged synthetic evidence bytes. Existing assessment and hostname regressions are also run. No real evidence, provider calls, ingestion, or full suite is used. Results: `tests/test_assessment_time_scope.py tests/test_assessment.py tests/test_briefing_entities.py`: 71 passed in 59.66 seconds. After adding explicit audit-scope assertions, the affected application test passed again (1 passed in 5.51 seconds). `git diff --check` passed. Initial failures were new test-fixture mistakes (CLI-normalized time inputs and missing EVTX XML namespace/channel), corrected without changing forensic validation.

## Manual acceptance

After installing this checkout, verify:

```powershell
.\.venv\Scripts\python.exe locard.py --version
```

Expected version: 6.160. In the shell, with the intended case and accepted briefing selected:

```text
evidence source list
investigation assess --source SOURCE_ID --start 2026-11-17T00:00:00-06:00 --end 2026-11-18T00:00:00-06:00
```

Replace `SOURCE_ID` with the existing source's complete ID. UTC bounds are November 17 at 06:00 through November 18 at 06:00. Review the seven routes and unavailable families. Copy an unwanted route's complete displayed `A-...` ID into the exclusion prompt; approve the remaining plan once. Alternatively decline to confirm no searches run. An invalid ID must list valid IDs and abort without searching. All-excluded plans explain coverage-only persistence and how to retry.

Review retained evidence and coverage limitations before further investigation. This overview does not discover timestamp-less evidence, classify unusual activity, or establish causal relationships. Real-case responsiveness and manual acceptance remain pending. No schema/index migration, evidence mutation, commit or push is part of this change.

# Locard 6.161 — Canonical briefing compatibility

## Diagnosis and scope

Inspected clean 6.160 HEAD `02dee0d`, compared with 6.159 `ea9e0aa`. The reported real case was not accessed.

Case activation follows `interactive.shell.Shell.activate` → `case_management.validate_identity` → `briefing_store.Store.load/_load` → `content` → `briefing_canonical.check_envelope/check` → `briefing_semantics.technical` → `briefing_entities.valid_host`.

6.160 expanded `PROSE`, shared by extraction and canonical technical validation. Thus a format-1 briefing previously accepted with a hostname value such as `on` became unreadable. `Store.load` concealed that technical-validation failure behind its generic structural-error message. Neither the date-discovery query nor a database migration caused this regression.

Synthetic reproduction confirms that `canonical.document.categories.systems[0].value = "on"` passes the 6.159 policy and fails the 6.160 policy. The live case's exact category/index remains unverified: the old displayed `on [hostname]` lead is consistent with this defect, not proof of its precise persisted location. There is no evidence of database corruption.

## Correction

Format-1 canonical validation uses its frozen historical hostname exclusion policy. Syntax, technical-type rules, required fields, bounds, provenance consistency, revision digests and case identity remain validated. Current extraction and search eligibility continue using the stricter policy. Keeping an accepted historical assertion readable does not authorize searching it or reclassify it as evidence.

This applies consistently to canonical loading, rendering, review and assessment preflight. It also covers hostname components of historical URL values because they shared the same changed validator. Canonical imports remain format-1 analyst assertions; downstream searches must revalidate current technical eligibility.

No migration or adaptation of stored values is needed. The original narrative, summary status/text/uncertainty, original provenance, revisions and analysis metadata are returned unchanged. Existing optional `interviews` and `canonical` content members remain optional; no invented defaults are persisted. Unknown fields, invalid syntax, unsupported formats, altered digests and provenance mismatches remain errors.

`CanonicalValidationError` adds fixed schema paths and sanitized rules for structural and technical-value failures, for example:

```text
BRIEFING_MALFORMED: canonical.document.categories.systems[0].value: invalid_technical_value; original preserved
```

The stable category and existing error presentation are retained. Diagnostics do not print analyst values or unknown field names. Other existing error categories remain unchanged.

## Validation

Only synthetic focused tests are used. New compatibility tests reproduce the old failure; preserve original briefing/database/activity bytes during validation; read accepted summaries and narrative-only revisions; reject malformed data without writes; exercise remembered and explicit opening; and run a source-scoped assessment from the historical representation. Actual shell opening appends a legitimate new audit session, preserving the historical audit prefix; read-only identity validation does not write audit data. Existing canonical, persistence, entity and date-discovery suites check current records and authorization behavior.

Focused command: `python -m pytest tests/test_briefing_legacy_compatibility.py tests/test_briefing_canonical.py tests/test_briefing_persistence.py tests/test_assessment_time_scope.py tests/test_briefing_entities.py -q --tb=short -p no:cacheprovider`. Initial run: 108 passed, seven stale CLI invocation failures. Updated only those calls to current import-json/export/analyze subcommands, retaining safety assertions and adding parser-level rejection of export/search combinations. Final focused run: 114 passed, one sandbox hard-link PermissionError, in 52.74 seconds. The unchanged export test passed separately outside the sandbox with a fresh unique temporary directory: one passed in 1.08 seconds. An intervening attempt was blocked by permissions on the shared pytest temporary directory. No permissions were changed. Thus all 115 selected tests have passed; no full suite was run. `git diff --check` passed. No real evidence, provider requests, broad suite, commit or push.

## Manual acceptance

After the analyst updates and installs the separate checkout:

```powershell
cd C:\tmp\locard
git pull
python .\locard.py --version
python .\locard.py
```

Expected version: **6.161**. Accept the remembered case, or explicitly select its existing path. Do not delete or regenerate briefing history if another validation error appears; retain the sanitized diagnostic for investigation.

```text
case status
audit verify
investigation assess --source src-d3c195d3068e4906a805082df44c1a57 --start 2026-11-17T00:00:00-06:00 --end 2026-11-18T00:00:00-06:00
```

Review the proposed bounded plan and exclusions before approval. Confirm the old `on` assertion does not become a searchable hostname, while historical briefing decisions remain readable. Real-case acceptance is pending; development did not open `KFI-5070790-V2`.

Version check returned Locard 6.161. The launcher also emitted 'session audit coverage degraded; required actions are blocked' in the development environment. This separate audit-storage warning was not diagnosed or bypassed; no case was selected. Manual acceptance should include audit verify as above.

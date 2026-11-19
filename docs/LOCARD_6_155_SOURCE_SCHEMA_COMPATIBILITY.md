# Locard 6.155 — Source schema compatibility

Implemented November 18, 2026. Manual acceptance pending; no real case/evidence
inspection, provider requests, commit or push during development.

## Confirmed cause

`interactive/case.py::expected_schema` constructs a trusted in-memory reference
from the current application DDL. Version 6.154 added nullable `time_zone` to
`database/sources.py::DDL`, but `case.check_structure` still required exact equality
with that single new column layout. Consequently a valid pre-6.154 case failed
validation before `sources.current` could supply its intended unknown value.

The remembered-case path is `Shell.startup` → `case.validate` → URI `mode=ro`
`investigation_ai.case.open_readonly` → `case.check_structure`. Explicit existing-case
opening also calls `check_structure` through `case.open_existing` (`mode=rw`, no
creation). A write-capable connection does not itself write or migrate the case.

This is an initialization/validation mismatch, reproduced with disposable cases.
It does not require a partially applied migration to explain the reported error.
The user's actual database structure has not been inspected; unrelated corruption
or unexpected structure would still require separate diagnosis.

## Correction and boundaries

`case.check_source_assertions` accepts exactly two column-metadata tuples:

1. The trusted current source-assertion layout, including nullable TEXT `time_zone`
   with no default or primary-key role.
2. That same layout with only `time_zone` absent.

Column names, order, declared types, nullability, defaults and primary-key metadata
retain exact comparison. Extra ordinary columns, wrong types, required time zones,
defaults and other mismatches remain rejected. Other table checks, supported schema
versions and the trigger/view prohibition are unchanged. This retains the existing
PRAGMA table-info validation model; it is not a new general SQLite schema auditor.
The existing read-only authorizer is unchanged.

`database/source_timezone.py::enable_for_assertion` now checks the source table
before attempting an extension for a supplied zone, including repeated writes when
the column already exists. It adds the column only when absent. No reinitialization,
table replacement or migration is added to opening, remembered selection, source
inspection or update previews. Schema-4/5 cases work with either supported layout;
existing schema-3 source-operation limitations are unchanged.

## Transaction, audit and history semantics

The existing source create/update or confirmed guided-ingestion mutation owns the
SQLite transaction. When necessary, an explicit BEGIN precedes ALTER so rollback
includes both the column addition and subsequent assertion insertion. A successful
update appends an assertion with the existing `supersedes` chain. Existing values,
assertion IDs, source identity, membership and evidence remain unchanged. Historical
rows receive NULL, not invented time zones. Ordinary reads represent an absent
column as unknown.

Required audit intents/completions and existing failure handling are unchanged.
**SQLite DDL, audit sidecars and derived records do not form one atomic transaction.**
In particular, a committed metadata mutation can survive an audit-completion failure;
the existing durable-intent/error behavior must remain visible. This patch neither
bypasses auditing nor claims to make independent storage systems atomic.

An authorized schema/assertion mutation changes the current case fingerprint. Old
fingerprints, transcripts, findings and report bundles are not rewritten or rebound.
Their original validation meanings remain. Time zones remain declarative metadata:
no timestamp conversion, parser, normalization, query, authorization or AI change.

## Focused verification

Final command:

```powershell
$env:PYTHONUTF8='1'
.\.venv\Scripts\python.exe -m pytest tests/test_source_schema_compatibility.py tests/test_source_timezone.py tests/test_sources_model.py -q --tb=short -p no:cacheprovider
```

Result: **47 passed in 8.06 seconds**. No full suite or broad unrelated tests.

- Real case-validation/opening functions tested against old, new-NULL, populated
  and migrated disposable databases; schema-4 and schema-5 compatibility covered.
- Database bytes, modification time, sqlite_master content and fingerprint remain
  identical after validation/opening; protected read-only connections reject writes.
- Remembered old-case startup reaches activation (activation mocked to avoid unrelated
  startup effects) without rejection or database mutation.
- Unexpected source extensions and unrelated malformed table/trigger cases reject.
- Injected assertion INSERT failure after ALTER rolls back schema and revision.
- Repeated updates preserve original rows, supersession, source membership and
  synthetic audit-chain bytes/verification. Historical fingerprint remains recorded
  unchanged while the current fingerprint changes.
- Existing zone tests cover guided confirmation, cancellation, single source audit,
  validation, unknown defaults, timestamp preservation and CLI preview/correction.

`git diff --check` passes. These are synthetic results, not a claim that the user's
two cases have already been opened successfully by this development session.

## Windows manual acceptance

After transferring the reviewed changes to the test checkout:

```powershell
Set-Location C:\tmp\locard260927\locard
.\.venv\Scripts\python.exe -m pip install -e .
.\.venv\Scripts\python.exe locard.py --version
.\.venv\Scripts\python.exe locard.py
```

Expect **Locard 6.155**. Accept the remembered case if it is the intended one. No
source-table migration should be requested or performed. In the shell:

```text
case open KFI-5070790-V2
case status
evidence source list --ids
evidence source show <source-id> --json
case open KFI-5070790
case status
evidence source list --ids
evidence source show <source-id> --json
```

Use each case's actual source ID. If a name is not registered, use its known full
database path (`case open "D:\Locard\Cases\KFI-5070790-V2\case.db"` for V2).
Do not guess a path for the other case. Check original IDs, names and assertion
history. Missing time zones should be null/unknown. Do not update either real case
for this smoke test. Normal session auditing can append sidecar records; that is
separate from unchanged forensic database content.

Use a new, disposable empty case for mutation acceptance:

```text
case new TZ-6155-Smoke
evidence source create --name Smoke --time-zone America/Chicago
evidence source list --ids
evidence source show <smoke-source-id> --json
evidence source update <smoke-source-id> --time-zone Europe/Paris
evidence source show <smoke-source-id> --json
```

Choose no ingestion if prompted. Confirm only the disposable source update. Expect
the original America/Chicago assertion plus a later Europe/Paris revision linked
by `supersedes`; the source ID stays the same. There are no evidence timestamps to
change in this empty smoke case. Preservation of populated original/normalized
timestamps is covered by synthetic tests, without mutating real evidence. For a
manual old-schema migration test, use a separately prepared SQLite-consistent
disposable copy of an older case, never the original.

Stop on any remaining structural error and retain its exact message. Do not delete,
recreate or automatically migrate a real case to bypass validation.

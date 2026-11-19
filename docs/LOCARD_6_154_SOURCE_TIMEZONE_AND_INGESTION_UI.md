# Locard 6.154 — Source time zone and guided ingestion

Implemented November 18, 2026. Manual acceptance pending. `pyproject.toml` remains
the application-version authority. No real evidence, case database, provider or
original audit record was accessed during implementation.

## Metadata contract

`database/sources.py` stores nullable `source_assertions.time_zone`. This is an
analyst-supplied IANA identifier belonging to one source, not the case, workstation,
display preferences or investigation window. There is no inferred default.
Empty input becomes SQL NULL / JSON null and displays as **unknown**.

`sources.create`, `update`, `current`, `listing` and `detail` use the established
source assertion model. Corrections append a revision with `supersedes` and an
analyst-supplied basis. Omitted update fields retain their current values. Clearing
the zone creates another revision; it does not delete history. Source IDs,
memberships and ingestion occurrences are unchanged. Existing SOURCE_CREATE and
SOURCE_UPDATE audit mutations include the new assertion/change without an extra
audit operation. JSON adds `time_zone`; existing fields remain available.

### Existing cases and explicit extension

The analyst explicitly approved this additive metadata extension:

- Fresh cases include the nullable column in the existing source DDL.
- Existing schema-4/5 cases without the column read as unknown, including historical
  assertion records. Opening, listing, showing and previewing never add the column.
- An explicit create/update, or confirmed wizard ingestion, with a supplied zone
  adds the column within the caller-owned transaction. Failure/rollback also rolls
  back the ALTER. Existing assertion rows remain NULL.
- Creating unknown metadata or correcting other metadata in an old case does not
  require the column. Case `user_version` remains unchanged. This does not add
  support for source operations in older schemas that lacked sources entirely.

Metadata correction changes the ordinary whole-case fingerprint, as existing
source corrections do; this is expected derived-state invalidation. No evidence
content digest, ID or timestamp is recomputed. An older application that creates
a new assertion without copying this newly introduced column can leave that new
revision unknown; use 6.154 for time-zone corrections. Earlier revisions remain.

## IANA validation and Windows

`database/source_timezone.py::validate` uses Python `zoneinfo.ZoneInfo`. Valid
identifiers are retained as entered, not reduced to a fixed offset. Invalid keys,
relative/absolute file keys and malformed inputs are rejected. Unknown stays
unknown even if no time-zone database is installed.

Windows commonly lacks a system IANA database. The standard `tzdata>=2024.1`
dependency is declared for Windows in `pyproject.toml`; install through the normal
editable/package installation. This checkout initially had no usable IANA data;
`tzdata 2026.6` was installed for focused validation. If even UTC cannot be resolved,
the diagnostic identifies the missing database and suggests installing tzdata or
leaving the assertion empty. A missing requested key in an available database is
reported separately. No workstation-zone fallback exists.

**No timestamp conversion is implemented.** EVTX, MFT, Registry, Prefetch and
Browser parsing/normalization, UTC serialization, timeline/query ordering and
authorization windows are unchanged. Using these assertions to interpret local-time
artifact fields requires a separately approved parser-by-parser review.

## Guided presentation

`interactive/setup.py::collect` adds the optional time-zone question after the
original volume root. Invalid answers reprompt; `cancel` uses the existing wizard
cancellation path. All five metadata fields appear in the existing final
confirmation, with unknown values explicit. Collection does not write metadata.
`setup.execute` persists it only after the existing confirmation.

Shared `TextSpan`/palette roles now cover menus, discovered artifact names/counts,
paths, profiles and metadata. Headings use `heading`; data uses `value`; option
numbers use `command`; limitations use `forensic_note`; unsupported status uses
`unknown`; invalid profile selections use `error`. Existing ReaderProxy supplies
the `question` role and recording once—prompts are not pre-colored a second time.
NO_COLOR and ANSI-incapable output use the existing plain projection.

Browser selection asks `Select profiles (all, none, or numbers):`. The single-profile
empty default, multiple-profile explicit selection, comma-separated indexes and
identity qualification are preserved. Junction/access limitations remain visible.

`interactive/setup_display.py::FileProgress` uses centralized `progress` cyan for
all artifact families. No new spinner or timing logic: repaint suppression,
counters, elapsed time, cancellation, supervision and cleanup are unchanged.

## Focused validation

Final successful sets (synthetic fixtures/mock clocks only; no full suite):

| Set | Result |
|---|---|
| `test_source_timezone`, `test_sources_model`, `test_ingestion_spinner`, `test_observation` | **47 passed, 4.63 s** |
| `test_source_workflows`, `test_add_evidence`, `test_ingest_wizard_ux`, `test_guided_setup`, selected relevant workflows | **88 passed, 9 deselected, 112.29 s** |

New tests cover IANA validation/missing database, multiple independent sources,
old-case non-migrating reads, transactional ALTER rollback, correction history,
clearing metadata, preview without mutation, unchanged non-assertion tables
(including original/normalized timestamps and membership), CLI audit changes,
wizard validation/cancellation/confirmation, one source audit/assertion, browser
defaults, semantic/plain equivalence and all five spinner families.

Existing test inputs now supply an empty answer for the new optional question;
the metadata-dictionary expectation includes NULL and the confirmation label
expects `Name`. No parser, forensic, audit or authorization assertion was weakened.

The broader initial sandbox run reported 15 failures/47 passes: audit/rename/worker
environment failures and pre-existing top-level ingest alias/help expectations.
The first outside-sandbox attempt could not initialize pytest temporary fixtures
(76 errors/12 passes) because its default temporary root was inaccessible. The
successful 88-test run used a new explicit `--basetemp`, a separate temporary
LOCALAPPDATA and no permission changes. Nine excluded tests were six old alias
dispatch cases, two old help expectations and the unrelated junction-creation test.
Those tests were not weakened or represented as passing.

`git diff --check` passes. Windows visual acceptance remains manual. No commit or push.

## Windows acceptance

After transferring the reviewed changes to the test checkout, in PowerShell:

```powershell
Set-Location C:\tmp\locard260927\locard
.\.venv\Scripts\python.exe -m pip install -e .
.\.venv\Scripts\python.exe locard.py --version
.\.venv\Scripts\python.exe locard.py
```

Expected version: **6.154**. Before creating the new case, use the existing shell
case-root workflow (this changes the root for future cases; it does not move cases):

```text
case root
case root set D:\Locard\Cases
case root
case new KFI-5070790-V2
```

Review/confirm the root change. Select mounted-volume discovery and `E:\`, choose
the intended artifacts, then choose optional source metadata. Enter the desired
hostname/user/original root, and **only a zone you have independently established**
(for example `America/Chicago` if applicable). An empty zone is valid. Check the
proposed workspace and metadata before final confirmation; `cancel` stops without
creating/ingesting. If the case already exists, open it and use `evidence ingest
wizard` rather than attempting to recreate it.

Review or correct a source in the shell, substituting its exact ID:

```text
evidence source list --ids
evidence source show <source-id>
evidence source show <source-id> --json
evidence source update <source-id> --time-zone America/Chicago
evidence source update <source-id> --time-zone
```

The update commands use the existing confirmation. The last explicitly clears the
zone. For scripts, preview without `--yes`, then repeat with `--yes` to apply.
New source creation also accepts `--time-zone America/Chicago`; existing direct
ingest commands can reuse that source via `--source <source-id>`. There is no new
parser time-zone option. Paginate `show --json --limit ... --offset ...` to review
long assertion histories.

For plain rendering, start a separate invocation with `--no-color` or set
`$env:NO_COLOR='1'`. Inspect discovery, profile selection and final confirmation,
then cancel if no ingestion is desired. Verify that no raw ANSI appears, all
qualifications remain readable, and unknown metadata stays unknown.

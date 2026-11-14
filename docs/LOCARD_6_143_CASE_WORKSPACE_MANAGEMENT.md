# Locard 6.143 — Case workspace management

## Inspected storage and identity boundary (before cloning)

The starting committed revision is `a227b5e` (6.142). `database.db.connect` initializes schema.sql plus context/artifacts/sources/browser DDL, effective schema 5; existing schemas 3/4/5 remain supported. These tables hold retained observations, raw data, timestamps, ingestion outcomes/errors, source assertions/assignments and browser contexts/occurrences. There is no case-directory-name identity column to rewrite.

| Component | Location and binding | Clone policy |
|---|---|---|
| Evidence/provenance | case.db, including SQLite WAL committed state | SQLite backup of known tables, unchanged IDs/values |
| Briefing | case.db.briefing/state.json; Store binds canonical path, device and inode; revision content digests | Not copied |
| Assessment | case.db.assessments; same identity plus integrity/authorization digests | Not copied |
| Activity | case.db.audit.jsonl (activity.sidecar); independent chain | Not copied; new session creates its own trail |
| Investigations | case.db.investigations or explicit transcript root; read-view, grant and disclosure contracts | Not copied |
| Findings | Explicit .findings workspace; UUID/revision and transcript binding | Not copied |
| Reports | Explicit published bundle directory; original grounding/digests | Not copied |
| Semantic indexes | Derived index/model locations | Not copied; rebuild explicitly |
| UI preferences | LOCALAPPDATA/Locard/ui-state.json | Unchanged; last database remains a validated absolute path |
| New case preference/registrations | LOCALAPPDATA/Locard/case-workspaces.json | Application configuration only |

Source references: `interactive.workspace`, `interactive.case`, `briefing_store.Store`, `assessment_store.AssessmentStore`, `activity.sidecar`, `investigation_ai.storage.DirectoryGuard`, `reporting.transcripts.safe_path`. No evidence schema or historical digest contract changes are needed. New `clone-origin.json` describes this copy operation only; it is not evidence or a historic authorization.

## Root, discovery and selection

New cases default to USERPROFILE/Locard/Cases. `case root set PATH` changes future creation/discovery, never moves data. The old LOCALAPPDATA/Locard/cases root remains discoverable. Discovery examines at most 1,000 immediate entries per root and 1,000 registrations, never recursively scans disks or opens case databases. Entries are labeled discovered/not validated; selecting validates schema and existing briefing/assessment bindings.

`case open NAME` requires unique case-insensitive resolution. Ambiguous locations are displayed, never silently prioritized. The menu uses #number so a literal case name 14 is not confused with menu item 14. Absolute case.db or workspace paths remain supported. Registration validates the original location and existing bindings, persists path/device/file identity, and flags a replaced file instead of silently accepting it; unregister removes configuration only. Root/registration writes use an exclusive configuration lock and atomic replacement. Stale locks are preserved for review.

Names are single directory names: traversal, reserved Windows device names, separators, invalid characters, trailing spaces/periods, hidden names and overlong names are rejected rather than sanitized into another identifier. Filesystem redirection is rejected with the existing local-path and directory-handle guards. No administrator privileges or cloud service are required.

## Clone architecture and safeguards

`case_management.clone` is an explicit potentially expensive operation. It validates the source schema, requires exactly the known table set, runs SQLite integrity and foreign-key checks, rejects unfinished ingestion runs/batches in the selected snapshot, estimates database size plus disk reserve, and uses SQLite backup from a pinned read transaction. WAL contents are included. It never copies the main file blindly, normalizes records again, or copies original external artifacts.

A later source commit is outside the selected snapshot. There is no claim to enumerate all operating-system processes: unfinished application ingestion is detected in the pinned database; SQLite snapshot isolation makes unrelated later writes irrelevant to the copied state. The source is opened mode=ro with uri=True. Source files/sidecars are not rewritten or repaired. Ordinary SQLite read locking/WAL shared-memory coordination may occur; this is not a claim that a filesystem read has no OS bookkeeping effects.

Destination reservation is exclusive and private to the current user using the existing private-directory creation helper; no existing permissions are changed. The CLI shows resolved source/destination before confirmation and refuses a changed destination or source identity afterward. Until the verified database is atomically published with a no-overwrite link, no case.db is discoverable. Metadata is flushed first. Source/destination identities are rechecked; paths cannot overlap. Failure/cancellation removes only owned temporary outputs, never recursively deletes unrelated content. Unexpected leftovers produce a cleanup limitation. Windows filesystems lacking hard-link support fail safely rather than using an overwrite-capable fallback. A one-hour operation deadline bounds backup/integrity work; Ctrl+C interrupts without changing source evidence. This does not change ingestion/investigation timeouts.

The new database has a fresh filesystem identity and no investigative sidecars. Evidence/source IDs and ingestion limitations remain copied observations, not newly ingested evidence. `clone-origin.json` records origin path/device/file identity, snapshot size/schema and a bounded external-reference sample. It does not claim independent verification, self-containment, or cryptographic history. Relative references, if present historically, remain unchanged; source locations must be reviewed before using external files.

## Manual copy diagnosis and conversion limitation

Read-only metadata inspection confirmed format 1 and matching path/device/inode in case 14's briefing. The requested legacy 14-test path was absent in this environment. Therefore the exact mismatch in that copy is not claimed as directly inspected. Synthetic copies demonstrate that path and file identity differ even when database bytes and briefing JSON remain identical. Assessments inherit the same file-identity binding. Registering such a copy is refused rather than rebinding its history.

No in-place conversion is exposed. Resetting a manually copied directory would require reliably identifying every externally located findings/report/transcript relationship and quiescing concurrent writers while atomically detaching multiple historical sidecars. The current services have no workspace-wide lease or multi-sidecar atomic reset contract. Renaming/deleting sidecars would silently orphan history or expose a mixed state after interruption. That storage-boundary change is outside this release; use an evidence-only clone to a new unused name when storage permits. Never overwrite or delete the existing copy. `case clone` can read its evidence database without accepting its copied briefing as valid authority.

## Diagnostics

Briefing diagnostics distinguish malformed envelope, unsupported schema, missing sidecar, inaccessible file, integrity failure and case-identity mismatch. Assessment diagnostics separately identify integrity, identity and plan-binding failures. No narrative is included in identity errors. No automatic repair occurs. Existing historical transcript/report/source validators retain their separate contracts.

## Manual Windows acceptance

In the test checkout:

```powershell
cd C:\tmp\locard
.\.venv\Scripts\python.exe -m pip install -e .
.\.venv\Scripts\python.exe locard.py --version
.\.venv\Scripts\python.exe locard.py
```

Inside Locard (choose unique unused names):

```text
case root
case list
case open 14
investigation briefing show
investigation list
case root set C:\tmp\Locard-Acceptance-Cases
case new Small-Smoke
case clone Small-Smoke Small-Smoke-Clone
case open Small-Smoke-Clone
case status
investigation briefing show
investigation list
investigation start
```

The empty clone has no inherited briefing/assessments. In start, edit is the default when no briefing exists; cancel before any interview/provider approval for a provider-free smoke test. Plain edited narrative is saved without being promoted to a structured assessment: Locard directs the analyst to `investigation briefing analyze` for explicit AI-assisted proposal/review before `investigation assess`. Interview/provider calls remain separately authorized. Use a small synthetic ingested case to compare actual inventory and perform a deterministic assessment after explicitly accepting a structured briefing and approving a time-bounded plan. No full case 14 clone is required. Restore the preferred root explicitly with `case root set` afterward; nothing is moved.

For external registration use `case register LegacyCase D:\ExistingCases\LegacyCase`, then `case open LegacyCase`. `case unregister LegacyCase` removes only the reference. Scripted configuration/clone mutations require explicit `--yes`; `case open ABSOLUTE_PATH` validates and reports the path rather than pretending a separate process can persist shell activation.

For the invalid manual copy, leave it untouched. When space permits: `case clone C:\Users\jl-du\AppData\Local\Locard\cases\14-test\case.db 14-test-clean`. Choose a fresh name and review the reported external references. No real-case clone has been performed or claimed here.

## Validation

Focused runs (overlapping selections, not a full-suite total):

| Selection | Result | Duration |
|---|---|---|
| Briefing persistence, assessment, shell, workflow, catalog and completion | 208 passed | 94.83 s |
| Initial complete workspace/clone tests | 35 passed | 22.58 s |
| Expanded workspace, naming, setup and guided workflow | 97 passed | 27.66 s |
| Private publication/failure cleanup and briefing diagnostic regressions | 61 passed | 21.04 s |
| Registration identity, lock contention and root preference checks | 4 passed | 3.73 s |
| Shared creation service and name/menu checks | 3 passed | 3.42 s |
| Final source redirection recheck and no-overwrite publication | 2 passed | 1.83 s |
| Confirmed CLI clone and root-change refusal | 1 passed | 1.29 s |

Final listed runs had zero failed, skipped or deselected tests. Early focused development failures identified a Windows read-only-handle fsync error and a stale expected error-code prefix; these were corrected and affected checks rerun. Atomic hard-link/private-directory tests ran with normal host filesystem access because the sandbox can deny publication; no existing ACLs were changed. WAL tests include committed state and a later concurrent commit excluded from the snapshot. Synthetic MFT records, IDs, raw/normalized values, timestamps, source lineage, ingestion outcomes/errors, briefing/assessment history and activity integrity were checked. Rival publication, cancellation, storage shortage, unfinished ingestion, corrupt/unknown schema, redirected paths, empty clone state and no-overwrite behavior were exercised. No real-case cloning or interactive Windows manual acceptance is claimed.

`git diff --check` passed. Direct launcher version is 6.143. No full suite, live provider calls, commit or push. Original evidence and historical sidecars are unchanged. Existing permissions were not modified. Remaining verification: analyst manual Windows acceptance and the later approved full regression suite.

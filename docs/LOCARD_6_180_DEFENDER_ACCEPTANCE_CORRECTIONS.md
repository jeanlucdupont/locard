# Locard 6.180 — Defender acceptance corrections

Implemented for manual acceptance on 2026-11-26, starting from clean commit `4b99310`. Application version is **6.180**, from `pyproject.toml`; Defender parser version is **2**. No new dependencies or database schema changes. No actual analyst case, mounted volume, personal logs or provider was accessed during development.

## Acceptance findings and confirmed causes

The analyst reported 297,949 retained Defender records: 1,459 BM records all marked partial, 114,016 unknown records, and 295,775 records without usable normalized timestamps. These are user-reported baseline measurements, not measurements repeated against the case here.

`artifacts/defender.py` version 1 used an ISO-only validator for text timestamps. Consequently, valid BM `MM-DD-YYYY HH:MM:SS` values were rejected. Its invalid-time branch also set the record's incomplete flag. Separately, all suffix-free leading timestamps remained timezone-unknown. `artifacts/defender_query.py` simply selected the first eight fields, excluding later ImagePath entries.

These issues are corrected without changing authorization intervals or treating diagnostic telemetry as findings.

## Timestamp research and policy

[Dissect's Defender plugin](https://github.com/fox-it/dissect.target/blob/main/dissect/target/plugins/os/windows/defender/_plugin.py) explicitly defaults suffix-free MPLog ISO timestamps to UTC in `parse_iso_datetime`. Its `_mplog_bmtelemetry` parses month-day-year CreationTime with a UTC default. This is corroborating forensic implementation evidence, not a Microsoft guarantee covering every engine and field. No source code was copied.

[Microsoft's Defender portal time-settings documentation](https://learn.microsoft.com/en-us/defender-endpoint/time-settings) concerns portal display; it does **not** establish the timezone of local MPLog fields. It is not used to justify a blanket conversion.

The four supplied BM examples corroborate the supported UTC convention, while ProcessCreationTime and CreationTime remain distinct observations. Their approximate alignment is not itself proof of a universal timezone convention, event identity or execution.

| Input / policy | Treatment |
|---|---|
| Explicit `Z` or numeric offset, supported text format | Honor recorded offset, regardless of selected default policy |
| ProcessCreationTime FILETIME variant | Existing UTC epoch conversion, exact 100 ns precision |
| `format-utc` (default), ISO leading timestamp in recognized `MPLog-*` input | UTC format interpretation with explicit basis and uncertainty |
| `format-utc`, BM CreationTime in `MM-DD-YYYY HH:MM:SS` | UTC format interpretation; fractional seconds and explicit offsets supported |
| Other suffix-free fields, BM ISO CreationTime, MPDetection/renamed inputs | Unknown timezone by default; no inference from mount, host or source metadata |
| `unknown` | Leave all suffix-free text timestamps timezone-unknown; explicit offsets/FILETIME remain usable |
| `UTC` or explicit `+HH:MM` / `-HH:MM` | Analyst assigns the specified offset to supported suffix-free text timestamps |
| Invalid date / unsupported format / empty field | Separate `invalid`, `unsupported_format`, or `missing` status; no fabricated timestamp |

An offset is a fixed interpretation, not an IANA/DST timezone. Choose it only with independent support for the relevant period. The source's configured timezone and the workstation's timezone are never consulted. File modification times and neighboring records are not substitutes.

Original text and value remain unchanged. Timestamp metadata records original format, meaning, precision, normalized value, policy, parser version, interpretation basis and uncertainty in `detail.timestamp_interpretations`. Common timestamp rows retain their existing schema. The normal evidence display shows interpretation basis. Nanosecond canonical formatting does not imply nanosecond source precision: second-resolution values have `precision_ns=1000000000`.

New scripted ingestion accepts `--defender-time-policy`; guided ingestion uses `format-utc`. Direct file diagnostics accept `--time-policy`. Models have no policy-setting tool.

## Completeness and discovery presentation

Record metadata now separates structural status, decoding status, parsing status and individual timestamp normalization statuses. Unsupported/invalid/unknown-time timestamps produce limitations but do not make a structurally complete BM block incomplete. Missing END markers, fragmentation and decoding failures still produce partial records. Repeated fields keep separate ordinals and timestamp slots; absent fields are not invented.

Grouped BM summaries prioritize ImagePath, ProcessID, ProcessCreationTime, CreationTime, SessionID, Operations and parent/behavior fields. Other categories prioritize their executable, command, target, action or original status as appropriate. Selection keeps the original array indices and uses existing truncation/redaction helpers. Signature identifiers remain available through original inspection. Group equivalence, counts, exclusive authorization end and original-field verification restrictions are unchanged.

## Existing-case repair design

`artifacts/defender_maintenance.py` is a provider-independent service. `scripts/defender_maintenance.py` exposes read-only population diagnostics, a read-only preview and explicitly confirmed execution.

1. Select Defender files belonging to the specified source. Refuse shared-source content for repair rather than silently applying a source-specific policy elsewhere.
2. Start one consistent read transaction for preview, or `BEGIN IMMEDIATE` for execution.
3. Stream retained Base64 bytes in original offset order into a private, disposable file, one source file at a time. The reused private-directory facility applies restrictive permissions only when creating this new temporary directory; existing permissions are untouched.
4. Validate Base64, decoded original text, original locations, parser provenance, ordinal/offset continuity, EID construction, total byte size and the full original SHA-256. The temporary file named `snapshot.db` is a byte stream, not a SQLite database.
5. Reparse through the production parser. Require identical record boundaries, EIDs, original bytes/text, encoding, category, fields and grouping identities. Unexpected changes fail closed.
6. Replace only derived timestamp rows, normalization metadata, justified parsing status/limitations and parser version. Objects, source membership and original content stay unchanged.
7. Append per-record normalization history containing previous timestamps/status/limitations, policy and a repair-operation ID. Preserve all historical ingestion runs/errors unchanged. No artificial ingestion attempt or new evidence record is created.
8. Commit once after every file passes and temporary files are cleaned up. Failure, cancellation, disk-full or cleanup failure before commit rolls back the entire repair.

Execution requires `--apply --confirm`, and a mandatory activity intent precedes mutation. The completion records counts, policy and comparison digest. If completion auditing fails after commit, the existing audit boundary reports that the action completed but completion auditing failed. The durable intent and per-record repair IDs support reconciliation; do not infer rollback from that message. A cancellation concurrent with SQLite commit also requires checking the persisted state.

Identical repeat repair changes zero records and adds no per-record history. A deliberately different policy can add a new auditable normalization revision. Preview and execution both recompute the full checks; preview is not a grant to skip validation later. Repair metadata/history changes the existing logical case fingerprint, so fingerprint-bound derived indexes/results may become stale. Existing pinned read views remain their original snapshots; start new investigations after maintenance.

No case rebuild or reingestion of other families is needed. Retained originals must reconstruct the entire original file. Missing records, conflicting sources, tampered fields or incomplete retained byte coverage prevent repair. Do not bypass this by changing hashes. Such cases require a separately reviewed recovery from the original acquired file; this release does not delete or replace evidence automatically.

Close other writers/investigations before maintenance. Keep a consistent case backup under your usual case-management procedure. The transaction can require rollback-journal space proportional to changed database pages, plus temporary space for the largest retained log. Low disk space fails the operation rather than partially committing. No real-case repair duration is claimed.

## Provider-free inventory

The maintenance diagnostic reports:

- Record counts by category and parsing status.
- Records with/without at least one normalized timestamp.
- Timestamp counts by meaning and normalization status.
- Counts of recorded interpretation bases (legacy records have no basis metadata).
- Bounded representative original BM records and timestamp metadata.
- Unknown-record counts grouped by exact first 64 characters after a leading timestamp, with representative EIDs/text and truncation flags.

Unknown grouping is conservative prefix inventory, **not** semantic equivalence or incident deduplication. Counts cover the selected population; only the requested number of examples/groups is displayed. The real unknown population has not been inspected during development. Unknown content is never discarded or arbitrarily reclassified.

## Windows acceptance commands

Use the existing environment. No pip install is required.

```powershell
cd C:\tmp\locard
git pull
python .\locard.py --version
```

Expected: `Locard 6.180`.

Set the explicit case/source once:

```powershell
$casePath = 'D:\Locard\Cases\KFI-5070790-V2\case.db'
$sourceId = 'src-d3c195d3068e4906a805082df44c1a57'
```

Read-only baseline counts, timestamp semantics, unknown formats and original BM examples:

```powershell
python .\scripts\defender_maintenance.py --db $casePath --source $sourceId --examples 5 > defender-before.json
```

Preview complete original-byte validation and derived changes:

```powershell
python .\scripts\defender_maintenance.py --db $casePath --source $sourceId --preview --time-policy format-utc > defender-preview.json
```

Review the preview before explicitly authorizing execution:

```powershell
python .\scripts\defender_maintenance.py --db $casePath --source $sourceId --apply --confirm --time-policy format-utc > defender-repair.json
python .\scripts\defender_maintenance.py --db $casePath --source $sourceId --examples 5 > defender-after.json
python .\scripts\defender_maintenance.py --db $casePath --source $sourceId --preview --time-policy format-utc
```

The repeated preview should report `changed: 0`. Redirection affects JSON output only; long-running progress goes to stderr. Ctrl+C requests cancellation. Compare before/after categories, total records, parsing status and normalized-time counts. Expect unchanged total 297,949 only if that remains the actual selected population; do not require all 1,459 BM records to become parsed or all timestamps to normalize. Genuine limitations remain.

For an uncertain variant, preview `--time-policy unknown`, `--time-policy UTC`, or an independently justified fixed offset such as `--time-policy=-06:00`. These are explicit alternatives, not automatic recommendations for the reference case.

Review original timestamp interpretations and retained normalization history using an actual returned EID:

```powershell
python .\locard.py --db $casePath evidence show '<returned-EID>'
python .\locard.py --db $casePath evidence show '<returned-EID>' --raw --json
```

Repeat scoped grouped discovery:

```powershell
python .\scripts\discover_security_signals.py --db $casePath --source $sourceId --start 2026-11-17T06:00:00.000000000Z --end 2026-11-18T06:00:00.000000000Z --overview defender_groups --json
```

This window has an exclusive end. Compare time-unassignable records with the reported 6.179 baseline of 295,775, and inspect ImagePath in BM summaries. No zero-unknown-time acceptance criterion applies. Empty results with incomplete coverage never establish absence.

For future ingestion with the same explicit policy:

```powershell
python .\locard.py --db $casePath evidence ingest defender 'E:\ProgramData\Microsoft\Windows Defender\Support' --source $sourceId --defender-time-policy format-utc
```

Duplicate ingestion does not replace existing derivations; use the repair operation for retained version-1 records.

## Changed components and validation

Production: `artifacts/defender.py`, new `artifacts/defender_maintenance.py`, `artifacts/defender_query.py`, `artifacts/ingest.py`, `retrieval/defender_display.py`, `retrieval/evidence.py`, `v2_cli.py`; scripts `defender_artifacts.py` and new `defender_maintenance.py`. Version: `pyproject.toml`. Documentation/script allowlist: `.gitignore`.

Tests: new `tests/test_defender_acceptance.py`; three existing Defender test expectations were updated for the intentional timestamp distinction (unknown-time fixture now genuinely lacks time; arbitrary text has unsupported-format status rather than invalid-date status). No security assertion was removed.

Focused execution results are recorded below once final checks complete. No full suite, live provider request, actual case access, commit or push.


### Recorded focused results

- Defender acceptance, original Defender, security discovery, conversational integration, Prefetch, Registry, Browser parser and source-schema compatibility: **126 passed in 99.14 seconds**.
- Repair plus MFT regression subset after maintenance-receipt refinement: **30 passed in 17.20 seconds**.
- Defender acceptance plus original Defender after structural-status refinement: **46 passed in 26.71 seconds**.
- Final acceptance-specific suite including malformed-suffix protection, category/status inventory and unsupported-parser refusal: **27 passed in 13.94 seconds**.

These sets overlap; they are not an aggregate full-suite count. Synthetic fixtures and mock/scripted providers only. Tests cover explicit/default/unknown policies, precision, multiple timestamp meanings, complete/incomplete blocks, category-aware pointers, byte/hash validation, unchanged identities/membership/unrelated evidence, audit refusal, idempotency, rollback, cancellation and temporary cleanup. Initial development failures were corrected before these passing runs. Remaining live acceptance: exact coverage improvement and performance on the analyst's retained population.

Version execution returned `Locard 6.180`; `git diff --check` passed. Git's LF-to-CRLF advisory for `.gitignore` is informational. No commit or push.

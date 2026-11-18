# Locard 6.150 — Timeline responsiveness and presentation

Implemented 2026-11-15 against committed baseline `66e441e` (`better text 3`).
Changes remain uncommitted for manual acceptance. `pyproject.toml` is the application
version authority; this patch sets it to 6.150.

## Cause and correction

| Area | Cause | Correction |
|---|---|---|
| Timeline feedback | `cli._dispatch` wrapped status/search in the shared activity indicator, but omitted timeline. | Add `timeline: Retrieving timeline...` to that existing operation map. It surrounds `v2_cli.dispatch`, including retrieval and complete-group pagination, and exits before result rendering. |
| Compact timestamps | `mixed_display.compact_timeline` displayed the original nanosecond UTC strings. | Reuse `around_display.display_time`: integer half-up rounding to milliseconds, then replace the date/time separator for compact display. |
| Identity notes | Status independently appended unknown-identity and conflict notes; source detail emitted both original limitations. | `source_cli.identity_note` selects one identity note from each source's structured hostname/conflict state. Compact source details replace only the corresponding application-owned notes; other limitations remain. |

The indicator retains the existing 500 ms delay, cyan `progress` frame, white
`label` text, single-line ownership, Unicode/ASCII selection and cleanup. It does
not run while waiting for command input. JSON, redirected/noninteractive output,
file output, append output and paging suppress animation. Frame writes and clearing
remain inside the existing session-recording suppression context. No new timer,
query timeout, cancellation mechanism or audit event has been introduced.

## Precision and scope

Only the compact text time cell changes. Examples:

| Original UTC value | Compact UTC display |
|---|---|
| `2026-09-30T00:00:00.123499999Z` | `2026-09-30 00:00:00.123` |
| `2026-09-30T00:00:00.123500000Z` | `2026-09-30 00:00:00.124` |
| `2026-09-30T23:59:59.999500000Z` | `2026-10-01 00:00:00.000` |

The shared formatter uses integer nanoseconds, not floating-point seconds. Grouping
still uses original evidence IDs and unrounded timestamps. Two distinct timestamps
rounding to the same millisecond remain distinct displayed groups. Timestamp slots,
ordering, pagination, authorization/time filters, stored values, JSON and existing
raw/detailed renderers are unchanged. Displayed milliseconds are not new forensic
precision or an assertion that different artifact timestamp meanings are equivalent.

## Source limitations

For a single source with conflicting hosts, normal case status now says:

> Source computer identity is unconfirmed; conflicting hostnames were observed.

Normal source detail says:

> Source identity is unconfirmed. Conflicting hostnames were observed; evaluate host attribution per evidence record.

Unknown identity without conflict retains a separate unknown-identity note.
Multiple sources are identified by their source-page row number, including sources
with identical display names. An unknown source is not merged with a different
source's conflict. Unknown sources outside the bounded coverage page are counted
separately. Source-list conflicts retain their row scope and multiple-membership
warnings. Existing status limits (12 displayed limitation summaries) still apply
and explicitly report omitted summaries.

This is structured presentation selection, not arbitrary text deduplication:
`compact_limitations` replaces only the two known application-owned identity
messages when their corresponding structured condition holds on that source.
Detailed source/status output and source JSON retain the original limitations.
No host is inferred, no assertion is rewritten, and evidence-search warning
deduplication is unchanged.

## Files changed

- `forensic_assistant/cli.py`: shared operation map.
- `forensic_assistant/retrieval/mixed_display.py`: compact display time.
- `forensic_assistant/source_cli.py`: source-scoped identity presentation.
- `forensic_assistant/retrieval/status_display.py`: scoped identity notes and unlisted-source accounting.
- `pyproject.toml`: version increment.
- `tests/test_timeline_responsiveness.py`: new synthetic regressions.
- `tests/test_evidence_exploration.py`: update the old compact nanosecond presentation expectation; original-record equality assertion retained.
- `docs/LOCARD_SHELL_COMMAND_REFERENCE.md`: current timeline behavior.
- This document and `.gitignore`: include the release note in the repository's explicit documentation allowlist.

## Focused validation

Final focused run: **84 passed in 16.52 seconds**. No provider calls or live case
access. All databases used in these tests were disposable synthetic fixtures.
`git diff --check` passed without diagnostics.

```powershell
.\.venv\Scripts\python.exe -m pytest -q -p no:cacheprovider `
  tests/test_timeline_responsiveness.py tests/test_terminal_activity.py `
  tests/test_cli_responsiveness.py tests/test_evidence_exploration.py `
  tests/test_mft_presentation.py::test_same_values_one_group_different_values_and_records_separate `
  tests/test_mft_presentation.py::test_distinct_submillisecond_values_not_merged_by_rounding `
  tests/test_mft_presentation.py::test_multiple_fn_instances_do_not_lose_distinct_slots `
  tests/test_registry_ux.py::test_status_human_json_sources_and_historical_logs `
  tests/test_evtx_presentation.py::test_timeline_group_pagination_vs_structured `
  tests/test_evtx_presentation.py::test_raw_render_unchanged_and_detailed_ids_available `
  tests/test_evtx_presentation.py::test_mixed_timeline_keeps_mft_groups_and_prefetch_individual_slots
git diff --check
```

Coverage includes real indicator lifecycle around mocked timeline retrieval,
error/Ctrl+C cleanup, 500 ms delay, no competing indicator, terminal/file/JSON
suppression, semantic colors and recording suppression; half-millisecond and
calendar rollover; unchanged grouping, structured pagination and raw output;
same-source consolidation, different-source separation and unchanged limitation data.

The first focused run had 67 passes and one new test failure: it incorrectly
expected `ValueError` to escape dispatch instead of the existing exit code 2.
Only that test expectation was corrected. An intermediate corrected/expanded run
passed 28 tests before the final combined run above.

No full suite, live Windows terminal acceptance, provider requests or real-case
benchmarks were performed. This adds feedback rather than speeding up SQL.

## Manual Windows acceptance

After installing your reviewed checkout, check the version and open Locard:

```powershell
.\.venv\Scripts\python.exe locard.py --version
.\.venv\Scripts\python.exe locard.py
```

In an analyst-selected case, use a suitable time range (these are example dates):

```text
evidence timeline --start 2026-09-30 --end 2026-10-01 --text
evidence timeline --start 2026-09-30 --end 2026-10-01 --text --details
evidence timeline --start 2026-09-30 --end 2026-10-01 --json
evidence timeline --start 2026-09-30 --end 2026-10-01 --raw
case status
case status --details
case status --json
evidence source list
evidence source show
```

For a query lasting more than 500 ms, confirm the cyan spinner/white label clears
before results. Interrupt a slow query once with Ctrl+C; confirm a clean prompt
and no remaining animation. Fast queries should not flash an indicator. Compare
compact milliseconds with exact JSON timestamps, including distinct rows that
share a displayed millisecond. In source selection, choose the same source to
compare normal detail with `evidence source show <source-id> --details` and
`evidence source show <source-id> --json` (replace the placeholder with its actual ID).

For redirected output, set `$casePath` yourself to your acceptance database:

```powershell
.\.venv\Scripts\python.exe locard.py --db $casePath evidence timeline --start 2026-09-30 --end 2026-10-01 --json > timeline-acceptance.json
.\.venv\Scripts\python.exe locard.py --db $casePath evidence timeline --start 2026-09-30 --end 2026-10-01 --text > timeline-acceptance.txt
```

Neither file should contain spinner frames or terminal escape sequences. Repeat
the interactive checks in the supported Windows terminals you use. Manual
acceptance remains pending; no commit or push was made.

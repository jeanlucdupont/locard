# Locard 6.146 — Semantic presentation migration

## Revision and scope

Inspected/implemented 2026-11-14 in the development checkout, based on committed
HEAD `aab3080` on branch `main`. This document describes the uncommitted working tree. Application
version is declared only in `pyproject.toml`: 6.146. No commit, push, provider call,
full regression suite or real-case operation forms part of this work.

## Architecture and palette

`terminal.py` owns `TextSpan`, safe plain/ANSI projections, `field`, question and
shell-prompt helpers, capability detection and the palette. Domain renderers assign
roles; they do not select colors. No database query or model call selects styling.
`render_json` is now a plain JSON projection even when passed a colored palette.
`value_role` and obsolete type/legacy prompt roles were removed.

| Role | Terminal appearance | Meaning |
|---|---|---|
| shell_prompt | SGR 1;3;94 | Original bold italic blue command prompt |
| question | Blue | Entire input/confirmation request |
| value, command, syntax | Bright cyan | Neutral values and command syntax |
| heading | Bright white | Section title |
| label | White | Labels and explanatory prose |
| forensic_note | Brown on extended-color terminals; neutral fallback | Qualifications and uncertainty |
| success | Green | Explicit successful operational state |
| warning | Yellow | Operational warning |
| error | Red | Operational failure |
| unknown, punctuation | Gray | Unknown state and syntax delimiters |

A failed-logon evidence event, severity label, zero counter, or suspicious filename
is a neutral value. A hypothesis is not success. Stored error counts are values;
actual ingestion failure is an error. No keyword classifier assigns these colors.

## Shared mechanics

- `terminal.shell_prompt` renders the whole prompt using its dedicated role.
  `interactive.console.LineReader` recognizes the central prompt/question style
  during redraw; typed text retains normal styling. No editing algorithm changed.
- `cli_parser.semantic_help` uses argparse action metadata for compact columns,
  wrapped descriptions and narrow-terminal fallback. Native argparse color remains
  disabled. Parser choices and requirements are unchanged.
- `retrieval.layout.table` accepts a `TextSpan` cell as well as existing values.
  Widths and truncation use plain content, preserving the existing table layout.
  No additional result-query/materialization mechanism was introduced.
- `session_recording.ReaderProxy` and `read_response` decorate questions using the
  current session policy. The existing recording path still captures logical input
  once; no second recorder, schema or chain encoding was introduced.
- Existing Output/pager/file paths retain their plain-output policy. Explicit JSON
  contains no roles, decoration or human commentary.

## Command-family coverage and boundaries

| Family/path | Migrated presentation | Explicit boundary |
|---|---|---|
| Startup/case selection | Database labels/paths, questions, menu choices, startup errors | Branded banner remains its existing central capability-gated artwork |
| Help | Metadata syntax, headings, aligned descriptions, nested help | Long usage may naturally wrap in the terminal |
| Case | list/open/status/root/register/unregister and clone result fields | Case status delegates to the existing status renderer; no case behavior change |
| Settings / AI | Shared questions; provider/model fields; explicit readiness states; blank Details suppressed | Diagnostic payloads and raw provider-log capture remain plain verbatim diagnostic data |
| Ingestion | Category/count/status roles, structured completion role, progress role, forensic qualifications | Compact progress format/spinner and parser diagnostic payloads unchanged |
| Evidence | Search/show/timeline/around; Browser/EVTX/MFT/Prefetch/Registry and mixed tables | Raw diagnostic JSON intentionally plain; original field strings remain unchanged |
| Analyze | Session/logon/process/detection/relationship views | Evidence event severity is not application error severity |
| Investigation | Main results, interpretations, limitations, decomposition and synthesis/D2 headings; nested palette propagation | S1/S2/S3 canonical/bounded document content and explanation/packet pages retain plain rendering where serialized display participates in byte limits or replay contracts |
| Briefing / assessment | Unverified headings, canonical values/notes, assessment evidence and limitation spans; common question path | Technical `--details` JSON and existing concise narrative/chronology prose remain plain labels, not guessed subfield roles |
| Findings | IDs, states, origin, workspace/revision; dedicated decision-history human view | Full candidate support and decision payloads available in unchanged JSON; acceptance is not forensic verification |
| Reporting | Published result fields and recorded-history verification statuses; interactive human view | Persisted report HTML/Markdown/JSON, document links and content digests deliberately unchanged |
| Audit / activity | Session integrity states and limitations, activity table roles | Historical recorded payloads are not retrospectively reclassified or recolored |
| Unknown diagnostic result shapes | Plain JSON | No arbitrary JSON-to-colored-prose conversion |

These are deliberate boundaries, not claims that all prose has been decomposed
into colored value spans. Existing plain prose is safe and readable. In particular,
`investigation_ai/explanation_display.py` measures `render(...).encode('utf-8')`
while admitting pages: decorating that renderer would change budget behavior.
Moving that contract to a separate terminal projection requires its own bounded
rendering review. No scope/security/budget change is hidden in this migration.

## Files and functions

- Shared: `terminal.py`, `cli_parser.py`, `session_recording.py`, `terminal_activity.py`.
- Startup/ingestion: `interactive/{console,shell,creation,setup,setup_display,sources,advisory_display}.py`.
- Artifact/domain views: `retrieval/*_display.py`, `layout.py`, `investigation_summary.py`,
  `source_cli.py`, `activity.py`, `semantic/presentation.py`, `llm/presentation.py`.
- Application adapters: `workflow_cli.render`, `cli.py`, `ai/{cli,readiness}.py`,
  `briefing_{cli,canonical,report,workflow}.py`, `assessment.py`, `assessment_display.py`.
- Investigation presentation: `investigation_ai/{cli,presentation,decomposition,
  synthesis_consumer,d2_presentation,d2_reasoning}.py`; only render/palette plumbing
  changes, not request, grounding, journal or execution contracts.
- Reporting: `reporting.cli` result rendering/options and `reporting.recorded`
  human result rendering. Scripted JSON default preserved; interactive defaults to
  text with explicit `--json`/`--text` switches.

## Human/JSON and recording contracts

Visible content of colored and plain projections must match after SGR removal.
Safe escaping precedes terminal decoration. Persisted forensic values, JSON field
names, evidence IDs, timestamps, provenance and counters are not rewritten.
Legacy JSON syntax highlighting is intentionally gone, including `--raw` views.

Questions use the current shell color policy, so color toggling takes effect
without recreating the reader. Existing suppression prevents double recording of
nested prompts. Output capture retains ANSI stripping, secret redaction, byte
bounds, pager/progress handling and historical integrity checks.

## Validation and performance

Focused automated results are recorded below after the final targeted checks.
No full suite is authorized at this stage. Tests use synthetic data and mock
providers; filesystem tests publish only disposable fixture outputs.

A five-repeat in-memory benchmark rendered 10,000 synthetic rows, five spans per
row, using the same safe semantic projector:

| Projection | Median wall time | Output characters |
|---|---:|---:|
| Plain | 0.328187 s | 527,780 |
| ANSI | 0.296463 s | 977,780 |

Stripped ANSI output exactly equaled plain output. The small negative measured
overhead is timing noise, not evidence that coloring accelerates rendering.
This measures presentation only, not database retrieval or terminal throughput.

## Manual Windows acceptance

From the test checkout after installing the reviewed changes:

```powershell
.\.venv\Scripts\python.exe locard.py --version
.\.venv\Scripts\python.exe locard.py
.\.venv\Scripts\python.exe -m forensic_assistant.cli
.\.venv\Scripts\locard.exe
.\locard.ps1
```

In the same terminal compare the banner, restored prompt, question styling and
help columns. Use only a disposable synthetic case for mutations:

```text
help
help all
help audit
help evidence search
case list
case status
ai status
evidence search --limit 3 --ids
evidence search --limit 3 --json
settings color off
help evidence search
settings color on
```

Exercise cursor movement, history, Delete/Backspace, horizontal scrolling,
Unicode, narrow window and Ctrl+C. Confirm typed input is not prompt-colored.
Review an unverified hypothesis/forensic caveat versus an operational error.
Check a zero count is neutral. Review an existing synthetic findings history and
report verification in both text and JSON modes.

```powershell
.\.venv\Scripts\python.exe locard.py --help > .\help-plain.txt
$env:NO_COLOR='1'
.\.venv\Scripts\python.exe locard.py --help
Remove-Item Env:NO_COLOR
.\.venv\Scripts\python.exe locard.py --no-color --help
```

Repeat under PowerShell 7 and Windows PowerShell 5.1 where policy permits,
Windows Terminal and Console Host. Check redirection contains no raw ESC bytes.
Do not alter execution policy merely to run acceptance. Verify the disposable
session recording has readable plain output, redacted secrets and a valid chain.

Manual visual acceptance remains pending; mocked terminal capabilities do not
prove every Windows host/font combination renders identically.

## Recorded focused results and qualifications

These are separate, overlapping focused sets, not a unique total or a full suite:

- Artifact/investigation presentation: **128 passed**, 48.26 s (fresh disposable
  publication outputs outside the filesystem sandbox).
- Shared help/terminal/case/AI/audit/report checks: **186 passed, 2 failed,
  1 deselected**, 120.59 s. The two failures were old ingestion-feedback fixtures:
  EVTX minor version 3.2 is now supported, so the revised fixture explicitly
  damages the header checksum; Registry companions now have their own summary.
  Assertions still protect retained data and unchanged ingestion rows.
- Follow-up ingestion feedback/terminal usability: **81 passed, 1 deselected**,
  42.14 s. The excluded test asserts no doubled backslashes anywhere, although
  the existing original-EventData diagnostic intentionally escapes them.
  That assertion and production escaping remain unchanged.
- Complex renderers/recorded reports/terminal checks: **232 passed, 1 failed,
  1 skipped, 7 deselected**, 134.14 s. The failure was the briefing CLI fixture
  using the default database under mandatory auditing. It now uses a disposable
  synthetic case rather than bypassing audit authorization.
- Final briefing, new migration checks and guided feedback: **38 passed**,
  39.54 s; this includes the corrected CLI fixture and both ingestion fixtures.
- Python 3.14.6 standalone metadata-help/native-color suppression smoke: passed.
  Focused pytest runs use the checkout Python 3.12.14 virtual environment; Python 3.11 was not available for a separate run.
- Production Python AST parsing and `git diff --check`: passed.

Initial expanded checks also exposed seven older canonical-briefing tests using
removed flag-style commands (`--analyze`, `--import-json`, `--export-json`). They
fail in argument parsing, before rendering. They were not weakened or silently
counted as passes; their command migration is outside this presentation patch.
Windows PowerShell 5.1 launch tests are blocked by `AuthorizationManager check
failed`; no policy or permissions were changed. Mock Win32, direct/module/console
launch and other focused checks do not substitute for manual 5.1 acceptance.

Other stale presentation assertions updated in this patch concern retired role
names, neutral counters, relationship labels, raw JSON becoming uncolored and
current canonical CLI paths. Exact evidence/counter/JSON equality checks remain.
The corrected EVTX fixture uses the existing in-process decoder fixture, because
monkeypatches do not propagate into spawned parser workers.

The working tree is ready for review of the migration and documented boundaries,
not a claim that the repository's complete regression suite is green. No full
suite was run. Historical forensic bytes were not revalidated by this task.

Final shared policy/progress/readiness/CLI/recording/help set: **121 passed, 1 deselected in 59.59 s**. The deselection is the policy-blocked Windows PowerShell 5.1 launcher.

Editor/completion/prompt/shutdown spot checks: **24 passed**; the two additional
AI-shell prompt cases initially used removed `exit` syntax and depended on first-run
provider setup. After changing the test helper to `quit` and isolating setup from
this prompt-only test, **2 passed in 2.55 s**. Prompt role expectations in the
existing shell, completion and session tests now use `shell_prompt`. No production
command aliases or provider behavior were changed to satisfy these tests.

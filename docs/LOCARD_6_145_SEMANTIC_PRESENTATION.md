# Semantic presentation foundation and command help

Implementation date: 2026-11-14. Source version is resolved from `pyproject.toml`; no additional runtime version constant was introduced. Manual acceptance is pending.

## Architecture and scope

The prior architecture already provided `terminal.Palette`, capability checks, domain renderers, layout helpers, `Output`, and bounded session recording. This release extends those components. It does not replace artifact displays, application services, parser validation, investigation contracts or forensic storage.

`terminal.TextSpan` is a frozen dataclass containing text and an explicit role. `render_spans` produces a plain string by default or applies the existing `Palette` supplied by the caller. The two projections share the same safe text. Untrusted ESC, carriage return, control, surrogate and formatting characters are escaped; Unicode printable text is retained. Newlines and tabs remain available for intentional layout. Unknown role names fall back to the neutral label role. Supplied legacy ANSI is escaped as content, not executed or nested.

`write_spans` captures the plain projection once through the existing recording API, then emits the terminal projection under capture suspension. It checks the destination stream's existing color policy. No semantic roles are inserted into JSON or session events. Callers should pass bounded lines or sections rather than collect unbounded evidence output.

## Authoritative palette

All mappings remain in `forensic_assistant/terminal.py:STYLES` and `Palette`.

| Role | SGR / appearance | Meaning |
|---|---|---|
| value | 96, bright cyan | Neutral values, counts and identifiers |
| command / syntax | 96, bright cyan | Commands, options, metavariables, choices |
| question | 94, bright blue | Analyst question, distinct from shell prompt |
| heading | 97, bright white | Section heading |
| label | 37, normal white | Label or ordinary explanation |
| success | 32, green | Explicit operational success |
| warning | 33, yellow | Explicit operational warning |
| error | 31, red | Actual error |
| unknown | 90, gray | Unknown/unavailable state |
| punctuation | 90, gray | Syntax delimiters |
| forensic_note | Existing extended brown 38;5;136; otherwise neutral 37 | Forensic qualification, never a yellow fallback |

Legacy `key`, string/number/boolean roles, prompt roles and evidence-ID styling remain for unmigrated code. They are not the API for new semantic views. Text is never classified by words such as ERROR, blocked, failed or success. Existing textual qualification labels must remain; the renderer does not invent or rewrite forensic caveats.

## Color policy and branding

Existing `enabled`, `capable`, Windows VT initialization, Unicode support and per-stream handling remain authoritative. `NO_COLOR` presence, explicit no-color, a disabled shell palette, JSON/file output and incapable/redirected streams disable styling at the relevant output boundary. Low-level `render_spans(..., Palette(True))` deliberately permits deterministic encoding tests; production callers obtain palettes through the existing policy.

The branded resources are unchanged. Startup banner gating remains as implemented: NO_COLOR and redirection suppress ANSI; changing shell color later affects subsequent output, not the previously displayed banner. This release does not change fonts, Unicode width handling, cursor control or Windows console initialization.

## Help implementation

`LocardParser` disables native argparse color using the public `color=False` constructor parameter when the installed Python exposes it. Older supported Python versions receive no unsupported parameter. Python's private color module is not patched.

`semantic_help` builds spans from parser actions, argument groups and subparser metadata. It uses argparse's existing argument/default expansion helpers for metavar, nargs, choice and description expansion. Syntax delimiters receive punctuation roles; action syntax receives cyan roles; headings and descriptions have separate roles. It does not recolor already formatted prose or infer status from words.

Required options remain unbracketed, optional options bracketed, mutually exclusive alternatives retain their group delimiters, and hidden help actions/options remain suppressed. Parsing and error handling remain unchanged. Existing helper APIs inside argparse still constitute a compatibility seam; the supported Python checks cover the paths used here.

Shell catalog, `help`, `?`, `help all`, built-in help and nested detailed help share the new roles. The command tree uses a bounded first-line synopsis (90 characters), with complete descriptions preserved in detailed help. Detailed descriptions are wrapped using plain safe text. Usage/action syntax may still be long and wrap naturally in narrow terminals; full display-cell/grapheme layout is deferred.

Explicit no-color/JSON flags propagate to nested help before its early exit. Parser reuse resets this help-only state; no global mutable rendering mode was added.

## Prompt and representative views

`shell_prompt` assigns cyan to the case name and gray to brackets/separator. Typed input remains unstyled. The console editor recognizes this exact trusted prompt projection and reapplies its roles to the visible prompt portion during redraw, including horizontal clipping. Arbitrary input ANSI is not trusted. Legacy prompt recognition remains for callers not yet migrated.

The shared question role is available. Broad question/menu migration is deferred rather than changing workflow input behavior in this foundation release.

Two small views demonstrate reuse:

- `settings version`: existing text and source version, with a label/value split.
- Read-only `case root`: labeled root path and the existing effect qualification. Its JSON mapping is unchanged. Root mutation confirmations are not redesigned.

`workflow_cli.render` accepts an optional palette; CLI adapters pass their existing stream/session policy. Services continue returning ordinary mappings.

## JSON and recording

Explicit JSON serialization and forensic schemas are unchanged. Tests exercise unchanged field sets and parseability, plain file output, and the existing sanitization protections. No spans enter service data.

`session_recording.Recorder.output` now strips complete ANSI sequences **before** UTF-8 byte bounding. This prevents an otherwise complete color sequence being cut into a persisted fragment and avoids charging color bytes against visible-output capacity. Existing redaction, overlap handling for secrets, limits, omission counters, correlation identifiers and chain formats remain in place. Display text is not replaced with redacted text.

`write_spans` uses a plain capture plus suspended terminal write. Legacy producers still use the existing recorder/stream paths, now with ANSI removed before byte accounting. Prompt capture, stream coalescing, pager deduplication, operation exclusions and history verification are retained. This is not a general redesign of hostile arbitrary terminal protocols; new semantic spans escape control characters before reaching capture.

## Migrated and deferred files

Production changes: `terminal.py`, `cli_parser.py`, `interactive/help.py`, `interactive/shell.py`, `interactive/console.py`, `workflow_cli.py`, CLI rendering adapters, and the narrow recording byte-boundary correction. `pyproject.toml` contains the version increment.

Deferred role consumers are inventoried in `LOCARD_PRESENTATION_ARCHITECTURE_AUDIT.md`: artifact `retrieval/*_display.py`, ingestion setup/creation summaries, source views, provider/readiness views, advisory and investigation renderers, semantic views, findings and recorded reporting. Their domain semantics must be preserved during later migrations. Human JSON fallbacks remain for recorded-history details, unadapted workflow kinds and diagnostic results; explicit JSON contracts are not changed to improve human appearance.

`Output`, table layout, paging and file publication remain shared infrastructure. No replacement palette, database query, provider call, evidence rehydration or audit-chain reconstruction was added to presentation.

## Validation and limitations

Provider-free synthetic tests cover roles and counterexamples, controls, plain/ANSI equality, unknown roles, full parser-tree construction, nested no-color propagation, help metadata/choices/defaults/mutex requirements, prompt editing, representative views, capture limits, split stream ANSI, redaction and session verification. Existing focused help/color tests were updated only to use the canonical command paths introduced before this release and disposable recording roots; their content, JSON, publication and parser assertions remain.

Final focused selection: **235 passed, 13 deselected in 108.34 seconds**. Separately, **6 passed, 29 deselected in 8.34 seconds** for file-output tests outside the sandbox (241 distinct passing tests across these selections). No full suite or live provider requests were run. `git diff --check` passed.

The final selection covered semantic presentation, hidden help, terminal color/initialization/activity/usability, session recording and CLI consolidation. Its 13 exclusions were two blocked PowerShell 5.1 cases, six separately executed file-output cases, and five unrelated legacy terminal-usability cases (two bare process-tree guidance cases, missing-time/candidate messaging, pager help wording and service-installation account presentation). No skipped or failed test is counted as passing.

- Python 3.14: direct synthetic parser/semantic-help probe passed, including `parser.color is False` and absence of native magenta/green syntax colors. Main pytest runtime: Python 3.12.14. Python 3.11 was not available for a runtime check.
- Six existing file-output/append regressions passed outside the sandbox (8.34 s). Three atomic publication tests were denied inside the sandbox, including when temporary files were inside the workspace. No publication safeguards or assertions were changed.
- Windows PowerShell 5.1 launcher checks were blocked by `AuthorizationManager check failed / UnauthorizedAccess`. Execution policy was not changed. PowerShell 7, direct Python, module and console executable redirected help are exercised by the focused tests.
- Earlier broad terminal regression selection also included old pre-consolidation process-tree/pager commands and an unrelated service-installation display assertion. Those unrelated tests/production paths were not changed; the final selection explicitly excludes them. This is not a claim that the entire historical terminal suite is green.
- Synthetic benchmark: 1,000 lines / 3,000 prebuilt spans; median of five repeats of ten renders on the development runtime. Plain: **4.718 ms**; ANSI: **5.188 ms**; legacy ANSI concatenation without equivalent control sanitization: **1.715 ms**. The additional approximately 3.5 ms per 1,000 colored lines includes safety/projection work, not I/O. These are local measurements, not throughput guarantees.

Live Console Host/Windows Terminal visual equivalence, native input editing and the unavailable/blocked configurations remain manual acceptance items. No real case or historical transcript was used to test this change.

## Manual Windows acceptance

From the updated test checkout, using its existing environment:

```powershell
.\.venv\Scripts\python.exe locard.py --version
.\.venv\Scripts\python.exe locard.py --help
.\.venv\Scripts\python.exe -m forensic_assistant.cli evidence source list --help
.\.venv\Scripts\locard.exe audit diagnostics --help
.\locard.ps1 audit diagnostics --help
.\.venv\Scripts\python.exe locard.py --no-color evidence search --help
.\.venv\Scripts\python.exe locard.py evidence search --help > "$env:TEMP\locard-help.txt"
Get-Content "$env:TEMP\locard-help.txt"
.\.venv\Scripts\python.exe locard.py case root --json
.\.venv\Scripts\python.exe locard.py
```

Inside the shell, use an existing selected workspace without running evidence/provider commands:

```text
help
?
help all
help evidence source list
help audit diagnostics
settings version
case root
settings color off
help audit diagnostics
settings color on
help audit diagnostics
quit
```

Check cyan commands/choices (including ERROR), white descriptions, gray punctuation, no magenta syntax, complete detailed descriptions, and immediate color-off behavior. Exercise arrows, history, backspace/delete, Unicode input and Ctrl+C; typed commands should remain in the terminal input color. Repeat in Windows Terminal and Console Host, with PS 7 and PS 5.1 where script execution is permitted. Do not alter machine execution policy solely for these checks.

For NO_COLOR, temporarily set it in the process and restore its prior value afterward; an empty value must also disable Locard color where the shell can preserve an empty environment variable. No banner/help ANSI should enter redirected output. Existing application audit verification remains available via `audit verify --application --json`; inspect only the disposable acceptance recordings when testing redaction.

No commit or push was made. Release acceptance remains the analyst's decision.

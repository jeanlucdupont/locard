# Locard terminal presentation and color architecture audit

Date: 2026-11-14. Application version: **6.144**. Branch: `main`.
Inspected HEAD: `0dff1c567376dffdb72993078706cdafc09490dc`.
The working tree was clean before this audit. This document is the only intended addition; application source, tests, configuration and version were not changed.

## 1. Executive summary

Locard already has a central ANSI palette, shared terminal capability checks, a managed output layer, reusable table formatting and domain-specific human renderers. Extend these components rather than introducing a parallel presentation framework.

The main gaps are semantic, not an absence of infrastructure:

- Many existing roles describe Python data types (`string_value`, `number_value`) rather than meaning. Labels and command syntax share `key`; limitations and operational warnings often share `warning`.
- Detailed help can acquire an independent palette from Python 3.14 `argparse` before Locard applies whole-line styling. This explains a concrete source of magenta and inconsistent option/choice colors. It is standard-library behavior, not evidence of a third-party styling library.
- Human output is assembled in multiple renderers and command handlers. Some interactive paths still fall back to JSON. Explicit JSON output generally disables Locard color, but serialization and human presentation are not uniformly separated.
- Session recording captures rendered strings and strips ANSI. Semantic roles are not retained. A new presentation layer must preserve recording boundaries, redaction, limits and integrity behavior.

Recommended direction: retain `terminal.py` as the capability/palette foundation; add a small semantic span representation and plain/ANSI rendering boundary; adapt existing tables and help; migrate individual human renderers incrementally. Keep JSON serialization independent and retain original forensic data contracts.

**Evidence standard:** “Confirmed” below means observed in source, not a successful runtime acceptance test. Test references describe assertions present in code, not tests executed for this audit. No tests, provider calls, ingestion, live-case inspection or terminal acceptance sessions were run. Runtime observations were limited to read-only inspection of Python/argparse versions and source. Risks explicitly described as unverified require the proposed synthetic checks.

## 2. Current presentation architecture

```text
locard.py / module / console script / PowerShell wrapper
  -> cli.main -> recording scope -> terminal initialization -> command or shell
  -> structured services + command-specific human renderers
  -> Palette / table helpers / direct print / Output
  -> session capture and ANSI stripping -> original stream / pager / file
```

This is a conceptual trace, not a claim that every command passes through `Output`.

| Component | Source-confirmed responsibility | Recommendation |
|---|---|---|
| Entrypoints | `locard.py:1–6`, `pyproject.toml:19–20`, `locard.ps1:1–16`; Python and console entrypoints converge on `cli.main` | Reuse; do not duplicate terminal initialization in launchers |
| Initialization | `forensic_assistant/cli.py:190` (`main`, `_recorded_main`, `_main`); shared Windows VT setup before interactive output | Preserve |
| Capability and styling | `terminal.py:29–91`: `windows_ansi`, `initialize`, `capable`, `enabled`, `Palette` | Extend semantic roles; retain per-stream capability checks |
| Managed output | `output.py:293–397`, `Output`: output selection, spool, JSON, capture, paging, publication | Reuse as an output boundary; make human/JSON intent explicit |
| Tables | `retrieval/layout.py:44–87`, `table`: safe cells, width calculation, column roles and cell callbacks | Adapt roles without replacing layout machinery |
| Domain presentation | `retrieval/*_display.py`, `investigation_ai/presentation.py`, `llm/presentation.py`, `source_cli.py` | Retain forensic meaning in domain adapters |
| Interactive input | `interactive/shell.py`, `interactive/console.py`, setup and metadata modules | Separate ordinary shell prompt from analyst questions |
| Recording | `session_recording.py`: stream proxy, logical output capture, prompt capture, redaction and diagnostic handler | Preserve contracts; capture plain projection once |

Formatting is partly centralized, but choosing a role remains distributed. That is appropriate when a domain adapter knows the meaning of a field; it is problematic when adapters infer meaning from wording or use a type-based role for operational state.

## 3. Color and ANSI inventory

### 3.1 Central palette

`forensic_assistant/terminal.py:9–26`, `STYLES`, is the main color definition. `Palette.__call__` at lines 81–91 adds SGR/reset around text when enabled.

| Current role | SGR | Current meaning / mismatch |
|---|---|---|
| `prompt` | `1;3;94` | Bold italic bright-blue shell prompt; not an analyst question |
| `ai_prompt` | `1;3;95` | Bold italic bright-magenta AI prompt; conflicts with proposed normal palette |
| `key` | `36` | Cyan labels, JSON keys, help commands, table headers; conflates syntax and labels |
| `string_value` | `32` | Green strings; neutral values are not positive status |
| `number_value` | `35` | Magenta numbers; conflicts with proposed palette |
| `boolean_value` | `34` | Dark-blue booleans; type-based rather than semantic |
| `evidence_id` | `1;36` | Bold cyan identifier |
| `heading` | `1` | Bold terminal-default color, not explicitly bright white |
| `secondary_text` | `0` | Default/reset text; not explicit gray |
| `inactive` | `2` | Dim; terminal-dependent approximation of gray |
| `warning` | `33` | Yellow; used for both operational warnings and limitations |
| `error` | `31` | Red |
| `success` | `32` | Green |
| `info_bar` | `3;30;107` | Italic black on bright-white background, pager status |
| `forensic_note` | `33` | Basic fallback yellow; indexed `38;5;136` when extended color is inferred |

`Palette` infers extended forensic-note color from `WT_SESSION`, `TERM` containing `256color`, or `COLORTERM` truecolor/24bit. This is a capability heuristic, not a guarantee that every renderer displays the same brown. Basic 16-color terminals have no portable exact brown; retain the textual annotation label and decide an explicit fallback.

`value_role` (`terminal.py:94–101`) classifies types and recognized evidence-ID prefixes. It does not implement general keyword classification. Its prefix tuple at line 27 includes EVTX, Prefetch, MFT and Registry, but not Browser. Adding generic semantic identifiers should avoid another artifact-prefix heuristic.

### 3.2 Literal ANSI and control operations

| Location | Behavior | Treatment |
|---|---|---|
| `resources/banner.txt:1–6` | Embedded blue, white, bright-blue and blue-background SGR | Preserve branding; treat as trusted resource with plain alternative |
| `resources/ender.txt:1–3` | Embedded blue and bright white | Same |
| `resources/liner.txt:1`, `resources/thin.txt:1` | Embedded blue | Same |
| `terminal.py:7–8,81–91` | SGR matcher, reset, palette construction | Centralize here; legitimate encoding layer |
| `terminal.py:140–165` | `wrap_line` recognizes zero-width SGR and resets wrapped rows | Reuse, but semantic layout should measure plain text before encoding |
| `terminal.py:176–218` | `clear_screen`, `replace_progress_line`, `redraw_viewport` emit capability-gated cursor controls | Preserve; cursor movement is not a semantic color role |
| `terminal.py:229` onward | Windows console fallback operations | Preserve capability support |
| `output.py:97–135` | Escape-key decoding | Input protocol, not color styling; do not remove as palette cleanup |
| `session_recording.py:36,80` | CSI/OSC recognition and removal | Recording safety boundary, not display palette |

A source/resource scan found actual ESC characters in the four resource types above, rather than scattered literal ESC strings in command implementations. Searches found no application imports of Rich, Colorama, Pygments or Termcolor. This does not prove transitive dependencies never emit terminal output; it establishes that those libraries are not Locard's application presentation API.

### 3.3 Command-local role decisions and renderer inventory

Paths below are relative to `forensic_assistant/`. These are significant presentation decisions, not an exhaustive list of every print statement.

| File/function or region | Behavior and concern | Reuse/refactor |
|---|---|---|
| `interactive/help.py:9–35`, `command_help`, catalog output | Commands use `key`; descriptions plain; delegates detailed parser help | Reuse catalog, adapt semantic roles |
| `cli_parser.py:57–70`, `InteractiveParser.print_help` | Styles whole formatted lines based on leading dash, usage or trailing colon | Replace line inference with structured help adapter |
| `interactive/shell.py:54–65,109,279,369–372` | Shell prompt, AI prompt and error messages | Preserve control flow; change presentation only |
| `interactive/console.py:163–180`, editor paint logic | Recognizes exact `Palette(True)('prompt', plain_prompt)` form | Adapt before introducing styled questions; otherwise redraw can lose style |
| `interactive/setup_display.py:12–22`, `role`, `category_line` | Status-to-role mapping; zero duplicate/error counts can be green | Use neutral numeric counts; explicit status separately |
| `interactive/setup_display.py:188–193` | Completion-role decisions from exact text prefixes | Replace wording-dependent decision with explicit status |
| `interactive/setup.py:62,468–476,620–622` | Discovered counts and conditional summary count colors | Refactor presentation seam only; preserve ingestion decisions |
| `interactive/creation.py:138–187` | Summary rendering beside completion/control logic | Extract presentation incrementally, not workflow rewrite |
| `source_cli.py:78,187,200,214,250` | Human list/preview/update/assignment/show; type roles and warning limitations | Reuse renderers, distinguish annotations |
| `ai/cli.py:253–296`, `render` | Selected status strings map to success/inactive/error; saved-message exact comparison | Prefer explicit operational status fields, preserve provider behavior |
| `ai/readiness.py:248–250` | Readiness warning/success | Retain operational semantics |
| `retrieval/analyst_display.py:12–31,70,113,159,218` | Event-label/status mappings, forensic notes, logon/detection/process-tree tables | Keep explicit event meaning; distinguish recorded event outcome from application failure |
| `retrieval/search_display.py:139–188` | Context/coverage warnings and ASR forensic note | Keep qualifications, assign annotation versus operational warning explicitly |
| `retrieval/browser_display.py:27,73,89,93,123` | Browser blocks, note-role choice, grouped search/shared notes | Reuse semantics and grouping |
| `retrieval/mft_display.py:134,200` | MFT blocks and timeline | Preserve SI/FN and timestamp meaning |
| `retrieval/evtx_display.py:55,148,169,179` | Blocks, segments, timeline and around | Preserve original/interpreted field separation |
| `retrieval/prefetch_display.py:14`, `around_display.py:58`, `mixed_display.py:53` | Family and mixed timeline/group renderers | Adapt shared roles without flattening artifact meaning |
| `retrieval/analysis_display.py:30,95,147,249` | View abstraction and session/investigation notes | Reuse existing view boundary |
| `investigation_ai/presentation.py:176–340` | Supported statuses, lookup counts, termination, limitations | Refactor presentation only; do not alter epistemic or termination state |
| `llm/presentation.py:20–131`, `interactive/advisory_display.py:28–43` | Separate advisory/answer layouts | Adapt roles, retain unverified/grounded distinctions |
| `reporting/cli.py:128–146`, `render_result` | Human report-operation result | Low-risk migration candidate |
| `v1_cli.py:174–187`, `v2_cli.py:319,335` | Compatibility rendering, including JSON fallback | Keep compatibility; retire fallback only after callers are accounted for |

Other palette consumers include `activity.py`, `interactive/sources.py`, `interactive/metadata.py`, `semantic/presentation.py`, `investigation_ai/cli.py`, and retrieval `registry_display.py`, `show_display.py`, `status_display.py`, `investigation_summary.py`. They should join a migration inventory, not be rewritten as a prerequisite to the shared layer.

## 4. Fit to the desired semantic model

| Proposed semantic role | Existing support | Required adjustment |
|---|---|---|
| Neutral value: cyan | Type-based `value_role` | Explicit neutral role independent of string/number/bool |
| Command/selectable syntax: cyan | `key` used for commands | Dedicated syntax role; choice `ERROR` remains neutral syntax |
| Question/confirmation: bright blue | Questions often plain `Reader.read` strings | Explicit question role; keep normal shell prompt separate |
| Forensic annotation: brown | `forensic_note`, inconsistently used | Classify limitations at producer, define terminal fallback |
| Section heading: bright white | Bold/default `heading` | Central palette adjustment |
| Label/description: normal white | `key` or plain | Separate label from cyan syntax/value |
| Positive operational status: green | `success` | Retain only explicit positive state, not zero failure count |
| Operational warning: amber | `warning` | Stop using it for every forensic qualification |
| Failure/error: red | `error` | Preserve explicit failures; never classify arbitrary text by keyword |
| Unknown/unavailable/not checked: gray | `inactive`/plain | Explicit unknown role independent of falsy values |
| Syntax punctuation: gray | Mostly plain | Separate punctuation spans where useful |

The palette can support these roles without altering forensic structures. The missing piece is a role-preserving representation until rendering. Current `Palette` immediately returns a string, so later consumers cannot distinguish a label, value or limitation except by interpreting that string.

Keep textual status labels, uncertainty and limitations visible in plain output. Do not infer success from `0`, failure from a literal `ERROR` choice, or execution from an event label. Numeric counters should remain neutral unless a separate operational state is explicitly presented.

## 5. Help-rendering assessment

### Confirmed origins

- `interactive/help.py` controls the shell command catalog and built-in help.
- `command_surface.py:8–35` supplies canonical families/paths; reuse this registry.
- `cli_parser.py:23–29`, `LocardParser.__init__`, calls `argparse` without disabling native color.
- `InteractiveParser.print_help:58–70` receives already formatted help and styles whole lines. `configure_interactive:93` and `classify_help:105` configure context and option groups, not a full semantic token renderer.

Two locally installed standard-library implementations differ:

| Inspected runtime | Source observation |
|---|---|
| Development `.venv`: Python 3.12.14 | Its `argparse` has no native help-color palette |
| Installed Python 3.14, `C:/Users/jl-du/AppData/Local/Programs/Python/Python314/Lib/argparse.py` | `ArgumentParser` defaults `color=True` (around 1882/1899); formatter color setup at 199–206 and 2728–2730 |
| Python 3.14 `_colorize.py:157–171` | Usage/heading blue, program magenta, options cyan/green, metavariables/labels yellow; separate summary/detail styles |

Python 3.14 `_colorize.py:274–316` also has its own environment/capability policy: `PYTHON_COLORS`, truthy `NO_COLOR`, `FORCE_COLOR`, `TERM` and platform checks. Locard checks **presence** of `NO_COLOR`. These policies are not identical.

Therefore commands, options, positional labels, choices and usage punctuation can differ because one path is Locard's catalog, another is plain argparse, and another is native-colored argparse wrapped by Locard. Embedded escapes can also defeat line-prefix classification or reset an outer style. This is source-confirmed potential behavior; no claim is made that a specific user terminal/run used Python 3.14 without inspecting that run.

### Recommendation

Disable native argparse color through its supported `color=False` facility when available, with compatibility for the project's Python >=3.11 support. Do not modify private `_colorize` globals. Then use a Locard help adapter based on parser actions/groups and the existing command catalog, assigning explicit syntax, label, heading and punctuation roles. Preserve parser validation, choices, defaults, metavar content, hidden compatibility commands and grouping. Avoid recoloring a completed help string with regular expressions.

## 6. Human output, JSON and application boundaries

Most services provide mappings/lists suitable for both renderers, but the boundary is uneven.

| Path | Confirmed behavior | Implication |
|---|---|---|
| `terminal.render_json:104–138` | Plain `json.dumps(... ensure_ascii=True, indent=2)` when disabled; type-colored JSON otherwise | Useful legacy human fallback, not a universal machine-output boundary |
| `Output.__init__:293–303`, `Output.json:336` | Palette eligibility excludes JSON/file output; rejects JSON/pager conflict; sanitization hook before serialization | Preserve machine contracts and secret registration |
| `cli._dispatch:332` and `emit:335` | Mixes human branches and generic JSON emission | Explicit human adapters should cover intentional defaults |
| `cli.py:242–267` | Recorded-history show uses JSON serialization; workflow falls back to JSON | Some interactive commands remain raw JSON by design/implementation |
| `cli.py:372–434` | Report generation, investigation and source operations have differing human/JSON branches; ai-history uses generic emission | Inventory per subcommand before migration |
| `workflow_cli.py:149–184`, `render` | Known kinds rendered as text, unknown kinds JSON fallback | Add supported human adapters without changing service schemas |
| `reporting/recorded.py:234–247` | JSON result/error paths and cancellation text | Verify stdout purity for each JSON invocation, not only serializer |
| `workflow.py:135–143` | Captures/redirects stdout/stderr for JSON paths | Existing protection to retain |
| `briefing_cli.py:145–146` | Human import explanation/narrative before confirmation | Potential JSON contamination seam; requires command-specific synthetic verification before calling it a defect |
| `v2_cli.py:184,201,237,287` | Presentation context/grouped text accompanies structured results | Do not mechanically remove human context needed by existing renderers |

`retrieval/presentation.py:13–31` supplies `safe`, Unicode-preserving `safe_text`, `safe_path`, and structured Windows `human_error`. Reuse these escaping boundaries. A semantic span is not permission to print untrusted escape/control characters. `retrieval/analyst_display.py:34`, `evtx_context`, performs a human-display context query: presentation is not uniformly pure formatting today. A future web adapter must use an authorized application service for this data, not silently perform its own evidence lookup.

Smallest separation: explicit human-render methods consume unchanged structured results; explicit JSON mode uses one ANSI-free serializer and sends operational diagnostics to stderr where compatible. Keep existing JSON fields, ordering guarantees where required, null semantics and publication behavior. Do not insert color metadata into forensic JSON. Treat output-file formats separately from terminal selection.

## 7. Audit and session-recording interaction

Confirmed in `session_recording.py`:

- `Redactor` (72 onward) strips recognized CSI/OSC sequences at line 80 before persisted text is redacted. Captured display normally becomes ANSI-free text.
- `output` (317) and `stream` (338) handle bounded output and coalescing. `Stream` (445) forwards original text to the display while recording a sanitized copy.
- `read_response` (398) and `ReaderProxy` (434) record logical prompts/responses while suspending low-level echo capture. This avoids recording every editor repaint as a separate answer.
- `Output.write` (`output.py:330`) records an already rendered string on a logical channel, then suspends duplicate stream capture. Pager/file paths also use suspension (`finish`, around 394–397).
- Semantic roles are not retained in persisted output. Stripping ANSI cannot recover them.
- `DiagnosticHandler` (460) and `execution` (479–512) install diagnostic capture and adjust logger levels, then restore them. `terminal_activity.py:35–44` disables its normal spinner when relevant debug loggers are active. Recording/logging can therefore affect visible progress behavior even without changing the palette.
- `operation` (518) treats review/raw-debug output specially; a replacement renderer must not bypass those exclusions.

JSON is recorded as text through the applicable capture path. `Output.json` invokes the structured sanitization hook; direct serialization relies on the stream path rather than that exact hook. Do not assume every JSON producer has identical recording behavior.

**Unverified edge risk:** output bounds are applied before all text sanitization. A cut through an escape sequence could leave a fragment that the complete-sequence regex cannot recognize. Test this synthetically; do not claim existing records are damaged. ANSI bytes can also consume the pre-redaction byte allowance, so equal visible colored/plain output need not have identical truncation boundaries.

Recommendation: render a plain semantic projection for recording and an ANSI projection for display, with a single logical capture point. Preserve redaction, channels, operation identity, truncation accounting, bounded append behavior, session format and integrity chain. Initially persist the same plain text representation; semantic-role storage is **not required** and would be a separate format decision. Do not rewrite historical recordings or re-record pager repaints. Validate that prompt instrumentation still records one logical prompt/answer, not raw keystrokes.

## 8. Windows and output compatibility

`terminal.windows_ansi:29–48` reads per-handle console modes, enables `ENABLE_VIRTUAL_TERMINAL_PROCESSING` when requested, preserves other flags and verifies the result. `initialize:51–60` processes interactive stdout/stderr independently. `capable:63–72` checks TTY/TERM and Windows mode; `enabled:75–78` adds JSON, output-file, no-color and environment policy.

| Environment/path | Source-confirmed policy | Remaining verification |
|---|---|---|
| Direct Python, module, console executable | Shared CLI initialization | Same-terminal launcher acceptance matrix |
| PowerShell wrapper | Delegates to venv console executable; no independent palette/VT dependency | PS 5.1 and 7 process/stream behavior |
| Windows Terminal / Console Host | Win32 VT capability, Unicode encoding checks; extended-color environment heuristics | Actual font, encoding and color rendering |
| Redirected stdout | Not capable; ordinary Locard palette disabled | Native argparse environment overrides and bypasses |
| Redirected stderr | `terminal.message:168` evaluates stderr separately | Mixed stdout/stderr redirection matrix |
| `NO_COLOR` | Presence disables Locard coloring | Native argparse mismatch described above |
| Shell color setting | Shell tracks `no_color`; parser context uses palette | Resource getters sometimes evaluate capability without command args |
| Failed VT / TERM=dumb | Plain-color fallback; cursor helpers independently gated | Mock failure coverage exists; live hosts not tested here |
| Unicode unsupported | `supports_unicode:220`; activity has fallback support | Width/grapheme handling is separate from encoding support |

`terminal.banner:172` removes SGR when disabled. `cli.get_liner/get_thin/get_ender:33–49` use that helper; `get_banner:25` loads the raw resource and its caller must apply policy. The historical decision allowing a styled startup banner independently of later session color is a product-policy question, not automatically a defect. Agree on whether the new rule supersedes it; redirected output must still remain safe.

Raw-escape risks primarily involve bypassing the gated palette with raw trusted resources, native argparse's independent policy, or accepting already-styled strings at a new boundary. Ordinary command palettes are centrally gated. `wrap_line` counts characters, not full grapheme/display-cell width; a palette migration must not promise complete wide-character alignment without additional work.

## 9. Ranked architectural concerns

These rankings prioritize migration risk, not a claim of forensic corruption.

| Priority | Finding | Evidence / impact |
|---|---|---|
| High | Independent argparse color policy | Confirmed native 3.14 palette plus Locard line styling; inconsistent colors and possible redirected ANSI under overrides |
| High | Human/JSON boundaries vary by handler | Confirmed fallback JSON and direct print paths; stdout contamination risk requires targeted tests |
| High | Audit observes encoded strings rather than semantic/plain output | Confirmed role loss and bounded capture; changing capture casually risks duplicate records or altered limits |
| Medium | Type roles and semantic roles conflated | Confirmed cyan labels, green strings, magenta numbers, green zero error counts |
| Medium | Limitations styled as operational warnings | Confirmed in multiple domain renderers; undermines intended distinction, but text remains present |
| Medium | Questions lack a consistent role and editor redraw assumes shell-prompt encoding | Confirmed console comparison; naive question recoloring could regress editing |
| Medium | Wording-dependent status coloring | Confirmed setup/AI render comparisons; text edits can change role unintentionally |
| Low | Resource/capability policies need one documented exception rule | Banner branding versus session preferences; decision pending |
| Low | Terminal-dependent gray/brown and character width | Known capability limits; require fallback and representative terminal checks |

No source evidence from this audit establishes a change to evidence integrity, AI authorization or provider routing caused by colors. Presentation work must nevertheless preserve those boundaries.

## 10. Recommended minimal target architecture

1. **Keep structured application results authoritative.** Domain schemas and JSON remain unchanged. Human adapters select what to display and attach roles.
2. **Extend `terminal.py` with a small span primitive**, conceptually `TextSpan(text, role)`, plus plain and ANSI encoders. Plain text is the canonical layout/capture input. Do not build a general UI framework or put evidence-query logic in spans.
3. **Retain one palette and policy.** `enabled`/`capable` decide stream eligibility; role mapping decides color. No keyword classifier, artifact-specific color registry or provider-specific palette is needed.
4. **Adapt existing layout helpers.** Headers, labels and cells can accept spans/explicit roles. Measure widths before ANSI encoding. Existing domain renderers remain responsible for forensic semantics.
5. **Use modest presentation structures only where useful:** labeled fields, headings, rows and notes. Do not require every existing string to become a document tree immediately.
6. **Make output mode explicit.** Human output gets plain/ANSI encoding; machine JSON gets serialization only. Recording captures the plain human projection or intended machine output exactly once under existing safeguards.
7. **Use one help adapter** over parser metadata and catalog entries; disable competing native palette.
8. **Future web interface:** consume existing structured service results and optional semantic presentation structures. It must not parse ANSI or terminal prose. No web implementation is required now.

An initial compatibility adapter can accept existing strings while new renderers return spans. Mark trusted legacy ANSI paths explicitly rather than allowing every value to carry escapes. Eventually retire whole-line help heuristics and human use of type-colored JSON where a proper adapter replaces them. Do not retire domain renderers, safe escaping helpers, Win32 controls, or the recording redactor merely because a semantic layer exists.

## 11. Likely modification boundaries and staged migration

| Stage | Files/components | Acceptance boundary |
|---|---|---|
| 1: shared primitives | `terminal.py`, focused terminal tests | Explicit roles, safe plain/ANSI rendering, unchanged machine schemas; no broad command migration |
| 2: help | `cli_parser.py`, `interactive/help.py`, catalog adapter | Python-version-independent help palette; identical parser behavior and help content |
| 3: low-risk views | `source_cli.py` human rendering, `reporting/cli.py`, `retrieval/status_display.py`, `retrieval/layout.py` | Identical values/counts/order; explicit labels, values and statuses |
| 4: input/progress | `interactive/console.py`, shell/setup prompts, `terminal_activity.py` | Editing/cancel/history/prompt recording unchanged; no new diagnostic verbosity |
| 5: complex views | Artifact displays, ingestion summaries, advisory/investigation presentation | Preserve timestamp semantics, original/interpreted distinction, partial coverage and uncertainty |
| 6: output/audit consolidation | `output.py`, `session_recording.py`, remaining CLI adapters | One logical capture, redaction and publication semantics intact; no session-format migration implied |

Audit integration must be tested from stage 1, even if consolidation is deferred. Avoid changing all call sites in one patch. Do not move business logic or alter evidence retrieval just to make renderer interfaces uniform. Keep work proportional to presentation needs.

Performance: stream lines/spans rather than materializing entire evidence results; preserve spooling/paging and bounded recording. Avoid repeated ANSI strip/recolor passes, repeated sanitization or database lookups from styling. Benchmark large synthetic output only if the implementation introduces measurable overhead.

## 12. Validation strategy and existing test evidence

Existing tests inspected include:

| Test file | Assertions represented in source; not executed here |
|---|---|
| `tests/test_terminal_initialization.py:23–116` | Windows VT success/failure, resources/prompt, stderr/NO_COLOR, entry initialization, redirected launcher paths |
| `tests/test_terminal_color.py:34–201` | Plain/color JSON equivalence, circular values, no-color/file output, wrapping/pager, styles/banner/shell and external-call avoidance |
| `tests/test_terminal_activity.py`, `test_terminal_usability.py` | Activity and terminal interaction behavior |
| `tests/test_session_recording.py:37–354` | Recording lifecycle, ANSI/redaction, bounded output and operation boundaries |
| `tests/test_cli_consolidation.py:75–85`, `test_hidden_help.py` | Nested help and command-surface compatibility |
| `tests/test_focused_shell_presentation.py` and artifact/presentation suites | Human layouts, captions, evidence display and limitations |
| `tests/test_investigation_presentation.py`, `test_incremental_result_presentation.py`, `test_explanation_display.py`, `test_recorded_presentation.py` | Investigation/report output and distinctions |

Test existence is not evidence of a current passing baseline. Some legacy test commands may need checking against the consolidated command surface; do not weaken behavioral assertions merely to update colors.

Proposed focused regressions:

- Semantic counterexamples: selectable `ERROR` stays neutral; `Failed: 0` remains a neutral count; unknown is not failure; forensic limitation is not automatically an operational warning.
- Plain and colored human projections have identical visible text, values, evidence IDs, ordering and qualification content.
- Native argparse color disabled on supported versions; Python 3.11/3.12 compatibility; 3.14 help under `PYTHON_COLORS`, `FORCE_COLOR`, `NO_COLOR` and redirected streams.
- Exact JSON parsing and schema/value equality for each migrated command, including failures, prompts and cancellation paths; no ANSI or extra stdout messages.
- Four launcher paths, stdout/stderr independently redirected, VT unavailable/failure, TERM=dumb, Unicode and ASCII fallback. Manual PS 5.1/7, Console Host and Windows Terminal checks supplement mocks.
- Question editing/redraw, shell prompt, history and Ctrl+C unchanged; prompts recorded once with existing redaction.
- Recording equality of visible plain text; no duplicated pager/progress output; secret removal; complete and split escape sequences at byte limits; integrity checks and historical record readability unchanged.
- Forensic regressions preserve SI/FN distinctions, ASR blocking qualifications, unavailable/partial coverage, exact citations and unverified AI labels. No provider calls are needed.
- Large synthetic rows remain bounded and layout does not query evidence. Wide Unicode behavior should be tested explicitly rather than assumed from encoding support.

## 13. Architectural decisions still needed

1. Should the intentional startup-banner styling exception survive a session-level color disable? Resolve separately from noninteractive safety and `NO_COLOR` policy.
2. What basic-terminal fallback should brown annotations use? Exact brown cannot be guaranteed with standard 16-color ANSI; meaning must remain textual.
3. Should all interactive raw-JSON fallbacks gain human views, or should some diagnostic commands intentionally retain plain JSON by default? Specify per command without changing explicit JSON contracts.
4. Should future audit versions store semantic roles? Not needed for the recommended first migration; requires an explicit compatibility decision, not an incidental palette change.
5. Should prompt styling retain current branding or use another non-question role? The normal prompt must not be recategorized as an analyst question.

No implementation is authorized or supplied by this report. The smallest next implementation prompt should select the shared primitives and help adapter, define banner/NO_COLOR policy, and require focused output/audit equivalence tests before migrating complex forensic views.


## Implementation follow-up — 2026-11-14

The historical findings above describe the inspected 6.144 baseline and remain
unchanged. The subsequent foundation implementation adds `terminal.TextSpan`,
`render_spans`, `write_spans` and `shell_prompt`; metadata-based
`cli_parser.semantic_help`; native argparse color suppression; semantic catalog
help; trusted prompt redraw; version/root human views; and ANSI removal before
recording byte limits. See
[implementation, tests, limitations and acceptance](LOCARD_6_145_SEMANTIC_PRESENTATION.md).
This follow-up is implementation evidence, not manual acceptance. Domain-renderer
migration and broader human JSON fallbacks remain deferred.

## 6.146 working-tree implementation update (2026-11-14)

This is an implementation update, not a replacement of the historical audit.
Legacy type roles and `value_role` are removed; diagnostic JSON is uncolored.
The dedicated shell prompt is restored, help uses metadata-driven columns, and
startup, artifact, analysis, AI, case, findings, report-result and audit adapters
use central semantic roles. Input decoration uses the existing recording reader.
No forensic schemas or persisted document renderers were recolored.

See [the migration coverage matrix](LOCARD_6_146_COMPLETE_SEMANTIC_PRESENTATION.md)
for exact boundaries: bounded explanation/packet pages, persisted report documents,
historical event payloads and diagnostic JSON remain plain intentionally. This is
not a claim that every legacy prose line has been split into independently colored
label/value spans. Windows visual acceptance remains required.

# Locard 6.141 — Windows terminal rendering

## Diagnosis

Inspected clean 6.140 baseline `a7d8f3b` on 2026-11-14.
`locard.py`, module execution and the console script all call `cli.main`.
`locard.ps1` forwards to the installed console executable through the existing
Windows process helper. Neither that helper nor the Python entry point enabled
`ENABLE_VIRTUAL_TERMINAL_PROCESSING` on output handles.

`terminal.windows_ansi` only inspected the current console mode. If VT was off,
the normal palette and main banner became plain. However `get_liner`, `get_thin`
and `get_ender` returned raw styled resources without capability filtering.
They could therefore print literal `ESC[0;34m` despite the palette being disabled.
Guided setup also cached a styled separator at module import.

These are source-confirmed omissions, not a Python argument or version-resolution
defect. Successful rendering through a particular launcher depended on the console
state already being enabled. No captured console-mode measurement establishes
which host/session component enabled it during the user's earlier successful run.

## Correction

`cli.main` now invokes `terminal.initialize` before application startup. On Windows
it independently handles interactive stdout/stderr, reads each console mode and
enables VT with `SetConsoleMode` while retaining all existing bits. Already-enabled
handles are left alone. Redirected streams and `TERM=dumb` are not changed. Failed
initialization is nonfatal; subsequent capability checks select plain text.
Initialization is idempotent, has no launcher-specific implementation, and adds no
dependency or subprocess. It does not change stdin modes, encodings or code pages.

Decorative resource getters now use the existing `terminal.banner` SGR filter.
Shell decorations receive the shell's color setting. Guided setup renders its
separator using the current palette at display time instead of caching ANSI at
import. Banner text, box drawing, resource bytes, prompt styles and output wording
remain unchanged. The plain fallback removes styling rather than replacing Unicode
artwork with ASCII. Windows console Unicode handling remains Python's existing
behavior; custom redirected streams still own their chosen encoding.

`NO_COLOR`, `--no-color`, shell color-off and noninteractive output suppress styles.
Enabling output VT itself does not override color preferences: VT is also used by
existing cursor/progress presentation. Console mode is not reset on exit, avoiding
overwriting shared console changes made while Locard runs. No permanent Windows
setting is written.

Only terminal presentation and the source release number changed. CLI parsing,
case selection, provider readiness, AI authorization/execution, findings,
reporting, forensic logic and 6.140 version resolution are unchanged.

## Validation

Tests mock Windows mode inspection/mutation, verify existing bits and idempotence,
exercise failed initialization and independent output handles, check resource and
prompt text equivalence, and deny ANSI in redirected output. Synthetic startup and
shutdown regressions cover the shared application path. Subprocess smoke tests
exercise direct Python, module, console executable, PowerShell 7 and Windows
PowerShell 5.1 with captured output. No provider calls or protected evidence are
needed. Actual visible host rendering remains a manual acceptance step; captured
output is not proof of visual rendering in either Windows Terminal or Console Host.

Focused results (overlapping sets):

| Run | Result |
|---|---|
| Initialization, colors, shell presentation/startup and guided setup | 129 passed, 5 environment failures, 81.61 s |
| Initialization including added startup checks, plus sandbox-blocked tests outside sandbox | 21 passed, 7.22 s |
| Activity indicator, session UX and ingestion-wizard presentation | 97 passed, 48.36 s |

The five initial failures were denied hard-link publication (three), denied
synthetic junction creation (one), and Windows PowerShell 5.1 script authorization
inside the sandbox (one). They passed unchanged outside it; no execution policy
or permissions were altered. Both installed PowerShell versions passed captured
launcher tests. `git diff --check` and untracked-file whitespace checks passed;
direct Python reports 6.141. Visible Windows Terminal/Console Host testing remains
manual, not a claim established by the automated run.

## Manual acceptance

Use the same installed editable checkout/interpreter for all paths. No reinstall
is needed for this source/version-only change after the initial editable setup.
In each available PowerShell version, repeat in both Windows Terminal and Console
Host. Start a fresh terminal session where practical to avoid inheriting VT from a
previous application.

```powershell
cd C:\path\to\locard
.\.venv\Scripts\python.exe locard.py --version
.\.venv\Scripts\python.exe locard.py
.\.venv\Scripts\python.exe -m forensic_assistant.cli
.\.venv\Scripts\locard.exe
.\locard.ps1
```

Expect 6.141. At each interactive launch inspect banner, separators, prompts and
shutdown artwork, then exit normally. No ingestion or AI operation is necessary.
All four should have equivalent colors and intact Unicode in the same host.

```powershell
.\.venv\Scripts\python.exe locard.py --no-color
# Test conventional color disabling without permanently changing configuration:
$savedNoColor = $env:NO_COLOR
try {
    $env:NO_COLOR = '1'
    .\.venv\Scripts\python.exe locard.py
} finally { $env:NO_COLOR = $savedNoColor }

# Files must contain plain text, not escape sequences:
.\.venv\Scripts\python.exe locard.py --version > locard-version-check.txt
.\.venv\Scripts\python.exe locard.py 2> locard-error-check.txt > locard-output-check.txt
```

The last command refuses interactive startup because stdout is redirected; this is
existing behavior. Inspect the temporary files, then remove them when finished.
Use `powershell.exe -NoProfile` for Windows PowerShell 5.1 or `pwsh.exe -NoProfile`
for PowerShell 7. A terminal where VT genuinely cannot be enabled must show readable
plain text, never raw SGR sequences. Mocks cover this fallback without changing
system-wide console settings.

No full suite, live provider requests, commit or push is part of this task.

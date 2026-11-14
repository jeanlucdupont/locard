# Locard 6.140 — Simplified launch and development

## Inspected baseline

On 2026-11-14 the starting checkout was clean at 6.139 commit
`9d562bd1d73680b715f62a9b9ff2e995c280e098` (`Embed cloud LLM`).

Previously both `forensic_assistant.__init__` and `cli` read the installed
`locard-forensics` metadata independently. Activity session-start and case-creation
writers also read that metadata directly. Editable source could therefore execute
new code but display and record an old installed release number.

The console entry point is `forensic_assistant.cli:main`. Module execution already
calls the same function. `locard.ps1` selects `.venv/Scripts/locard.exe`, uses
`scripts/windows-process.ps1` for Windows argument/process handling, and forwards
the exit code. It does not initialize cases, logging, providers or forensic state.
Those responsibilities stay in Python. The PowerShell launcher and installer are
unchanged.

## Launch and update

The new root `locard.py` imports `cli.main` and calls it under a main guard,
preserving multiprocessing behavior and the existing return code. It neither
adjusts `sys.path` nor selects, installs or activates an environment.

```powershell
cd C:\path\to\locard
# Activate the intended environment first, or use its Python's full path.
python -m pip install -e .

# Later source/version-only changes:
git pull
python locard.py

# Equivalent application entry points:
python -m forensic_assistant.cli
locard
```

No arguments enters the existing shell; arguments use the existing parser.
PowerShell is optional. The plain `python` command must identify an interpreter
with the required dependencies. `locard.ps1` still selects the checkout's `.venv`
executable, so use an editable install in that environment for Git-based updates.
The existing Windows installer performs a conventional wheel installation; that
installation still needs updating to receive new code.

An editable install loads the source checkout. A new process sees source and
release changes after a pull. Already-running processes are not hot-reloaded.
Re-run `python -m pip install -e .` for dependencies, constraints, entry points,
distribution metadata or packaging changes that editable hooks do not refresh.
Changing the version alone no longer requires it. Locard never invokes pip or Git
at startup. Reporting a source version is not a claim that dependencies are up to
date; the existing missing-dependency diagnostics remain available.

## Version resolution

`forensic_assistant.version.resolve` inspects only the immediate parent of the
actual executing package path, independent of the caller's working directory.
It does not walk arbitrary ancestors. Git directory/worktree-file or Locard
PowerShell launcher markers identify a checkout even when its TOML is damaged or
missing. Matching `project.name` also recognizes an unpacked source layout.

An identified checkout must provide `project.name = "locard-forensics"`, the
existing `locard = "forensic_assistant.cli:main"` console entry and a string
`MAJOR.RELEASE` version. Missing, malformed or inconsistent metadata raises a
clear source-version diagnostic; stale installed metadata cannot hide the error.
These layout checks identify application packaging, not cryptographic source
authenticity. No Git subprocess is involved.

A conventional installed package without a source layout uses
`importlib.metadata.version("locard-forensics")` and needs no source TOML. Source
execution works even with absent distribution metadata. Missing both authorities
fails clearly rather than inventing a version. `pyproject.toml` remains the sole
source release declaration; no generated or manually synchronized version file
was added.

`forensic_assistant.__version__` resolves at import. CLI version output, banner,
interactive `version`, AI case context, readiness cache identity, transcript
implementation identity, report producers and activity records all use it.
Parser/dependency versions remain independent distribution metadata reads.

```powershell
python locard.py --version
python locard.py --version-details
```

The second command prints local JSON: `application_version`, `execution`,
`source_version`, `installed_metadata_version`, and `metadata_mismatch`.
For editable development a mismatch is expected after version-only updates, not
an application failure. Unknown installed metadata is null. Diagnostics require
no database, provider, network, recorded history or environment modification.

## Provenance and compatibility

New transcripts and reports record the executing source release. Transcripts
retain their separate existing code SHA-256 identity; a release number is not a
Git commit or code digest. Activity `SESSION_START` and `CASE_CREATE` now use the
same version authority. AI diagnostic event formats were not changed; readiness
uses the existing version-dependent cache identity.

Historical transcript/report versions, serialization, validation and digest
encodings remain untouched. Existing report generation envelopes remain preserved
when supplied for reconstruction. No case data, findings workspace or historical
artifact was opened or rewritten for this change. Compatibility is tested with
disposable synthetic fixtures, not claimed from inspection of protected cases.

## Validation and acceptance

Provider-free tests cover source versions older/newer than installed metadata,
absent installed metadata, conventional fallback, outside-working-directory
execution, damaged/missing metadata, wrong project identity, simulated pull-only
updates, all three launch paths, shared startup/shutdown, and process/network-free
resolution. Existing presentation tests now expect the effective source version
instead of requiring stale editable metadata to match it. Existing historical
format rejection assertions are retained. Synthetic reporting checks also assert
the new producer version and deterministic historical reconstruction.

Focused results (overlapping sets; not additive):

| Validation | Result |
|---|---|
| Launcher/version, interactive shell and local-only readiness | 66 passed, 14.43 s |
| Final version tests including simulated pull and direct main delegation | 20 passed, 4.33 s |
| Recorded reporting/history, historical contracts, presentation, activity and case creation | 182 passed, 4 failed, 198.60 s inside sandbox |
| The four unchanged hard-link publication tests outside sandbox | 4 passed, 10.10 s |

The four initial failures were Windows access-denied errors publishing disposable
test output; no code or permissions were changed to pass them. `git diff --check`
and separate untracked-file whitespace checks passed. The unchanged PowerShell
launcher also printed `Locard 6.140`. Local version diagnostics reported source
6.140 against installed metadata 6.94, demonstrating the intended mismatch
handling without installation. No full suite, live provider request,
installation, commit or push was performed.

Manual acceptance in the test checkout:

```powershell
# One-time editable setup (or refresh changed dependencies/packaging):
.\.venv\Scripts\python.exe -m pip install -e .
.\.venv\Scripts\python.exe -m pip check

# After a later source/version-only pull, no reinstall is needed:
git pull
.\.venv\Scripts\python.exe locard.py --version
.\.venv\Scripts\python.exe -m forensic_assistant.cli --version
.\.venv\Scripts\locard.exe --version
.\.venv\Scripts\python.exe locard.py --version-details
.\locard.ps1 --version
.\.venv\Scripts\python.exe locard.py
```

Expect source release 6.140 for this checkout. Exercise the normal shell and quit
normally; no AI diagnostic request is required. For a conventional installed
wheel, install the update to receive its code and metadata together. Source import
checks do not establish that all runtime dependencies are current.

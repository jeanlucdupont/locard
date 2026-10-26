# Locard Python file map

A brief reference to the Python source files in the current checkout. Each row
explains a file's main responsibility; it is not a function-by-function API guide.
Paths are relative to the repository root and link to the corresponding source.

**Scope:** application files in `forensic_assistant/` and the maintenance utility
in `scripts/`. Tests, `poc/`, temporary profiling/benchmark scripts, virtual
environments and third-party dependency files are excluded. The integrated native
MFT acquisition module is included because it is production application code.

## How the packages fit together

`cli.py` and `interactive/` receive analyst commands. `ingest/` and `artifacts/`
parse supported evidence and use `database/` to retain it. `retrieval/`,
`correlation/` and `detections/` provide deterministic analysis. Optional
`semantic/` helps locate records by similarity. `ai/` supplies model transport and
runtime management, while `llm/` and `investigation_ai/` control bounded analysis.
`reporting/` creates derived reports. Terminal, output and activity modules handle
presentation and analyst-side records separately from the evidence model.

Names such as `v1_cli.py`, `v2_cli.py`, `view_v2.py` and `legacy_render.py` describe
historical layers or compatibility contracts. They do not, by themselves, mean
that the files are unused or safe to remove.

## Packages

- [Application entry points and shared services](#forensic-assistant)
- [Interactive shell and guided workflows](#forensic-assistant-interactive)
- [EVTX ingestion and shared ingestion support](#forensic-assistant-ingest)
- [Artifact parsing, acquisition and private staging](#forensic-assistant-artifacts)
- [SQLite storage and provenance](#forensic-assistant-database)
- [Evidence retrieval and human-readable presentation](#forensic-assistant-retrieval)
- [Deterministic evidence relationships](#forensic-assistant-correlation)
- [Detection engine and rule contracts](#forensic-assistant-detections)
- [Individual detection-rule families](#forensic-assistant-detections-rules)
- [Optional local semantic retrieval](#forensic-assistant-semantic)
- [Bounded model context and analysis workflows](#forensic-assistant-llm)
- [AI providers, local runtime and diagnostics](#forensic-assistant-ai)
- [Supervised, bounded AI investigation](#forensic-assistant-investigation-ai)
- [Grounded derived reports](#forensic-assistant-reporting)
- [Maintenance utilities](#scripts)

<a id="forensic-assistant"></a>

## Application entry points and shared services

`forensic_assistant/` — 16 Python files.

| File | What it does |
|---|---|
| [__init__.py](../forensic_assistant/__init__.py) | Exposes the installed application version through package metadata; it does not hardcode a version number. |
| [activity.py](../forensic_assistant/activity.py) | Records and verifies the derived analyst activity log, including command events and mutation intent/completion records. |
| [cli.py](../forensic_assistant/cli.py) | Builds the main command parser, starts interactive mode when appropriate, and dispatches commands to their implementations. |
| [cli_parser.py](../forensic_assistant/cli_parser.py) | Adapts argparse help/errors for CLI and shell use, resolves display defaults, and wires canonical ingestion commands and aliases. |
| [command_catalog.py](../forensic_assistant/command_catalog.py) | Centralizes command names, short help descriptions, aliases, and the capability descriptions supplied to advisory workflows. |
| [config.py](../forensic_assistant/config.py) | Defines basic application defaults such as the database path, local endpoint, request timeout, and batch-size setting. |
| [dump_cli.py](../forensic_assistant/dump_cli.py) | Exports retained evidence to fixed case-local CSV files, preserving structured fields and applying spreadsheet-formula protection. |
| [dump_timing.py](../forensic_assistant/dump_timing.py) | Measures CSV-dump phases and database access time without recording evidence content. |
| [model.py](../forensic_assistant/model.py) | Defines normalized event records and helpers for UTC timestamps and deterministic evidence IDs. |
| [output.py](../forensic_assistant/output.py) | Manages the internal pager and explicit derived-output files, including destination checks, append/replace behavior, and hashing. |
| [registry_dump_profile.py](../forensic_assistant/registry_dump_profile.py) | Collects bounded, content-free performance diagnostics for Registry CSV exports. |
| [source_cli.py](../forensic_assistant/source_cli.py) | Implements source listing, inspection, creation, updates and retrospective assignment, including previews and human output. |
| [terminal.py](../forensic_assistant/terminal.py) | Provides ANSI styles, safe terminal rendering, width-aware wrapping, banners, and screen/progress-line operations. |
| [terminal_activity.py](../forensic_assistant/terminal_activity.py) | Displays transient activity indicators and coordinates their output with normal terminal messages. |
| [v1_cli.py](../forensic_assistant/v1_cli.py) | Wires deterministic process, logon, session, detection and investigation commands, plus bounded timeline analysis. |
| [v2_cli.py](../forensic_assistant/v2_cli.py) | Wires multi-artifact ingestion and retrieval, including show/status, timestamp anchors, and artifact-aware command output. |

<a id="forensic-assistant-interactive"></a>

## Interactive shell and guided workflows

`forensic_assistant/interactive/` — 18 Python files.

| File | What it does |
|---|---|
| [__init__.py](../forensic_assistant/interactive/__init__.py) | Marks this directory as a Python package; contains no executable workflow logic. |
| [advisory.py](../forensic_assistant/interactive/advisory.py) | Builds and validates structured advisory responses from bounded case metadata; handles model-free inventory answers without directly dispatching tools. |
| [advisory_display.py](../forensic_assistant/interactive/advisory_display.py) | Renders validated advisory structures into consistent human-readable sections without interpreting them as commands. |
| [ai_context.py](../forensic_assistant/interactive/ai_context.py) | Reads a fresh, bounded case-metadata snapshot for advisory requests without retaining a database connection. |
| [ai_routing.py](../forensic_assistant/interactive/ai_routing.py) | Conservatively decides whether a question requires bounded investigation or should remain advisory. |
| [case.py](../forensic_assistant/interactive/case.py) | Normalizes and validates existing case paths/schema and opens existing databases without creating or migrating them. |
| [completion.py](../forensic_assistant/interactive/completion.py) | Implements Tab completion from command-parser metadata rather than scanning evidence or querying case contents. |
| [console.py](../forensic_assistant/interactive/console.py) | Implements synchronous terminal input, editing, session history and timed approval input without background stdin readers. |
| [creation.py](../forensic_assistant/interactive/creation.py) | Validates new-case destinations, initializes databases safely, reuses ingestion, and renders completion counts and limitations. |
| [discovery.py](../forensic_assistant/interactive/discovery.py) | Scans mounted/extracted Windows roots or manual selections for supported candidates while respecting access and redirection limits. |
| [help.py](../forensic_assistant/interactive/help.py) | Builds the shell command catalog and command help from the shared parser and shell-command metadata. |
| [metadata.py](../forensic_assistant/interactive/metadata.py) | Collects and validates interactive source metadata such as the original volume root. |
| [setup.py](../forensic_assistant/interactive/setup.py) | Collects a guided setup/ingestion plan, obtains confirmation, then runs shared case-creation and ingestion operations. |
| [setup_display.py](../forensic_assistant/interactive/setup_display.py) | Renders discovery, compact ingestion progress, file outcomes, exceptions, limitations and completion summaries. |
| [shell.py](../forensic_assistant/interactive/shell.py) | Runs the command loop, manages the active case, handles shell-only commands and ! requests, and cleans up session resources. |
| [sources.py](../forensic_assistant/interactive/sources.py) | Prepares source selection for an individual command without implicitly carrying source choices into later commands. |
| [state.py](../forensic_assistant/interactive/state.py) | Persists bounded recent-case preferences separately from evidence and command history. |
| [workspace.py](../forensic_assistant/interactive/workspace.py) | Manages analyst case-workspace names, destinations, initialization and display labels without copying original evidence. |

<a id="forensic-assistant-ingest"></a>

## EVTX ingestion and shared ingestion support

`forensic_assistant/ingest/` — 11 Python files.

| File | What it does |
|---|---|
| [__init__.py](../forensic_assistant/ingest/__init__.py) | Marks this directory as a Python package; contains no executable workflow logic. |
| [evtx.py](../forensic_assistant/ingest/evtx.py) | Hashes and ingests EVTX files through disk-backed staging, normalizes retained records, and records outcomes and errors. |
| [evtx_arrays.py](../forensic_assistant/ingest/evtx_arrays.py) | Extends the pinned EVTX decoder's substitution/rendering support for numeric arrays without modifying installed dependencies globally. |
| [evtx_recovery.py](../forensic_assistant/ingest/evtx_recovery.py) | Reads recoverable aligned EVTX records and reports structural limitations without arbitrary-byte carving. |
| [evtx_worker.py](../forensic_assistant/ingest/evtx_worker.py) | Supervises EVTX decoding in a separate process with bounded disk transport, progress/stall deadlines and a hard ceiling. |
| [interruption.py](../forensic_assistant/ingest/interruption.py) | Records graceful ingestion interruption while preserving and accurately reporting previously committed work. |
| [normalize.py](../forensic_assistant/ingest/normalize.py) | Maps provider-aware EVTX fields into normalized records while retaining unmapped data in original XML/JSON. |
| [observation.py](../forensic_assistant/ingest/observation.py) | Carries transient ingestion progress observations; it does not control timeouts or mutate evidence. |
| [service.py](../forensic_assistant/ingest/service.py) | Recognizes provider-qualified service-installation events and extracts their fields without claiming service execution. |
| [sysmon.py](../forensic_assistant/ingest/sysmon.py) | Handles Sysmon FileCreate-specific fields and timestamp meanings. |
| [validation.py](../forensic_assistant/ingest/validation.py) | Creates and recognizes nonfatal EVTX identifier-validation notes stored alongside normalization warnings. |

<a id="forensic-assistant-artifacts"></a>

## Artifact parsing, acquisition and private staging

`forensic_assistant/artifacts/` — 18 Python files.

| File | What it does |
|---|---|
| [__init__.py](../forensic_assistant/artifacts/__init__.py) | Marks this directory as a Python package; contains no executable workflow logic. |
| [browser.py](../forensic_assistant/artifacts/browser.py) | Creates consistent private Chromium History snapshots and parses browser visits/downloads with explicit browser/profile context. |
| [browser_probe.py](../forensic_assistant/artifacts/browser_probe.py) | Checks browser-database candidates read-only on private copies inside the bounded parser worker. |
| [context.py](../forensic_assistant/artifacts/context.py) | Validates volume-root assertions and binds/resolves source context without treating analyst metadata as artifact observations. |
| [ingest.py](../forensic_assistant/artifacts/ingest.py) | Discovers artifact types, hashes inputs, supervises parsers and atomically publishes eligible private-stage records into the case. |
| [mft.py](../forensic_assistant/artifacts/mft.py) | Parses MFT records using Dissect, preserves attribute/timestamp identities, and reconstructs paths conservatively from parent references. |
| [mft_stage.py](../forensic_assistant/artifacts/mft_stage.py) | Batches private MFT timestamp/object writes within row/byte limits and flushes them at explicit transaction boundaries. |
| [native_mft.py](../forensic_assistant/artifacts/native_mft.py) | Acquires a temporary derived MFT, checks destination/storage safety, then reuses ordinary artifact ingestion and failure accounting. |
| [ntfs_acquisition.py](../forensic_assistant/artifacts/ntfs_acquisition.py) | Implements native read-only NTFS volume access, boot/MFT geometry and runlist handling, acquisition, and comparison helpers. |
| [paths.py](../forensic_assistant/artifacts/paths.py) | Normalizes evidence paths for comparison without consulting the analyst machine's filesystem or environment. |
| [prefetch.py](../forensic_assistant/artifacts/prefetch.py) | Extracts Prefetch records, execution-time slots and references using libscca. |
| [registry.py](../forensic_assistant/artifacts/registry.py) | Traverses offline Registry hives and preserves keys, values and key last-write semantics. |
| [registry_extractors.py](../forensic_assistant/artifacts/registry_extractors.py) | Runs registered Registry interpretation/extraction rules while keeping each derived view linked to its source key/value. |
| [registry_logs.py](../forensic_assistant/artifacts/registry_logs.py) | Identifies filename-designated Registry companion logs and describes their limitations without replaying them. |
| [storage.py](../forensic_assistant/artifacts/storage.py) | Writes validated parser output into common evidence and artifact-specific tables, preserving duplicate and source-identity rules. |
| [times.py](../forensic_assistant/artifacts/times.py) | Converts integer Windows FILETIME values while preserving source precision and normalization status. |
| [userassist.py](../forensic_assistant/artifacts/userassist.py) | Decodes supported UserAssist values and projects their execution-related metadata/timestamps conservatively. |
| [worker.py](../forensic_assistant/artifacts/worker.py) | Runs artifact parsers in a bounded subprocess, builds the private stage, records parser errors and performs required post-processing. |

<a id="forensic-assistant-database"></a>

## SQLite storage and provenance

`forensic_assistant/database/` — 7 Python files.

| File | What it does |
|---|---|
| [__init__.py](../forensic_assistant/database/__init__.py) | Marks this directory as a Python package; contains no executable workflow logic. |
| [artifacts.py](../forensic_assistant/database/artifacts.py) | Defines common/artifact table structures and helpers for evidence registration, timestamps, objects, EVTX projection and artifact counts. |
| [browser.py](../forensic_assistant/database/browser.py) | Defines explicit browser contexts and run-specific occurrences, and resolves browser provenance through those relationships. |
| [context.py](../forensic_assistant/database/context.py) | Extracts and stores derived event lookup fields used for host, process and logon correlation. |
| [db.py](../forensic_assistant/database/db.py) | Initializes and opens databases, registers source-file hashes/locations, and inserts normalized events. |
| [source_selection.py](../forensic_assistant/database/source_selection.py) | Selects existing evidence files for retrospective source assignment from recorded hashes/paths, with bounded previews. |
| [sources.py](../forensic_assistant/database/sources.py) | Manages source identities, analyst assertions, memberships and coverage without rewriting artifact-derived evidence. |

<a id="forensic-assistant-retrieval"></a>

## Evidence retrieval and human-readable presentation

`forensic_assistant/retrieval/` — 23 Python files.

| File | What it does |
|---|---|
| [__init__.py](../forensic_assistant/retrieval/__init__.py) | Marks this directory as a Python package; contains no executable workflow logic. |
| [analysis_display.py](../forensic_assistant/retrieval/analysis_display.py) | Formats deterministic session/investigation results and relationships without querying or inventing new links. |
| [analyst_display.py](../forensic_assistant/retrieval/analyst_display.py) | Renders human-facing logon, detection and process-tree results. |
| [around_display.py](../forensic_assistant/retrieval/around_display.py) | Formats nearby evidence with time deltas, artifact labels, source context and timestamp semantics. |
| [artifact_notes.py](../forensic_assistant/retrieval/artifact_notes.py) | Centralizes reusable human-readable forensic notes while leaving stored warnings unchanged. |
| [browser_display.py](../forensic_assistant/retrieval/browser_display.py) | Formats browser evidence and grouped browser-search results using shared terminal escaping and styles. |
| [browser_query.py](../forensic_assistant/retrieval/browser_query.py) | Builds fixed, parameterized browser filters over normalized records. |
| [evidence.py](../forensic_assistant/retrieval/evidence.py) | Retrieves individual evidence records and bounded mixed-artifact searches/timelines, including host-aware temporal windows. |
| [evtx_display.py](../forensic_assistant/retrieval/evtx_display.py) | Groups and renders EVTX search, timeline and nearby-event output without replacing the underlying evidence observations. |
| [investigation_summary.py](../forensic_assistant/retrieval/investigation_summary.py) | Prioritizes already retrieved evidence into deterministic investigation text without new queries or inferred relationships. |
| [layout.py](../forensic_assistant/retrieval/layout.py) | Provides width-aware tables, path fitting and pagination for terminal output. |
| [mft_display.py](../forensic_assistant/retrieval/mft_display.py) | Renders grouped MFT observations, allocation state, paths and distinct SI/FN timestamp meanings. |
| [mixed_display.py](../forensic_assistant/retrieval/mixed_display.py) | Displays mixed-artifact temporal results without merging identities or inferring relationships. |
| [planner.py](../forensic_assistant/retrieval/planner.py) | Converts a small set of question patterns into bounded retrieval plans, not generated SQL. |
| [prefetch_display.py](../forensic_assistant/retrieval/prefetch_display.py) | Displays Prefetch executable and execution-time observations without altering path or evidence semantics. |
| [presentation.py](../forensic_assistant/retrieval/presentation.py) | Provides shared safe-text/path/error formatting and basic evidence/timeline display helpers. |
| [process_names.py](../forensic_assistant/retrieval/process_names.py) | Builds process-name comparison predicates for CLI conveniences without rewriting stored evidence. |
| [queries.py](../forensic_assistant/retrieval/queries.py) | Implements parameterized normalized-event queries, time validation, pagination and basic coverage statistics. |
| [registry_display.py](../forensic_assistant/retrieval/registry_display.py) | Renders Registry keys, independent value records, UserAssist summaries and hive limitations. |
| [search_display.py](../forensic_assistant/retrieval/search_display.py) | Formats compact search results while retaining the existing selection and evidence hydration behavior. |
| [show_display.py](../forensic_assistant/retrieval/show_display.py) | Renders analyst-facing summaries for an individual evidence record. |
| [status_display.py](../forensic_assistant/retrieval/status_display.py) | Builds concise status/error displays from recorded case state without rewriting ingestion outcomes. |
| [v1_planner.py](../forensic_assistant/retrieval/v1_planner.py) | Adds explicit process/session/detection question patterns and enrichment to the original bounded retrieval planner. |

<a id="forensic-assistant-correlation"></a>

## Deterministic evidence relationships

`forensic_assistant/correlation/` — 7 Python files.

| File | What it does |
|---|---|
| [__init__.py](../forensic_assistant/correlation/__init__.py) | Marks this directory as a Python package; contains no executable workflow logic. |
| [cross_artifact.py](../forensic_assistant/correlation/cross_artifact.py) | Compares objects and timestamps across artifact families, distinguishing agreement from execution identity or causation. |
| [investigation.py](../forensic_assistant/correlation/investigation.py) | Assembles a bounded deterministic evidence bundle and related observations around an anchor. |
| [models.py](../forensic_assistant/correlation/models.py) | Defines relationship records and common evidence/time ordering and selection helpers. |
| [processes.py](../forensic_assistant/correlation/processes.py) | Reconstructs process relationships conservatively using available identifiers, host context and time constraints. |
| [sessions.py](../forensic_assistant/correlation/sessions.py) | Finds logon activity and reconstructs host-scoped sessions using role-aware Logon IDs and observed boundaries. |
| [temporal.py](../forensic_assistant/correlation/temporal.py) | Validates temporal anchors and retrieves evidence before, after or around them. |

<a id="forensic-assistant-detections"></a>

## Detection engine and rule contracts

`forensic_assistant/detections/` — 3 Python files.

| File | What it does |
|---|---|
| [__init__.py](../forensic_assistant/detections/__init__.py) | Marks this directory as a Python package; contains no executable workflow logic. |
| [engine.py](../forensic_assistant/detections/engine.py) | Discovers local rule modules and evaluates bounded candidate evidence against their detection rules. |
| [models.py](../forensic_assistant/detections/models.py) | Defines the shared detection-rule contract and observation structure. |

<a id="forensic-assistant-detections-rules"></a>

## Individual detection-rule families

`forensic_assistant/detections/rules/` — 6 Python files.

| File | What it does |
|---|---|
| [__init__.py](../forensic_assistant/detections/rules/__init__.py) | Marks this directory as a Python package; contains no executable workflow logic. |
| [authentication.py](../forensic_assistant/detections/rules/authentication.py) | Flags bounded authentication-failure sequences followed by success for analyst review. |
| [cross.py](../forensic_assistant/detections/rules/cross.py) | Provides cross-artifact and persistence-reference review rules without declaring compromise. |
| [events.py](../forensic_assistant/detections/rules/events.py) | Flags recorded task creation, service installation, log clearing, account creation and explicit credential-use events. |
| [office.py](../forensic_assistant/detections/rules/office.py) | Identifies process relationships involving Office applications and child processes for review. |
| [powershell.py](../forensic_assistant/detections/rules/powershell.py) | Identifies review-worthy PowerShell characteristics in supported event evidence. |

<a id="forensic-assistant-semantic"></a>

## Optional local semantic retrieval

`forensic_assistant/semantic/` — 8 Python files.

| File | What it does |
|---|---|
| [__init__.py](../forensic_assistant/semantic/__init__.py) | Marks this directory as a Python package; contains no executable workflow logic. |
| [cli.py](../forensic_assistant/semantic/cli.py) | Handles semantic search/status and the explicit interactive setup/rebuild lifecycle. |
| [documents.py](../forensic_assistant/semantic/documents.py) | Builds bounded evidence text projections and deterministic, logically ordered case fingerprints for semantic indexing. |
| [hybrid.py](../forensic_assistant/semantic/hybrid.py) | Combines deterministic retrieval with bounded semantic candidates without turning similarity into forensic relationships. |
| [index.py](../forensic_assistant/semantic/index.py) | Builds and searches rebuild-only derived semantic indexes, checking compatibility and avoiding unsafe native/pickle loading. |
| [model.py](../forensic_assistant/semantic/model.py) | Sets up/verifies embedding assets and loads the local embedding model through reviewed dependencies. |
| [presentation.py](../forensic_assistant/semantic/presentation.py) | Renders semantic search/status results and progress without changing machine-readable metadata. |
| [runtime.py](../forensic_assistant/semantic/runtime.py) | Manages user-local embedding-model preferences and checks optional semantic dependency availability. |

<a id="forensic-assistant-llm"></a>

## Bounded model context and analysis workflows

`forensic_assistant/llm/` — 9 Python files.

| File | What it does |
|---|---|
| [__init__.py](../forensic_assistant/llm/__init__.py) | Marks this directory as a Python package; contains no executable workflow logic. |
| [artifact_fields.py](../forensic_assistant/llm/artifact_fields.py) | Selects compact artifact fields for bounded model context while keeping originals accessible in the case. |
| [ask.py](../forensic_assistant/llm/ask.py) | Runs the retrieval-oriented question/answer workflow: gather bounded evidence, call the model when requested, and validate the answer. |
| [client.py](../forensic_assistant/llm/client.py) | Provides direct local-model HTTP transport restricted to numeric loopback addresses, without proxies or redirects. |
| [context.py](../forensic_assistant/llm/context.py) | Builds prioritized model-context bundles that retain supporting records alongside deterministic relationships. |
| [grounding.py](../forensic_assistant/llm/grounding.py) | Applies conservative evidence-selection roles and artifact limitations to the ask workflow. |
| [presentation.py](../forensic_assistant/llm/presentation.py) | Displays retrieved context and labels model-authored analysis distinctly from deterministic evidence. |
| [prompts.py](../forensic_assistant/llm/prompts.py) | Constructs evidence-based prompts and validates the structured answer contract. |
| [timeline.py](../forensic_assistant/llm/timeline.py) | Builds a bounded timeline-analysis bundle and validates the optional model-generated summary. |

<a id="forensic-assistant-ai"></a>

## AI providers, local runtime and diagnostics

`forensic_assistant/ai/` — 21 Python files.

| File | What it does |
|---|---|
| [__init__.py](../forensic_assistant/ai/__init__.py) | Marks this directory as a Python package; contains no executable workflow logic. |
| [anthropic_diagnostics.py](../forensic_assistant/ai/anthropic_diagnostics.py) | Extracts allowlisted Anthropic error categories/metadata without retaining raw provider messages. |
| [anthropic_strategy.py](../forensic_assistant/ai/anthropic_strategy.py) | Implements the bounded Anthropic-specific two-call response transport while retaining the canonical Locard contract. |
| [backend.py](../forensic_assistant/ai/backend.py) | Selects and invokes the configured local/cloud backend; retrieval, authorization and evidence validation remain with callers. |
| [capabilities.py](../forensic_assistant/ai/capabilities.py) | Defines explicit supported cloud request modes instead of guessing capabilities from model names. |
| [cli.py](../forensic_assistant/ai/cli.py) | Implements provider selection, configuration, status, local-runtime start/stop and diagnostic commands. |
| [cloud_worker.py](../forensic_assistant/ai/cloud_worker.py) | Runs a single isolated LiteLLM request and extracts its response without executing model-proposed tools. |
| [diagnostics.py](../forensic_assistant/ai/diagnostics.py) | Drains runtime output and records bounded Locard-controlled diagnostic categories rather than raw server content. |
| [gemini_adapter.py](../forensic_assistant/ai/gemini_adapter.py) | Extracts and validates Gemini responses and reports bounded extraction diagnostics. |
| [gemini_usage.py](../forensic_assistant/ai/gemini_usage.py) | Extracts numeric Gemini usage information without retaining provider payloads. |
| [local_diagnostics.py](../forensic_assistant/ai/local_diagnostics.py) | Records local-model request timing/status categories and routes explicitly enabled raw diagnostics. |
| [openai_schema.py](../forensic_assistant/ai/openai_schema.py) | Adapts canonical investigation contracts to OpenAI wire schemas and converts responses back to Locard's representation. |
| [options.py](../forensic_assistant/ai/options.py) | Parses and validates the limited local-runtime performance options without constructing shell commands. |
| [provider_diagnostics.py](../forensic_assistant/ai/provider_diagnostics.py) | Classifies cloud failures and renders allowlisted request/error diagnostics without serializing arbitrary provider exceptions. |
| [raw_diagnostics.py](../forensic_assistant/ai/raw_diagnostics.py) | Manages explicitly enabled, sanitized, session-only raw-response capture and display without writing it to disk. |
| [readiness.py](../forensic_assistant/ai/readiness.py) | Checks cloud compatibility with fixed evidence-free probes and retains session-only readiness state. |
| [response_contract.py](../forensic_assistant/ai/response_contract.py) | Validates canonical cloud response structures without resolving external schema resources. |
| [runtime.py](../forensic_assistant/ai/runtime.py) | Starts, monitors and stops Locard-owned llama.cpp resources using owned process handles and authenticated loopback control. |
| [schema_diagnostics.py](../forensic_assistant/ai/schema_diagnostics.py) | Describes bounded schema shapes and constraints without exposing property or enum values. |
| [settings.py](../forensic_assistant/ai/settings.py) | Validates and persists analyst AI preferences separately from evidence; credentials remain outside stored settings. |
| [validation_diagnostics.py](../forensic_assistant/ai/validation_diagnostics.py) | Produces allowlisted structural-validation diagnostics without retaining rejected values or validator message text. |

<a id="forensic-assistant-investigation-ai"></a>

## Supervised, bounded AI investigation

`forensic_assistant/investigation_ai/` — 20 Python files.

| File | What it does |
|---|---|
| [__init__.py](../forensic_assistant/investigation_ai/__init__.py) | Marks this directory as a Python package; contains no executable workflow logic. |
| [case.py](../forensic_assistant/investigation_ai/case.py) | Opens existing cases read-only and establishes controlled read transactions with SQLite restrictions. |
| [cli.py](../forensic_assistant/investigation_ai/cli.py) | Wires advanced investigation/history commands, approval prompts, budgets and human result presentation. |
| [contracts.py](../forensic_assistant/investigation_ai/contracts.py) | Defines the closed tool/response vocabulary and strictly validates model JSON and arguments. |
| [controller.py](../forensic_assistant/investigation_ai/controller.py) | Runs the investigation loop: validate proposals, enforce approvals/budgets, execute allowed operations and validate findings. |
| [diagnostics.py](../forensic_assistant/investigation_ai/diagnostics.py) | Measures investigation startup phases using bounded diagnostics without evidence or arbitrary exception prose. |
| [feedback.py](../forensic_assistant/investigation_ai/feedback.py) | Builds small deterministic correction messages for rejected model proposals. |
| [lifecycle.py](../forensic_assistant/investigation_ai/lifecycle.py) | Owns Windows worker-job containment and cleanup so the actual process tree can be terminated safely. |
| [presentation.py](../forensic_assistant/investigation_ai/presentation.py) | Renders validated observations, proposed lookups, termination reasons and limitations from controller-owned structures. |
| [rejection.py](../forensic_assistant/investigation_ai/rejection.py) | Extracts bounded rejection diagnostics without changing validation or authorization decisions. |
| [replay.py](../forensic_assistant/investigation_ai/replay.py) | Replays validated saved forensic operations rather than arbitrary code or a model conversation. |
| [runner.py](../forensic_assistant/investigation_ai/runner.py) | Provides the parent-side interface to the bounded forensic worker and handles its lifecycle and errors. |
| [snapshot.py](../forensic_assistant/investigation_ai/snapshot.py) | Creates and guards private SQLite-consistent case snapshots and manages their identity/fingerprint and cleanup support. |
| [state.py](../forensic_assistant/investigation_ai/state.py) | Tracks investigation budgets, evidence actually exposed to the model, and validated finding structures. |
| [storage.py](../forensic_assistant/investigation_ai/storage.py) | Validates and pins local transcript directories, rejecting traversal and filesystem redirection. |
| [supervision.py](../forensic_assistant/investigation_ai/supervision.py) | Supervises the disposable investigation controller process under one deadline and handles termination/recovery. |
| [timing.py](../forensic_assistant/investigation_ai/timing.py) | Accounts for execution time using a monotonic clock and controlled analyst-wait credits. |
| [tools.py](../forensic_assistant/investigation_ai/tools.py) | Implements the fixed forensic tool adapters and bounded result envelopes; model prose cannot supply SQL or dynamic dispatch. |
| [transcript.py](../forensic_assistant/investigation_ai/transcript.py) | Writes and loads bounded derived investigation transcripts with integrity hashes and implementation metadata. |
| [worker.py](../forensic_assistant/investigation_ai/worker.py) | Serves trusted, validated requests inside the private read-only forensic worker process. |

<a id="forensic-assistant-reporting"></a>

## Grounded derived reports

`forensic_assistant/reporting/` — 16 Python files.

| File | What it does |
|---|---|
| [__init__.py](../forensic_assistant/reporting/__init__.py) | Marks this directory as a Python package; contains no executable workflow logic. |
| [boundaries.py](../forensic_assistant/reporting/boundaries.py) | Provides approved report-scope and interpretation statements that are not themselves evidence claims. |
| [bundle.py](../forensic_assistant/reporting/bundle.py) | Generates, publishes, inspects and validates report bundles, separating file hashes from structural and grounding checks. |
| [cli.py](../forensic_assistant/reporting/cli.py) | Implements report generation, inspection and validation commands and their output/audit integration. |
| [collect.py](../forensic_assistant/reporting/collect.py) | Collects bounded report inputs and verifies claims against current evidence at report time. |
| [legacy_render.py](../forensic_assistant/reporting/legacy_render.py) | Renders historical report HTML safely and provides shared CSS used by current rendering. |
| [model.py](../forensic_assistant/reporting/model.py) | Defines report limits, the claim vocabulary, canonical data/hashing and claim/evidence graph structures. |
| [narrative.py](../forensic_assistant/reporting/narrative.py) | Optionally composes current report narrative from approved claim-backed wording and validates every selected statement. |
| [narrative_v2.py](../forensic_assistant/reporting/narrative_v2.py) | Retains the earlier controlled-narrative contract for validating compatible historical report bundles. |
| [redact.py](../forensic_assistant/reporting/redact.py) | Builds redacted output views without altering stored evidence or promising complete anonymization. |
| [render.py](../forensic_assistant/reporting/render.py) | Renders current report views into standalone HTML and Markdown, with a historical-rendering fallback. |
| [semantics.py](../forensic_assistant/reporting/semantics.py) | Maps timestamp fields to Locard-controlled forensic labels rather than accepting artifact text as interpretation. |
| [transcripts.py](../forensic_assistant/reporting/transcripts.py) | Loads supported historical investigation transcript formats for reports with explicit compatibility checks. |
| [view.py](../forensic_assistant/reporting/view.py) | Builds the current human report view from validated claims and delegates compatible historical views when needed. |
| [view_v2.py](../forensic_assistant/reporting/view_v2.py) | Preserves the earlier report-view projection for historical report compatibility. |
| [worker.py](../forensic_assistant/reporting/worker.py) | Collects and verifies report evidence in a private worker without accepting model SQL or executable code. |

<a id="scripts"></a>

## Maintenance utilities

`scripts/` — 1 Python files.

| File | What it does |
|---|---|
| [protected_manifest.py](../scripts/protected_manifest.py) | Creates and verifies SHA-256 manifests for explicitly selected protected files; a new manifest establishes a future baseline, not historical integrity. |

**Coverage:** 184 Python files, each listed once. Descriptions reflect the current source, not a guarantee of forensic conclusions.

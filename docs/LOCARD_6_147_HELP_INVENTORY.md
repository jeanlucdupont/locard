# Locard 6.147 help editorial inventory

Generated from canonical interactive parser metadata. Length is characters / words. Safety categories are advisory triage, not authorization decisions.

| Command | Entry | Previous | Revised | Old length | New length | Changed | Review category |
|---|---|---|---|---|---|---|---|
| (root) | --db |  | Case database path | 0 / 0 | 18 / 3 | True | routine |
| (root) | --version | show program's version number and exit | show program's version number and exit | 38 / 6 | 38 / 6 | False | routine |
| (root) | --version-details | Show effective source and installed metadata versions (JSON) | Show source and installed versions as JSON | 60 / 8 | 42 / 7 | True | forensic meaning |
| (root) | [command] | Locard — local evidence-first Windows forensics | Locard — local evidence-first Windows forensics | 47 / 6 | 47 / 6 | False | forensic meaning |
| (root) | [subcommand] ai | Configure AI provider and local runtime | Configure AI provider and local runtime | 39 / 6 | 39 / 6 | False | external disclosure |
| (root) | [subcommand] analyze | Model-free forensic correlation and detections | Correlate evidence and review detections | 46 / 5 | 40 / 5 | True | forensic meaning |
| (root) | [subcommand] audit | Analyst activity and integrity verification | Review activity and verify audit integrity | 43 / 5 | 42 / 6 | True | mutation/integrity |
| (root) | [subcommand] case | Open, create and inspect a case | Open, create and inspect a case | 31 / 6 | 31 / 6 | False | routine |
| (root) | [subcommand] evidence | Ingest, find, inspect and export evidence | Ingest, find, inspect and export evidence | 41 / 6 | 41 / 6 | False | forensic meaning |
| (root) | [subcommand] investigation | Guided investigation, recorded review and findings | Investigate a case and review findings | 50 / 6 | 38 / 6 | True | routine |
| (root) | [subcommand] report | Generate a forensic investigation report | Generate a forensic investigation report | 40 / 5 | 40 / 5 | False | routine |
| (root) | [subcommand] settings | Terminal preferences and application version | Set terminal preferences and view the version | 44 / 5 | 45 / 7 | True | routine |
| (root) | family |  |  | 0 / 0 | 0 / 0 | False | routine |
| ai | [command] | Local uses llama.cpp / llama-server with a compatible user-selected GGUF model. Status distinguishes configuration readiness from runtime state. Cloud use sends bounded model context to the selected provider. | Local uses llama.cpp / llama-server with a compatible user-selected GGUF model. Status distinguishes configuration readiness from runtime state. Cloud use sends bounded model context to the selected provider. | 208 / 28 | 208 / 28 | False | external disclosure |
| ai | [footer] | Status and Quick are provider-free; connectivity/full checks and runtime start are explicit operations. | Status and Quick are provider-free; connectivity/full checks and runtime start are explicit operations. | 103 / 13 | 103 / 13 | False | external disclosure |
| ai | [subcommand] check | Check local configuration or explicitly diagnose the provider | Check configuration or run an authorized provider diagnostic | 61 / 8 | 60 / 8 | True | authorization, external disclosure |
| ai | [subcommand] configure | Configure provider/model or local paths | Configure the provider, model or local paths | 39 / 5 | 44 / 7 | True | external disclosure |
| ai | [subcommand] logs | Show private runtime or cloud provider diagnostics | Review AI diagnostics | 50 / 7 | 21 / 3 | True | routine |
| ai | [subcommand] provider | View or select provider | View or select provider | 23 / 4 | 23 / 4 | False | external disclosure |
| ai | [subcommand] start | Start the owned local runtime | Start the owned local runtime | 29 / 5 | 29 / 5 | False | routine |
| ai | [subcommand] status | Show provider and runtime status | Show provider configuration and readiness | 32 / 5 | 41 / 5 | True | external disclosure |
| ai | [subcommand] stop | Stop only the Locard-owned runtime | Stop only the Locard-owned runtime | 34 / 5 | 34 / 5 | False | routine |
| ai | ai_command |  |  | 0 / 0 | 0 / 0 | False | routine |
| ai check | --authorize-diagnostic | Authorize synthetic model requests for this diagnostic only | Authorize synthetic model requests for this diagnostic only | 59 / 8 | 59 / 8 | False | authorization |
| ai check | --connectivity | Non-generative authentication/reachability check | Non-generative authentication/reachability check | 48 / 3 | 48 / 3 | False | routine |
| ai check | --full | Potentially billable synthetic compatibility diagnostic | Potentially billable synthetic compatibility diagnostic | 55 / 5 | 55 / 5 | False | routine |
| ai check | --json |  | Output as JSON | 0 / 0 | 14 / 3 | True | routine |
| ai check | [command] |  | Check configuration or run an authorized provider diagnostic | 0 / 0 | 60 / 8 | True | authorization, external disclosure |
| ai configure | --acknowledge-cloud | Explicitly acknowledge transmission to the selected cloud provider | Explicitly acknowledge transmission to the selected cloud provider | 66 / 8 | 66 / 8 | False | external disclosure |
| ai configure | --context |  | Local model context size | 0 / 0 | 24 / 4 | True | routine |
| ai configure | --executable |  | Local llama-server executable | 0 / 0 | 29 / 3 | True | routine |
| ai configure | --extra-options | Validated performance options; -ngl/-c update dedicated settings, never duplicate defaults | Validated performance options; -ngl/-c update dedicated settings, never duplicate defaults | 90 / 10 | 90 / 10 | False | routine |
| ai configure | --gpu-layers |  | Number of model layers assigned to GPU | 0 / 0 | 38 / 7 | True | routine |
| ai configure | --json |  | Output as JSON | 0 / 0 | 14 / 3 | True | routine |
| ai configure | --model | Explicit cloud model name, without provider prefix | Cloud model name without provider prefix | 50 / 7 | 40 / 6 | True | external disclosure |
| ai configure | --model-path |  | Local GGUF model file | 0 / 0 | 21 / 4 | True | routine |
| ai configure | --port | Preferred loopback port; 0 selects a free port | Loopback port; 0 selects an available port | 46 / 8 | 42 / 7 | True | routine |
| ai configure | [command] |  | Configure the provider, model or local paths | 0 / 0 | 44 / 7 | True | external disclosure |
| ai configure | provider |  | AI provider | 0 / 0 | 11 / 2 | True | external disclosure |
| ai logs | --json |  | Output as JSON | 0 / 0 | 14 / 3 | True | routine |
| ai logs | --raw | Enable session capture and display buffered cloud output; may contain case data | Enable session capture and display buffered cloud output; may contain case data | 79 / 12 | 79 / 12 | False | external disclosure |
| ai logs | [command] |  | Review AI diagnostics | 0 / 0 | 21 / 3 | True | routine |
| ai provider | --acknowledge-cloud | Explicitly acknowledge transmission to the selected cloud provider | Explicitly acknowledge transmission to the selected cloud provider | 66 / 8 | 66 / 8 | False | external disclosure |
| ai provider | --json |  | Output as JSON | 0 / 0 | 14 / 3 | True | external disclosure |
| ai provider | --model | Explicit cloud model name, without provider prefix | Cloud model name without provider prefix | 50 / 7 | 40 / 6 | True | external disclosure |
| ai provider | [command] |  | View or select provider | 0 / 0 | 23 / 4 | True | external disclosure |
| ai provider | provider |  | AI provider | 0 / 0 | 11 / 2 | True | external disclosure |
| ai start | --json |  | Output as JSON | 0 / 0 | 14 / 3 | True | routine |
| ai start | [command] |  | Start the owned local runtime | 0 / 0 | 29 / 5 | True | routine |
| ai status | --json |  | Output as JSON | 0 / 0 | 14 / 3 | True | routine |
| ai status | [command] |  | Show provider configuration and readiness | 0 / 0 | 41 / 5 | True | external disclosure |
| ai stop | --json |  | Output as JSON | 0 / 0 | 14 / 3 | True | routine |
| ai stop | [command] |  | Stop only the Locard-owned runtime | 0 / 0 | 34 / 5 | True | routine |
| analyze | [command] | Model-free forensic correlation and detections | Correlate evidence and review detections | 46 / 5 | 40 / 5 | True | forensic meaning |
| analyze | [subcommand] correlate | Gather and correlate evidence around a specific evidence record | Gather and correlate evidence around a specific evidence record | 63 / 9 | 63 / 9 | False | forensic meaning |
| analyze | [subcommand] detections | Show evidence matching Locard detection rules | Show evidence matching Locard detection rules | 45 / 6 | 45 / 6 | False | forensic meaning |
| analyze | [subcommand] logons | Review Windows logon-related activity from normalized Windows Event Log evidence | Review recorded Windows logon activity | 80 / 10 | 38 / 5 | True | routine |
| analyze | [subcommand] process-tree | Reconstruct process parent-child relationships | Reconstruct process parent-child relationships | 46 / 4 | 46 / 4 | False | routine |
| analyze | [subcommand] session | Reconstruct activity within a Windows logon session | Reconstruct activity within a Windows logon session | 51 / 7 | 51 / 7 | False | routine |
| analyze | analyze_operation |  |  | 0 / 0 | 0 / 0 | False | routine |
| analyze correlate | --append | Append rendered output to a derived UTF-8 file | Append output to a file | 46 / 8 | 23 / 5 | True | routine |
| analyze correlate | --candidate-limit | Maximum candidate volume (default: 500) | Maximum candidate volume (default: 500) | 39 / 5 | 39 / 5 | False | routine |
| analyze correlate | --force | Permit replacing an existing derived output file without confirmation | Overwrite an existing output file | 69 / 9 | 33 / 5 | True | mutation/integrity |
| analyze correlate | --json | Structured JSON output | Output as JSON | 22 / 3 | 14 / 3 | True | routine |
| analyze correlate | --output | Write a derived UTF-8 file; existing files require confirmation or --force | Save output to a file | 74 / 11 | 21 / 5 | True | routine |
| analyze correlate | --page | Review output with the internal pager (Up/Down, PgUp/PgDn, Home/End, Q) | View output page by page | 71 / 10 | 24 / 5 | True | routine |
| analyze correlate | --raw |  | Show the full diagnostic result as JSON | 0 / 0 | 39 / 7 | True | routine |
| analyze correlate | --seconds | Time window around the anchor, in seconds (default: 120) | Time window around the anchor, in seconds (default: 120) | 56 / 9 | 56 / 9 | False | routine |
| analyze correlate | --text | Human-readable text output | Show readable text | 26 / 3 | 18 / 3 | True | routine |
| analyze correlate | --timestamp-slot | Select the anchor timestamp slot when multiple slots exist | Select the anchor timestamp slot when multiple slots exist | 58 / 9 | 58 / 9 | False | forensic meaning |
| analyze correlate | [command] | Deterministic correlation around a specific evidence record identified by its canonical evidence_id. Gathers nearby and related evidence within bounded criteria; no AI required. | Deterministic correlation around a specific evidence record identified by its canonical evidence_id. Gathers nearby and related evidence within bounded criteria; no AI required. | 177 / 23 | 177 / 23 | False | forensic meaning |
| analyze correlate | [footer] | Interactive shell defaults to human text; direct CLI defaults to JSON. --raw retains diagnostic output, defaulting to JSON. Use --text for human paging; JSON paging is not supported. | Interactive shell defaults to human text; direct CLI defaults to JSON. --raw retains diagnostic output, defaulting to JSON. Use --text for human paging; JSON paging is not supported. | 182 / 28 | 182 / 28 | False | routine |
| analyze correlate | evidence_id | Canonical evidence ID of the anchor record | Anchor evidence ID | 42 / 7 | 18 / 3 | True | forensic meaning |
| analyze detections | --append | Append rendered output to a derived UTF-8 file | Append output to a file | 46 / 8 | 23 / 5 | True | routine |
| analyze detections | --candidate-limit |  | Maximum candidate records examined | 0 / 0 | 34 / 4 | True | routine |
| analyze detections | --end |  | End time with timezone | 0 / 0 | 22 / 4 | True | routine |
| analyze detections | --failure-threshold |  | Minimum failed logons for a detection | 0 / 0 | 37 / 6 | True | routine |
| analyze detections | --failure-window |  | Failed-logon window in seconds | 0 / 0 | 30 / 4 | True | routine |
| analyze detections | --force | Permit replacing an existing derived output file without confirmation | Overwrite an existing output file | 69 / 9 | 33 / 5 | True | mutation/integrity |
| analyze detections | --hostname |  | Hostname filter | 0 / 0 | 15 / 2 | True | routine |
| analyze detections | --json | Structured JSON output | Output as JSON | 22 / 3 | 14 / 3 | True | routine |
| analyze detections | --limit |  | Maximum number of results | 0 / 0 | 25 / 4 | True | routine |
| analyze detections | --output | Write a derived UTF-8 file; existing files require confirmation or --force | Save output to a file | 74 / 11 | 21 / 5 | True | routine |
| analyze detections | --page | Review output with the internal pager (Up/Down, PgUp/PgDn, Home/End, Q) | View output page by page | 71 / 10 | 24 / 5 | True | routine |
| analyze detections | --raw |  | Show the full diagnostic result as JSON | 0 / 0 | 39 / 7 | True | routine |
| analyze detections | --rule |  | Detection rule | 0 / 0 | 14 / 2 | True | routine |
| analyze detections | --severity |  | Recorded severity filter | 0 / 0 | 24 / 3 | True | routine |
| analyze detections | --start |  | Start time with timezone | 0 / 0 | 24 / 4 | True | routine |
| analyze detections | --text | Human-readable text output | Show readable text | 26 / 3 | 18 / 3 | True | routine |
| analyze detections | --user |  | Username filter | 0 / 0 | 15 / 2 | True | routine |
| analyze detections | [command] |  | Show evidence matching Locard detection rules | 0 / 0 | 45 / 6 | True | forensic meaning |
| analyze detections | [footer] | Interactive shell defaults to human text; direct CLI defaults to JSON. --raw retains diagnostic output, defaulting to JSON. Use --text for human paging; JSON paging is not supported. | Interactive shell defaults to human text; direct CLI defaults to JSON. --raw retains diagnostic output, defaulting to JSON. Use --text for human paging; JSON paging is not supported. | 182 / 28 | 182 / 28 | False | routine |
| analyze logons | --append | Append rendered output to a derived UTF-8 file | Append output to a file | 46 / 8 | 23 / 5 | True | routine |
| analyze logons | --end |  | End time with timezone | 0 / 0 | 22 / 4 | True | routine |
| analyze logons | --force | Permit replacing an existing derived output file without confirmation | Overwrite an existing output file | 69 / 9 | 33 / 5 | True | mutation/integrity |
| analyze logons | --hostname |  | Hostname filter | 0 / 0 | 15 / 2 | True | routine |
| analyze logons | --ip |  | IP address filter | 0 / 0 | 17 / 3 | True | routine |
| analyze logons | --json | Structured JSON output | Output as JSON | 22 / 3 | 14 / 3 | True | routine |
| analyze logons | --limit |  | Maximum number of results | 0 / 0 | 25 / 4 | True | routine |
| analyze logons | --offset |  | Skip this many results | 0 / 0 | 22 / 4 | True | routine |
| analyze logons | --output | Write a derived UTF-8 file; existing files require confirmation or --force | Save output to a file | 74 / 11 | 21 / 5 | True | routine |
| analyze logons | --page | Review output with the internal pager (Up/Down, PgUp/PgDn, Home/End, Q) | View output page by page | 71 / 10 | 24 / 5 | True | routine |
| analyze logons | --raw |  | Show the full diagnostic result as JSON | 0 / 0 | 39 / 7 | True | routine |
| analyze logons | --start |  | Start time with timezone | 0 / 0 | 24 / 4 | True | routine |
| analyze logons | --text | Human-readable text output | Show readable text | 26 / 3 | 18 / 3 | True | routine |
| analyze logons | --user |  | Username filter | 0 / 0 | 15 / 2 | True | routine |
| analyze logons | [command] | Review Windows logon-related activity from normalized Windows Event Log evidence | Review recorded Windows logon activity | 80 / 10 | 38 / 5 | True | routine |
| analyze logons | [footer] | Interactive shell defaults to human text; direct CLI defaults to JSON. --raw retains diagnostic output, defaulting to JSON. Use --text for human paging; JSON paging is not supported. | Interactive shell defaults to human text; direct CLI defaults to JSON. --raw retains diagnostic output, defaulting to JSON. Use --text for human paging; JSON paging is not supported. | 182 / 28 | 182 / 28 | False | routine |
| analyze process-tree | --append | Append rendered output to a derived UTF-8 file | Append output to a file | 46 / 8 | 23 / 5 | True | routine |
| analyze process-tree | --around |  | Anchor time with timezone | 0 / 0 | 25 / 4 | True | routine |
| analyze process-tree | --evidence |  | Process-creation evidence ID | 0 / 0 | 28 / 3 | True | forensic meaning |
| analyze process-tree | --force | Permit replacing an existing derived output file without confirmation | Overwrite an existing output file | 69 / 9 | 33 / 5 | True | mutation/integrity |
| analyze process-tree | --hostname |  | Hostname filter | 0 / 0 | 15 / 2 | True | routine |
| analyze process-tree | --json | Structured JSON output | Output as JSON | 22 / 3 | 14 / 3 | True | routine |
| analyze process-tree | --max-depth |  | Maximum process relationship depth | 0 / 0 | 34 / 4 | True | routine |
| analyze process-tree | --max-nodes |  | Maximum process nodes | 0 / 0 | 21 / 3 | True | routine |
| analyze process-tree | --output | Write a derived UTF-8 file; existing files require confirmation or --force | Save output to a file | 74 / 11 | 21 / 5 | True | routine |
| analyze process-tree | --page | Review output with the internal pager (Up/Down, PgUp/PgDn, Home/End, Q) | View output page by page | 71 / 10 | 24 / 5 | True | routine |
| analyze process-tree | --pid-window |  | PID reuse lookback window in seconds | 0 / 0 | 36 / 6 | True | routine |
| analyze process-tree | --process |  | Process name filter | 0 / 0 | 19 / 3 | True | routine |
| analyze process-tree | --raw |  | Show the full diagnostic result as JSON | 0 / 0 | 39 / 7 | True | routine |
| analyze process-tree | --seconds |  | Child-process window in seconds | 0 / 0 | 31 / 4 | True | routine |
| analyze process-tree | --text | Human-readable text output | Show readable text | 26 / 3 | 18 / 3 | True | routine |
| analyze process-tree | [command] |  | Reconstruct process parent-child relationships | 0 / 0 | 46 / 4 | True | routine |
| analyze process-tree | [footer] | Interactive shell defaults to human text; direct CLI defaults to JSON. --raw retains diagnostic output, defaulting to JSON. Use --text for human paging; JSON paging is not supported. | Interactive shell defaults to human text; direct CLI defaults to JSON. --raw retains diagnostic output, defaulting to JSON. Use --text for human paging; JSON paging is not supported. | 182 / 28 | 182 / 28 | False | routine |
| analyze session | --append | Append rendered output to a derived UTF-8 file | Append output to a file | 46 / 8 | 23 / 5 | True | routine |
| analyze session | --around |  | Anchor time with timezone | 0 / 0 | 25 / 4 | True | routine |
| analyze session | --evidence | Successful-logon evidence ID to disambiguate | Successful-logon evidence ID for disambiguation | 44 / 5 | 47 / 5 | True | forensic meaning |
| analyze session | --force | Permit replacing an existing derived output file without confirmation | Overwrite an existing output file | 69 / 9 | 33 / 5 | True | mutation/integrity |
| analyze session | --hostname |  | Hostname filter | 0 / 0 | 15 / 2 | True | routine |
| analyze session | --json | Structured JSON output | Output as JSON | 22 / 3 | 14 / 3 | True | routine |
| analyze session | --limit |  | Maximum number of results | 0 / 0 | 25 / 4 | True | routine |
| analyze session | --logon-id | Windows authentication Logon ID, decimal or hexadecimal (for example 0x1cd8f6); not a Locard evidence ID | Windows authentication Logon ID, decimal or hexadecimal (for example 0x1cd8f6); not a Locard evidence ID | 104 / 15 | 104 / 15 | False | forensic meaning |
| analyze session | --max-hours |  | Maximum session duration in hours | 0 / 0 | 33 / 5 | True | routine |
| analyze session | --output | Write a derived UTF-8 file; existing files require confirmation or --force | Save output to a file | 74 / 11 | 21 / 5 | True | routine |
| analyze session | --page | Review output with the internal pager (Up/Down, PgUp/PgDn, Home/End, Q) | View output page by page | 71 / 10 | 24 / 5 | True | routine |
| analyze session | --raw |  | Show the full diagnostic result as JSON | 0 / 0 | 39 / 7 | True | routine |
| analyze session | --text | Human-readable text output | Show readable text | 26 / 3 | 18 / 3 | True | routine |
| analyze session | [command] |  | Reconstruct activity within a Windows logon session | 0 / 0 | 51 / 7 | True | routine |
| analyze session | [footer] | Interactive shell defaults to human text; direct CLI defaults to JSON. --raw retains diagnostic output, defaulting to JSON. Use --text for human paging; JSON paging is not supported. | Interactive shell defaults to human text; direct CLI defaults to JSON. --raw retains diagnostic output, defaulting to JSON. Use --text for human paging; JSON paging is not supported. | 182 / 28 | 182 / 28 | False | routine |
| audit | [command] | Analyst activity and integrity verification | Review activity and verify audit integrity | 43 / 5 | 42 / 6 | True | mutation/integrity |
| audit | [subcommand] activity | Review and verify analyst activity | Review and verify analyst activity | 34 / 5 | 34 / 5 | False | mutation/integrity |
| audit | [subcommand] diagnostics | Review bounded, linked process recordings; not original evidence | Review Locard's internal diagnostic logs | 64 / 8 | 40 / 5 | True | mutation/integrity |
| audit | [subcommand] session | Session | Session | 7 / 1 | 7 / 1 | False | mutation/integrity |
| audit | [subcommand] sessions | Review bounded, linked process recordings; not original evidence | Review Locard's internal diagnostic logs | 64 / 8 | 40 / 5 | True | mutation/integrity |
| audit | [subcommand] verify | Verify the existing analyst activity chain; read-only | Verify activity and session integrity | 53 / 7 | 37 / 5 | True | mutation/integrity |
| audit | audit_operation |  |  | 0 / 0 | 0 / 0 | False | mutation/integrity |
| audit activity | --append | Append rendered output to a derived UTF-8 file | Append output to a file | 46 / 8 | 23 / 5 | True | mutation/integrity |
| audit activity | --force | Permit replacing an existing derived output file without confirmation | Overwrite an existing output file | 69 / 9 | 33 / 5 | True | mutation/integrity |
| audit activity | --json |  | Output as JSON | 0 / 0 | 14 / 3 | True | mutation/integrity |
| audit activity | --limit |  | Maximum number of results | 0 / 0 | 25 / 4 | True | mutation/integrity |
| audit activity | --output | Write a derived UTF-8 file; existing files require confirmation or --force | Save output to a file | 74 / 11 | 21 / 5 | True | mutation/integrity |
| audit activity | --page | Review output with the internal pager (Up/Down, PgUp/PgDn, Home/End, Q) | View output page by page | 71 / 10 | 24 / 5 | True | mutation/integrity |
| audit activity | [command] |  | Review and verify analyst activity | 0 / 0 | 34 / 5 | True | mutation/integrity |
| audit activity | [footer] | Read-only examination by default; derived output files and activity records may be written. Coverage limitations remain significant. |  | 132 / 17 | 0 / 0 | True | forensic meaning, mutation/integrity |
| audit diagnostics | --application | Review pre-case application logs instead of case logs | Review application logs instead of case logs | 53 / 8 | 44 / 7 | True | mutation/integrity |
| audit diagnostics | --json |  | Output as JSON | 0 / 0 | 14 / 3 | True | mutation/integrity |
| audit diagnostics | --limit | Last matching records, 1..1000 | Maximum recent records, 1..1000 | 30 / 4 | 31 / 4 | True | mutation/integrity |
| audit diagnostics | --operation-id | Exact operation correlation ID | Filter by operation ID | 30 / 4 | 22 / 4 | True | mutation/integrity |
| audit diagnostics | --severity |  | Recorded severity filter | 0 / 0 | 24 / 3 | True | mutation/integrity |
| audit diagnostics | --since | Include records since ISO 8601 time with timezone | Include records since a time with timezone | 49 / 8 | 42 / 7 | True | mutation/integrity |
| audit diagnostics | [command] | Review bounded, linked process recordings; not original evidence | Review Locard's internal diagnostic logs | 64 / 8 | 40 / 5 | True | mutation/integrity |
| audit diagnostics | session | Exact recording ID or latest by start time then ID | Session ID or latest session | 50 / 10 | 28 / 5 | True | mutation/integrity |
| audit session | [command] | Session | Session | 7 / 1 | 7 / 1 | False | mutation/integrity |
| audit session | [subcommand] show | Review bounded, linked process recordings; not original evidence | Review Locard's internal diagnostic logs | 64 / 8 | 40 / 5 | True | mutation/integrity |
| audit session | audit_session_operation |  |  | 0 / 0 | 0 / 0 | False | mutation/integrity |
| audit session show | --application | Review pre-case application logs instead of case logs | Review application logs instead of case logs | 53 / 8 | 44 / 7 | True | mutation/integrity |
| audit session show | --json |  | Output as JSON | 0 / 0 | 14 / 3 | True | mutation/integrity |
| audit session show | --limit | Last matching records, 1..1000 | Maximum recent records, 1..1000 | 30 / 4 | 31 / 4 | True | mutation/integrity |
| audit session show | --operation-id | Exact operation correlation ID | Filter by operation ID | 30 / 4 | 22 / 4 | True | mutation/integrity |
| audit session show | --since | Include records since ISO 8601 time with timezone | Include records since a time with timezone | 49 / 8 | 42 / 7 | True | mutation/integrity |
| audit session show | [command] | Review bounded, linked process recordings; not original evidence | Review Locard's internal diagnostic logs | 64 / 8 | 40 / 5 | True | mutation/integrity |
| audit session show | session | Exact recording ID or latest by start time then ID | Session ID or latest session | 50 / 10 | 28 / 5 | True | mutation/integrity |
| audit sessions | --application | Review pre-case application logs instead of case logs | Review application logs instead of case logs | 53 / 8 | 44 / 7 | True | mutation/integrity |
| audit sessions | --json |  | Output as JSON | 0 / 0 | 14 / 3 | True | mutation/integrity |
| audit sessions | [command] | Review bounded, linked process recordings; not original evidence | Review Locard's internal diagnostic logs | 64 / 8 | 40 / 5 | True | mutation/integrity |
| audit verify | --application | Review pre-case application logs instead of case logs | Review application logs instead of case logs | 53 / 8 | 44 / 7 | True | mutation/integrity |
| audit verify | --json |  | Output as JSON | 0 / 0 | 14 / 3 | True | mutation/integrity |
| audit verify | [command] | Verify the existing analyst activity chain; read-only | Verify activity and session integrity | 53 / 7 | 37 / 5 | True | mutation/integrity |
| case | [command] | Open, create and inspect a case | Open, create and inspect a case | 31 / 6 | 31 / 6 | False | routine |
| case | [subcommand] clone | Case workspace clone; no automatic relocation or history rebinding | Create an independent case copy | 66 / 9 | 31 / 5 | True | mutation/integrity |
| case | [subcommand] list | Case workspace list; no automatic relocation or history rebinding | List available cases | 65 / 9 | 20 / 3 | True | routine |
| case | [subcommand] new | Interactive case new; no evidence ingestion is implied | Create a case | 54 / 8 | 13 / 3 | True | routine |
| case | [subcommand] open | Interactive case open; no evidence ingestion is implied | Open a case | 55 / 8 | 11 / 3 | True | routine |
| case | [subcommand] register | Case workspace register; no automatic relocation or history rebinding | Register an existing case | 69 / 9 | 25 / 4 | True | mutation/integrity |
| case | [subcommand] root | Case workspace root; no automatic relocation or history rebinding | View or change the case directory | 65 / 9 | 33 / 6 | True | routine |
| case | [subcommand] status | Show case ingestion and evidence status | Show case ingestion and evidence status | 39 / 6 | 39 / 6 | False | forensic meaning |
| case | [subcommand] unregister | Case workspace unregister; no automatic relocation or history rebinding | Remove a case registration | 71 / 9 | 26 / 4 | True | mutation/integrity |
| case | case_operation |  |  | 0 / 0 | 0 / 0 | False | routine |
| case clone | --json |  | Output as JSON | 0 / 0 | 14 / 3 | True | mutation/integrity |
| case clone | --yes | Explicitly confirm the described local change; no evidence/provider authorization | Explicitly confirm the described local change; no evidence/provider authorization | 81 / 9 | 81 / 9 | False | authorization, external disclosure, forensic meaning, mutation/integrity |
| case clone | [command] | Case workspace clone; no automatic relocation or history rebinding | Create an independent case copy | 66 / 9 | 31 / 5 | True | mutation/integrity |
| case clone | name |  | Case name | 0 / 0 | 9 / 2 | True | mutation/integrity |
| case clone | source |  | Source case path | 0 / 0 | 16 / 3 | True | forensic meaning, mutation/integrity |
| case list | --json |  | Output as JSON | 0 / 0 | 14 / 3 | True | routine |
| case list | [command] | Case workspace list; no automatic relocation or history rebinding | List available cases | 65 / 9 | 20 / 3 | True | routine |
| case new | [command] | Interactive case new; no evidence ingestion is implied | Create a case | 54 / 8 | 13 / 3 | True | routine |
| case new | name |  | New case name | 0 / 0 | 13 / 3 | True | routine |
| case open | [command] | Interactive case open; no evidence ingestion is implied | Open a case | 55 / 8 | 11 / 3 | True | routine |
| case open | path |  | Existing case path | 0 / 0 | 18 / 3 | True | routine |
| case register | --json |  | Output as JSON | 0 / 0 | 14 / 3 | True | mutation/integrity |
| case register | --yes | Explicitly confirm the described local change; no evidence/provider authorization | Explicitly confirm the described local change; no evidence/provider authorization | 81 / 9 | 81 / 9 | False | authorization, external disclosure, forensic meaning, mutation/integrity |
| case register | [command] | Case workspace register; no automatic relocation or history rebinding | Register an existing case | 69 / 9 | 25 / 4 | True | mutation/integrity |
| case register | name |  | Case name | 0 / 0 | 9 / 2 | True | mutation/integrity |
| case register | path |  | File or directory path | 0 / 0 | 22 / 4 | True | mutation/integrity |
| case root | --json |  | Output as JSON | 0 / 0 | 14 / 3 | True | routine |
| case root | --yes | Explicitly confirm the described local change; no evidence/provider authorization | Explicitly confirm the described local change; no evidence/provider authorization | 81 / 9 | 81 / 9 | False | authorization, external disclosure, forensic meaning |
| case root | [command] | Case workspace root; no automatic relocation or history rebinding | View or change the case directory | 65 / 9 | 33 / 6 | True | routine |
| case root | action |  | Select set to change the root | 0 / 0 | 29 / 6 | True | routine |
| case root | path |  | File or directory path | 0 / 0 | 22 / 4 | True | routine |
| case status | --append | Append rendered output to a derived UTF-8 file | Append output to a file | 46 / 8 | 23 / 5 | True | routine |
| case status | --force | Permit replacing an existing derived output file without confirmation | Overwrite an existing output file | 69 / 9 | 33 / 5 | True | mutation/integrity |
| case status | --json |  | Output as JSON | 0 / 0 | 14 / 3 | True | routine |
| case status | --output | Write a derived UTF-8 file; existing files require confirmation or --force | Save output to a file | 74 / 11 | 21 / 5 | True | routine |
| case status | --page | Review output with the internal pager (Up/Down, PgUp/PgDn, Home/End, Q) | View output page by page | 71 / 10 | 24 / 5 | True | routine |
| case status | [command] |  | Show case ingestion and evidence status | 0 / 0 | 39 / 6 | True | forensic meaning |
| case status | [footer] | Read-only examination by default; derived output files and activity records may be written. Coverage limitations remain significant. |  | 132 / 17 | 0 / 0 | True | forensic meaning |
| case unregister | --json |  | Output as JSON | 0 / 0 | 14 / 3 | True | mutation/integrity |
| case unregister | --yes | Explicitly confirm the described local change; no evidence/provider authorization | Explicitly confirm the described local change; no evidence/provider authorization | 81 / 9 | 81 / 9 | False | authorization, external disclosure, forensic meaning, mutation/integrity |
| case unregister | [command] | Case workspace unregister; no automatic relocation or history rebinding | Remove a case registration | 71 / 9 | 26 / 4 | True | mutation/integrity |
| case unregister | name |  | Case name | 0 / 0 | 9 / 2 | True | mutation/integrity |
| evidence | [command] | Ingest, find, inspect and export evidence | Ingest, find, inspect and export evidence | 41 / 6 | 41 / 6 | False | forensic meaning |
| evidence | [subcommand] around | Show evidence near a specific event or timestamp | Show evidence near a specific event or timestamp | 48 / 8 | 48 / 8 | False | forensic meaning |
| evidence | [subcommand] export | Export retained evidence to case-local CSV files | Export retained evidence to case-local CSV files | 48 / 7 | 48 / 7 | False | forensic meaning |
| evidence | [subcommand] ingest | Ingest | Ingest | 6 / 1 | 6 / 1 | False | forensic meaning |
| evidence | [subcommand] search | Search case evidence | Search case evidence | 20 / 3 | 20 / 3 | False | forensic meaning |
| evidence | [subcommand] semantic | Search case evidence by meaning | Search case evidence by meaning | 31 / 5 | 31 / 5 | False | forensic meaning |
| evidence | [subcommand] show | Show details about an evidence record | Show details about an evidence record | 37 / 6 | 37 / 6 | False | forensic meaning |
| evidence | [subcommand] source | Manage evidence sources | Manage evidence sources | 23 / 3 | 23 / 3 | False | forensic meaning |
| evidence | [subcommand] timeline | Browse evidence chronologically | Browse evidence chronologically | 31 / 3 | 31 / 3 | False | forensic meaning |
| evidence | evidence_operation |  |  | 0 / 0 | 0 / 0 | False | forensic meaning |
| evidence around | --append | Append rendered output to a derived UTF-8 file | Append output to a file | 46 / 8 | 23 / 5 | True | forensic meaning |
| evidence around | --direction |  | Select evidence before, after or around the anchor | 0 / 0 | 50 / 8 | True | forensic meaning |
| evidence around | --force | Permit replacing an existing derived output file without confirmation | Overwrite an existing output file | 69 / 9 | 33 / 5 | True | forensic meaning, mutation/integrity |
| evidence around | --ids | Include full evidence/source IDs, timestamp slots and original timestamp precision in --text output | Show exact IDs, timestamp types and full precision | 99 / 13 | 50 / 8 | True | forensic meaning |
| evidence around | --json | JSON output (default) | Output as JSON (default) | 21 / 3 | 24 / 4 | True | forensic meaning |
| evidence around | --limit |  | Maximum number of results | 0 / 0 | 25 / 4 | True | forensic meaning |
| evidence around | --offset |  | Skip this many results | 0 / 0 | 22 / 4 | True | forensic meaning |
| evidence around | --output | Write a derived UTF-8 file; existing files require confirmation or --force | Save output to a file | 74 / 11 | 21 / 5 | True | forensic meaning |
| evidence around | --page | Review output with the internal pager (Up/Down, PgUp/PgDn, Home/End, Q) | View output page by page | 71 / 10 | 24 / 5 | True | forensic meaning |
| evidence around | --raw |  | Include original record details where available | 0 / 0 | 47 / 6 | True | forensic meaning |
| evidence around | --seconds |  | Seconds around the anchor | 0 / 0 | 25 / 4 | True | forensic meaning |
| evidence around | --text | Compact readable output | Show a compact readable result | 23 / 3 | 30 / 5 | True | forensic meaning |
| evidence around | --timestamp-slot |  | Anchor timestamp type | 0 / 0 | 21 / 3 | True | forensic meaning |
| evidence around | [command] | Compact text rounds timestamps and exact deltas to milliseconds (nearest, ties away from zero). JSON/raw and --ids retain full precision. Temporal proximity is not causation; timestamp meanings differ by artifact. | Compact text rounds timestamps and exact deltas to milliseconds (nearest, ties away from zero). JSON/raw and --ids retain full precision. Temporal proximity is not causation; timestamp meanings differ by artifact. | 213 / 30 | 213 / 30 | False | forensic meaning |
| evidence around | [footer] | Read-only examination by default; derived output files and activity records may be written. Coverage limitations remain significant. |  | 132 / 17 | 0 / 0 | True | forensic meaning |
| evidence around | evidence_id |  | Evidence record identifier | 0 / 0 | 26 / 3 | True | forensic meaning |
| evidence export | --force | Replace requested derived CSV files | Replace requested derived CSV files | 35 / 5 | 35 / 5 | False | forensic meaning, mutation/integrity |
| evidence export | [command] | Usage:<br>  evidence export <type> [--force]<br><br>Types: browser, evtx, mft, prefetch, registry, all<br><br>Examples: evidence export browser; evidence export evtx; evidence export mft; evidence export prefetch; evidence export registry; evidence export all<br>Fixed destination: <case database directory>/dump/<type>.csv<br>Existing files require --force. Empty categories are skipped.<br>CSV files are derived analyst output, not evidence. | Usage:<br>  evidence export <type> [--force]<br><br>Types: browser, evtx, mft, prefetch, registry, all<br><br>Examples: evidence export browser; evidence export evtx; evidence export mft; evidence export prefetch; evidence export registry; evidence export all<br>Fixed destination: <case database directory>/dump/<type>.csv<br>Existing files require --force. Empty categories are skipped.<br>CSV files are derived analyst output, not evidence. | 419 / 52 | 419 / 52 | False | forensic meaning, mutation/integrity |
| evidence export | [footer] | Read-only examination by default; derived output files and activity records may be written. Coverage limitations remain significant. |  | 132 / 17 | 0 / 0 | True | forensic meaning |
| evidence export | dump_type |  | Artifact family to export | 0 / 0 | 25 / 4 | True | forensic meaning |
| evidence ingest | [command] | Ingest | Ingest | 6 / 1 | 6 / 1 | False | forensic meaning |
| evidence ingest | [subcommand] all | Import all supported forensic artifacts | Import all supported forensic artifacts | 39 / 5 | 39 / 5 | False | forensic meaning |
| evidence ingest | [subcommand] browser | Ingest Chrome or Edge browsing history and downloads | Ingest Chrome or Edge browsing history and downloads | 52 / 8 | 52 / 8 | False | forensic meaning |
| evidence ingest | [subcommand] evtx | Import Windows Event Logs (EVTX) | Import Windows Event Logs (EVTX) | 32 / 5 | 32 / 5 | False | forensic meaning |
| evidence ingest | [subcommand] mft | Import NTFS Master File Table (MFT) evidence | Import NTFS Master File Table (MFT) evidence | 44 / 7 | 44 / 7 | False | forensic meaning |
| evidence ingest | [subcommand] prefetch | Import Windows Prefetch evidence | Import Windows Prefetch evidence | 32 / 4 | 32 / 4 | False | forensic meaning |
| evidence ingest | [subcommand] registry | Import Windows Registry evidence | Import Windows Registry evidence | 32 / 4 | 32 / 4 | False | forensic meaning |
| evidence ingest | [subcommand] wizard | Guided evidence selection; confirmation required | Guided evidence selection; confirmation required | 48 / 5 | 48 / 5 | False | authorization, forensic meaning |
| evidence ingest | evidence_ingest_operation |  |  | 0 / 0 | 0 / 0 | False | forensic meaning |
| evidence ingest all | --append | Append rendered output to a derived UTF-8 file | Append output to a file | 46 / 8 | 23 / 5 | True | forensic meaning |
| evidence ingest all | --evtx-hard-timeout | EVTX emergency absolute ceiling in seconds (default: 21600) | EVTX emergency absolute ceiling in seconds (default: 21600) | 59 / 8 | 59 / 8 | False | forensic meaning |
| evidence ingest all | --force | Permit replacing an existing derived output file without confirmation | Overwrite an existing output file | 69 / 9 | 33 / 5 | True | forensic meaning, mutation/integrity |
| evidence ingest all | --hostname |  | Analyst-supplied source hostname | 0 / 0 | 32 / 3 | True | forensic meaning |
| evidence ingest all | --json |  | Output as JSON | 0 / 0 | 14 / 3 | True | forensic meaning |
| evidence ingest all | --output | Write a derived UTF-8 file; existing files require confirmation or --force | Save output to a file | 74 / 11 | 21 / 5 | True | forensic meaning |
| evidence ingest all | --page | Review output with the internal pager (Up/Down, PgUp/PgDn, Home/End, Q) | View output page by page | 71 / 10 | 24 / 5 | True | forensic meaning |
| evidence ingest all | --parser-timeout | EVTX: seconds without parser advancement; other artifacts: wall-clock limit | EVTX: seconds without parser advancement; other artifacts: wall-clock limit | 75 / 9 | 75 / 9 | False | forensic meaning |
| evidence ingest all | --record-size |  | MFT record size in bytes | 0 / 0 | 24 / 5 | True | forensic meaning |
| evidence ingest all | --source | Reuse this source ID; omitted in scripts creates a NEW automatic source for this invocation, never inferred or reused | Reuse this source ID; omitted in scripts creates a NEW automatic source for this invocation, never inferred or reused | 117 / 19 | 117 / 19 | False | forensic meaning |
| evidence ingest all | --user |  | Analyst-supplied source username | 0 / 0 | 32 / 3 | True | forensic meaning |
| evidence ingest all | --volume-root |  | Original volume root asserted by the analyst | 0 / 0 | 44 / 7 | True | forensic meaning |
| evidence ingest all | [command] |  | Import all supported forensic artifacts | 0 / 0 | 39 / 5 | True | forensic meaning |
| evidence ingest all | [footer] | Mutates the selected case through the existing ingestion service; source evidence is read-only. Review partial outcomes. | Mutates the selected case through the existing ingestion service; source evidence is read-only. Review partial outcomes. | 120 / 16 | 120 / 16 | False | forensic meaning |
| evidence ingest all | path |  | File or directory path | 0 / 0 | 22 / 4 | True | forensic meaning |
| evidence ingest browser | --append | Append rendered output to a derived UTF-8 file | Append output to a file | 46 / 8 | 23 / 5 | True | forensic meaning |
| evidence ingest browser | --browser | Explicit browser product; never inferred | Browser product; never inferred | 40 / 5 | 31 / 4 | True | forensic meaning |
| evidence ingest browser | --force | Permit replacing an existing derived output file without confirmation | Overwrite an existing output file | 69 / 9 | 33 / 5 | True | forensic meaning, mutation/integrity |
| evidence ingest browser | --hostname |  | Analyst-supplied source hostname | 0 / 0 | 32 / 3 | True | forensic meaning |
| evidence ingest browser | --json |  | Output as JSON | 0 / 0 | 14 / 3 | True | forensic meaning |
| evidence ingest browser | --output | Write a derived UTF-8 file; existing files require confirmation or --force | Save output to a file | 74 / 11 | 21 / 5 | True | forensic meaning |
| evidence ingest browser | --page | Review output with the internal pager (Up/Down, PgUp/PgDn, Home/End, Q) | View output page by page | 71 / 10 | 24 / 5 | True | forensic meaning |
| evidence ingest browser | --parser-timeout | EVTX: seconds without parser advancement; other artifacts: wall-clock limit | EVTX: seconds without parser advancement; other artifacts: wall-clock limit | 75 / 9 | 75 / 9 | False | forensic meaning |
| evidence ingest browser | --profile | Explicit browser profile; separate from Windows user | Browser profile, not the Windows username | 52 / 7 | 41 / 6 | True | forensic meaning |
| evidence ingest browser | --source | Reuse this source ID; omitted in scripts creates a NEW automatic source for this invocation, never inferred or reused | Reuse this source ID; omitted in scripts creates a NEW automatic source for this invocation, never inferred or reused | 117 / 19 | 117 / 19 | False | forensic meaning |
| evidence ingest browser | --user |  | Analyst-supplied source username | 0 / 0 | 32 / 3 | True | forensic meaning |
| evidence ingest browser | --volume-root |  | Original volume root asserted by the analyst | 0 / 0 | 44 / 7 | True | forensic meaning |
| evidence ingest browser | [command] |  | Ingest Chrome or Edge browsing history and downloads | 0 / 0 | 52 / 8 | True | forensic meaning |
| evidence ingest browser | [footer] | Mutates the selected case through the existing ingestion service; source evidence is read-only. Review partial outcomes. | Mutates the selected case through the existing ingestion service; source evidence is read-only. Review partial outcomes. | 120 / 16 | 120 / 16 | False | forensic meaning |
| evidence ingest browser | path |  | File or directory path | 0 / 0 | 22 / 4 | True | forensic meaning |
| evidence ingest evtx | --append | Append rendered output to a derived UTF-8 file | Append output to a file | 46 / 8 | 23 / 5 | True | forensic meaning |
| evidence ingest evtx | --evtx-hard-timeout | EVTX emergency absolute ceiling in seconds (default: 21600) | EVTX emergency absolute ceiling in seconds (default: 21600) | 59 / 8 | 59 / 8 | False | forensic meaning |
| evidence ingest evtx | --force | Permit replacing an existing derived output file without confirmation | Overwrite an existing output file | 69 / 9 | 33 / 5 | True | forensic meaning, mutation/integrity |
| evidence ingest evtx | --hostname |  | Analyst-supplied source hostname | 0 / 0 | 32 / 3 | True | forensic meaning |
| evidence ingest evtx | --json |  | Output as JSON | 0 / 0 | 14 / 3 | True | forensic meaning |
| evidence ingest evtx | --output | Write a derived UTF-8 file; existing files require confirmation or --force | Save output to a file | 74 / 11 | 21 / 5 | True | forensic meaning |
| evidence ingest evtx | --page | Review output with the internal pager (Up/Down, PgUp/PgDn, Home/End, Q) | View output page by page | 71 / 10 | 24 / 5 | True | forensic meaning |
| evidence ingest evtx | --parser-timeout | EVTX: seconds without parser advancement; other artifacts: wall-clock limit | EVTX: seconds without parser advancement; other artifacts: wall-clock limit | 75 / 9 | 75 / 9 | False | forensic meaning |
| evidence ingest evtx | --source | Reuse this source ID; omitted in scripts creates a NEW automatic source for this invocation, never inferred or reused | Reuse this source ID; omitted in scripts creates a NEW automatic source for this invocation, never inferred or reused | 117 / 19 | 117 / 19 | False | forensic meaning |
| evidence ingest evtx | --user |  | Analyst-supplied source username | 0 / 0 | 32 / 3 | True | forensic meaning |
| evidence ingest evtx | --volume-root |  | Original volume root asserted by the analyst | 0 / 0 | 44 / 7 | True | forensic meaning |
| evidence ingest evtx | [command] |  | Import Windows Event Logs (EVTX) | 0 / 0 | 32 / 5 | True | forensic meaning |
| evidence ingest evtx | [footer] | Mutates the selected case through the existing ingestion service; source evidence is read-only. Review partial outcomes. | Mutates the selected case through the existing ingestion service; source evidence is read-only. Review partial outcomes. | 120 / 16 | 120 / 16 | False | forensic meaning |
| evidence ingest evtx | path |  | File or directory path | 0 / 0 | 22 / 4 | True | forensic meaning |
| evidence ingest mft | --append | Append rendered output to a derived UTF-8 file | Append output to a file | 46 / 8 | 23 / 5 | True | forensic meaning |
| evidence ingest mft | --force | Permit replacing an existing derived output file without confirmation | Overwrite an existing output file | 69 / 9 | 33 / 5 | True | forensic meaning, mutation/integrity |
| evidence ingest mft | --hostname |  | Analyst-supplied source hostname | 0 / 0 | 32 / 3 | True | forensic meaning |
| evidence ingest mft | --json |  | Output as JSON | 0 / 0 | 14 / 3 | True | forensic meaning |
| evidence ingest mft | --output | Write a derived UTF-8 file; existing files require confirmation or --force | Save output to a file | 74 / 11 | 21 / 5 | True | forensic meaning |
| evidence ingest mft | --page | Review output with the internal pager (Up/Down, PgUp/PgDn, Home/End, Q) | View output page by page | 71 / 10 | 24 / 5 | True | forensic meaning |
| evidence ingest mft | --parser-timeout | EVTX: seconds without parser advancement; other artifacts: wall-clock limit | EVTX: seconds without parser advancement; other artifacts: wall-clock limit | 75 / 9 | 75 / 9 | False | forensic meaning |
| evidence ingest mft | --record-size |  | MFT record size in bytes | 0 / 0 | 24 / 5 | True | forensic meaning |
| evidence ingest mft | --source | Reuse this source ID; omitted in scripts creates a NEW automatic source for this invocation, never inferred or reused | Reuse this source ID; omitted in scripts creates a NEW automatic source for this invocation, never inferred or reused | 117 / 19 | 117 / 19 | False | forensic meaning |
| evidence ingest mft | --user |  | Analyst-supplied source username | 0 / 0 | 32 / 3 | True | forensic meaning |
| evidence ingest mft | --volume-root |  | Original volume root asserted by the analyst | 0 / 0 | 44 / 7 | True | forensic meaning |
| evidence ingest mft | [command] |  | Import NTFS Master File Table (MFT) evidence | 0 / 0 | 44 / 7 | True | forensic meaning |
| evidence ingest mft | [footer] | Mutates the selected case through the existing ingestion service; source evidence is read-only. Review partial outcomes. | Mutates the selected case through the existing ingestion service; source evidence is read-only. Review partial outcomes. | 120 / 16 | 120 / 16 | False | forensic meaning |
| evidence ingest mft | path |  | File or directory path | 0 / 0 | 22 / 4 | True | forensic meaning |
| evidence ingest prefetch | --append | Append rendered output to a derived UTF-8 file | Append output to a file | 46 / 8 | 23 / 5 | True | forensic meaning |
| evidence ingest prefetch | --force | Permit replacing an existing derived output file without confirmation | Overwrite an existing output file | 69 / 9 | 33 / 5 | True | forensic meaning, mutation/integrity |
| evidence ingest prefetch | --hostname |  | Analyst-supplied source hostname | 0 / 0 | 32 / 3 | True | forensic meaning |
| evidence ingest prefetch | --json |  | Output as JSON | 0 / 0 | 14 / 3 | True | forensic meaning |
| evidence ingest prefetch | --output | Write a derived UTF-8 file; existing files require confirmation or --force | Save output to a file | 74 / 11 | 21 / 5 | True | forensic meaning |
| evidence ingest prefetch | --page | Review output with the internal pager (Up/Down, PgUp/PgDn, Home/End, Q) | View output page by page | 71 / 10 | 24 / 5 | True | forensic meaning |
| evidence ingest prefetch | --parser-timeout | EVTX: seconds without parser advancement; other artifacts: wall-clock limit | EVTX: seconds without parser advancement; other artifacts: wall-clock limit | 75 / 9 | 75 / 9 | False | forensic meaning |
| evidence ingest prefetch | --source | Reuse this source ID; omitted in scripts creates a NEW automatic source for this invocation, never inferred or reused | Reuse this source ID; omitted in scripts creates a NEW automatic source for this invocation, never inferred or reused | 117 / 19 | 117 / 19 | False | forensic meaning |
| evidence ingest prefetch | --user |  | Analyst-supplied source username | 0 / 0 | 32 / 3 | True | forensic meaning |
| evidence ingest prefetch | --volume-root |  | Original volume root asserted by the analyst | 0 / 0 | 44 / 7 | True | forensic meaning |
| evidence ingest prefetch | [command] |  | Import Windows Prefetch evidence | 0 / 0 | 32 / 4 | True | forensic meaning |
| evidence ingest prefetch | [footer] | Mutates the selected case through the existing ingestion service; source evidence is read-only. Review partial outcomes. | Mutates the selected case through the existing ingestion service; source evidence is read-only. Review partial outcomes. | 120 / 16 | 120 / 16 | False | forensic meaning |
| evidence ingest prefetch | path |  | File or directory path | 0 / 0 | 22 / 4 | True | forensic meaning |
| evidence ingest registry | --append | Append rendered output to a derived UTF-8 file | Append output to a file | 46 / 8 | 23 / 5 | True | forensic meaning |
| evidence ingest registry | --force | Permit replacing an existing derived output file without confirmation | Overwrite an existing output file | 69 / 9 | 33 / 5 | True | forensic meaning, mutation/integrity |
| evidence ingest registry | --hostname |  | Analyst-supplied source hostname | 0 / 0 | 32 / 3 | True | forensic meaning |
| evidence ingest registry | --json |  | Output as JSON | 0 / 0 | 14 / 3 | True | forensic meaning |
| evidence ingest registry | --output | Write a derived UTF-8 file; existing files require confirmation or --force | Save output to a file | 74 / 11 | 21 / 5 | True | forensic meaning |
| evidence ingest registry | --page | Review output with the internal pager (Up/Down, PgUp/PgDn, Home/End, Q) | View output page by page | 71 / 10 | 24 / 5 | True | forensic meaning |
| evidence ingest registry | --parser-timeout | EVTX: seconds without parser advancement; other artifacts: wall-clock limit | EVTX: seconds without parser advancement; other artifacts: wall-clock limit | 75 / 9 | 75 / 9 | False | forensic meaning |
| evidence ingest registry | --source | Reuse this source ID; omitted in scripts creates a NEW automatic source for this invocation, never inferred or reused | Reuse this source ID; omitted in scripts creates a NEW automatic source for this invocation, never inferred or reused | 117 / 19 | 117 / 19 | False | forensic meaning |
| evidence ingest registry | --user |  | Analyst-supplied source username | 0 / 0 | 32 / 3 | True | forensic meaning |
| evidence ingest registry | --volume-root |  | Original volume root asserted by the analyst | 0 / 0 | 44 / 7 | True | forensic meaning |
| evidence ingest registry | [command] |  | Import Windows Registry evidence | 0 / 0 | 32 / 4 | True | forensic meaning |
| evidence ingest registry | [footer] | Mutates the selected case through the existing ingestion service; source evidence is read-only. Review partial outcomes. | Mutates the selected case through the existing ingestion service; source evidence is read-only. Review partial outcomes. | 120 / 16 | 120 / 16 | False | forensic meaning |
| evidence ingest registry | path |  | File or directory path | 0 / 0 | 22 / 4 | True | forensic meaning |
| evidence ingest wizard | [command] | Guided evidence selection; confirmation required | Guided evidence selection; confirmation required | 48 / 5 | 48 / 5 | False | authorization, forensic meaning |
| evidence search | --append | Append rendered output to a derived UTF-8 file | Append output to a file | 46 / 8 | 23 / 5 | True | forensic meaning |
| evidence search | --artifact |  | Artifact family filter | 0 / 0 | 22 / 3 | True | forensic meaning |
| evidence search | --browser |  | Browser product filter | 0 / 0 | 22 / 3 | True | forensic meaning |
| evidence search | --browser-kind | Browser evidence subtype (one record per visit or download) | Select browser visits or downloads | 59 / 9 | 34 / 5 | True | forensic meaning |
| evidence search | --download-path | Exact browser field match | Exact browser field match | 25 / 4 | 25 / 4 | False | forensic meaning |
| evidence search | --download-path-contains | Literal browser field substring; no wildcards | Literal browser field substring; no wildcards | 45 / 6 | 45 / 6 | False | forensic meaning |
| evidence search | --end |  | End time with timezone | 0 / 0 | 22 / 4 | True | forensic meaning |
| evidence search | --event-id |  | Windows event identifier | 0 / 0 | 24 / 3 | True | forensic meaning |
| evidence search | --evtx-after | Copy the continuation cursor; retain the same filters and unchanged case contents | Copy the continuation cursor; retain the same filters and unchanged case contents | 81 / 12 | 81 / 12 | False | forensic meaning |
| evidence search | --evtx-match | Whole-value exact or literal substring match; default contains | Whole-value exact or literal substring match; default contains | 62 / 8 | 62 / 8 | False | forensic meaning |
| evidence search | --evtx-text | Explicit literal, case-sensitive EVTX field search; requires --artifact evtx and a paired time window <=24 hours; bounded coverage, no raw/offset | Explicit literal, case-sensitive EVTX field search; requires --artifact evtx and a paired time window <=24 hours; bounded coverage, no raw/offset | 145 / 20 | 145 / 20 | False | forensic meaning |
| evidence search | --force | Permit replacing an existing derived output file without confirmation | Overwrite an existing output file | 69 / 9 | 33 / 5 | True | forensic meaning, mutation/integrity |
| evidence search | --hostname |  | Hostname filter | 0 / 0 | 15 / 2 | True | forensic meaning |
| evidence search | --ids | Include full copyable evidence IDs, numbered to match table rows; display paths may be shortened. Use evidence show for details, --json for the existing structured projection, --raw for available raw payloads. | Show complete, copyable evidence IDs | 209 / 31 | 36 / 5 | True | forensic meaning |
| evidence search | --ip |  | IP address filter | 0 / 0 | 17 / 3 | True | forensic meaning |
| evidence search | --json |  | Output as JSON | 0 / 0 | 14 / 3 | True | forensic meaning |
| evidence search | --key | Registry key path: exact literal match (SQLite NOCASE); includes its values; no filesystem normalization | Registry key path: exact literal match (SQLite NOCASE); includes its values; no filesystem normalization | 104 / 14 | 104 / 14 | False | forensic meaning |
| evidence search | --key-contains | Registry key path: literal substring (SQLite NOCASE); no wildcards; includes matching keys and their values | Registry key path: literal substring (SQLite NOCASE); no wildcards; includes matching keys and their values | 107 / 15 | 107 / 15 | False | forensic meaning |
| evidence search | --kind |  | Normalized record kind | 0 / 0 | 22 / 3 | True | forensic meaning |
| evidence search | --limit | Maximum results (default: %(default)s) | Maximum results (default: %(default)s) | 38 / 4 | 38 / 4 | False | forensic meaning |
| evidence search | --offset |  | Skip this many results | 0 / 0 | 22 / 4 | True | forensic meaning |
| evidence search | --output | Write a derived UTF-8 file; existing files require confirmation or --force | Save output to a file | 74 / 11 | 21 / 5 | True | forensic meaning |
| evidence search | --page | Review output with the internal pager (Up/Down, PgUp/PgDn, Home/End, Q) | View output page by page | 71 / 10 | 24 / 5 | True | forensic meaning |
| evidence search | --path |  | Path filter | 0 / 0 | 11 / 2 | True | forensic meaning |
| evidence search | --process | Exact executable name, case-insensitive; .exe may be omitted for a bare name. Explicit paths remain exact. | Exact executable name, case-insensitive; .exe may be omitted for a bare name. Explicit paths remain exact. | 106 / 16 | 106 / 16 | False | forensic meaning |
| evidence search | --process-contains | Case-insensitive literal substring of the executable basename; no wildcards | Case-insensitive literal substring of the executable basename; no wildcards | 75 / 9 | 75 / 9 | False | forensic meaning |
| evidence search | --profile |  | Browser profile filter | 0 / 0 | 22 / 3 | True | forensic meaning |
| evidence search | --raw | Include original XML or available artifact bytes/details | Include original record details where available | 56 / 7 | 47 / 6 | True | forensic meaning |
| evidence search | --source | Filter Locard source membership, not hostname identity | Filter Locard source membership, not hostname identity | 54 / 7 | 54 / 7 | False | forensic meaning |
| evidence search | --start |  | Start time with timezone | 0 / 0 | 24 / 4 | True | forensic meaning |
| evidence search | --title | Exact browser field match | Exact browser field match | 25 / 4 | 25 / 4 | False | forensic meaning |
| evidence search | --title-contains | Literal browser field substring; no wildcards | Literal browser field substring; no wildcards | 45 / 6 | 45 / 6 | False | forensic meaning |
| evidence search | --url | Exact browser field match | Exact browser field match | 25 / 4 | 25 / 4 | False | forensic meaning |
| evidence search | --url-contains | Literal browser field substring; no wildcards | Literal browser field substring; no wildcards | 45 / 6 | 45 / 6 | False | forensic meaning |
| evidence search | --user |  | Username filter | 0 / 0 | 15 / 2 | True | forensic meaning |
| evidence search | --value-name | Registry value name: exact raw or decoded UserAssist name (SQLite NOCASE) | Registry value name: exact raw or decoded UserAssist name (SQLite NOCASE) | 73 / 11 | 73 / 11 | False | forensic meaning |
| evidence search | --value-name-contains | Registry value name: literal substring of raw or decoded UserAssist name (SQLite NOCASE); no wildcards | Registry value name: literal substring of raw or decoded UserAssist name (SQLite NOCASE); no wildcards | 102 / 15 | 102 / 15 | False | forensic meaning |
| evidence search | [command] |  | Search case evidence | 0 / 0 | 20 / 3 | True | forensic meaning |
| evidence search | [footer] | Read-only examination by default; derived output files and activity records may be written. Coverage limitations remain significant. |  | 132 / 17 | 0 / 0 | True | forensic meaning |
| evidence semantic | --append | Append rendered output to a derived UTF-8 file | Append output to a file | 46 / 8 | 23 / 5 | True | forensic meaning |
| evidence semantic | --force | Permit replacing an existing derived output file without confirmation | Overwrite an existing output file | 69 / 9 | 33 / 5 | True | forensic meaning, mutation/integrity |
| evidence semantic | --output | Write a derived UTF-8 file; existing files require confirmation or --force | Save output to a file | 74 / 11 | 21 / 5 | True | forensic meaning |
| evidence semantic | --page | Review output with the internal pager (Up/Down, PgUp/PgDn, Home/End, Q) | View output page by page | 71 / 10 | 24 / 5 | True | forensic meaning |
| evidence semantic | [command] |  | Search case evidence by meaning | 0 / 0 | 31 / 5 | True | forensic meaning |
| evidence semantic | [footer] | Read-only examination by default; derived output files and activity records may be written. Coverage limitations remain significant. |  | 132 / 17 | 0 / 0 | True | forensic meaning |
| evidence semantic | [subcommand] search | Search current case evidence by semantic similarity | Search current case evidence by semantic similarity | 51 / 7 | 51 / 7 | False | forensic meaning |
| evidence semantic | [subcommand] status | Show semantic runtime, model, and current-case index status | Show semantic search and index status | 59 / 8 | 37 / 6 | True | forensic meaning |
| evidence semantic | semantic_command |  |  | 0 / 0 | 0 / 0 | False | forensic meaning |
| evidence semantic search | --append | Append rendered output to a derived UTF-8 file | Append output to a file | 46 / 8 | 23 / 5 | True | forensic meaning |
| evidence semantic search | --artifact |  | Artifact family filter | 0 / 0 | 22 / 3 | True | forensic meaning |
| evidence semantic search | --end |  | End time with timezone | 0 / 0 | 22 / 4 | True | forensic meaning |
| evidence semantic search | --force | Permit replacing an existing derived output file without confirmation | Overwrite an existing output file | 69 / 9 | 33 / 5 | True | forensic meaning, mutation/integrity |
| evidence semantic search | --hostname |  | Hostname filter | 0 / 0 | 15 / 2 | True | forensic meaning |
| evidence semantic search | --index | Advanced case-specific derived index directory override | Use a different case-specific semantic index | 55 / 6 | 44 / 6 | True | forensic meaning |
| evidence semantic search | --json | Full structured metadata, without terminal styling | Output complete metadata as JSON | 50 / 6 | 32 / 5 | True | forensic meaning |
| evidence semantic search | --limit |  | Maximum number of results | 0 / 0 | 25 / 4 | True | forensic meaning |
| evidence semantic search | --model-path | Advanced local model-directory override; does not change other commands | Override the local model for this command | 71 / 9 | 41 / 7 | True | forensic meaning |
| evidence semantic search | --output | Write a derived UTF-8 file; existing files require confirmation or --force | Save output to a file | 74 / 11 | 21 / 5 | True | forensic meaning |
| evidence semantic search | --page | Review output with the internal pager (Up/Down, PgUp/PgDn, Home/End, Q) | View output page by page | 71 / 10 | 24 / 5 | True | forensic meaning |
| evidence semantic search | --path |  | Literal evidence path filter | 0 / 0 | 28 / 4 | True | forensic meaning |
| evidence semantic search | --show-weak | Show candidates below the human display cutoff; JSON always retains all results | Show candidates below the human display cutoff; JSON always retains all results | 79 / 12 | 79 / 12 | False | forensic meaning |
| evidence semantic search | --start |  | Start time with timezone | 0 / 0 | 24 / 4 | True | forensic meaning |
| evidence semantic search | --text | Concise human-readable output | Show a concise readable result | 29 / 3 | 30 / 5 | True | forensic meaning |
| evidence semantic search | --user |  | Username filter | 0 / 0 | 15 / 2 | True | forensic meaning |
| evidence semantic search | [command] | Search current case evidence by semantic similarity | Search current case evidence by semantic similarity | 51 / 7 | 51 / 7 | False | forensic meaning |
| evidence semantic search | question |  | Question to investigate | 0 / 0 | 23 / 3 | True | forensic meaning |
| evidence semantic status | --append | Append rendered output to a derived UTF-8 file | Append output to a file | 46 / 8 | 23 / 5 | True | forensic meaning |
| evidence semantic status | --force | Permit replacing an existing derived output file without confirmation | Overwrite an existing output file | 69 / 9 | 33 / 5 | True | forensic meaning, mutation/integrity |
| evidence semantic status | --index | Advanced case-specific derived index directory override | Use a different case-specific semantic index | 55 / 6 | 44 / 6 | True | forensic meaning |
| evidence semantic status | --json | Full structured metadata, without terminal styling | Output complete metadata as JSON | 50 / 6 | 32 / 5 | True | forensic meaning |
| evidence semantic status | --model-path | Advanced local model-directory override; does not change other commands | Override the local model for this command | 71 / 9 | 41 / 7 | True | forensic meaning |
| evidence semantic status | --output | Write a derived UTF-8 file; existing files require confirmation or --force | Save output to a file | 74 / 11 | 21 / 5 | True | forensic meaning |
| evidence semantic status | --page | Review output with the internal pager (Up/Down, PgUp/PgDn, Home/End, Q) | View output page by page | 71 / 10 | 24 / 5 | True | forensic meaning |
| evidence semantic status | --text | Concise human-readable output | Show a concise readable result | 29 / 3 | 30 / 5 | True | forensic meaning |
| evidence semantic status | [command] | Show semantic runtime, model, and current-case index status | Show semantic search and index status | 59 / 8 | 37 / 6 | True | forensic meaning |
| evidence show | --append | Append rendered output to a derived UTF-8 file | Append output to a file | 46 / 8 | 23 / 5 | True | forensic meaning |
| evidence show | --force | Permit replacing an existing derived output file without confirmation | Overwrite an existing output file | 69 / 9 | 33 / 5 | True | forensic meaning, mutation/integrity |
| evidence show | --json |  | Output as JSON | 0 / 0 | 14 / 3 | True | forensic meaning |
| evidence show | --output | Write a derived UTF-8 file; existing files require confirmation or --force | Save output to a file | 74 / 11 | 21 / 5 | True | forensic meaning |
| evidence show | --page | Review output with the internal pager (Up/Down, PgUp/PgDn, Home/End, Q) | View output page by page | 71 / 10 | 24 / 5 | True | forensic meaning |
| evidence show | --raw |  | Include original record details where available | 0 / 0 | 47 / 6 | True | forensic meaning |
| evidence show | [command] | Human summary with populated timestamps and bounded references. --json preserves the structured projection; --raw includes available XML/artifact bytes. Both retain existing 100-object/reference/value-ID bounds and truncation flags. | Human summary with populated timestamps and bounded references. --json preserves the structured projection; --raw includes available XML/artifact bytes. Both retain existing 100-object/reference/value-ID bounds and truncation flags. | 232 / 26 | 232 / 26 | False | forensic meaning |
| evidence show | [footer] | Read-only examination by default; derived output files and activity records may be written. Coverage limitations remain significant. |  | 132 / 17 | 0 / 0 | True | forensic meaning |
| evidence show | evidence_id |  | Evidence record identifier | 0 / 0 | 26 / 3 | True | forensic meaning |
| evidence source | --append | Append rendered output to a derived UTF-8 file | Append output to a file | 46 / 8 | 23 / 5 | True | forensic meaning |
| evidence source | --force | Permit replacing an existing derived output file without confirmation | Overwrite an existing output file | 69 / 9 | 33 / 5 | True | forensic meaning, mutation/integrity |
| evidence source | --output | Write a derived UTF-8 file; existing files require confirmation or --force | Save output to a file | 74 / 11 | 21 / 5 | True | forensic meaning |
| evidence source | --page | Review output with the internal pager (Up/Down, PgUp/PgDn, Home/End, Q) | View output page by page | 71 / 10 | 24 / 5 | True | forensic meaning |
| evidence source | [command] |  | Manage evidence sources | 0 / 0 | 23 / 3 | True | forensic meaning |
| evidence source | [footer] | Read-only list/show; create/update/assign mutate analyst source metadata and retain existing confirmations. | Read-only list/show; create/update/assign mutate analyst source metadata and retain existing confirmations. | 107 / 11 | 107 / 11 | False | authorization, forensic meaning |
| evidence source | [subcommand] assign |  | Assign retained files to a source after confirmation | 0 / 0 | 52 / 8 | True | authorization, forensic meaning |
| evidence source | [subcommand] create |  | Create analyst-supplied source metadata | 0 / 0 | 39 / 4 | True | forensic meaning |
| evidence source | [subcommand] list |  | List evidence sources | 0 / 0 | 21 / 3 | True | forensic meaning |
| evidence source | [subcommand] show |  | Show a source and its provenance | 0 / 0 | 32 / 6 | True | forensic meaning |
| evidence source | [subcommand] update |  | Update source metadata after confirmation | 0 / 0 | 41 / 5 | True | authorization, forensic meaning |
| evidence source | source_command |  |  | 0 / 0 | 0 / 0 | False | forensic meaning |
| evidence source assign | --append | Append rendered output to a derived UTF-8 file | Append output to a file | 46 / 8 | 23 / 5 | True | forensic meaning |
| evidence source assign | --confirmation-fingerprint | Require the case fingerprint returned by a reviewed preview before applying | Require the case fingerprint returned by a reviewed preview before applying | 75 / 11 | 75 / 11 | False | authorization, forensic meaning |
| evidence source assign | --file-hash | Explicit existing file SHA-256; repeat or combine with --path (deduplicated union) | Explicit existing file SHA-256; repeat or combine with --path (deduplicated union) | 82 / 11 | 82 / 11 | False | forensic meaning |
| evidence source assign | --force | Permit replacing an existing derived output file without confirmation | Overwrite an existing output file | 69 / 9 | 33 / 5 | True | forensic meaning, mutation/integrity |
| evidence source assign | --json |  | Output as JSON | 0 / 0 | 14 / 3 | True | forensic meaning |
| evidence source assign | --output | Write a derived UTF-8 file; existing files require confirmation or --force | Save output to a file | 74 / 11 | 21 / 5 | True | forensic meaning |
| evidence source assign | --page | Review output with the internal pager (Up/Down, PgUp/PgDn, Home/End, Q) | View output page by page | 71 / 10 | 24 / 5 | True | forensic meaning |
| evidence source assign | --path | Recorded absolute Windows file/directory path; repeatable, no filesystem scan or wildcards. Requires --path or --file-hash. | Recorded absolute Windows file/directory path; repeatable, no filesystem scan or wildcards. Requires --path or --file-hash. | 123 / 15 | 123 / 15 | False | forensic meaning |
| evidence source assign | --reason | Reason for retrospective assignment (does not reconstruct ingestion) | Reason for retrospective assignment (does not reconstruct ingestion) | 68 / 8 | 68 / 8 | False | forensic meaning |
| evidence source assign | --yes | Apply without interactive confirmation; otherwise confirm in the shell or preview in scripts | Apply without interactive confirmation; otherwise confirm in the shell or preview in scripts | 92 / 13 | 92 / 13 | False | authorization, forensic meaning |
| evidence source assign | [command] |  | Assign retained files to a source after confirmation | 0 / 0 | 52 / 8 | True | authorization, forensic meaning |
| evidence source assign | source_id |  | Source identifier | 0 / 0 | 17 / 2 | True | forensic meaning |
| evidence source create | --append | Append rendered output to a derived UTF-8 file | Append output to a file | 46 / 8 | 23 / 5 | True | forensic meaning |
| evidence source create | --force | Permit replacing an existing derived output file without confirmation | Overwrite an existing output file | 69 / 9 | 33 / 5 | True | forensic meaning, mutation/integrity |
| evidence source create | --hostname |  | Analyst-supplied source hostname | 0 / 0 | 32 / 3 | True | forensic meaning |
| evidence source create | --json |  | Output as JSON | 0 / 0 | 14 / 3 | True | forensic meaning |
| evidence source create | --name |  | Source display name | 0 / 0 | 19 / 3 | True | forensic meaning |
| evidence source create | --output | Write a derived UTF-8 file; existing files require confirmation or --force | Save output to a file | 74 / 11 | 21 / 5 | True | forensic meaning |
| evidence source create | --page | Review output with the internal pager (Up/Down, PgUp/PgDn, Home/End, Q) | View output page by page | 71 / 10 | 24 / 5 | True | forensic meaning |
| evidence source create | --user |  | Analyst-supplied source username | 0 / 0 | 32 / 3 | True | forensic meaning |
| evidence source create | --volume-root |  | Analyst-supplied original volume root | 0 / 0 | 37 / 4 | True | forensic meaning |
| evidence source create | [command] |  | Create analyst-supplied source metadata | 0 / 0 | 39 / 4 | True | forensic meaning |
| evidence source list | --append | Append rendered output to a derived UTF-8 file | Append output to a file | 46 / 8 | 23 / 5 | True | forensic meaning |
| evidence source list | --force | Permit replacing an existing derived output file without confirmation | Overwrite an existing output file | 69 / 9 | 33 / 5 | True | forensic meaning, mutation/integrity |
| evidence source list | --ids | Show full copyable source IDs below the compact table; --json also retains complete values | Show complete, copyable source IDs | 90 / 14 | 34 / 5 | True | forensic meaning |
| evidence source list | --json |  | Output as JSON | 0 / 0 | 14 / 3 | True | forensic meaning |
| evidence source list | --limit |  | Maximum number of results | 0 / 0 | 25 / 4 | True | forensic meaning |
| evidence source list | --offset |  | Skip this many results | 0 / 0 | 22 / 4 | True | forensic meaning |
| evidence source list | --output | Write a derived UTF-8 file; existing files require confirmation or --force | Save output to a file | 74 / 11 | 21 / 5 | True | forensic meaning |
| evidence source list | --page | Review output with the internal pager (Up/Down, PgUp/PgDn, Home/End, Q) | View output page by page | 71 / 10 | 24 / 5 | True | forensic meaning |
| evidence source list | [command] | Display abbreviations (...) are not command IDs; use --ids for full copyable IDs or --json for complete values. | Display abbreviations (...) are not command IDs; use --ids for full copyable IDs or --json for complete values. | 111 / 18 | 111 / 18 | False | forensic meaning |
| evidence source show | --append | Append rendered output to a derived UTF-8 file | Append output to a file | 46 / 8 | 23 / 5 | True | forensic meaning |
| evidence source show | --details | Existing structured provenance detail, paginated with --limit/--offset; --json is equivalent | Show paginated provenance as JSON | 92 / 10 | 33 / 5 | True | forensic meaning |
| evidence source show | --force | Permit replacing an existing derived output file without confirmation | Overwrite an existing output file | 69 / 9 | 33 / 5 | True | forensic meaning, mutation/integrity |
| evidence source show | --json |  | Output as JSON | 0 / 0 | 14 / 3 | True | forensic meaning |
| evidence source show | --limit |  | Maximum number of results | 0 / 0 | 25 / 4 | True | forensic meaning |
| evidence source show | --offset |  | Skip this many results | 0 / 0 | 22 / 4 | True | forensic meaning |
| evidence source show | --output | Write a derived UTF-8 file; existing files require confirmation or --force | Save output to a file | 74 / 11 | 21 / 5 | True | forensic meaning |
| evidence source show | --page | Review output with the internal pager (Up/Down, PgUp/PgDn, Home/End, Q) | View output page by page | 71 / 10 | 24 / 5 | True | forensic meaning |
| evidence source show | [command] |  | Show a source and its provenance | 0 / 0 | 32 / 6 | True | forensic meaning |
| evidence source show | source_id |  | Source identifier | 0 / 0 | 17 / 2 | True | forensic meaning |
| evidence source update | --append | Append rendered output to a derived UTF-8 file | Append output to a file | 46 / 8 | 23 / 5 | True | forensic meaning |
| evidence source update | --force | Permit replacing an existing derived output file without confirmation | Overwrite an existing output file | 69 / 9 | 33 / 5 | True | forensic meaning, mutation/integrity |
| evidence source update | --hostname |  | Analyst-supplied source hostname | 0 / 0 | 32 / 3 | True | forensic meaning |
| evidence source update | --json |  | Output as JSON | 0 / 0 | 14 / 3 | True | forensic meaning |
| evidence source update | --name |  | Source display name | 0 / 0 | 19 / 3 | True | forensic meaning |
| evidence source update | --output | Write a derived UTF-8 file; existing files require confirmation or --force | Save output to a file | 74 / 11 | 21 / 5 | True | forensic meaning |
| evidence source update | --page | Review output with the internal pager (Up/Down, PgUp/PgDn, Home/End, Q) | View output page by page | 71 / 10 | 24 / 5 | True | forensic meaning |
| evidence source update | --user |  | Analyst-supplied source username | 0 / 0 | 32 / 3 | True | forensic meaning |
| evidence source update | --volume-root |  | Analyst-supplied original volume root | 0 / 0 | 37 / 4 | True | forensic meaning |
| evidence source update | --yes | Apply without interactive confirmation; otherwise confirm in the shell or preview in scripts | Apply without interactive confirmation; otherwise confirm in the shell or preview in scripts | 92 / 13 | 92 / 13 | False | authorization, forensic meaning |
| evidence source update | [command] |  | Update source metadata after confirmation | 0 / 0 | 41 / 5 | True | authorization, forensic meaning |
| evidence source update | source_id |  | Source identifier | 0 / 0 | 17 / 2 | True | forensic meaning |
| evidence timeline | --append | Append rendered output to a derived UTF-8 file | Append output to a file | 46 / 8 | 23 / 5 | True | forensic meaning |
| evidence timeline | --around | Anchor time as ISO 8601 with Z or an explicit UTC offset, e.g. 2026-06-29T19:08:00Z | Anchor time with UTC or explicit offset | 83 / 14 | 39 / 7 | True | forensic meaning |
| evidence timeline | --artifact |  | Artifact family filter | 0 / 0 | 22 / 3 | True | forensic meaning |
| evidence timeline | --artifact-type |  | Normalized artifact type filter | 0 / 0 | 31 / 4 | True | forensic meaning |
| evidence timeline | --end | End time as ISO 8601 with Z or an explicit UTC offset, e.g. 2026-06-29T19:08:30Z | End time with UTC or explicit offset | 80 / 14 | 36 / 7 | True | forensic meaning |
| evidence timeline | --event-id |  | Windows event identifier | 0 / 0 | 24 / 3 | True | forensic meaning |
| evidence timeline | --force | Permit replacing an existing derived output file without confirmation | Overwrite an existing output file | 69 / 9 | 33 / 5 | True | forensic meaning, mutation/integrity |
| evidence timeline | --hostname |  | Hostname filter | 0 / 0 | 15 / 2 | True | forensic meaning |
| evidence timeline | --ip |  | IP address filter | 0 / 0 | 17 / 3 | True | forensic meaning |
| evidence timeline | --json | JSON output (default) | Output as JSON (default) | 21 / 3 | 24 / 4 | True | forensic meaning |
| evidence timeline | --limit | Maximum results (default: %(default)s) | Maximum results (default: %(default)s) | 38 / 4 | 38 / 4 | False | forensic meaning |
| evidence timeline | --minutes |  | Minutes on either side of the anchor | 0 / 0 | 36 / 7 | True | forensic meaning |
| evidence timeline | --offset |  | Skip this many results | 0 / 0 | 22 / 4 | True | forensic meaning |
| evidence timeline | --output | Write a derived UTF-8 file; existing files require confirmation or --force | Save output to a file | 74 / 11 | 21 / 5 | True | forensic meaning |
| evidence timeline | --page | Review output with the internal pager (Up/Down, PgUp/PgDn, Home/End, Q) | View output page by page | 71 / 10 | 24 / 5 | True | forensic meaning |
| evidence timeline | --path |  | Path filter | 0 / 0 | 11 / 2 | True | forensic meaning |
| evidence timeline | --process |  | Process name filter | 0 / 0 | 19 / 3 | True | forensic meaning |
| evidence timeline | --raw | Include original XML or available artifact bytes/details | Include original record details where available | 56 / 7 | 47 / 6 | True | forensic meaning |
| evidence timeline | --start | Start time as ISO 8601 with Z or an explicit UTC offset, e.g. 2026-06-29T19:07:30Z | Start time with UTC or explicit offset | 82 / 14 | 38 / 7 | True | forensic meaning |
| evidence timeline | --text | Compact readable output | Show a compact readable result | 23 / 3 | 30 / 5 | True | forensic meaning |
| evidence timeline | --user |  | Username filter | 0 / 0 | 15 / 2 | True | forensic meaning |
| evidence timeline | [command] |  | Browse evidence chronologically | 0 / 0 | 31 / 3 | True | forensic meaning |
| evidence timeline | [footer] | Read-only examination by default; derived output files and activity records may be written. Coverage limitations remain significant. |  | 132 / 17 | 0 / 0 | True | forensic meaning |
| evidence timeline | timestamp | Anchor time as ISO 8601 with Z or an explicit UTC offset, e.g. 2026-06-29T19:08:00Z | Anchor time with UTC or explicit offset | 83 / 14 | 39 / 7 | True | forensic meaning |
| investigation | [command] | Guided investigation, recorded review and findings | Investigate a case and review findings | 50 / 6 | 38 / 6 | True | routine |
| investigation | [subcommand] advanced | Advanced | Advanced | 8 / 1 | 8 / 1 | False | routine |
| investigation | [subcommand] assess | Plan and approve a new deterministic assessment | Plan and approve a new deterministic assessment | 47 / 7 | 47 / 7 | False | authorization |
| investigation | [subcommand] briefing | Saved analyst briefing and explicit lead discovery; not forensic findings | Saved analyst briefing and explicit lead discovery; not forensic findings | 73 / 10 | 73 / 10 | False | routine |
| investigation | [subcommand] findings | Findings | Findings | 8 / 1 | 8 / 1 | False | routine |
| investigation | [subcommand] history | Review or replay saved AI investigations | Review or replay saved AI investigations | 40 / 6 | 40 / 6 | False | mutation/integrity |
| investigation | [subcommand] list | List saved assessments | List saved assessments | 22 / 3 | 22 / 3 | False | routine |
| investigation | [subcommand] reason | Advanced recorded D2 preview / explicitly authorized execution and optional capture | Preview or authorize AI reasoning over recorded evidence | 83 / 11 | 56 / 8 | True | authorization, forensic meaning |
| investigation | [subcommand] reauthorize | Reauthorize an assessment in a NEW read view; not continuation | Reauthorize an assessment in a NEW read view; not continuation | 62 / 10 | 62 / 10 | False | authorization |
| investigation | [subcommand] run | Review a saved assessment scope and authorize investigation stages | Authorize an investigation from a saved assessment | 66 / 9 | 50 / 7 | True | authorization |
| investigation | [subcommand] show | Review a saved assessment | Review a saved assessment | 25 / 4 | 25 / 4 | False | routine |
| investigation | [subcommand] start | Guided briefing, assessment and separately authorized AI investigation | Start a guided investigation | 70 / 8 | 28 / 4 | True | routine |
| investigation | investigation_operation |  |  | 0 / 0 | 0 / 0 | False | routine |
| investigation advanced | [command] | Advanced | Advanced | 8 / 1 | 8 / 1 | False | routine |
| investigation advanced | [subcommand] assessment | Historical assessment handoff with per-tool approval; distinct from autonomous run | Investigate a saved assessment with per-tool approval | 82 / 10 | 53 / 7 | True | routine |
| investigation advanced | [subcommand] current-case | Analyze case evidence using the local AI model | Analyze case evidence using the local AI model | 46 / 8 | 46 / 8 | False | forensic meaning |
| investigation advanced | [subcommand] local-query | Ask the local AI questions about case evidence | Ask the local AI questions about case evidence | 46 / 8 | 46 / 8 | False | forensic meaning |
| investigation advanced | [subcommand] timeline | Analyze a bounded timeline bundle using the local AI model | Analyze a bounded timeline bundle using the local AI model | 58 / 10 | 58 / 10 | False | routine |
| investigation advanced | investigation_advanced_operation |  |  | 0 / 0 | 0 / 0 | False | routine |
| investigation advanced assessment | --details |  | Show technical details | 0 / 0 | 22 / 3 | True | routine |
| investigation advanced assessment | --end |  | End time with timezone | 0 / 0 | 22 / 4 | True | routine |
| investigation advanced assessment | --json |  | Output as JSON | 0 / 0 | 14 / 3 | True | routine |
| investigation advanced assessment | --question |  | Investigation question | 0 / 0 | 22 / 2 | True | routine |
| investigation advanced assessment | --start |  | Start time with timezone | 0 / 0 | 24 / 4 | True | routine |
| investigation advanced assessment | [command] | Historical assessment handoff with per-tool approval; distinct from autonomous run | Investigate a saved assessment with per-tool approval | 82 / 10 | 53 / 7 | True | routine |
| investigation advanced assessment | assessment |  | Saved assessment ID or latest | 0 / 0 | 29 / 5 | True | routine |
| investigation advanced current-case | --append | Append rendered output to a derived UTF-8 file | Append output to a file | 46 / 8 | 23 / 5 | True | routine |
| investigation advanced current-case | --approve-tools | Require interactive approval for each proposed operation | Require interactive approval for each proposed operation | 56 / 7 | 56 / 7 | False | authorization |
| investigation advanced current-case | --date |  | Date for time-only questions | 0 / 0 | 28 / 4 | True | routine |
| investigation advanced current-case | --details | Show technical observations, full evidence IDs and provenance | Show technical observations, full evidence IDs and provenance | 61 / 8 | 61 / 8 | False | forensic meaning |
| investigation advanced current-case | --dry-run | Initial retrieval plus one model proposal; no iterative tool execution | Retrieve evidence and request one AI proposal; no tools | 70 / 10 | 55 / 9 | True | forensic meaning |
| investigation advanced current-case | --embedding-model |  | Local embedding model directory | 0 / 0 | 31 / 4 | True | routine |
| investigation advanced current-case | --endpoint | Advanced existing loopback endpoint; overrides configured provider for this invocation | Advanced existing loopback endpoint; overrides configured provider for this invocation | 86 / 10 | 86 / 10 | False | external disclosure |
| investigation advanced current-case | --explain | Include step-by-step transcript data | Include step-by-step transcript data | 36 / 4 | 36 / 4 | False | routine |
| investigation advanced current-case | --force | Permit replacing an existing derived output file without confirmation | Overwrite an existing output file | 69 / 9 | 33 / 5 | True | mutation/integrity |
| investigation advanced current-case | --json |  | Output as JSON | 0 / 0 | 14 / 3 | True | routine |
| investigation advanced current-case | --max-seconds |  | Maximum investigation duration in seconds | 0 / 0 | 41 / 5 | True | routine |
| investigation advanced current-case | --max-steps |  | Maximum investigation steps | 0 / 0 | 27 / 3 | True | routine |
| investigation advanced current-case | --max-tool-calls |  | Maximum approved tool calls | 0 / 0 | 27 / 4 | True | authorization |
| investigation advanced current-case | --no-semantic |  | Disable semantic retrieval | 0 / 0 | 26 / 3 | True | routine |
| investigation advanced current-case | --output | Write a derived UTF-8 file; existing files require confirmation or --force | Save output to a file | 74 / 11 | 21 / 5 | True | routine |
| investigation advanced current-case | --page | Review output with the internal pager (Up/Down, PgUp/PgDn, Home/End, Q) | View output page by page | 71 / 10 | 24 / 5 | True | routine |
| investigation advanced current-case | --semantic-index |  | Case-specific semantic index directory | 0 / 0 | 38 / 4 | True | routine |
| investigation advanced current-case | --transcripts | Sensitive local derived records, not evidence; default: DATABASE.investigations. Analyst controls retention/deletion. | Sensitive local derived records, not evidence; default: DATABASE.investigations. Analyst controls retention/deletion. | 117 / 11 | 117 / 11 | False | forensic meaning |
| investigation advanced current-case | [command] | Advanced / Diagnostic interface. Use ! <question> for normal interactive AI requests. | Advanced / Diagnostic interface. Use ! <question> for normal interactive AI requests. | 85 / 12 | 85 / 12 | False | routine |
| investigation advanced current-case | [footer] | Advanced model-consuming operation; existing provider disclosure and operation-specific approval controls apply. | Advanced model-consuming operation; existing provider disclosure and operation-specific approval controls apply. | 112 / 11 | 112 / 11 | False | external disclosure |
| investigation advanced current-case | question |  | Question to investigate | 0 / 0 | 23 / 3 | True | routine |
| investigation advanced local-query | --append | Append rendered output to a derived UTF-8 file | Append output to a file | 46 / 8 | 23 / 5 | True | routine |
| investigation advanced local-query | --date | UTC date for time-only questions | UTC date for time-only questions | 32 / 5 | 32 / 5 | False | routine |
| investigation advanced local-query | --dry-run | Show plan and evidence without contacting the model | Show plan and evidence without contacting the model | 51 / 8 | 51 / 8 | False | forensic meaning |
| investigation advanced local-query | --embedding-model |  | Local embedding model directory | 0 / 0 | 31 / 4 | True | routine |
| investigation advanced local-query | --endpoint |  | Local model endpoint | 0 / 0 | 20 / 3 | True | routine |
| investigation advanced local-query | --force | Permit replacing an existing derived output file without confirmation | Overwrite an existing output file | 69 / 9 | 33 / 5 | True | mutation/integrity |
| investigation advanced local-query | --json | Structured output | Output as JSON | 17 / 2 | 14 / 3 | True | routine |
| investigation advanced local-query | --limit |  | Maximum number of results | 0 / 0 | 25 / 4 | True | routine |
| investigation advanced local-query | --output | Write a derived UTF-8 file; existing files require confirmation or --force | Save output to a file | 74 / 11 | 21 / 5 | True | routine |
| investigation advanced local-query | --page | Review output with the internal pager (Up/Down, PgUp/PgDn, Home/End, Q) | View output page by page | 71 / 10 | 24 / 5 | True | routine |
| investigation advanced local-query | --semantic-index |  | Case-specific semantic index directory | 0 / 0 | 38 / 4 | True | routine |
| investigation advanced local-query | --text | Human-readable output | Show readable text | 21 / 2 | 18 / 3 | True | routine |
| investigation advanced local-query | --timeout |  | Request timeout in seconds | 0 / 0 | 26 / 4 | True | routine |
| investigation advanced local-query | [command] | Advanced bounded local query with deterministic planning and optional semantic retrieval. Deterministic search retrieves evidence by exact/filter-based criteria. Semantic retrieval discovers meaning-based candidate leads, not evidence for the queried concept. The local LLM analyzes only the bounded supplied bundle. Model analysis is not evidence. | Advanced bounded local query with deterministic planning and optional semantic retrieval. Deterministic search retrieves evidence by exact/filter-based criteria. Semantic retrieval discovers meaning-based candidate leads, not evidence for the queried concept. The local LLM analyzes only the bounded supplied bundle. Model analysis is not evidence. | 348 / 44 | 348 / 44 | False | forensic meaning |
| investigation advanced local-query | [footer] | Advanced model-consuming operation; existing provider disclosure and operation-specific approval controls apply. | Advanced model-consuming operation; existing provider disclosure and operation-specific approval controls apply. | 112 / 11 | 112 / 11 | False | external disclosure |
| investigation advanced local-query | question |  | Question to investigate | 0 / 0 | 23 / 3 | True | routine |
| investigation advanced timeline | --append | Append rendered output to a derived UTF-8 file | Append output to a file | 46 / 8 | 23 / 5 | True | routine |
| investigation advanced timeline | --candidate-limit |  | Maximum candidate records examined | 0 / 0 | 34 / 4 | True | routine |
| investigation advanced timeline | --dry-run |  | Preview without contacting AI | 0 / 0 | 29 / 4 | True | routine |
| investigation advanced timeline | --end |  | End time with timezone | 0 / 0 | 22 / 4 | True | routine |
| investigation advanced timeline | --endpoint |  | Local model endpoint | 0 / 0 | 20 / 3 | True | routine |
| investigation advanced timeline | --force | Permit replacing an existing derived output file without confirmation | Overwrite an existing output file | 69 / 9 | 33 / 5 | True | mutation/integrity |
| investigation advanced timeline | --hostname |  | Hostname filter | 0 / 0 | 15 / 2 | True | routine |
| investigation advanced timeline | --json | Structured JSON output | Output as JSON | 22 / 3 | 14 / 3 | True | routine |
| investigation advanced timeline | --output | Write a derived UTF-8 file; existing files require confirmation or --force | Save output to a file | 74 / 11 | 21 / 5 | True | routine |
| investigation advanced timeline | --page | Review output with the internal pager (Up/Down, PgUp/PgDn, Home/End, Q) | View output page by page | 71 / 10 | 24 / 5 | True | routine |
| investigation advanced timeline | --raw |  | Show the full diagnostic result as JSON | 0 / 0 | 39 / 7 | True | routine |
| investigation advanced timeline | --start |  | Start time with timezone | 0 / 0 | 24 / 4 | True | routine |
| investigation advanced timeline | --text | Human-readable text output | Show readable text | 26 / 3 | 18 / 3 | True | routine |
| investigation advanced timeline | --timeout |  | Request timeout in seconds | 0 / 0 | 26 / 4 | True | routine |
| investigation advanced timeline | --user |  | Username filter | 0 / 0 | 15 / 2 | True | routine |
| investigation advanced timeline | [command] | Specialized workflow: deterministic retrieval and correlation in an explicit time range, followed by local AI analysis. --dry-run builds the bounded evidence bundle without calling the model. Model analysis is not evidence; citation checks do not establish factual correctness. | Specialized workflow: deterministic retrieval and correlation in an explicit time range, followed by local AI analysis. --dry-run builds the bounded evidence bundle without calling the model. Model analysis is not evidence; citation checks do not establish factual correctness. | 277 / 38 | 277 / 38 | False | forensic meaning |
| investigation advanced timeline | [footer] | Advanced model-consuming operation; existing provider disclosure and operation-specific approval controls apply. | Advanced model-consuming operation; existing provider disclosure and operation-specific approval controls apply. | 112 / 11 | 112 / 11 | False | external disclosure |
| investigation assess | --end |  | End time with timezone | 0 / 0 | 22 / 4 | True | routine |
| investigation assess | --json | Structured result; prompts remain explicit | Structured result; prompts remain explicit | 42 / 5 | 42 / 5 | False | routine |
| investigation assess | --start |  | Start time with timezone | 0 / 0 | 24 / 4 | True | routine |
| investigation assess | [command] | Plan and approve a new deterministic assessment | Plan and approve a new deterministic assessment | 47 / 7 | 47 / 7 | False | authorization |
| investigation briefing | --append | Append rendered output to a derived UTF-8 file | Append output to a file | 46 / 8 | 23 / 5 | True | routine |
| investigation briefing | --force | Permit replacing an existing derived output file without confirmation | Overwrite an existing output file | 69 / 9 | 33 / 5 | True | mutation/integrity |
| investigation briefing | --output | Write a derived UTF-8 file; existing files require confirmation or --force | Save output to a file | 74 / 11 | 21 / 5 | True | routine |
| investigation briefing | --page | Review output with the internal pager (Up/Down, PgUp/PgDn, Home/End, Q) | View output page by page | 71 / 10 | 24 / 5 | True | routine |
| investigation briefing | [command] |  | Saved analyst briefing and explicit lead discovery; not forensic findings | 0 / 0 | 73 / 10 | True | routine |
| investigation briefing | [footer] | Analyst-supplied derived information, not evidence. Interview/AI interpretation may contact the configured provider; writes require confirmation. | Analyst-supplied derived information, not evidence. Interview/AI interpretation may contact the configured provider; writes require confirmation. | 145 / 15 | 145 / 15 | False | authorization, external disclosure, forensic meaning |
| investigation briefing | [subcommand] analyze | Briefing analyze | Analyze the saved briefing | 16 / 2 | 26 / 4 | True | routine |
| investigation briefing | [subcommand] edit | Briefing edit | Edit the saved briefing | 13 / 2 | 23 / 4 | True | routine |
| investigation briefing | [subcommand] export | Briefing export | Export the saved briefing | 15 / 2 | 25 / 4 | True | routine |
| investigation briefing | [subcommand] import | Briefing import | Import an analyst narrative | 15 / 2 | 27 / 4 | True | routine |
| investigation briefing | [subcommand] import-json | Briefing import-json | Import a briefing for explicit review | 20 / 2 | 37 / 6 | True | routine |
| investigation briefing | [subcommand] inspect | Briefing inspect | Inspect a narrative without saving it | 16 / 2 | 37 / 6 | True | routine |
| investigation briefing | [subcommand] interview | Briefing interview | Build a briefing through an AI interview | 18 / 2 | 40 / 7 | True | routine |
| investigation briefing | [subcommand] show | Briefing show | Show the saved briefing | 13 / 2 | 23 / 4 | True | routine |
| investigation briefing | briefing_operation |  |  | 0 / 0 | 0 / 0 | False | routine |
| investigation briefing analyze | --append | Append rendered output to a derived UTF-8 file | Append output to a file | 46 / 8 | 23 / 5 | True | routine |
| investigation briefing analyze | --approve | Approve exactly this reviewed lead; repeat for at most six leads | Approve exactly this reviewed lead; repeat for at most six leads | 64 / 11 | 64 / 11 | False | authorization |
| investigation briefing analyze | --artifact | Search one family or all available families (six queries total; review unsearched coverage) | Search one family or all available families (six queries total; review unsearched coverage) | 91 / 13 | 91 / 13 | False | forensic meaning |
| investigation briefing analyze | --details | Show full provenance, search packets and validation diagnostics | Show provenance, search coverage and diagnostics | 63 / 8 | 48 / 6 | True | forensic meaning |
| investigation briefing analyze | --deterministic | Analyze saved briefing without AI | Analyze saved briefing without AI | 33 / 5 | 33 / 5 | False | routine |
| investigation briefing analyze | --discover | Execute approved lead lookups; requires --approve, --artifact, --start and --end | Execute approved lead lookups; requires --approve, --artifact, --start and --end | 80 / 10 | 80 / 10 | False | authorization |
| investigation briefing analyze | --discovery-after | Resume one explicitly approved lead/family using its discovery continuation token | Resume one explicitly approved lead/family using its discovery continuation token | 81 / 10 | 81 / 10 | False | authorization |
| investigation briefing analyze | --end | Authorized search end with UTC/offset; maximum 24-hour window | Authorized search end with UTC/offset; maximum 24-hour window | 61 / 8 | 61 / 8 | False | authorization |
| investigation briefing analyze | --force | Permit replacing an existing derived output file without confirmation | Overwrite an existing output file | 69 / 9 | 33 / 5 | True | mutation/integrity |
| investigation briefing analyze | --json | Include original narrative, spans, leads, packet and plan; sensitive derived output | Include original narrative, spans, leads, packet and plan; sensitive derived output | 83 / 11 | 83 / 11 | False | routine |
| investigation briefing analyze | --output | Write a derived UTF-8 file; existing files require confirmation or --force | Save output to a file | 74 / 11 | 21 / 5 | True | routine |
| investigation briefing analyze | --page | Review output with the internal pager (Up/Down, PgUp/PgDn, Home/End, Q) | View output page by page | 71 / 10 | 24 / 5 | True | routine |
| investigation briefing analyze | --revision | Required current briefing revision for saved-briefing discovery approval | Required current briefing revision for saved-briefing discovery approval | 72 / 8 | 72 / 8 | False | routine |
| investigation briefing analyze | --start | Authorized search start with UTC/offset; never inferred from narrative | Authorized search start with UTC/offset; never inferred from narrative | 70 / 9 | 70 / 9 | False | authorization |
| investigation briefing analyze | [command] |  | Analyze the saved briefing | 0 / 0 | 26 / 4 | True | routine |
| investigation briefing edit | --append | Append rendered output to a derived UTF-8 file | Append output to a file | 46 / 8 | 23 / 5 | True | routine |
| investigation briefing edit | --details | Show full provenance, search packets and validation diagnostics | Show provenance, search coverage and diagnostics | 63 / 8 | 48 / 6 | True | forensic meaning |
| investigation briefing edit | --force | Permit replacing an existing derived output file without confirmation | Overwrite an existing output file | 69 / 9 | 33 / 5 | True | mutation/integrity |
| investigation briefing edit | --json | Include original narrative, spans, leads, packet and plan; sensitive derived output | Include original narrative, spans, leads, packet and plan; sensitive derived output | 83 / 11 | 83 / 11 | False | routine |
| investigation briefing edit | --output | Write a derived UTF-8 file; existing files require confirmation or --force | Save output to a file | 74 / 11 | 21 / 5 | True | routine |
| investigation briefing edit | --page | Review output with the internal pager (Up/Down, PgUp/PgDn, Home/End, Q) | View output page by page | 71 / 10 | 24 / 5 | True | routine |
| investigation briefing edit | [command] |  | Edit the saved briefing | 0 / 0 | 23 / 4 | True | routine |
| investigation briefing export | --append | Append rendered output to a derived UTF-8 file | Append output to a file | 46 / 8 | 23 / 5 | True | routine |
| investigation briefing export | --details | Show full provenance, search packets and validation diagnostics | Show provenance, search coverage and diagnostics | 63 / 8 | 48 / 6 | True | forensic meaning |
| investigation briefing export | --force | Permit replacing an existing derived output file without confirmation | Overwrite an existing output file | 69 / 9 | 33 / 5 | True | mutation/integrity |
| investigation briefing export | --json | Include original narrative, spans, leads, packet and plan; sensitive derived output | Include original narrative, spans, leads, packet and plan; sensitive derived output | 83 / 11 | 83 / 11 | False | routine |
| investigation briefing export | --output | Write a derived UTF-8 file; existing files require confirmation or --force | Save output to a file | 74 / 11 | 21 / 5 | True | routine |
| investigation briefing export | --page | Review output with the internal pager (Up/Down, PgUp/PgDn, Home/End, Q) | View output page by page | 71 / 10 | 24 / 5 | True | routine |
| investigation briefing export | [command] |  | Export the saved briefing | 0 / 0 | 25 / 4 | True | routine |
| investigation briefing export | export_json | Fresh JSON destination; no overwrite | New JSON file; overwriting is forbidden | 36 / 5 | 39 / 6 | True | routine |
| investigation briefing import | --append | Append rendered output to a derived UTF-8 file | Append output to a file | 46 / 8 | 23 / 5 | True | routine |
| investigation briefing import | --details | Show full provenance, search packets and validation diagnostics | Show provenance, search coverage and diagnostics | 63 / 8 | 48 / 6 | True | forensic meaning |
| investigation briefing import | --file | UTF-8 analyst narrative, at most 32 KiB | UTF-8 analyst narrative, at most 32 KiB | 39 / 7 | 39 / 7 | False | routine |
| investigation briefing import | --force | Permit replacing an existing derived output file without confirmation | Overwrite an existing output file | 69 / 9 | 33 / 5 | True | mutation/integrity |
| investigation briefing import | --json | Include original narrative, spans, leads, packet and plan; sensitive derived output | Include original narrative, spans, leads, packet and plan; sensitive derived output | 83 / 11 | 83 / 11 | False | routine |
| investigation briefing import | --output | Write a derived UTF-8 file; existing files require confirmation or --force | Save output to a file | 74 / 11 | 21 / 5 | True | routine |
| investigation briefing import | --page | Review output with the internal pager (Up/Down, PgUp/PgDn, Home/End, Q) | View output page by page | 71 / 10 | 24 / 5 | True | routine |
| investigation briefing import | --text | Inline analyst narrative | Inline analyst narrative | 24 / 3 | 24 / 3 | False | routine |
| investigation briefing import | [command] |  | Import an analyst narrative | 0 / 0 | 27 / 4 | True | routine |
| investigation briefing import-json | --append | Append rendered output to a derived UTF-8 file | Append output to a file | 46 / 8 | 23 / 5 | True | routine |
| investigation briefing import-json | --details | Show full provenance, search packets and validation diagnostics | Show provenance, search coverage and diagnostics | 63 / 8 | 48 / 6 | True | forensic meaning |
| investigation briefing import-json | --force | Permit replacing an existing derived output file without confirmation | Overwrite an existing output file | 69 / 9 | 33 / 5 | True | mutation/integrity |
| investigation briefing import-json | --json | Include original narrative, spans, leads, packet and plan; sensitive derived output | Include original narrative, spans, leads, packet and plan; sensitive derived output | 83 / 11 | 83 / 11 | False | routine |
| investigation briefing import-json | --output | Write a derived UTF-8 file; existing files require confirmation or --force | Save output to a file | 74 / 11 | 21 / 5 | True | routine |
| investigation briefing import-json | --page | Review output with the internal pager (Up/Down, PgUp/PgDn, Home/End, Q) | View output page by page | 71 / 10 | 24 / 5 | True | routine |
| investigation briefing import-json | [command] |  | Import a briefing for explicit review | 0 / 0 | 37 / 6 | True | routine |
| investigation briefing import-json | import_json | Canonical JSON file; confirmation required | Canonical JSON file; confirmation required | 42 / 5 | 42 / 5 | False | authorization |
| investigation briefing inspect | --ai | One bounded narrative interpretation using the configured provider; no tools | One bounded narrative interpretation using the configured provider; no tools | 76 / 10 | 76 / 10 | False | external disclosure |
| investigation briefing inspect | --append | Append rendered output to a derived UTF-8 file | Append output to a file | 46 / 8 | 23 / 5 | True | routine |
| investigation briefing inspect | --approve | Approve exactly this reviewed lead; repeat for at most six leads | Approve exactly this reviewed lead; repeat for at most six leads | 64 / 11 | 64 / 11 | False | authorization |
| investigation briefing inspect | --artifact | Search one family or all available families (six queries total; review unsearched coverage) | Search one family or all available families (six queries total; review unsearched coverage) | 91 / 13 | 91 / 13 | False | forensic meaning |
| investigation briefing inspect | --correction | Separate analyst correction; original wording remains intact | Separate analyst correction; original wording remains intact | 60 / 7 | 60 / 7 | False | routine |
| investigation briefing inspect | --details | Show full provenance, search packets and validation diagnostics | Show provenance, search coverage and diagnostics | 63 / 8 | 48 / 6 | True | forensic meaning |
| investigation briefing inspect | --discover | Execute approved lead lookups; requires --approve, --artifact, --start and --end | Execute approved lead lookups; requires --approve, --artifact, --start and --end | 80 / 10 | 80 / 10 | False | authorization |
| investigation briefing inspect | --discovery-after | Resume one explicitly approved lead/family using its discovery continuation token | Resume one explicitly approved lead/family using its discovery continuation token | 81 / 10 | 81 / 10 | False | authorization |
| investigation briefing inspect | --end | Authorized search end with UTC/offset; maximum 24-hour window | Authorized search end with UTC/offset; maximum 24-hour window | 61 / 8 | 61 / 8 | False | authorization |
| investigation briefing inspect | --file | UTF-8 analyst narrative, at most 32 KiB | UTF-8 analyst narrative, at most 32 KiB | 39 / 7 | 39 / 7 | False | routine |
| investigation briefing inspect | --force | Permit replacing an existing derived output file without confirmation | Overwrite an existing output file | 69 / 9 | 33 / 5 | True | mutation/integrity |
| investigation briefing inspect | --json | Include original narrative, spans, leads, packet and plan; sensitive derived output | Include original narrative, spans, leads, packet and plan; sensitive derived output | 83 / 11 | 83 / 11 | False | routine |
| investigation briefing inspect | --output | Write a derived UTF-8 file; existing files require confirmation or --force | Save output to a file | 74 / 11 | 21 / 5 | True | routine |
| investigation briefing inspect | --page | Review output with the internal pager (Up/Down, PgUp/PgDn, Home/End, Q) | View output page by page | 71 / 10 | 24 / 5 | True | routine |
| investigation briefing inspect | --start | Authorized search start with UTC/offset; never inferred from narrative | Authorized search start with UTC/offset; never inferred from narrative | 70 / 9 | 70 / 9 | False | authorization |
| investigation briefing inspect | --text | Inline analyst narrative | Inline analyst narrative | 24 / 3 | 24 / 3 | False | routine |
| investigation briefing inspect | [command] |  | Inspect a narrative without saving it | 0 / 0 | 37 / 6 | True | routine |
| investigation briefing interview | --append | Append rendered output to a derived UTF-8 file | Append output to a file | 46 / 8 | 23 / 5 | True | routine |
| investigation briefing interview | --details | Show full provenance, search packets and validation diagnostics | Show provenance, search coverage and diagnostics | 63 / 8 | 48 / 6 | True | forensic meaning |
| investigation briefing interview | --force | Permit replacing an existing derived output file without confirmation | Overwrite an existing output file | 69 / 9 | 33 / 5 | True | mutation/integrity |
| investigation briefing interview | --json | Include original narrative, spans, leads, packet and plan; sensitive derived output | Include original narrative, spans, leads, packet and plan; sensitive derived output | 83 / 11 | 83 / 11 | False | routine |
| investigation briefing interview | --output | Write a derived UTF-8 file; existing files require confirmation or --force | Save output to a file | 74 / 11 | 21 / 5 | True | routine |
| investigation briefing interview | --page | Review output with the internal pager (Up/Down, PgUp/PgDn, Home/End, Q) | View output page by page | 71 / 10 | 24 / 5 | True | routine |
| investigation briefing interview | [command] |  | Build a briefing through an AI interview | 0 / 0 | 40 / 7 | True | routine |
| investigation briefing show | --append | Append rendered output to a derived UTF-8 file | Append output to a file | 46 / 8 | 23 / 5 | True | routine |
| investigation briefing show | --details | Show full provenance, search packets and validation diagnostics | Show provenance, search coverage and diagnostics | 63 / 8 | 48 / 6 | True | forensic meaning |
| investigation briefing show | --force | Permit replacing an existing derived output file without confirmation | Overwrite an existing output file | 69 / 9 | 33 / 5 | True | mutation/integrity |
| investigation briefing show | --json | Include original narrative, spans, leads, packet and plan; sensitive derived output | Include original narrative, spans, leads, packet and plan; sensitive derived output | 83 / 11 | 83 / 11 | False | routine |
| investigation briefing show | --output | Write a derived UTF-8 file; existing files require confirmation or --force | Save output to a file | 74 / 11 | 21 / 5 | True | routine |
| investigation briefing show | --page | Review output with the internal pager (Up/Down, PgUp/PgDn, Home/End, Q) | View output page by page | 71 / 10 | 24 / 5 | True | routine |
| investigation briefing show | [command] |  | Show the saved briefing | 0 / 0 | 23 / 4 | True | routine |
| investigation findings | [command] | Findings | Findings | 8 / 1 | 8 / 1 | False | routine |
| investigation findings | [subcommand] accept | Explicit findings workspace: accept | Accept a finding as an analyst decision | 35 / 4 | 39 / 7 | True | routine |
| investigation findings | [subcommand] create | Explicit findings workspace: create | Create a findings workspace | 35 / 4 | 27 / 4 | True | routine |
| investigation findings | [subcommand] history | Explicit findings workspace: history | Review finding decisions | 36 / 4 | 24 / 3 | True | routine |
| investigation findings | [subcommand] list | Explicit findings workspace: list | List findings | 33 / 4 | 13 / 2 | True | routine |
| investigation findings | [subcommand] register | Explicit findings workspace: register | Register a proposed finding | 37 / 4 | 27 / 4 | True | mutation/integrity |
| investigation findings | [subcommand] reject | Explicit findings workspace: reject | Reject a proposed finding | 35 / 4 | 25 / 4 | True | routine |
| investigation findings | [subcommand] select | Explicit findings workspace: select | Review a findings workspace | 35 / 4 | 27 / 4 | True | routine |
| investigation findings | [subcommand] show | Explicit findings workspace: show | Show a finding | 33 / 4 | 14 / 3 | True | routine |
| investigation findings | [subcommand] supersede | Explicit findings workspace: supersede | Replace a finding with an auditable decision | 38 / 4 | 44 / 7 | True | mutation/integrity |
| investigation findings | investigation_findings_operation |  |  | 0 / 0 | 0 / 0 | False | routine |
| investigation findings accept | --actor | Locally asserted analyst identity | Locally asserted analyst identity | 33 / 4 | 33 / 4 | False | routine |
| investigation findings accept | --json |  | Output as JSON | 0 / 0 | 14 / 3 | True | routine |
| investigation findings accept | --rationale |  | Reason for this analyst decision | 0 / 0 | 32 / 5 | True | routine |
| investigation findings accept | --revision | Expected current workspace revision | Expected current workspace revision | 35 / 4 | 35 / 4 | False | routine |
| investigation findings accept | --workspace | Explicit .findings directory; never silently selected | Explicit .findings directory; never silently selected | 53 / 6 | 53 / 6 | False | routine |
| investigation findings accept | --workspace-id | UUID from explicit workspace review | UUID from explicit workspace review | 35 / 5 | 35 / 5 | False | routine |
| investigation findings accept | [command] |  | Accept a finding as an analyst decision | 0 / 0 | 39 / 7 | True | routine |
| investigation findings accept | finding_id |  | Finding ID | 0 / 0 | 10 / 2 | True | routine |
| investigation findings create | --actor | Locally asserted analyst identity | Locally asserted analyst identity | 33 / 4 | 33 / 4 | False | routine |
| investigation findings create | --json |  | Output as JSON | 0 / 0 | 14 / 3 | True | routine |
| investigation findings create | --run |  | Saved investigation ID | 0 / 0 | 22 / 3 | True | routine |
| investigation findings create | --transcripts |  | Recorded investigation directory | 0 / 0 | 32 / 3 | True | routine |
| investigation findings create | --workspace | Explicit .findings directory; never silently selected | Explicit .findings directory; never silently selected | 53 / 6 | 53 / 6 | False | routine |
| investigation findings create | [command] |  | Create a findings workspace | 0 / 0 | 27 / 4 | True | routine |
| investigation findings history | --json |  | Output as JSON | 0 / 0 | 14 / 3 | True | routine |
| investigation findings history | --workspace | Explicit .findings directory; never silently selected | Explicit .findings directory; never silently selected | 53 / 6 | 53 / 6 | False | routine |
| investigation findings history | [command] |  | Review finding decisions | 0 / 0 | 24 / 3 | True | routine |
| investigation findings list | --json |  | Output as JSON | 0 / 0 | 14 / 3 | True | routine |
| investigation findings list | --workspace | Explicit .findings directory; never silently selected | Explicit .findings directory; never silently selected | 53 / 6 | 53 / 6 | False | routine |
| investigation findings list | [command] |  | List findings | 0 / 0 | 13 / 2 | True | routine |
| investigation findings register | --actor | Locally asserted analyst identity | Locally asserted analyst identity | 33 / 4 | 33 / 4 | False | mutation/integrity |
| investigation findings register | --contrary |  | Contrary evidence reference; repeat as needed | 0 / 0 | 45 / 6 | True | forensic meaning, mutation/integrity |
| investigation findings register | --json |  | Output as JSON | 0 / 0 | 14 / 3 | True | mutation/integrity |
| investigation findings register | --kind |  | Finding classification | 0 / 0 | 22 / 2 | True | mutation/integrity |
| investigation findings register | --revision | Expected current workspace revision | Expected current workspace revision | 35 / 4 | 35 / 4 | False | mutation/integrity |
| investigation findings register | --statement |  | Proposed finding statement | 0 / 0 | 26 / 3 | True | mutation/integrity |
| investigation findings register | --support |  | Supporting reference; repeat for additional support | 0 / 0 | 51 / 6 | True | mutation/integrity |
| investigation findings register | --workspace | Explicit .findings directory; never silently selected | Explicit .findings directory; never silently selected | 53 / 6 | 53 / 6 | False | mutation/integrity |
| investigation findings register | --workspace-id | UUID from explicit workspace review | UUID from explicit workspace review | 35 / 5 | 35 / 5 | False | mutation/integrity |
| investigation findings register | [command] |  | Register a proposed finding | 0 / 0 | 27 / 4 | True | mutation/integrity |
| investigation findings reject | --actor | Locally asserted analyst identity | Locally asserted analyst identity | 33 / 4 | 33 / 4 | False | routine |
| investigation findings reject | --json |  | Output as JSON | 0 / 0 | 14 / 3 | True | routine |
| investigation findings reject | --rationale |  | Reason for this analyst decision | 0 / 0 | 32 / 5 | True | routine |
| investigation findings reject | --revision | Expected current workspace revision | Expected current workspace revision | 35 / 4 | 35 / 4 | False | routine |
| investigation findings reject | --workspace | Explicit .findings directory; never silently selected | Explicit .findings directory; never silently selected | 53 / 6 | 53 / 6 | False | routine |
| investigation findings reject | --workspace-id | UUID from explicit workspace review | UUID from explicit workspace review | 35 / 5 | 35 / 5 | False | routine |
| investigation findings reject | [command] |  | Reject a proposed finding | 0 / 0 | 25 / 4 | True | routine |
| investigation findings reject | finding_id |  | Finding ID | 0 / 0 | 10 / 2 | True | routine |
| investigation findings select | --json |  | Output as JSON | 0 / 0 | 14 / 3 | True | routine |
| investigation findings select | --workspace | Explicit .findings directory; never silently selected | Explicit .findings directory; never silently selected | 53 / 6 | 53 / 6 | False | routine |
| investigation findings select | [command] |  | Review a findings workspace | 0 / 0 | 27 / 4 | True | routine |
| investigation findings show | --json |  | Output as JSON | 0 / 0 | 14 / 3 | True | routine |
| investigation findings show | --workspace | Explicit .findings directory; never silently selected | Explicit .findings directory; never silently selected | 53 / 6 | 53 / 6 | False | routine |
| investigation findings show | [command] |  | Show a finding | 0 / 0 | 14 / 3 | True | routine |
| investigation findings show | finding_id |  | Finding ID | 0 / 0 | 10 / 2 | True | routine |
| investigation findings supersede | --actor | Locally asserted analyst identity | Locally asserted analyst identity | 33 / 4 | 33 / 4 | False | routine |
| investigation findings supersede | --contrary |  | Contrary evidence reference; repeat as needed | 0 / 0 | 45 / 6 | True | forensic meaning |
| investigation findings supersede | --json |  | Output as JSON | 0 / 0 | 14 / 3 | True | routine |
| investigation findings supersede | --rationale |  | Reason for this analyst decision | 0 / 0 | 32 / 5 | True | routine |
| investigation findings supersede | --revision | Expected current workspace revision | Expected current workspace revision | 35 / 4 | 35 / 4 | False | routine |
| investigation findings supersede | --statement |  | Proposed finding statement | 0 / 0 | 26 / 3 | True | routine |
| investigation findings supersede | --support |  | Supporting reference; repeat for additional support | 0 / 0 | 51 / 6 | True | routine |
| investigation findings supersede | --workspace | Explicit .findings directory; never silently selected | Explicit .findings directory; never silently selected | 53 / 6 | 53 / 6 | False | routine |
| investigation findings supersede | --workspace-id | UUID from explicit workspace review | UUID from explicit workspace review | 35 / 5 | 35 / 5 | False | routine |
| investigation findings supersede | [command] |  | Replace a finding with an auditable decision | 0 / 0 | 44 / 7 | True | mutation/integrity |
| investigation findings supersede | finding_id |  | Finding ID | 0 / 0 | 10 / 2 | True | routine |
| investigation history | [command] | Review or replay saved derived AI investigation records for audit and review. These records are not source evidence. | Review or replay saved derived AI investigation records for audit and review. These records are not source evidence. | 116 / 18 | 116 / 18 | False | forensic meaning, mutation/integrity |
| investigation history | [footer] | Saved records are derived data; replay does not establish forensic conclusions. Read-only examination by default; derived output files and activity records may be written. Coverage limitations remain significant. | Saved records are derived data; replay does not establish forensic conclusions. | 212 / 28 | 79 / 11 | True | mutation/integrity |
| investigation history | [subcommand] replay | Replay saved lookups against the current case | Replay saved lookups against the current case | 45 / 7 | 45 / 7 | False | mutation/integrity |
| investigation history | [subcommand] show | Review a saved AI investigation | Review a saved AI investigation | 31 / 5 | 31 / 5 | False | routine |
| investigation history | investigation_command |  |  | 0 / 0 | 0 / 0 | False | routine |
| investigation history replay | --append | Append rendered output to a derived UTF-8 file | Append output to a file | 46 / 8 | 23 / 5 | True | mutation/integrity |
| investigation history replay | --embedding-model |  | Local embedding model directory | 0 / 0 | 31 / 4 | True | mutation/integrity |
| investigation history replay | --explain | Include step-by-step transcript data | Include step-by-step transcript data | 36 / 4 | 36 / 4 | False | mutation/integrity |
| investigation history replay | --force | Permit replacing an existing derived output file without confirmation | Overwrite an existing output file | 69 / 9 | 33 / 5 | True | mutation/integrity |
| investigation history replay | --json |  | Output as JSON | 0 / 0 | 14 / 3 | True | mutation/integrity |
| investigation history replay | --no-semantic |  | Disable semantic retrieval | 0 / 0 | 26 / 3 | True | mutation/integrity |
| investigation history replay | --output | Write a derived UTF-8 file; existing files require confirmation or --force | Save output to a file | 74 / 11 | 21 / 5 | True | mutation/integrity |
| investigation history replay | --page | Review output with the internal pager (Up/Down, PgUp/PgDn, Home/End, Q) | View output page by page | 71 / 10 | 24 / 5 | True | mutation/integrity |
| investigation history replay | --semantic-index |  | Case-specific semantic index directory | 0 / 0 | 38 / 4 | True | mutation/integrity |
| investigation history replay | --transcripts | Sensitive local derived records, not evidence; default: DATABASE.investigations. Analyst controls retention/deletion. | Sensitive local derived records, not evidence; default: DATABASE.investigations. Analyst controls retention/deletion. | 117 / 11 | 117 / 11 | False | forensic meaning, mutation/integrity |
| investigation history replay | [command] |  | Replay saved lookups against the current case | 0 / 0 | 45 / 7 | True | mutation/integrity |
| investigation history replay | investigation_id |  | Saved investigation ID | 0 / 0 | 22 / 3 | True | mutation/integrity |
| investigation history show | --explain | Include step-by-step transcript data | Include step-by-step transcript data | 36 / 4 | 36 / 4 | False | routine |
| investigation history show | --json |  | Output as JSON | 0 / 0 | 14 / 3 | True | routine |
| investigation history show | --transcripts | Sensitive local derived records, not evidence; default: DATABASE.investigations. Analyst controls retention/deletion. | Sensitive local derived records, not evidence; default: DATABASE.investigations. Analyst controls retention/deletion. | 117 / 11 | 117 / 11 | False | forensic meaning |
| investigation history show | [command] |  | Review a saved AI investigation | 0 / 0 | 31 / 5 | True | routine |
| investigation history show | investigation_id |  | Saved investigation ID | 0 / 0 | 22 / 3 | True | routine |
| investigation list | --json | Structured result; prompts remain explicit | Structured result; prompts remain explicit | 42 / 5 | 42 / 5 | False | routine |
| investigation list | [command] | List saved assessments | List saved assessments | 22 / 3 | 22 / 3 | False | routine |
| investigation reason | --cross-artifact | Use the separate 16384-byte policy over saved authorized evidence | Use the separate 16384-byte policy over saved authorized evidence | 65 / 9 | 65 / 9 | False | authorization, forensic meaning |
| investigation reason | --execute | Ask to authorize one cloud request; no automatic approval | Ask to authorize one cloud request; no automatic approval | 57 / 9 | 57 / 9 | False | authorization, external disclosure |
| investigation reason | --exploratory |  | Preview organization without an objective-specific binding | 0 / 0 | 58 / 6 | True | routine |
| investigation reason | --findings-actor | Locally asserted actor for optional capture; not authenticated identity | Locally asserted actor for optional capture; not authenticated identity | 71 / 9 | 71 / 9 | False | routine |
| investigation reason | --findings-workspace | Existing source-bound findings directory; saving requires a separate choice after execution | Existing source-bound findings directory; saving requires a separate choice after execution | 91 / 11 | 91 / 11 | False | forensic meaning |
| investigation reason | --issue |  | Registered issue or question identifier | 0 / 0 | 39 / 5 | True | mutation/integrity |
| investigation reason | --json |  | Output as JSON | 0 / 0 | 14 / 3 | True | routine |
| investigation reason | --question | Analyst question for --cross-artifact | Analyst question for --cross-artifact | 37 / 4 | 37 / 4 | False | routine |
| investigation reason | [command] | Advanced recorded D2 preview / explicitly authorized execution and optional capture | Preview or authorize AI reasoning over recorded evidence | 83 / 11 | 56 / 8 | True | authorization, forensic meaning |
| investigation reason | root |  | Recorded investigation directory | 0 / 0 | 32 / 3 | True | routine |
| investigation reason | run_id |  | Saved investigation ID | 0 / 0 | 22 / 3 | True | routine |
| investigation reauthorize | --json | Structured result; prompts remain explicit | Structured result; prompts remain explicit | 42 / 5 | 42 / 5 | False | authorization |
| investigation reauthorize | [command] | Reauthorize an assessment in a NEW read view; not continuation | Reauthorize an assessment in a NEW read view; not continuation | 62 / 10 | 62 / 10 | False | authorization |
| investigation reauthorize | assessment |  | Saved assessment ID or latest | 0 / 0 | 29 / 5 | True | authorization |
| investigation run | --json | Structured result; prompts remain explicit | Structured result; prompts remain explicit | 42 / 5 | 42 / 5 | False | routine |
| investigation run | --question | Investigation question; otherwise prompted | Investigation question; otherwise prompted | 42 / 4 | 42 / 4 | False | routine |
| investigation run | [command] | Review a saved assessment scope and authorize investigation stages | Authorize an investigation from a saved assessment | 66 / 9 | 50 / 7 | True | authorization |
| investigation run | assessment |  | Saved assessment ID or latest | 0 / 0 | 29 / 5 | True | routine |
| investigation show | --json | Structured result; prompts remain explicit | Structured result; prompts remain explicit | 42 / 5 | 42 / 5 | False | routine |
| investigation show | [command] | Review a saved assessment | Review a saved assessment | 25 / 4 | 25 / 4 | False | routine |
| investigation show | assessment |  | Saved assessment ID or latest | 0 / 0 | 29 / 5 | True | routine |
| investigation start | --json | Structured result; prompts remain explicit | Structured result; prompts remain explicit | 42 / 5 | 42 / 5 | False | routine |
| investigation start | [command] | Guided briefing, assessment and separately authorized AI investigation | Start a guided investigation | 70 / 8 | 28 / 4 | True | routine |
| report | --append | Append rendered output to a derived UTF-8 file | Append output to a file | 46 / 8 | 23 / 5 | True | routine |
| report | --force | Permit replacing an existing derived output file without confirmation | Overwrite an existing output file | 69 / 9 | 33 / 5 | True | mutation/integrity |
| report | --output | Write a derived UTF-8 file; existing files require confirmation or --force | Save output to a file | 74 / 11 | 21 / 5 | True | routine |
| report | --page | Review output with the internal pager (Up/Down, PgUp/PgDn, Home/End, Q) | View output page by page | 71 / 10 | 24 / 5 | True | routine |
| report | [command] |  | Generate a forensic investigation report | 0 / 0 | 40 / 5 | True | routine |
| report | [footer] | Derived output publication. Case and recorded-history reports retain separate grounding contracts. | Derived output publication. Case and recorded-history reports retain separate grounding contracts. | 98 / 11 | 98 / 11 | False | forensic meaning |
| report | [subcommand] from-case |  | Create a report from selected case evidence | 0 / 0 | 43 / 7 | True | forensic meaning |
| report | [subcommand] from-history | Provider-free report from a validated recorded investigation | Create a report from validated investigation history | 60 / 7 | 52 / 7 | True | routine |
| report | [subcommand] show |  | Show a report bundle | 0 / 0 | 20 / 4 | True | routine |
| report | [subcommand] verify |  | Verify a report bundle and optional evidence grounding | 0 / 0 | 54 / 8 | True | forensic meaning |
| report | [subcommand] verify-history | Inspect bundle consistency; optionally revalidate recorded sources | Verify a report; optionally check recorded sources | 66 / 7 | 50 / 7 | True | forensic meaning |
| report | report_command |  |  | 0 / 0 | 0 / 0 | False | routine |
| report from-case | --analyst-name |  | Analyst name shown in report | 0 / 0 | 28 / 5 | True | routine |
| report from-case | --append | Append rendered output to a derived UTF-8 file | Append output to a file | 46 / 8 | 23 / 5 | True | routine |
| report from-case | --case-identifier |  | Case identifier shown in report | 0 / 0 | 31 / 5 | True | routine |
| report from-case | --case-name |  | Case name shown in report | 0 / 0 | 25 / 5 | True | routine |
| report from-case | --endpoint |  | Local model endpoint | 0 / 0 | 20 / 3 | True | routine |
| report from-case | --evidence | Explicit evidence ID (repeatable); not a complete investigation | Explicit evidence ID (repeatable); not a complete investigation | 63 / 8 | 63 / 8 | False | forensic meaning |
| report from-case | --force | Permit replacing an existing derived output file without confirmation | Overwrite an existing output file | 69 / 9 | 33 / 5 | True | mutation/integrity |
| report from-case | --include-source-locations |  | Include original source locations in the report | 0 / 0 | 47 / 7 | True | forensic meaning |
| report from-case | --investigation | Same-state V4 investigation ID (repeatable) | Same-state V4 investigation ID (repeatable) | 43 / 5 | 43 / 5 | False | routine |
| report from-case | --json | Structured generation result | Output as JSON | 28 / 3 | 14 / 3 | True | routine |
| report from-case | --llm-narrative | Optional grounded narrative composition through local MiniCPM; rejected output falls back safely | Optional grounded narrative composition through local MiniCPM; rejected output falls back safely | 96 / 12 | 96 / 12 | False | forensic meaning |
| report from-case | --max-claims |  | Maximum report claims | 0 / 0 | 21 / 3 | True | routine |
| report from-case | --max-timeline |  | Maximum timeline observations in the report | 0 / 0 | 43 / 6 | True | routine |
| report from-case | --organization |  | Organization shown in report | 0 / 0 | 28 / 4 | True | routine |
| report from-case | --output | New report directory under an existing parent | New report directory under an existing directory | 45 / 7 | 48 / 7 | True | routine |
| report from-case | --page | Review output with the internal pager (Up/Down, PgUp/PgDn, Home/End, Q) | View output page by page | 71 / 10 | 24 / 5 | True | routine |
| report from-case | --profile |  | Report detail level | 0 / 0 | 19 / 3 | True | routine |
| report from-case | --redact |  | Redact identifying information in the derived report | 0 / 0 | 52 / 7 | True | routine |
| report from-case | --scope-note |  | Report scope qualification | 0 / 0 | 26 / 3 | True | routine |
| report from-case | --seconds |  | Seconds around the anchor | 0 / 0 | 25 / 4 | True | routine |
| report from-case | --text | Human generation result | Show a readable result | 23 / 3 | 22 / 4 | True | routine |
| report from-case | --title |  | Report title | 0 / 0 | 12 / 2 | True | routine |
| report from-case | --transcript-root |  | Original investigation transcript directory | 0 / 0 | 43 / 4 | True | routine |
| report from-case | [command] |  | Create a report from selected case evidence | 0 / 0 | 43 / 7 | True | forensic meaning |
| report from-history | --json | Structured report result | Output as JSON | 24 / 3 | 14 / 3 | True | routine |
| report from-history | --output | Fresh local bundle directory | New local report directory | 28 / 4 | 26 / 4 | True | routine |
| report from-history | --profile |  | Report detail level | 0 / 0 | 19 / 3 | True | routine |
| report from-history | --protect-root | Additional evidence directory to exclude from destinations (repeatable) | Additional evidence directory to exclude from destinations (repeatable) | 71 / 8 | 71 / 8 | False | forensic meaning |
| report from-history | --run |  | Saved investigation ID | 0 / 0 | 22 / 3 | True | routine |
| report from-history | --text | Human-readable report result | Human-readable report result | 28 / 3 | 28 / 3 | False | routine |
| report from-history | --transcript-root |  | Original investigation transcript directory | 0 / 0 | 43 / 4 | True | routine |
| report from-history | --workspace | Optional matching .findings directory | Optional matching .findings directory | 37 / 4 | 37 / 4 | False | routine |
| report from-history | [command] |  | Create a report from validated investigation history | 0 / 0 | 52 / 7 | True | routine |
| report show | --append | Append rendered output to a derived UTF-8 file | Append output to a file | 46 / 8 | 23 / 5 | True | routine |
| report show | --force | Permit replacing an existing derived output file without confirmation | Overwrite an existing output file | 69 / 9 | 33 / 5 | True | mutation/integrity |
| report show | --output | Write a derived UTF-8 file; existing files require confirmation or --force | Save output to a file | 74 / 11 | 21 / 5 | True | routine |
| report show | --page | Review output with the internal pager (Up/Down, PgUp/PgDn, Home/End, Q) | View output page by page | 71 / 10 | 24 / 5 | True | routine |
| report show | [command] |  | Show a report bundle | 0 / 0 | 20 / 4 | True | routine |
| report show | directory | Report bundle directory, not a report ID | Report bundle directory, not a report ID | 40 / 7 | 40 / 7 | False | routine |
| report verify | --append | Append rendered output to a derived UTF-8 file | Append output to a file | 46 / 8 | 23 / 5 | True | routine |
| report verify | --case | Optional existing schema-3 case for fingerprint and grounding checks | Optional existing schema-3 case for fingerprint and grounding checks | 68 / 9 | 68 / 9 | False | forensic meaning |
| report verify | --force | Permit replacing an existing derived output file without confirmation | Overwrite an existing output file | 69 / 9 | 33 / 5 | True | mutation/integrity |
| report verify | --output | Write a derived UTF-8 file; existing files require confirmation or --force | Save output to a file | 74 / 11 | 21 / 5 | True | routine |
| report verify | --page | Review output with the internal pager (Up/Down, PgUp/PgDn, Home/End, Q) | View output page by page | 71 / 10 | 24 / 5 | True | routine |
| report verify | --transcript-root | Original transcripts for investigation-report grounding | Original transcripts for investigation-report grounding | 55 / 5 | 55 / 5 | False | forensic meaning |
| report verify | [command] |  | Verify a report bundle and optional evidence grounding | 0 / 0 | 54 / 8 | True | forensic meaning |
| report verify | directory |  | Report directory | 0 / 0 | 16 / 2 | True | routine |
| report verify-history | --json | Structured report result | Output as JSON | 24 / 3 | 14 / 3 | True | routine |
| report verify-history | --run |  | Saved investigation ID | 0 / 0 | 22 / 3 | True | routine |
| report verify-history | --text | Human-readable report result | Human-readable report result | 28 / 3 | 28 / 3 | False | routine |
| report verify-history | --transcript-root |  | Original investigation transcript directory | 0 / 0 | 43 / 4 | True | routine |
| report verify-history | --workspace |  | Matching findings workspace directory | 0 / 0 | 37 / 4 | True | routine |
| report verify-history | [command] |  | Verify a report; optionally check recorded sources | 0 / 0 | 50 / 7 | True | forensic meaning |
| report verify-history | directory |  | Report directory | 0 / 0 | 16 / 2 | True | routine |
| settings | [command] | Terminal preferences and application version | Set terminal preferences and view the version | 44 / 5 | 45 / 7 | True | routine |
| settings | [subcommand] color | Inspect or set terminal styling | View or change terminal colors | 31 / 5 | 30 / 5 | True | routine |
| settings | [subcommand] version | Show effective version; optional source/installed diagnostics | Show the version and optional installation details | 61 / 6 | 50 / 7 | True | routine |
| settings | settings_operation |  |  | 0 / 0 | 0 / 0 | False | routine |
| settings color | [command] | Inspect or set terminal styling | View or change terminal colors | 31 / 5 | 30 / 5 | True | routine |
| settings color | setting |  | Enable or disable terminal colors | 0 / 0 | 33 / 5 | True | routine |
| settings version | --details |  | Show technical details | 0 / 0 | 22 / 3 | True | routine |
| settings version | [command] | Show effective version; optional source/installed diagnostics | Show the version and optional installation details | 61 / 6 | 50 / 7 | True | routine |

## Advisory quality flags

Long safety explanations are intentionally permitted. Structural subparser placeholders need no duplicate description.

- `investigation advanced timeline [command]`: long: review safety context
- `investigation advanced local-query [command]`: long: review safety context
- `evidence export [command]`: long: review safety context

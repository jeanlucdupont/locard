# V0 validation

Implementation followed five stages, with the complete unit suite run at each stage:

| Stage | Result |
|---|---|
| Foundation: model, schema, IDs, timestamps, transactions | 4 passed |
| EVTX parsing, normalization, staged ingestion, provenance | 25 passed |
| Deterministic queries and CLI | 29 passed |
| Planner, evidence bundle, local client, citation checks | 55 passed |
| Integration fixes and final regression suite | 57 passed |

Final `pip check`: no broken requirements. The default database was initialized and
the `status` command reported zero events and zero ingestion runs; fixture/test data
was kept out of the deliverable database.

Tests use representative XML and mocked HTTP responses. No unit test requires a
running model or Internet access. Tests explicitly verify that duplicate ingestion
does not overwrite `events.source_file` and that `source_locations` retains both
observed paths for identical files.

## Real EVTX parser integration

Public fixtures were downloaded from the parser's upstream repository into the
development scratch directory, not the application's evidence database:

- [security.evtx](https://github.com/williballenthin/python-evtx/blob/master/tests/data/security.evtx)
  - SHA-256: `5f29a03cf8c1b4bfbd82c4074ccc81ecfe85d7ee15375afc352ed5025c9a4d8d`
  - 2,261 records inserted, zero ingestion errors, all 2,261 UTC timestamps normalized.
  - Re-ingestion: zero new records and 2,261 duplicates.
- [dns_log_malformed.evtx](https://github.com/williballenthin/python-evtx/blob/master/tests/data/dns_log_malformed.evtx)
  - SHA-256: `56884d5665a02dd4f26de67eabfad751843eff06f3fdeee7ea57a9911baa090b`
  - One readable event preserved with normalized UTC time; status `partial`.
  - Five reported errors: one XML/binary record-number discrepancy and four parser
    Unicode decoding failures. Source filenames and available offsets/record numbers
    were recorded in the error table.

The real fixture check revealed that python-evtx emits timestamp strings with a
space separator. Support and a regression assertion were added. Original parser
timestamp text remains unchanged in the stored record.

## Live MiniCPM integration

The existing server at `http://127.0.0.1:8080` reported
`models\MiniCPM5-2B-Q4_K_M.gguf`, an 8192-token context, and the expected local API.
A synthetic Security 4688 fixture was normalized and retrieved for a PowerShell
question. The model returned structured analysis with the exact supplied evidence ID,
which passed local validation. No investigator evidence was sent to this test.
The final live response also made an overconfident environment inference from test
labels and offered a weak "false positive" alternative for an audit record. These
illustrate why passing citation validation is not semantic validation or a guarantee
of sound forensic interpretation.

Initial live attempts exposed an exhausted generation budget and citation drift.
The client now disables thinking using the model's supported template option and
constrains structured citation values to supplied IDs using JSON Schema, while
retaining independent response validation. A rejected answer is never promoted to
evidence. The test establishes API interoperability, not general analytical accuracy.

## Limits of verification

The public samples are not representative of every Windows build, event provider,
corruption mode, audit policy, or real investigation. MiniCPM can produce shallow or
incorrect interpretations even with valid citations. Analyst validation is mandatory.
No performance benchmark, forensic certification, or complete attack-detection
coverage is claimed. External dependency downloads were setup-only; application
analysis uses loopback HTTP and local SQLite.

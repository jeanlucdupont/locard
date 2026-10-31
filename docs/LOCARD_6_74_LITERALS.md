# Locard 6.74: briefing literal reconciliation

## Diagnosis and limits of the evidence

The October 31 acceptance log records canonical structural success at 22:21:04 UTC
(668 completion tokens). It does not retain the three rejected interpretation
texts. Their categories, cited IDs, literal values/types and usefulness cannot be
reconstructed from the recorded generic rule. No live request was made to reproduce
them. The following are independently demonstrated synthetic defects, not a claim
to have identified the cause of those three live rejections.

Before this correction, reconciliation reused the broad narrative extractor and
compared exact `(type, normalized value)` pairs against leads supported by cited,
exposed source units. It did not use substring matching or whole-narrative support.
Filename/hash/domain/hostname case folding, IP normalization and path normalization
were inherited from extraction; Registry keys and usernames had stricter case
matching. Process names with executable extensions were filenames, not a separate
semantic process class. Generic PowerShell/WMI/persistence terminology was allowed.

Synthetic checks demonstrated that `command-line`, `process-creation`, `follow-up`
were classified as hostnames; `user activity preceded` was classified as a username.
They were rejected despite being ordinary investigative language. Conversely, an IP
followed by a sentence-ending period and `Event 1121` without `ID` escaped detection.
Unquoted trailing punctuation could also change a path/key comparison.

## Narrow correction

`briefing_literals.py` separates model-text reconciliation from analyst lead
extraction. The latter, its IDs and source-unit generation are unchanged.

- Only the three demonstrated compound terms are exempted from hostname matching
  in ordinary prose. Quoted terms or explicit host/computer/machine/server attribution
  still require source support. Arbitrary other host-like strings remain checked.
- Plain `user activity ...` is treated as generic activity wording; explicit
  `user named ...`, `username`, and `account` forms remain concrete.
- IPv4 sentence punctuation and `Event N`/`Event ID N` are recognized consistently.
- Path/key terminal sentence punctuation is ignored for unquoted values; Registry
  key comparisons are case-folded. Source strings are never rewritten.
- Command-like PowerShell/pwsh/cmd/wscript/cscript invocations with switches require
  support, even inside a question. This is a bounded lexical heuristic, not a shell
  parser or exhaustive command-language detector.

The same extraction rules run on model text and the exact cited input slices.
Adjacent cited chunks are reassembled within their actual source; gaps and different
inputs never create synthetic combined support. Known indicators elsewhere in the
narrative remain insufficient if their source units are not cited. Entity IDs still
require their own valid occurrence coverage. No AI text becomes a new executable
search lead, and no search runs without the existing analyst approvals.

The affirmative sentence form `Event [ID] N confirms/proves/establishes execution,
compromise, or causation` is rejected as `unsupported_factual_conclusion` (optionally
prefixed by Defender). This narrow guard handles the requested example, not all
possible assertions. Negated wording such as `No evidence confirms execution` is
not rejected by that rule. Lexical permission never establishes truth; all accepted
interpretations remain unverified and outside the forensic evidence ledger.

## Safe diagnostics

The existing `unsupported_technical_literal` rule now includes sorted fixed
`literal_types` and an `unsupported_count`, alongside the item index. It does not
print or persist technical values, quoted response text or narrative content.

Synthetic example:

```json
{"item_index":2,"rule":"unsupported_technical_literal","literal_types":["ipv4"],"unsupported_count":1}
```

Human output reports `Unsupported literal types: ipv4 (1)`. This distinguishes an
IP rejection from a hostname/username lexical collision on the next acceptance run.
It does not prove that the value was wholly invented rather than present only in
an uncited source. Full arbitrary semantic entailment remains out of scope.

## Validation and manual acceptance

Initial focused run: 151 passed in 12.12 seconds. Final targeted run after narrowing
the proof-claim guard: 58 passed in 2.03 seconds (overlapping tests). Coverage includes
generic terminology, invented indicators in questions, IPs, domains, filenames,
Unicode/case, paths, hashes, Registry keys, hosts, users, command-like strings,
source attribution, partial acceptance, source IDs, provider schema and diagnostics,
unchanged output budgets and existing investigation conclusions.

Thirty synthetic twelve-item reconciliations averaged 4.532 ms, maximum 8.683 ms.
No real provider latency or acceptance improvement is claimed. The three actual
rejected interpretations still need the next manually authorized observation.

Version is 6.74, set only in pyproject.toml. No provider settings, 4096-token ceiling,
case schemas, evidence records, approvals or grounding were changed. No full suite,
case-14 access, commit or push.

Install and then make one manually authorized request:

```powershell
& 'C:\tmp\locard260927\locard\.venv\Scripts\python.exe' -m pip install --no-deps -e 'C:\Users\jl-du\Documents\Codex\2026-09-16\we-x20\outputs\locard'
```

Inside Locard:

```text
briefing --file C:\tmp\locard-briefing.txt --ai --allow-cloud
```

If an item is still rejected, retain its index, rule and literal types. Do not infer
the missing model text or retry automatically. Ambiguous usernames, unquoted command
boundaries and natural-language host references remain conservative heuristic limits;
this change is not a complete natural-language or command-line parser.

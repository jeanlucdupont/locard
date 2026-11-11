# Locard 6.122 — S4-D2-0 offline foundation

Implementation record: 2026-11-10. Inspected base: main,
`bf26041524cd3b19d54775b6400dbbbe6c01c8f2` (6.121). This document describes the
uncommitted 6.122 working tree, not a released revision. The pre-existing
`docs/LOCARD_S4_D2_ARCHITECTURE.md` is preserved.

## Scope and contracts

`investigation_ai/d2.py` adds a backend service and a local module preview entry
point. `open_history()` validates the recorded manifest/hash chain, reconstructs
accepted analysis through the existing autonomous/B2/C1/D1b validators, and retains
a fixed transcript anchor. It never opens the forensic database. `_History`
rejects changed reconstructed state or a changed source head. A caller-supplied
serialized packet cannot become an independent evidence authority.

`investigation_ai/d2_contracts.py` defines closed, versioned contracts:

| Contract | Purpose |
|---|---|
| `d2-issue-preview-v1` | Local issues, bindings, packet selection and omissions |
| `d2-evidence-packet-v1` | Original supports, source/view binding and dependency closure |
| `d2-reasoning-request-v1` | Frozen packet identity and measured system/user messages |
| `d2-reasoning-proposal-v1` | Offline model-proposal fixture validation |
| `d2-offline-validation-v1` | Mechanically accepted, explicitly unverified output |

No provider adapter, execution grant, provider call, live journal, adaptive loop,
analyst decision workflow or new forensic lookup is implemented. Nothing is sent.
`actually_disclosed` and `dispatch_authorized` remain false.

## Selection and grounding

`_History.preview()` reuses B1 resolution and atomic dependency primitives without
editing B1/B2. Typed objectives require eligible decomposition and a resolved
technical binding. Rejected or unavailable decomposition requires explicit
`exploratory=True`; invalid objectives are not silently repaired.

Stable selection ranks typed issues, interpretations, relationships and recorded
fields, then question-term overlap and stable IDs. Mandatory seed closure is
constructed first. Complementary selection prefers fields not already represented
by the mandatory support or preceding packet, same-record support, question-term
overlap and stable IDs. There are no case-specific values or artifact quotas.
Recognized conflicting endpoints are closed transitively. Necessary original
premises and qualifications are never split to fit.

The planner shares the existing five-second/512-resolution ceiling across both
packets and repacking. At most 192 units are examined per packet. Original question
and original S3 assessment remain visible. Coverage distinguishes selected,
unassessed, unavailable and budget-omitted units; omitted does not mean irrelevant.
Per-field accounting preserves evidence identity, pointer and value digest.

`_encode()` measures the final serialized system and user content in UTF-8 bytes.
The limit is 5,600, with at most 12 support leaves and four interpretations.
Packet-local record/clause/source/lineage dictionaries and one shared leaf-contract
identifier eliminate repetition without shortening original values, descriptors,
timestamp semantics or qualifications. Request, packet and message identities are
distinct. Oversized mandatory bundles return `ATOMIC_BUNDLE_TOO_LARGE` and no packet.

`_History.validate()` reconstructs the expected packet before accepting any offline
proposal. It rejects changed values/lineage/view/source, stale or cross-packet
references, invalid JSON, duplicate keys/IDs, unknown fields, invalid cardinalities,
UTF-8 size violations, incomplete interpretation premises and unsupported registered
relationships. Registered S2 rules are independently recomputed. Invalid items
reject the whole response; no partial accepted state is persisted.

All free prose remains `mechanically_accepted_unverified`. Citation eligibility
does not establish entailment. Even assertive causal language cannot change S3 or
become a verified fact. Unsupported causal/execution predicates and authoritative
status fields are rejected structurally. This does not claim to detect every false
statement in unrestricted natural language. Prior-proposal references are disabled
in D2-0. Offline accepted results expand exact dependencies rather than treating
bare historical clause IDs as evidence.

## Final measurements

Read-only copies under `C:\tmp\locard-diagnostics\6.118-live` were reconstructed
without SQLite access or provider calls. Both successful histories produced the
same sizes below; their identities and transcript bindings remain distinct.

| Complete encoding | System + user bytes | Support bytes | Other envelope bytes | Outcome |
|---|---:|---:|---:|---|
| Four-premise ASR bundle, qualifications, final coverage metadata | 5,126 | 3,408 | 1,718 | Fits |
| Selected ASR bundle plus original EventData field | 5,558 | 3,840 | 1,718 | Fits |
| ASR bundle plus representative MFT contextual support | 6,800 | 5,082 | 1,718 | Cannot fit atomically |
| Default second relationship issue | 9,672 | — | — | `ATOMIC_BUNDLE_TOO_LARGE` |

Support bytes measure the serialized support dictionaries/arrays/qualifications;
the remainder includes instructions, question, source/view/issue, identity and
coverage metadata. The isolated mandatory/context comparisons used the selected
packet's final coverage metadata for a like-for-like envelope measurement. They
are capacity probes, not additional selected packets or asserted contradictions.
Actual final preview coverage comes from the selector.

The ASR packet preserves event ID, channel, provider, recognized interpretation
premises and limitations, plus an additional original EventData field. No claim of
successful script execution follows. Cross-record context does not fit this
encoding. D2-0 reports that limitation; broader cross-record reasoning capacity is
not accepted or enabled by this change.

The empty history returns `no_original_support` and no packet. Two independent
Python-process reconstructions agreed exactly for all three histories:

| Run | Final preview digest |
|---|---|
| `6ad0c85499564406aa4d949f3b0e72e5` | `cb1308c5873137b2a6feddcfbdbdca0cf7ef72e19bdea358e51c6df5680ab500` |
| `ffdabecc9ded47e6acd5f4977fa3c2fa` | `8717086a7e6cf2f18832dfb898c4c604e6001c16d9040e9fbaaffe456457ba2b` |
| `08cfd054f85a4a36b8520832427201c3` | `18348f984e0c23df4e00d4e43c8d3930a550eef062951c1aa7c8d5b14b444cdd` |

Existing B1/B2 reconstruction digests were equal before and after D2 inspection
for all three histories. SHA-256 comparisons of each copied manifest and event
file were unchanged. This verifies these inspection operations, not historical
forensic integrity beyond the existing transcript validators.

## Validation

Final focused invocation:

```powershell
.\.venv\Scripts\python.exe -B -m pytest -q -p no:cacheprovider --basetemp=.tmp-d2-final-20261110 tests/test_d2_preview.py tests/test_synthesis_packets.py tests/test_synthesis_consumer.py --tb=short
```

**106 passed in 38.90 seconds.** This includes 37 new D2 cases plus B1/B2 regressions.
Coverage includes typed and invalid bindings, explicit exploratory permission,
atomic ASR/conflict closure, forged references, strict proposal validation,
Unicode budgeting, injection-as-data, planning exhaustion, independent synthetic
reconstruction, immutable source checks and historical compatibility.

An earlier invocation had 93 passes and 13 fixture-setup errors because Windows
denied creation of a temporary directory under `C:\tmp`. Moving disposable test
output inside the workspace resolved the environmental issue; no test assertion
or permission was weakened. Earlier development failures led to copying returned
anchor data defensively and correcting a test that overwrote its own mutation.

No complete suite, live provider request, case inspection, commit or push was run.

## Manual acceptance (provider-free)

From the installed test checkout, verify metadata:

```powershell
.\.venv\Scripts\python.exe -c "from importlib.metadata import version; print(version('locard-forensics'))"
```

Expected after analyst installation: `6.122`. This task changes only the version
in `pyproject.toml`; it does not refresh an editable installation.

Preview a readable historical copy:

```powershell
.\.venv\Scripts\python.exe -B -m forensic_assistant.investigation_ai.d2 'C:\tmp\locard-diagnostics\6.118-live' 6ad0c85499564406aa4d949f3b0e72e5 --exploratory
.\.venv\Scripts\python.exe -B -m forensic_assistant.investigation_ai.d2 'C:\tmp\locard-diagnostics\6.118-live' 6ad0c85499564406aa4d949f3b0e72e5 --exploratory --json
```

The JSON `issues` list provides stable IDs for `--issue <id>` (maximum two).
Without `--exploratory`, rejected decomposition cannot authorize exploratory
selection. Neither option grants provider disclosure. The reusable Python API is
`open_history(root, run_id).preview(...)`; pass a resulting packet and a synthetic
JSON response to the same handle's `validate(packet, raw, ...)`, using identical
preview options. Never use the private `_History` constructor as an import API.

Only five implementation files are added/changed: `d2.py`, `d2_contracts.py`,
`tests/test_d2_preview.py`, this document and `pyproject.toml`. The separately
pre-existing architecture document remains untouched. Live D2 integration,
larger atomic bundle capacity and arbitrary prose entailment remain outside this
foundation's acceptance boundary.

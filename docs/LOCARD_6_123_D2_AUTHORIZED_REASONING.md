# Locard 6.123 — D2-1 admission blocker

Date: 2026-11-10. Inspected main at `179c588` (6.122), initially clean.
**D2-1 is not implemented or authorized for live acceptance by this report.**
The requested pre-dispatch measurement gate failed. Application version remains
6.122: there is no partial 6.123 executor to install.

## Confirmed budget mismatch

The new brief explicitly includes response format and provider overhead in the
5,600-byte cap. D2-0's `d2._encode()` counts UTF-8 system/user content only.
It does not count message-array JSON escaping, the structured output schema or
provider request fields. The earlier numbers were content measurements, not
complete provider request sizes.

Read-only reconstruction used the recorded original fields from:
`C:\tmp\locard-diagnostics\6.118-live\6ad0c85499564406aa4d949f3b0e72e5`.
Existing `d2.open_history()` performs the transcript and state validation. The
four-premise ASR bundle was reconstructed with B1 resolution/closure and D2's
existing encoder. No case database, provider or new evidence lookup was used.

| Component | Mandatory ASR bundle | Selected ASR plus EventData |
|---|---:|---:|
| System + user content | 5,126 | 5,558 |
| Compact serialized message array | 5,633 | 6,115 |
| Canonical D2 response schema | 3,176 | 3,176 |
| Proposed adapted response schema | 2,910 | 2,910 |
| Complete response_format object | 2,999 | 2,999 |
| Compact request body | **8,730** | **9,212** |
| Excess over 5,600 | **3,130** | **3,612** |

Measurement uses compact JSON (`ensure_ascii=False`, separators comma/colon),
UTF-8 encoding, `model=gpt-6.1-sol`, `stream=false`, an output ceiling of 1,024,
the actual D2 messages, and the existing `capabilities.configure()` response-format
wrapper. The proposed schema uses existing `openai_schema._wire()` transformation
to remove unsupported uniqueness keywords without changing canonical validation.
That transformation is measured in memory; D2 exact-schema recognition is **not**
registered in production. No SDK completion method is called.

These are locally constructed body sizes, not captured network requests. HTTP
headers, credentials, SDK additions and any future D2-specific instruction changes
are excluded. Even this compact body already fails admission. The smallest
message array alone exceeds 5,600 bytes before adding the response schema.

## Source-confirmed execution boundary

```mermaid
flowchart LR
  T[Read-only historical transcript] --> R[d2.open_history: validated reconstruction]
  R --> P[D2 complete packet preview]
  P --> G[Full request admission gate]
  G --> B[Blocked: request exceeds 5600 bytes]
  B -. no dispatch .-> M[ModelBackend / supervised cloud worker]
```

Relevant existing implementation:

- `investigation_ai/d2.py:_encode`: content-only byte accounting and original
  packet identity. `_History.validate`: offline source/reference validation.
- `investigation_ai/d2_contracts.py:SCHEMA`: canonical closed proposal contract.
- `ai/openai_schema.py:request_schema, _wire`: exact known-contract adaptation;
  D2 is not yet recognized.
- `ai/capabilities.py:configure`: strict response-format wrapper.
- `ai/cloud_worker.py:request_kwargs`: selected provider/model, no retries,
  response schema and output controls.
- `ai/backend.py:ModelBackend._cloud_request`: subprocess/Windows Job containment,
  parent communication timeout and cleanup. This existing route was inspected,
  not invoked or modified. No new D2 grant or executor has been added.

## Required decision before implementation

Do not reinterpret 5,600 as message-content-only without approval. Do not discard
ASR premises, source lineage or qualifications, split the mandatory bundle, or
silently substitute another packet.

The smallest continuation consistent with the current cap is a separately reviewed
lossless request/response wire-compaction design, with measured full-envelope
admission before any executor is enabled. It must retain exact original support
and canonical validation. Whether sufficient compaction is feasible is unproven.
An alternative is an explicitly approved separate full-envelope allowance while
retaining the existing content cap; that changes this task's resource contract.
Neither option has been implemented.

The new authorization, one-shot supervised execution, ephemeral result lifecycle,
presentation, mock dispatch matrix and live acceptance commands remain pending.
No live command is supplied for an unavailable feature. No claim of full historical
compatibility validation for a new executor is made. Existing D2-0 preview remains
available, without any provider disclosure authorization:

```powershell
.\.venv\Scripts\python.exe -B -m forensic_assistant.investigation_ai.d2 'C:\tmp\locard-diagnostics\6.118-live' 6ad0c85499564406aa4d949f3b0e72e5 --exploratory --json
```

No production code, tests, version, original/copy transcripts, database, sidecars
or permissions were modified. No provider request, commit or push was performed.

Focused validation: `tests/test_d2_preview.py`, **37 passed in 16.09 seconds**,
using `python -B -m pytest -q -p no:cacheprovider` and a disposable workspace
temporary directory. This verifies the unchanged offline foundation, not D2-1
execution. `git diff --check` passed. No full suite was run.

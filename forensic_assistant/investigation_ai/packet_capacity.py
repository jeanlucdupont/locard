"""Numerical serialization accounting, without evidence values or exception text."""
from .state import encoded

def size(value):return len(encoded(value).encode())


def measure(messages, follow, limit, required, mandatory_fields, omitted, *, cause='fits'):
    import json
    from forensic_assistant.ai.openai_schema import instruct
    body=json.loads(messages[1]['content']);evidence=body['UNTRUSTED FORENSIC EVIDENCE']
    adapted=instruct(messages) if follow else messages
    total=sum(len(m['content'].encode()) for m in adapted)
    fields=sum(size(r['observations'])+size(r['interpretations']) for r in evidence['records'])
    evidence_bytes=size(evidence)
    incremental=body.get('incremental',{})
    ledger=size(incremental.get('completed_context',{}))
    optional={k:v for k,v in incremental.items() if k not in ('completed_context','batch_instruction')}
    question=size(body['controller']['objective'])
    # Partition the actual serialized content. Structural punctuation and keys
    # not counted above belong to instructions/transport, not forensic values.
    overhead=total-evidence_bytes-ledger-size(optional)-question
    return dict(contract='packet-capacity-v1',ceiling=limit,required_bytes=required,
        actual_bytes=total,evidence_bytes=evidence_bytes,field_bytes=fields,
        identity_provenance_bytes=evidence_bytes-fields,ledger_bytes=ledger,
        optional_bytes=size(optional),question_bytes=question,instruction_transport_bytes=overhead,
        mandatory_fields=mandatory_fields,disclosed_fields=sum(len(r['observations']) for r in evidence['records']),
        omitted_fields=omitted,cause=cause)


def validate(value,limit):
    keys={'ceiling','required_bytes','actual_bytes','evidence_bytes','field_bytes','identity_provenance_bytes',
          'ledger_bytes','optional_bytes','question_bytes','instruction_transport_bytes','mandatory_fields','disclosed_fields','omitted_fields'}
    if (type(value) is not dict or set(value)!=keys|{'contract','cause'} or value['contract']!='packet-capacity-v1'
        or value['ceiling']!=limit or value['cause'] not in ('fits','mandatory_evidence','overhead')
        or any(type(value[k]) is not int or not 0<=value[k]<=16*1024*1024 for k in keys)
        or value['field_bytes']+value['identity_provenance_bytes']!=value['evidence_bytes']
        or sum(value[k] for k in ('evidence_bytes','ledger_bytes','optional_bytes','question_bytes','instruction_transport_bytes'))!=value['actual_bytes']):
        raise ValueError('Invalid packet budget diagnostics')

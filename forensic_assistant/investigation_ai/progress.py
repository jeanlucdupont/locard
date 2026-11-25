"""Application-owned operation history; never evidence or model conclusions."""
from . import disclosure

PROFILE='bounded-investigation-progress-v1'
INSTRUCTION=(' Do not repeat completed inspections for the same record/category. If context remains unavailable, '
    'record that limitation and examine another authorized lead. Ledger counts concern this request; omitted fields '
    'are not absent from the source. Other categories may differ. Names co-occurring do not establish attribution.')


def ledger(completed, exposure=None):
    """No values in operation history. Slot/ordinal pairs map original context fields.

    None reserves the maximum possible represented-field encoding before packing.
    Actual representation is matched by ordinal, name and unchanged value, not ID alone.
    """
    rows=[]
    decoded=disclosure.decode(exposure) if exposure is not None else None
    for result in completed:
        record=result['records'][0];plan=result['plan'];entries=record['original_event_data']
        available=[[i,e['ordinal']] for i,e in enumerate(entries)]
        represented=[]
        for slot,e in enumerate(entries):
            if decoded is None:
                represented.append(e['ordinal']);continue
            for group in decoded['records']:
                if group['id']!=record['id']:continue
                if any(o['field']['pointer'].startswith('/original_event_data/')
                       and o['field']['pointer'].endswith('/value')
                       and o['field']['semantic'].get('ordinal')==e['ordinal']
                       and o['field']['semantic'].get('name')==e['name']
                       and disclosure.encoded(o['field']['value'])==disclosure.encoded(e['value'])
                       for o in group['observations']):represented.append(e['ordinal']);break
        rows.append([record['id'],plan['category'],len(entries),len(represented),
                     bool(result['truncated'] or record.get('coverage_notes')),available,represented])
    value=dict(contract=PROFILE,columns=['id','category','retrieved','disclosed_now','partial','slots_ordinals','disclosed_ordinals'],
               completed=True,repeat_available=False,slot_pointer='/original_event_data/N/value',rows=rows)
    if not rows:return dict(contract=PROFILE,rows=[])
    if len(rows)>6 or len(disclosure.encoded(value).encode())>2400:
        from .failure_diagnostics import PacketFailure
        raise PacketFailure('PROMPT_BUDGET_EXHAUSTED')
    return value


def families(ids):
    return sorted({eid.split(':',1)[0].lower() for eid in ids})


def continuation(pending,requests,calls):
    # A new authorized seed lookup, never a repeat model request over the same batch.
    return min(pending) if pending and requests<6 and calls<6 else None

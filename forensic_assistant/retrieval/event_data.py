"""Bounded read-time views of original EVTX fields; never execution evidence."""
import json

MAX_PAYLOAD = 32768
MAX_FIELDS = 256
DISPLAY_BYTES = 2048
DEFENDER_FIELDS = ('Process Name', 'Path', 'Target Commandline', 'Parent Commandline', 'User', 'Detection Time', 'ID')
BLOCK_NOTE = 'Defender recorded an ASR blocking action; this does not establish successful target execution.'


def payload(record):
    raw = record.get('event_data_json')
    if not isinstance(raw, str):
        return [], ['Original EventData is missing or malformed']
    if len(raw.encode('utf-8')) > MAX_PAYLOAD:
        return [], ['Original EventData exceeds the inspection byte bound']
    try:
        data = json.loads(raw)
    except (ValueError, RecursionError):
        return [], ['Original EventData is malformed']
    if not isinstance(data, list):
        return [], ['Original EventData is not a field list']
    notes = []
    if len(data) > MAX_FIELDS:
        notes.append('Original EventData field-count bound reached')
    entries = []
    for ordinal, item in enumerate(data[:MAX_FIELDS]):
        if not isinstance(item, dict) or not isinstance(item.get('name'), str) or not (item.get('value') is None or isinstance(item.get('value'), str)):
            if 'Malformed original EventData entries omitted' not in notes:
                notes.append('Malformed original EventData entries omitted')
            continue
        entries.append(dict(ordinal=ordinal, name=item['name'], value=item.get('value')))
    return entries, notes


def is_defender_block(record):
    return (record.get('provider') == 'Microsoft-Windows-Windows Defender'
            and record.get('channel') == 'Microsoft-Windows-Windows Defender/Operational'
            and record.get('event_id') == 1121)


def projection(record, *, ordinals=(), offset=0, byte_limit=DISPLAY_BYTES):
    entries, notes = payload(record)
    preferred = set(ordinals)
    # Preserve ordinals, duplicates and recorded spelling, even when prioritizing.
    selected = [item for item in entries if item['ordinal'] >= offset]
    if not offset:
        selected = sorted(selected, key=lambda x: (x['ordinal'] not in preferred,
            not (is_defender_block(record) and x['name'] in DEFENDER_FIELDS), x['ordinal']))
    result = []
    for item in selected[:12]:
        value = item['value']
        shortened = dict(item, name=item['name'][:80], value=value[:240] if isinstance(value, str) else value,
                         truncated=len(item['name']) > 80 or (isinstance(value, str) and len(value) > 240))
        while (isinstance(shortened['value'], str) and shortened['value']
               and len(json.dumps(result + [shortened], ensure_ascii=True).encode()) > byte_limit):
            shortened['value'] = shortened['value'][:-1]
            shortened['truncated'] = True
        if len(json.dumps(result + [shortened], ensure_ascii=True).encode()) > byte_limit:
            break
        result.append(shortened)
    if len(result) < len(entries) or any(x['truncated'] for x in result):
        notes.append('Original EventData display truncated; ordinals refer to retained original fields')
    return result, notes


def interpretation(record):
    if not is_defender_block(record):
        return None
    return {'action': 'recorded ASR block', 'basis': 'provider, channel and Event ID 1121',
            'limitation': BLOCK_NOTE}

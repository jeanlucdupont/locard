"""Defender original-observation presentation; no interpretation authority."""
from .presentation import safe_text


def render(record,palette=None):
    d=record['detail'];source=record['source'];loc=source['locator']
    lines=['Defender diagnostic observation', 'Evidence: '+record['id'], 'Category: '+d['category'],
           'File: '+source['source_file'], 'SHA-256: '+source['sha256'],
           'Original location: '+str(loc), 'Parsing: '+d['parsing_status']]
    for t in record['timestamps']:
        lines.append(t['meaning']+': '+str(t['original_value'])+' | '+str(t['timestamp_utc'])+' | '+t['normalization_status'])
    for f in d['fields']:lines.append(f['name']+': '+f['value'])
    lines.extend(['Original text:',d['text']])
    lines.extend('Limitation: '+w for w in d['limitations'])
    return '\n'.join(safe_text(v) for v in lines)


def search_group(group,palette,ids,width):
    lines=['TIME (UTC, if known) | CATEGORY | RECORDED OBSERVATION']
    for index,r in group:
        d=r['detail'];text=d['text'].replace('\r',' ').replace('\n',' ')
        lines.append(safe_text(str(r.get('timestamp_utc') or 'unknown')+' | '+d['category']+' | '+text[:180]))
        if len(text)>180:lines.append('  [summary truncated; inspect original record]')
        if ids:lines.append('  Evidence: '+r['id'])
    return lines

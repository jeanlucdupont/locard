"""Compact search projections; selection and hydration remain unchanged."""
from .presentation import safe, detail, PREFETCH_CAUTIONS
from .layout import table, pagination
from forensic_assistant.ingest.validation import is_identifier_note
from .around_display import display_time


def timestamp(value):
    return display_time(value).replace('T',' ').removesuffix('Z') if value else '-'


def render(result, palette=None, *, ids=False, width=None):
    from forensic_assistant.terminal import Palette
    palette=palette or Palette()
    lines=[]
    records=result['records']
    # Group only adjacent kinds, preserving the exact query ordering.
    groups=[]
    for index,r in enumerate(records,1):
        kind=r['source_type']
        if not groups or groups[-1][0]!=kind:groups.append((kind,[]))
        groups[-1][1].append((index,r))
    for kind,group in groups:
        if lines:lines.append('')
        if len({r['source_type'] for r in records})>1:lines.append(palette('heading',kind.upper()))
        rows=[]
        for index,r in group:
            d=r.get('detail') or {};ctx=r.get('context',{})
            host='CONFLICT' if ctx.get('conflicts') else ctx.get('hostname') or 'unknown'
            if kind=='prefetch':
                times=[t['timestamp_utc'] for t in r.get('timestamps',[]) if t.get('timestamp_utc')]
                paths=sorted({o['original'] for o in r.get('objects',[]) if o['role']=='executable_path_candidate'})
                row=[timestamp(max(times) if times else None),d.get('run_count'),d.get('executable'),host,paths[0] if paths else '-']
            elif kind=='mft':
                names=d.get('names',[])
                row=[f"{d.get('record_number')}/{d.get('sequence_number')}",d.get('allocated'),d.get('file_size'),host,(names[0].get('reconstructed_path') or names[0].get('filename')) if names else '-']
            elif kind=='registry':row=[timestamp(r.get('timestamp_utc')),host,d.get('key_path'),d.get('value_name','(key)'),d.get('value_type','-')]
            else:row=[timestamp(r.get('timestamp_utc')),r.get('event_id'),host,r.get('username'),detail(r)]
            rows.append(([index] if ids else [])+row)
        headers={'prefetch':['LAST RUN (UTC)','RUNS','EXECUTABLE','HOST','CANDIDATE PATH'],
                 'mft':['RECORD/SEQ','ALLOCATED','SIZE','HOST','NAME/PATH'],
                 'registry':['KEY TIME (UTC)','HOST','KEY','VALUE','TYPE'],
                 'evtx':['TIME (UTC)','EVENT','HOST','USER','OBSERVATION']}[kind]
        minimums={'prefetch':[23,4,10,7,14],'mft':[10,9,5,7,12],'registry':[23,7,8,8,5],'evtx':[23,5,7,7,12]}[kind]
        roles=['number_value','number_value','string_value','secondary_text','string_value']
        maximums=[23,20,32,24,65]
        if kind=='registry':maximums=[23,24,65,32,16]
        if ids:headers=['#']+headers;minimums=[1]+minimums;maximums=[5]+maximums;roles=['number_value']+roles
        lines+=table(headers,rows,palette,minimums=minimums,maximums=maximums,roles=roles,width=width,tail=(len(headers)-1,) if kind in ('prefetch','mft') else ())
    if not records:lines.append('No matching evidence.')
    if ids:
        for index,r in enumerate(records,1):lines.append(f"{index}: "+palette('evidence_id',safe(r['id'])))
    for index,r in enumerate(records,1):
        ctx=r.get('context',{})
        for warning in r.get('warnings',[]):
            if is_identifier_note(warning):continue
            if r['source_type']!='prefetch' or warning not in PREFETCH_CAUTIONS:
                lines.append(palette('warning',f'Row {index}: '+safe(warning)))
        if ctx.get('conflicts'):lines.append(palette('warning',f"Row {index}: conflicting context: "+safe(', '.join(ctx['conflicts']))))
        if r['source_type']=='prefetch':
            paths={o['original'] for o in r.get('objects',[]) if o['role']=='executable_path_candidate'}
            if len(paths)>1:lines.append(palette('warning',f'Row {index}: multiple executable path candidates.'))
            if r.get('objects_truncated') and not paths:lines.append(palette('warning',f'Row {index}: executable path candidate unavailable in the bounded projection.'))
    footer=pagination(len(records),result['total'],result.get('offset',0))
    if footer:lines+=['',footer]
    return '\n'.join(lines)

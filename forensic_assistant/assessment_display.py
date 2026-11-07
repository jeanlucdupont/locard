"""Deterministic analyst presentation of saved assessments; no database/model access."""
from collections import Counter
from datetime import datetime, timezone
import json
import ntpath
import shutil
import textwrap
import time
from .interactive.console import safe


def prose(value):
    return safe(str(value)).replace('\\n',' ').replace('\n',' ').strip()


def reported_time(items):
    labels={'date':'Reported incident date','date_range':'Reported date range','ambiguous_time':'Approximate time',
            'timestamp':'Reported timestamp','timezone':'Reported timezone'}
    lines=[]
    for item in items:
        if item.get('kind') in labels and item.get('value'):
            lines.append(labels[item['kind']]+': '+prose(item['value'])+' ('+item.get('status','unknown')+')')
    if not lines:lines.append('Structured incident time unavailable; original statements remain in technical detail.')
    if not any(i.get('kind')=='timezone' and i.get('status')=='provided' for i in items):
        lines.append('Timezone: Unknown/not explicitly supplied; no UTC conversion inferred.')
    return lines


def utc(value):
    try:
        # Display only: retain the original precise string in the persisted packet.
        parsed=datetime.fromisoformat(value.replace('Z','+00:00'))
        if parsed.tzinfo is None:return prose(value)+' (timezone unavailable)'
        return parsed.astimezone(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')+' UTC'
    except (TypeError,ValueError):return prose(value)


def context_lines(plan):
    lines=['Briefing context — analyst information, not findings']
    objectives=plan.get('objectives',[])
    lines += ['  Objective: '+prose(v) for v in objectives] if objectives else ['  Structured objectives unavailable.']
    editorial=plan.get('editorial_summary')
    if editorial:
        lines += ['  Accepted editorial summary (unverified context; not structured objective fields):']
        lines += textwrap.wrap(prose(editorial),width=96,initial_indent='    ',subsequent_indent='    ')
    elif not objectives:lines.append('  No accepted editorial summary is retained in this assessment context.')
    lines += ['  '+line for line in reported_time(plan.get('reported_times',[]))]
    lines += ['  Authorized search window: '+utc(plan['start'])+' to '+utc(plan['end'])]
    return lines


def chronology(result, citations):
    groups={};omitted=0
    for t in result.get('timeline',[]):
        if not t.get('timestamp_utc') or t['evidence_id'] not in citations:continue
        family=t['artifact'];meaning=t.get('meaning','');slot=t.get('slot','')
        if family=='mft' and not ('created' in meaning.lower() or 'creation' in meaning.lower() or slot.lower().endswith('created')):
            omitted+=1;continue
        label={'browser':slot.replace('Browser.','Browser '),'prefetch':'Prefetch executable run (not referenced-file execution)',
               'evtx':'EVTX event time','mft':'MFT creation metadata','registry':'Registry '+meaning}.get(family,meaning or slot)
        if family=='mft':label += (' FN' if ' FN ' in meaning else ' SI' if ' SI ' in meaning else '')
        key=(t['timestamp_utc'],family,t['evidence_id'])
        groups.setdefault(key,set()).add(label)
    rows=[]
    for (stamp,family,eid),labels in sorted(groups.items()):
        rows.append('  '+utc(stamp)+' — '+' / '.join(sorted(labels))+' ['+citations[eid]+']')
    if len(rows)>20:omitted+=len(rows)-20
    return rows[:20],omitted


def render(result,details=False):
    if details:
        return ('TECHNICAL ASSESSMENT — saved projections; no new queries\n'
                'Per-page raw query responses were not retained by 6.91; rows contain aggregate coverage and continuation.\n'
                'Citation map: '+json.dumps({f'E{i+1}':eid for i,eid in enumerate(sorted(result['records']))})+'\n'+
                safe(json.dumps(result,ensure_ascii=True,indent=2)))
    plan=result['plan'];records=result['records'];citations={eid:f'E{i+1}' for i,eid in enumerate(sorted(records))}
    context=dict(plan)
    if result.get('briefing_report_context'):context.update(result['briefing_report_context'])
    case=ntpath.basename(ntpath.dirname(plan['case']['path']))
    completed=result['status'] in ('COMPLETE','COMPLETE_WITH_LIMITATIONS')
    lines=['INITIAL CASE ASSESSMENT — '+safe(case),'',
           'Discovery pass: '+('completed within authorized bounds' if completed else result['status'].lower()),
           'Forensic investigation: preliminary and incomplete.']
    incomplete=[r for r in result['rows'] if r['status'] in ('incomplete','failed','not_searched')]
    lines.append('Search coverage: '+('incomplete — '+', '.join(sorted({r['artifact'] for r in incomplete})) if incomplete else 'supported bounded searches completed; searchable fields remain limited'))
    if result['status']=='RUNNING':lines.append('Saved RUNNING checkpoint; completion and current process activity are unconfirmed.')
    lines += ['','Evidence discovered',
              f'  {len(records)} distinct records across {len({r["artifact"] for r in records.values()})} artifact families.']
    for family,title in [('browser','Browser activity'),('mft','Filesystem metadata'),('prefetch','Prefetch references'),('evtx','Recorded events'),('registry','Registry evidence')]:
        members=[(eid,r) for eid,r in sorted(records.items()) if r['artifact']==family]
        if not members:continue
        lines.append('  '+title)
        for eid,record in members[:12]:
            fields=[f for fs in record.get('matched_fields_by_lead',{}).values() for f in fs]
            values=list(dict.fromkeys(prose(f['value']) for f in fields))
            if family in ('mft','prefetch'):
                values=list(dict.fromkeys(ntpath.basename(v) or v for v in values))
            display=', '.join(v[:180]+('…' if len(v)>180 else '') for v in values[:3]) or 'Matching fields not retained'
            info=record.get('presentation',{})
            prefix={'mft':'MFT metadata matches','prefetch':'Prefetch references','browser':'Browser record matches',
                    'evtx':'Event record matches','registry':'Registry record matches'}[family]
            if family=='prefetch' and info.get('process_name'):prefix=prose(info['process_name'])+' Prefetch references'
            if family=='browser' and (info.get('artifact_type')=='browser_download' or any(t.get('slot') in ('Browser.DownloadStart','Browser.DownloadEnd') for t in record['match'].get('timestamps',[]))):prefix=(prose(info.get('browser_product') or 'Browser'))+' recorded a download matching'
            lines.append('    ['+citations[eid]+'] '+prefix+': '+display)
            associated=[l['occurrences'][0]['original'] for l in plan['leads'] if l['id'] in record['lead_ids']]
            lines.append('      Associated reported indicators: '+', '.join(prose(v) for v in associated))
            for interpretation in result.get('interpretations',[]):
                if interpretation['evidence_id']==eid:lines.append('      '+prose(interpretation.get('text','')))
            ctx=record.get('source_context',{})
            if ctx.get('conflicts') or len(ctx.get('source_ids') or [])>1:
                lines.append('      Host/source attribution is ambiguous; no same-host/file identity is inferred.')
            if info.get('truncated_fields') or any(f.get('truncated') for f in fields) or record['match'].get('timestamps_truncated') or record['match'].get('source_file_truncated'):
                lines.append('      Some saved fields are truncated; inspect --details.')
        if len(members)>12:lines.append(f'    {len(members)-12} further records retained in --details.')
        if family=='prefetch':lines.append('    A referenced filename does not establish execution of that referenced file.')
    if not records:lines.append('  No matches retained within the searched fields and coverage; this does not establish absence.')
    lines += ['',*context_lines(context)]
    chronology_rows,omitted=chronology(result,citations)
    lines += ['','Preliminary chronology — UTC; proximity does not establish causation',*(chronology_rows or ['  Other timestamp types are retained in --details.' if result.get('timeline') else '  No timestamps retained.'])]
    if omitted:lines.append(f'  {omitted} additional observations omitted from this concise view; retained timestamps are in --details.')
    lines += ['','What the records support',
              '  The cited records contain matching fields under the displayed search semantics.',
              '  MFT timestamps describe filesystem metadata, not process execution.',
              '  Basename equality does not establish the same underlying file, host or volume.',
              '','Not yet established by this discovery alone',
              '  Successful script execution, compromise, and a causal delivery/activity chain.',
              '  Reported objectives remain investigative questions; a filename match does not confirm the narrative.',
              '','Coverage and limitations']
    for family in sorted({r['artifact'] for r in result['rows']}):
        rows=[r for r in result['rows'] if r['artifact']==family];counts=Counter(r['status'] for r in rows)
        lines.append('  '+family+': '+', '.join(str(n)+' '+status.replace('_',' ') for status,n in sorted(counts.items()))+' lead searches.')
    unknown_hosts=sum(not r.get('source_context',{}).get('hostname') for r in records.values())
    if unknown_hosts:lines.append(f'  Host context unavailable for {unknown_hosts} records; no common host is assumed.')
    lines.append('  No-match results apply only to supported fields and covered ranges, not all possible evidence.')
    # Deduplicate material projection, consistency and cleanup warnings without raw diagnostics.
    notes=list(dict.fromkeys([*result.get('warnings',[]),*[n for r in result['rows'] for n in r.get('limitations',[])],
                             *[n for r in records.values() for n in r['match'].get('limitations',[])]]))
    important=[n for n in notes if any(term in n.lower() for term in ('truncat','dirty','replay','ambig','cleanup','failure','interrupt','not merged','consistency','final'))]
    lines += ['  '+prose(n) for n in important[:10]]
    if len(important)>10:lines.append('  Further limitations retained in --details.')
    if result.get('briefing_stale'):lines.append('  Based on an older briefing revision.')
    if not result.get('integrity_verified'):lines.append('  Final read-view consistency was not confirmed.')
    lines += ['  Current evidence freshness: unknown; this is a saved historical read view.',
              '','Next investigative steps',
              '  Use --details to map citations to evidence IDs, source paths and original matching fields.',
              '  Compare executable/process evidence, download provenance and source/host identity before linking activity.',
              '  Review incomplete coverage before drawing negative conclusions.',
              f"  Assessment {result['id']} | briefing revision {plan['revision']} | {result['metrics']['elapsed_seconds']:.1f}s elapsed"]
    return '\n'.join(safe(line) for line in lines)


class Progress:
    """Throttled normal progress; detailed mode retains original per-query messages."""
    def __init__(self,stream,details=False,clock=time.monotonic):
        self.stream=stream;self.details=details;self.clock=clock;self.last=None;self.family=None;self.width=0
    def assessment_update(self,text,result):
        family=text.split(' ',1)[0];at=self.clock();failure=' failed ' in text
        if self.details:print(safe(text),file=self.stream,flush=True);return
        if self.last is not None and at-self.last<2 and family==self.family and not failure:return
        self.last=at;self.family=family
        m=result['metrics'];line=f"{family}: {sum(r['pages'] for r in result['rows'])} queries completed | {m['candidates']} reported candidates | {len(result['records'])} distinct matches | {m['elapsed_seconds']:.1f}s elapsed"
        if failure:line+=' | lookup failed'
        if self.stream.isatty():
            line=line[:max(1,shutil.get_terminal_size(fallback=(100,24)).columns-1)]
            print('\r'+line.ljust(self.width),end='',file=self.stream,flush=True);self.width=len(line)
        else:print(line,file=self.stream,flush=True)
    def finish(self):
        if self.width:print(file=self.stream,flush=True);self.width=0

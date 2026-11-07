"""Bounded cross-family briefing discovery; analyst leads are never findings."""
import base64
import hashlib
import json
import time
from pathlib import Path


def available(db):
    from .briefing import ARTIFACTS
    # Indexed existence probes, not full inventory/count calculations.
    return [family for family in ARTIFACTS if db.execute(
        'SELECT 1 FROM evidence_records WHERE source_type=? LIMIT 1', (family,)
    ).fetchone()]


def matches(raw, args):
    """Attach bounded original matching values, separately from supporting records."""
    from .artifacts.paths import normalize_path
    key = next(k for k in args if k not in ('artifact', 'start', 'end', 'limit', 'object_after', 'evtx_after'))
    value = args[key]
    output = []
    for record in raw['records'][:10]:
        fields = []
        if key == 'object_basename':
            fields=[dict(field='objects.'+o['role'],slot=o['slot'],value=o['original']) for o in record.get('discovery_objects', [])]
        elif key == 'evtx_text':
            fields = [dict(field=m['name'], value=m['excerpt'], ordinal=m['ordinal'],
                           truncated=m['truncated'], basis=m['basis'])
                      for m in record.get('content_matches', [])]
        elif key in ('path', 'download_path_contains'):
            needle = normalize_path(value)
            for obj in record.get('objects', []):
                if key == 'download_path_contains':
                    found = obj['role'] in ('download_target', 'download_path') and value.lower() in obj['original'].lower()
                else:
                    found = (obj.get('basename') == needle['basename'] if '\\' not in value and '/' not in value
                             else obj.get('normalized') == needle['normalized'] or
                             (obj.get('path_kind') == 'volume_relative' and
                              (record.get('context', {}).get('volume_root') or '').lower() + obj.get('normalized', '') == needle['normalized']))
                if found:
                    fields.append(dict(field='objects.' + obj['role'], value=obj['original']))
        elif key in ('url_contains', 'title_contains'):
            detail = record.get('detail', {})
            name = key.removesuffix('_contains')
            candidates = [(name, detail.get(name))]
            if name == 'url':
                candidates += [('url_chain.url', item.get('url')) for item in detail.get('url_chain', [])]
            fields = [dict(field=name, value=text) for name, text in candidates if isinstance(text, str) and value in text]
        elif key == 'registry_key':
            fields = [dict(field='key_path', value=record['detail']['key_path'])] if record.get('detail', {}).get('key_path') is not None else []
        else:
            names = ('source_ip', 'destination_ip') if key == 'ip' else (key,)
            for name in names:
                observed = record.get(name)
                if observed is not None and str(observed).casefold() == str(value).casefold():
                    fields.append(dict(field=name, value=observed))
            if key == 'hostname' and not fields:
                observed = record.get('context', {}).get('hostname')
                if observed is not None:
                    fields.append(dict(field='context.hostname (attributed context)', value=observed))
        notes = ['A match is not proof of execution, compromise, causality, or maliciousness.']
        if key == 'object_basename':
            notes.append('Basename candidate only; directory, volume, host and file identity require comparison. Prefetch references do not prove execution of the referenced file.')
        if not fields:
            notes.append('Matching value is outside the bounded record projection; inspect the evidence record and query predicate.')
        if len(fields) > 8 or record.get('objects_truncated') or record.get('content_matches_truncated') or record.get('discovery_objects_truncated'):
            notes.append('Matching-field projection is truncated.')
        for field in fields[:8]:
            text = str(field['value'])
            field['value'] = text[:512]
            field['truncated'] = field.get('truncated', False) or len(text) > 512
        output.append(dict(evidence_id=record['id'], source_file=str(record.get('source_file') or '')[:512],
                           source_file_truncated=len(str(record.get('source_file') or '')) > 512,
                           timestamp_utc=record.get('timestamp_utc'),
                           timestamps_truncated=len(record.get('timestamps', [])) > 32,
                           timestamps=record.get('timestamps', [])[:32],
                           matched_fields=fields[:8], limitations=notes))
    return output


def discover_all(packet, case_path, approved, start, end, *, worker_factory=None, continuation=None):
    from . import briefing as b, activity
    from .investigation_ai.runner import ForensicWorker, WorkerError
    b.window(start, end, source='approved briefing window')
    leads = {lead['id']: lead for lead in packet['leads']}
    binding=hashlib.sha256(json.dumps([str(Path(case_path).absolute()),packet.get('saved_briefing'),start,end],sort_keys=True).encode()).hexdigest()
    resumed=None
    if continuation:
        try:
            if len(approved)!=1 or len(continuation)>8192:raise ValueError()
            resumed=json.loads(base64.b64decode(continuation,altchars=b'-_',validate=True))
            if not isinstance(resumed,list) or len(resumed)!=4 or resumed[0]!=binding or resumed[1]!=approved[0] or resumed[2] not in b.ARTIFACTS or not isinstance(resumed[3],str):raise ValueError()
        except (ValueError,TypeError,UnicodeError):raise ValueError('Invalid discovery continuation for this approval/revision/window') from None
    rows = [dict(lead_id=identity, indicator=leads[identity]['occurrences'][0]['original'],
                 artifact=family, status='not_searched', reason='aggregate_budget', matches=[])
            for identity in approved for family in b.ARTIFACTS]
    d = packet['discovery'] = dict(case_path=str(Path(case_path).absolute()), approved=list(approved),
        artifact='all', start=start, end=end, queries=[], unmapped=[], outcomes=rows,
        limitations=['Discovery is not a completed investigation. Unmatched leads do not establish absence.',
                     'Six queries total, ten records per query, 90 seconds and 192 KiB aggregate. Unsearched coverage is explicit.'])
    started = time.monotonic()
    total_bytes = attempted = 0
    plans = []
    try:
        with (worker_factory or ForensicWorker)(dict(case_path=str(case_path), semantic_enabled=False,
                _transaction_view=True, _briefing_initial=True, _briefing_all=True, _deadline=started+90)) as worker:
            initial = worker.call('initial', question='', seconds=10)
            d['evidence_state'] = initial.get('evidence_state')
            inventory = initial['result']['available_artifacts']
            d['available_artifacts'] = inventory
            for row in rows:
                q = b.query_for(leads[row['lead_id']], row['artifact'], start, end, cross=True)
                if row['artifact'] not in inventory:
                    row.update(status='unavailable', reason='No ingested records in this family')
                elif q is None:
                    row.update(status='unsupported', reason='No eligible deterministic mapping')
                elif resumed and row['artifact']!=resumed[2]:
                    row['reason']='outside explicit continuation scope'
                else:
                    if resumed:
                        if 'object_basename' in q:q['object_after']=resumed[3]
                        elif 'evtx_text' in q:q['evtx_after']=resumed[3]
                        else:raise ValueError('This route has no continuation')
                    plans.append((row, q))
            # Cheap indexed object candidates first, then other lookups, EVTX content last.
            # Round-robin leads within each cost tier; presentation keeps family order.
            plans.sort(key=lambda item: (0 if 'object_basename' in item[1] else 2 if 'evtx_text' in item[1] else 1))
            ranks = {}
            ranked = []
            for row, q in plans:
                rank = ranks.get(row['lead_id'], 0)
                ranks[row['lead_id']] = rank + 1
                tier=0 if 'object_basename' in q else 2 if 'evtx_text' in q else 1
                ranked.append((tier,rank, approved.index(row['lead_id']), row, q))
            plans = [(row,q) for _,_,_,row,q in sorted(ranked, key=lambda item: item[:3])]
            for row, q in plans:
                if attempted >= b.MAX_SEARCHES or time.monotonic()-started >= 85:
                    break
                attempted += 1
                activity.event('BRIEFING_LOOKUP','pending',lead_id=row['lead_id'],artifact=row['artifact'])
                at = time.perf_counter()
                try:
                    result = worker.call('briefing_search', q, seconds=min(15, 85-(time.monotonic()-started)))['result']
                except WorkerError as exc:
                    row.update(status='failed', reason='Bounded lookup failed or timed out',
                               failure_category='timeout' if exc.timed_out else 'worker_error', elapsed_seconds=time.perf_counter()-at)
                    activity.event('BRIEFING_LOOKUP','failure',lead_id=row['lead_id'],artifact=row['artifact'])
                    # Continue only if the SAME pinned read view is still valid. A killed
                    # worker or lost transaction stops safely; never mix fresh snapshots.
                    try:worker.call('check',seconds=min(5,max(.001,85-(time.monotonic()-started))))
                    except WorkerError:break
                    continue
                # Count both projections in the emitted packet conservatively.
                size = len(json.dumps(result,ensure_ascii=True).encode()) * 2
                if total_bytes + size > 192*1024:
                    row.update(status='truncated', reason='Aggregate payload bound; result omitted')
                    break
                total_bytes += size
                content = result.get('object_search', result.get('content_search', {}))
                truncated = (result['coverage'].get('matching_total', 0) or 0) > len(result.get('matches', [])) or content.get('complete') is False or content.get('has_more') or content.get('truncated')
                row.update(status='truncated' if truncated else 'match' if result.get('matches') else 'no_match',
                           reason='Bounded lookup; timestamp meanings are artifact-specific',
                           matches=result.get('matches', []), limitations=result.get('limitations', []),
                           coverage=result['coverage'], search_coverage=content,
                           content_search=result.get('content_search',{}))
                cursor=content.get('next_cursor')
                if cursor:
                    row['continuation']=base64.urlsafe_b64encode(json.dumps([binding,row['lead_id'],row['artifact'],cursor]).encode()).decode()
                d['queries'].append(dict(lead_id=row['lead_id'],arguments=q,result=result,elapsed_seconds=time.perf_counter()-at))
                activity.event('BRIEFING_LOOKUP','success',lead_id=row['lead_id'],artifact=row['artifact'],returned_count=len(row['matches']))
            try:
                worker.call('check',seconds=5)
            except WorkerError:
                d['limitations'].append('Final read-view validation could not be confirmed; packet is incomplete.')
                d['integrity_verified'] = False
            else:
                d['integrity_verified'] = True
    except WorkerError:
        d['limitations'].append('Discovery worker could not initialize or close successfully; coverage is incomplete.')
        d['integrity_verified'] = False
        for row in rows:
            if row['status'] == 'not_searched':
                row['reason'] = 'worker_failure'
    d['counts'] = {status: sum(row['status']==status for row in rows) for status in
                   ('match','no_match','unavailable','unsupported','failed','truncated','not_searched')}
    d['counts']['returned_matches'] = sum(len(row['matches']) for row in rows)
    packet['metrics'].update(proposed_searches=len(plans),attempted_searches=attempted,
        executed_searches=len(d['queries']),evidence_packet_bytes=total_bytes,discovery_seconds=time.monotonic()-started)
    packet['handoff'] = dict(type='reviewable_plan',automatic_execution=False,approved_leads=list(approved),
        scope=dict(start=start,end=end), evidence_ids=list(dict.fromkeys(m['evidence_id'] for row in rows for m in row['matches'])),
        instructions='Review evidence IDs with show. Discovery does not authorize an investigation or establish findings.')


def render(packet):
    from .interactive.console import safe
    d = packet['discovery']
    lines = ['Cross-artifact evidence discovery — analyst leads are unverified',
             'Authorized window: '+d['start']+' to '+d['end']]
    for identity in d['approved']:
        group = [row for row in d['outcomes'] if row['lead_id']==identity]
        lines.append('\nLead '+identity+': '+safe(group[0]['indicator']))
        for row in group:
            lines.append('  '+row['artifact']+': '+row['status']+' — '+row['reason'])
            for match in row['matches']:
                lines.append('    Evidence: '+safe(match['evidence_id']))
                lines.append('    Source: '+safe(match['source_file'] or 'not available'))
                lines.append('    Recorded time: '+safe(str(match['timestamp_utc'] or 'not available')))
                for stamp in match['timestamps']:
                    if stamp.get('timestamp_utc'):
                        lines.append('      '+safe(str(stamp['slot']))+': '+safe(stamp['timestamp_utc'])+' ('+safe(str(stamp.get('meaning', 'artifact-specific')))+')')
                if match['source_file_truncated'] or match['timestamps_truncated']:
                    lines.append('    Source/timestamp projection truncated; inspect show <evidence-id>.')
                for field in match['matched_fields']:
                    lines.append('    '+safe(field['field'])+': '+safe(field['value'])+(' [truncated]' if field['truncated'] else ''))
                for note in match['limitations']:
                    lines.append('    '+safe(note))
            if row.get('continuation'):
                lines.append('    Resume this lead with the same revision/window and --artifact all --discovery-after '+row['continuation'])
            for note in row.get('limitations', []):
                lines.append('    '+safe(note))
    lines.append('\nTotals: '+', '.join(str(n)+' '+status for status,n in d['counts'].items()))
    lines.extend(d['limitations'])
    return '\n'.join(lines)

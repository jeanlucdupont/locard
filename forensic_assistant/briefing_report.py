"""Presentation of validated briefing packets; no retrieval or model calls."""
import textwrap
from forensic_assistant.interactive.console import safe

LABELS = {'filename': 'Script or file', 'windows_path': 'File path', 'username': 'User',
          'hostname': 'Host', 'ipv4': 'IP address', 'ipv6': 'IP address', 'domain': 'Domain',
          'ambiguous_time': 'Approximate time reference', 'date': 'Time reference', 'timestamp': 'Time reference', 'term': 'Reported activity',
          'context': 'Reported context', 'event_id': 'Event ID', 'hash': 'File hash',
          'registry_path': 'Registry path'}


def render(packet):
    if packet.get('discovery', {}).get('artifact') == 'all':
        from .briefing_discovery import render as cross_render
        return cross_render(packet)
    if packet.get('canonical') and not packet.get('discovery'):
        from .briefing_canonical import render as render_canonical
        text=render_canonical(packet['canonical'])
        if packet.get('ai_error'):
            rejected=packet['ai_error'].get('rejected_items',[])
            if packet.get('summary_editorial') and rejected and all(v.get('component')=='summary' for v in rejected):
                text+='\nAI summary provenance limitation retained; editorial approval does not validate references.'
            else:text+='\nAI validation: '+packet['ai_error']['category']+'; '+str(len(rejected))+' rejected entries. Use --details for safe rejection diagnostics.'
        summary_only=bool(packet.get('summary_editorial') and packet.get('ai_error',{}).get('rejected_items') and all(v.get('component')=='summary' for v in packet['ai_error']['rejected_items']))
        text+='\n'+'\n'.join(safe(note) for note in packet['limitations'] if not (summary_only and note.startswith('AI interpretation failed:')))
        return text+'\nNo forensic evidence searched. Review does not authorize discovery.'
    lines = ['Case briefing — unverified analyst input']
    def paragraph(value, indent='  '):
        for original_line in str(value).splitlines():
            line = safe(original_line)
            lines.extend(textwrap.wrap(line, width=96, initial_indent=indent,
                                      subsequent_indent=indent) or [indent])
    if packet.get('saved_briefing'):
        paragraph('Analysis of saved briefing revision '+str(packet['saved_briefing']['revision'])+' (new analysis, not a cached result).')
    discovery = packet.get('discovery')
    if not discovery:
        lines.extend(['', 'Reported incident (original analyst text)'])
        for source, text in packet['inputs'].items():
            if source.startswith('field:'):
                from forensic_assistant.briefing_store import FIELDS
                lines.append('  '+FIELDS.get(source[6:], 'Analyst answer')+':')
            elif source.startswith('interview:'):lines.append('  Analyst interview response:')
            elif source == 'narrative':lines.append('  Narrative:')
            elif source != 'original':lines.append('  Analyst correction:')
            paragraph(text)
    leads = {lead['id']: lead for lead in packet['leads']}
    remaining=[lead for lead in leads.values() if not lead.get('semantic_candidates')]
    if remaining or not packet.get('ai_candidates'):
        lines.extend(['', 'Additional technical leads' if packet.get('ai_candidates') else 'Key leads'])
    for number, lead in enumerate(remaining, 1):
        paragraph(f"{number}. {lead['occurrences'][0]['original']} — {LABELS.get(lead['type'], 'Lead')}")
        if lead.get('conflicted') or lead['negated'] or lead['classification'] in ('partial', 'invalid', 'ambiguous'):
            paragraph('Not eligible for discovery: negated or incomplete/ambiguous input.')
    if not leads and not packet.get('ai_candidates'):
        paragraph('No supported leads extracted.')
    semantic_groups=[('People',('person','account')),('Systems',('hostname',)),
                     ('Files',('filename','windows_path','registry_path')),('Network indicators',('domain','ipv4','ipv6')),
                     ('Time references',('date','timestamp','ambiguous_time','timezone')),
                     ('Reported activity',('activity','alert','origin','relationship')),
                     ('Investigative objectives',('objective',)),('Unresolved',('unknown',))]
    for heading,kinds in semantic_groups:
        candidates=[c for c in packet.get('ai_candidates',[]) if c['type'] in kinds]
        if candidates:lines.extend(['',heading+' — AI classification of unverified analyst input'])
        for candidate in candidates:
            paragraph(candidate['literal']+' — '+candidate['description'])
            paragraph('Uncertainty: '+candidate['uncertainty'])
            if candidate['polarity']!='reported':paragraph('Analyst reference: '+candidate['polarity'])
    categories = [('Questions to investigate', ('question',)),
                  ('Possible explanations — tentative', ('hypothesis', 'alternative')),
                  ('AI descriptions of reported activity — unverified', ('reported_activity',)),
                  ('Unresolved information', ('ambiguity',))]
    uncertainties = []
    for heading, kinds in categories:
        items = [i for i in packet['ai_items'] if i['category'] in kinds]
        if items:
            lines.extend(['', heading])
        for item in items:
            paragraph('- ' + item['text'])
            if item.get('basis_note'):
                paragraph(item['basis_note'])
            if item['uncertainty'] not in uncertainties:
                uncertainties.append(item['uncertainty'])
    if uncertainties:
        lines.extend(['', 'Uncertainty'])
        for note in uncertainties:
            paragraph('- ' + note)
    lines.extend(['', 'Status'])
    status = packet.get('ai_status', 'not_requested')
    accepted = len(packet['ai_items'])
    if packet.get('ai_candidates'):paragraph(str(len(packet['ai_candidates']))+' source-supported semantic candidates; no forensic findings established.')
    rejected = len(packet.get('ai_error', {}).get('rejected_items', []))
    if status == 'partial':
        paragraph(f'AI interpretation partially accepted: {accepted} interpretations accepted; {rejected} rejected by validation.')
    elif status == 'success':
        paragraph(f'AI interpretation accepted: {accepted} interpretations. These are not forensic findings.')
    elif status == 'failed':
        paragraph('AI interpretation failed; no interpretations accepted. Deterministic leads remain available. Use --details for diagnostics.')
    elif status == 'skipped':
        paragraph('AI interpretation skipped; input could not be included within its bounds.')
    else:
        paragraph('Deterministic extraction only; no AI interpretation requested.')
    if status in ('success','partial') and not packet.get('ai_candidates'):
        paragraph('No semantic candidates accepted; technical leads and any accepted interpretations remain available.')
    # Technical rejection messages remain intact in the packet and detailed view.
    notes = [n for n in packet['limitations'] if not n.startswith('AI interpretation failed:')]
    notes.extend(n for n in packet['conflicts'] if not n.startswith('AI item rejected:'))
    if notes:
        lines.extend(['', 'Limitations'])
        for note in dict.fromkeys(notes):
            paragraph('- ' + note)
    if discovery:
        lines.extend(['', 'Evidence discovery'])
        paragraph('Artifact family: ' + discovery['artifact'])
        paragraph('Authorized window: ' + discovery['start'] + ' to ' + discovery['end'])
        for query in discovery['queries']:
            lead = leads[query['lead_id']]
            result = query['result']
            paragraph('Search: ' + lead['occurrences'][0]['original'])
            records = result['records']
            paragraph(f"{len(records)} evidence {'record' if len(records)==1 else 'records'} returned (bounded results).")
            if not records:
                paragraph('No evidence returned within this bounded search; this does not establish absence.')
            for number, record in enumerate(records, 1):
                paragraph(f'Result {number}')
                for key, label in [('timestamp_utc', 'Recorded event time'), ('timestamp', 'Recorded time'), ('hostname', 'Recorded host'),
                                   ('provider', 'Provider'), ('event_id', 'Event ID'),
                                   ('process_name', 'Process'), ('command_line', 'Recorded command')]:
                    if record.get(key) is not None:
                        paragraph(label + ': ' + str(record[key]), '    ')
                for field in record.get('original_event_data', []):
                    if field.get('name') not in ('CommandLine','Process Name','Path','FileName','TargetFilename','ProcessName'):
                        continue
                    paragraph('Original EventData: ' + str(field.get('name', '(unnamed)')) + ': ' + str(field.get('value', '')), '    ')
                from forensic_assistant.investigation_ai.conclusions import interpretations
                for interpretation in interpretations(record).values():
                    paragraph('Deterministic interpretation: ' + interpretation['text'], '    ')
                if record.get('truncated_fields'):
                    paragraph('Some displayed fields are truncated; inspect --details.', '    ')
            for note in result.get('limitations', []):
                paragraph('Coverage limitation: ' + note)
            paragraph(result['coverage']['note'])
            coverage = result.get('content_search', {})
            if coverage.get('complete') is False or coverage.get('has_more') or coverage.get('truncated'):
                paragraph('Search coverage is incomplete; no overall absence conclusion is supported. Inspect --details for continuation metadata.')
        for identity in discovery['unmapped']:
            paragraph('Not searched (no eligible mapping): ' + leads[identity]['occurrences'][0]['original'])
        for note in discovery['limitations']:
            paragraph(note)
        paragraph('Investigation has not yet been performed. Use --details to review full evidence IDs and inspect records with show <evidence-id>.')
    else:
        paragraph('No forensic evidence searched.')
    if discovery:
        return '\n'.join(lines)
    lines.extend(['', 'Next steps'])
    paragraph('Use --details for exact lead IDs, source references, evidence IDs and diagnostics; --json preserves the structured packet.')
    paragraph('To approve a lead, rerun the SAME briefing input and corrections with:')
    if packet.get('saved_briefing'):
        paragraph('For saved content: briefing --analyze --revision '+str(packet['saved_briefing']['revision'])+' plus the approval options below.')
    eligible = next((lead for lead in sorted(leads.values(), key=lambda lead: lead['type'] not in ('filename', 'windows_path', 'domain', 'ipv4', 'event_id')) if not lead.get('conflicted') and not lead['negated'] and lead['classification'] not in ('partial', 'invalid', 'ambiguous')), None)
    if eligible:
        suffix = (' --artifact ' + discovery['artifact'] + ' --start ' + discovery['start'] + ' --end ' + discovery['end']) if discovery else ' --artifact <family> --start <ISO-time-with-zone> --end <ISO-time-with-zone>'
        paragraph('--discover --approve ' + eligible['id'] + suffix)
        paragraph('Choose the family and a time window of at most 24 hours. Display numbers are labels only, not approval IDs.')
    return '\n'.join(lines)

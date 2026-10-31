"""Presentation of validated briefing packets; no retrieval or model calls."""
import textwrap
from forensic_assistant.interactive.console import safe

LABELS = {'filename': 'Script or file', 'windows_path': 'File path', 'username': 'User',
          'hostname': 'Host', 'ipv4': 'IP address', 'ipv6': 'IP address', 'domain': 'Domain',
          'date': 'Time reference', 'timestamp': 'Time reference', 'term': 'Reported activity',
          'context': 'Reported context', 'event_id': 'Event ID', 'hash': 'File hash',
          'registry_path': 'Registry path'}


def render(packet):
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
    lines.extend(['', 'Key leads'])
    leads = {lead['id']: lead for lead in packet['leads']}
    for number, lead in enumerate(leads.values(), 1):
        paragraph(f"{number}. {lead['occurrences'][0]['original']} — {LABELS.get(lead['type'], 'Lead')}")
        if lead['negated'] or lead['classification'] in ('partial', 'invalid', 'ambiguous'):
            paragraph('Not eligible for discovery: negated or incomplete/ambiguous input.')
    if not leads:
        paragraph('No supported leads extracted.')
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
        paragraph('For saved content: briefing --analyze --deterministic --revision '+str(packet['saved_briefing']['revision'])+' plus the approval options below.')
    eligible = next((lead for lead in sorted(leads.values(), key=lambda lead: lead['type'] not in ('filename', 'windows_path', 'domain', 'ipv4', 'event_id')) if not lead['negated'] and lead['classification'] not in ('partial', 'invalid', 'ambiguous')), None)
    if eligible:
        suffix = (' --artifact ' + discovery['artifact'] + ' --start ' + discovery['start'] + ' --end ' + discovery['end']) if discovery else ' --artifact <family> --start <ISO-time-with-zone> --end <ISO-time-with-zone>'
        paragraph('--discover --approve ' + eligible['id'] + suffix)
        paragraph('Choose the family and a time window of at most 24 hours. Display numbers are labels only, not approval IDs.')
    return '\n'.join(lines)

"""Static offline HTML. All dynamic text crosses html.escape exactly once."""
import html
import json
from .model import CATEGORIES, CAUTION

def text(value):
    if value is None: return 'Unknown / not recorded'
    return str(value) if isinstance(value,(str,int,float)) else json.dumps(value,ensure_ascii=True,sort_keys=True)

def esc(value): return html.escape(text(value),quote=True)

def assertion(item):
    data=item['assertion']
    if item['category']=='OBSERVED FACT':
        value=f"{data['subject']} reports {data['field']} = {text(data['value'])}. {data['qualifier']}"
        if data['truncated_fields']: value+=' Compact projection has omissions/truncation: '+text(data['truncated_fields'])+'.'
        return value
    if 'engine_object' in data:
        obj=data['engine_object']
        return text(obj)
    return text(data)

CSS='''body{margin:0;background:#eceeea;color:#202922;font:16px/1.55 Georgia,serif}main{max-width:1120px;margin:32px auto;padding:48px;background:white;border-top:8px solid #294f43}h1,h2,h3,nav,.label{font-family:Arial,sans-serif}h1{font-size:36px;margin-bottom:8px}h2{margin-top:42px;border-bottom:1px solid #ccd6cf;padding-bottom:8px}h3{font-size:17px}a{color:#244f43}p,td,li{overflow-wrap:anywhere}table{width:100%;border-collapse:collapse;font-size:13px}th,td{padding:9px;text-align:left;vertical-align:top;border:1px solid #d8dfd9}th{background:#edf2ee}article{padding:16px;border:1px solid #d8dfd9;margin:14px 0;break-inside:avoid}.notice{background:#fff4d9;border-left:4px solid #a77217;padding:16px}.muted{color:#526256;font-size:14px}code{font-size:12px}nav a{margin-right:15px;display:inline-block}@media print{body{background:white}main{margin:0;padding:0;border:0}nav{display:none}h2{break-after:avoid}thead{display:table-header-group}}'''

def render(report):
    data=report['data'];claims=data['claims']
    out=['<!doctype html><html lang="en"><head><meta charset="utf-8">',
         '<meta name="viewport" content="width=device-width, initial-scale=1">',
         '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'; base-uri \'none\'; form-action \'none\'">',
         '<title>Locard forensic report</title><style>'+CSS+'</style></head><body><main>',
         '<div class="label">LOCARD · DERIVED FORENSIC REPORT</div><h1>'+esc(data['analyst_metadata'].get('title','Forensic evidence report'))+'</h1>',
         '<p class="muted">Report '+esc(report['report_id'])+' · '+esc(report['created_utc'])+' · '+esc(report['profile'])+'</p>',
         '<p class="notice">'+esc(data['scope'])+'</p>',
         '<p>Status: <strong>'+esc(data['status'])+'</strong>. Completion applies to this bounded report only.</p>',
         '<nav><a href="#summary">Summary</a><a href="#scope">Scope</a><a href="#method">Methodology</a><a href="#findings">Findings</a><a href="#timeline">Timeline</a><a href="#references">References</a></nav>']
    def section(title,body,id=None):
        out.append('<section'+(' id="'+id+'"' if id else '')+'><h2>'+esc(title)+'</h2>'+body+'</section>')
    def table(headers,rows):
        if type(rows).__name__=='dict_items': rows=sorted(rows)
        return '<table><thead><tr>'+''.join('<th>'+esc(h)+'</th>' for h in headers)+'</tr></thead><tbody>'+''.join('<tr>'+''.join('<td>'+esc(c)+'</td>' for c in row)+'</tr>' for row in rows)+'</tbody></table>'
    def listing(items):return '<ul>'+''.join('<li>'+esc(item)+'</li>' for item in items)+'</ul>'
    if data.get('redaction_notice'):out.append('<p class="notice">'+esc(data['redaction_notice'])+'</p>')
    order=report.get('narrative',{}).get('claim_order',[])
    ordered=sorted(claims,key=lambda c:(order.index(c['claim_id']) if c['claim_id'] in order else len(order),c['claim_id']))
    overview=[c for c in ordered if c['category'] in ('OBSERVED FACT','DETERMINISTIC RELATIONSHIP','CORROBORATED RELATIONSHIP','DETECTION')][:8]
    caveats=[c for c in claims if c['category'] in ('CONFLICT','UNKNOWN','LIMITATION')]
    section('Executive summary',listing([c['category']+': '+assertion(c)+' ['+c['claim_id']+']' for c in overview]+[c['category']+': '+assertion(c) for c in caveats])+'<p>'+esc(CAUTION)+'</p>','summary')
    section('Case metadata and scope',table(['Metadata','Value'],data['analyst_metadata'].items())+'<p>'+esc(data['analyst_metadata_basis'])+'</p><p>'+esc(data['scope'])+'</p><p>Input mode: '+esc(data['input_mode'])+'</p><p>Selection: '+esc(data['selection'])+'</p>','scope')
    section('Evidence inventory',table(['SHA-256','Types','Parser metadata','Ingestion history','Case record count','Source locations'],[(sha,item['source_types'],item['parsers'],item['ingestion_runs'],item['evidence_count'],item.get('source_locations','Omitted from this report')) for sha,item in sorted(data['inventory'].items())])+'<p>Inventory covers referenced source files. Counts describe stored source records, not records individually examined by the model.</p>')
    section('Methodology',table(['Recorded property','Value'],data['methodology'].items())+'<p>Report-time hydration is separate from historical model exposure. Unrecorded operations are not asserted.</p>','method')
    section('Investigation questions',listing([p['question'] for p in data['investigations']]) if data['investigations'] else '<p>No investigation question: report generated from explicit evidence IDs.</p>')
    out.append('<section id="findings"><h2>Findings and detailed analysis</h2>')
    for category in CATEGORIES:
        out.append('<h3>'+esc(category)+'</h3>')
        group=[c for c in ordered if c['category']==category]
        if not group:out.append('<p>No claims in this category within the selected report inputs. This is not an investigative negative result.</p>')
        if report['profile']=='executive' and category in ('OBSERVED FACT','DETERMINISTIC RELATIONSHIP','CORROBORATED RELATIONSHIP','DETECTION') and len(group)>5:
            out.append('<p>'+str(len(group)-5)+' additional claims in this category are retained in report.json.</p>')
            group=group[:5]
        for c in group:
            # Claim IDs are generated hashes; validation precedes rendering.
            out.append('<article id="'+esc(c['claim_id'])+'"><div class="label">'+esc(c['category'])+'</div><p>'+esc(assertion(c))+'</p><p class="muted">Claim '+esc(c['claim_id'])+'<br>Evidence: '+esc(c['evidence_ids'])+'<br>Origins: '+esc(c['origins'])+'</p></article>')
    out.append('</section>')
    timeline=data['timeline'] if report['profile']=='technical' else data['timeline'][:50]
    section('Timestamp observations',table(['UTC / unknown','Original value','Timestamp source and meaning','Precision / normalization','Evidence / slot'],[(t['timestamp_utc'],t['original_value'],text(t['source'])+'; '+text(t['meaning']),text(t['precision_ns'])+'; '+text(t['normalization_status']),t['evidence_id']+' / '+t['slot']) for t in timeline])+f'<p>{len(data["timeline"])-len(timeline)} additional included observations are available in report.json. '+esc(data['omissions'])+'</p><p>Registry last-write belongs to its key. MFT SI/FN meanings remain separate. Prefetch observations are not a complete execution history.</p>','timeline')
    section('Conclusions', '<p>Within the selected inputs, the report contains '+str(len(claims))+' structured claims. The factual assertions are those listed above; no broader compromise, attribution, intent, or causal conclusion is established by report generation.</p>'+listing([assertion(c) for c in caveats]))
    section('Evidence references',table(['Evidence ID','Source / locator','Context','Warnings'],[(eid,r['source'],r['context'],r['warnings']) for eid,r in sorted(data['evidence'].items())])+'<p>The structured JSON contains forward and reverse claim/evidence mappings.</p>','references')
    section('Investigation provenance',listing(data['investigations']) if data['investigations'] else '<p>No V4 investigation supplied. Only report-time operations described above were performed.</p>')
    section('AI disclosure and integrity', '<p>Report narrative assistance: '+esc(report['narrative']['status'])+'. Assistance only orders validated claims; Locard renders factual text.</p><p>'+esc(report['narrative'])+'</p><p>Historical model request attempts: '+esc(any(p['exposure_requests'] for p in data['investigations']))+'</p><p>'+esc(CAUTION)+'</p><p>See manifest.json and checksums.sha256 for SHA-256 output hashes. Hashes are not signatures.</p>')
    out.append('</main></body></html>')
    return ''.join(out).encode('utf-8')

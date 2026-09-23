"""Hash-separated, atomic publication of derived report bundles."""
from datetime import datetime, timezone
import hashlib
import os
from pathlib import Path
import shutil
import tempfile
import uuid
import time
from forensic_assistant import __version__
from .collect import build
from .model import canonical, digest, FORMAT, MAX_FILE, claim, graph, Limits, DIRECT_SCOPE, CAUTION
from .redact import apply
from .render import render
from .transcripts import read, safe_path

FILES=('report.json','report.html','manifest.json','checksums.sha256')

def structure(report):
    try:
        if set(report)!={'format','report_id','created_utc','application_version','profile','redaction','data','narrative'}:
            raise ValueError('Unexpected report keys')
        if type(report['format']) is not int or report['format']!=FORMAT or report['profile'] not in ('technical','executive') or report['redaction'] not in ('none','identifiers'):
            raise ValueError('Unsupported report format/profile')
        data=report['data'];Limits(**data['limits'])
        keys={'format','schema','input_mode','scope','evidence_fingerprint','analyst_metadata','analyst_metadata_basis',
              'selection','limits','source_locations_included','status','claims','evidence','graph','timeline','inventory',
              'investigations','limitations','omissions','methodology','caution'}
        if report['redaction']=='identifiers':keys.add('redaction_notice')
        if set(data)!=keys:raise ValueError('Unexpected structured report fields')
        if data['format']!=FORMAT or data['schema']!=3 or data['status'] not in ('COMPLETE','COMPLETE_WITH_LIMITATIONS'):
            raise ValueError('Invalid report status/schema')
        if data['input_mode'] not in ('explicit_evidence_ids','investigations'): raise ValueError('Invalid input mode')
        if (data['input_mode']=='explicit_evidence_ids') != bool(data['selection']['evidence_ids']): raise ValueError('Input scope mismatch')
        if data['methodology']['input_mode']!=data['input_mode'] or data['methodology']['scope']!=data['scope'] or data['caution']!=CAUTION:
            raise ValueError('Methodology/scope mismatch')
        if data['input_mode']=='explicit_evidence_ids' and (data['scope']!=DIRECT_SCOPE or data['investigations'] or data['selection']['investigation_ids']):
            raise ValueError('Explicit selection cannot claim an investigation')
        if len(data['claims'])>data['limits']['claims'] or len(data['timeline'])>data['limits']['timeline'] or len(data['evidence'])>2000: raise ValueError('Report count limit')
        for c in data['claims']:
            if set(c)!={'claim_id','category','assertion','evidence_ids','origins'} or c!=claim(c['category'],c['assertion'],c['evidence_ids'],c['origins']):
                raise ValueError('Claim identity/structure mismatch')
            if c['category']=='OBSERVED FACT' and c['assertion']['subject'] not in c['evidence_ids']: raise ValueError('Observed subject lacks support')
            assertion=c['assertion'];category=c['category']
            if category=='OBSERVED FACT' and set(assertion)!={'field','value','subject','qualifier','truncated_fields'}:
                raise ValueError('Invalid observed assertion')
            if category in ('DETERMINISTIC RELATIONSHIP','CORROBORATED RELATIONSHIP','DETECTION'):
                if set(assertion)!={'engine_object'}:raise ValueError('Missing engine assertion')
                obj=assertion['engine_object']
                if set(obj['evidence_ids'])!=set(c['evidence_ids']):raise ValueError('Engine support mismatch')
                if category=='DETERMINISTIC RELATIONSHIP' and obj['status'] not in ('CONFIRMED','LIKELY','DETERMINISTICALLY_CORRELATED'):
                    raise ValueError('Relationship status upgrade')
                if category=='CORROBORATED RELATIONSHIP' and obj['status']!='CORROBORATED':raise ValueError('Corroboration status mismatch')
                if category=='DETECTION' and not obj.get('detection_id'):raise ValueError('Missing detection identity')
            if category=='CONFLICT' and set(assertion)!={'kind','fields','assertions','resolution'}:raise ValueError('Invalid conflict')
            if category=='MODEL/ANALYST HYPOTHESIS' and (set(assertion)!={'proposal','verification','contradictions','gaps'} or assertion['verification']!='UNVERIFIED'):
                raise ValueError('Hypothesis verification upgrade')
            if category=='LIMITATION' and (set(assertion)-{'items','original_item_count'} or type(assertion['items']) is not list):raise ValueError('Invalid limitations')
            if category=='UNKNOWN' and set(assertion) not in ({'engine_object'},{'model_proposal','verification'}):raise ValueError('Invalid unknown')
        if data['graph']!=graph(data['claims'],data['evidence']): raise ValueError('Graph mismatch')
        for eid,r in data['evidence'].items():
            if r['id']!=eid or not set(r['supporting_evidence_ids'])<=data['evidence'].keys(): raise ValueError('Missing supporting record')
        if any(t['evidence_id'] not in data['evidence'] for t in data['timeline']): raise ValueError('Unknown timeline evidence')
        narrative=report['narrative']
        if narrative['status'] not in ('NOT_REQUESTED','ACCEPTED','FALLBACK'): raise ValueError('Invalid narrative status')
        if set(narrative)-{'status','claim_order','model_metadata','configuration','prompt_sha256','prompt_bytes','reason'}: raise ValueError('Unexpected narrative keys')
        order=narrative['claim_order']
        if not isinstance(order,list) or len(order)>20 or len(order)!=len(set(order)) or not set(order)<={c['claim_id'] for c in data['claims']}:
            raise ValueError('Narrative references unknown claims')
        return True
    except (KeyError,TypeError,AttributeError) as exc: raise ValueError('Malformed report structure') from exc

def generate(case, output, *, profile='technical', redaction='none', narrative_client=None, **options):
    deadline=time.monotonic()+(options.get('limits') or Limits()).seconds
    if profile not in ('technical','executive'): raise ValueError('Unknown report profile')
    if redaction=='identifiers' and options.get('include_source_locations'): raise ValueError('Source locations incompatible with identifier redaction')
    destination=safe_path(output)
    if destination.exists(): raise ValueError('Report destination already exists')
    if not destination.parent.is_dir(): raise ValueError('Report parent directory must exist')
    data=apply(build(case,**options),redaction)
    report=dict(format=FORMAT,report_id=uuid.uuid4().hex,created_utc=datetime.now(timezone.utc).isoformat(),
        application_version=__version__,profile=profile,redaction=redaction,data=data,
        narrative={'status':'NOT_REQUESTED','claim_order':[]})
    if narrative_client is not None:
        from .narrative import assist
        if time.monotonic()>=deadline: raise ValueError('Report runtime exhausted')
        if hasattr(narrative_client,'timeout'): narrative_client.timeout=min(45,deadline-time.monotonic())
        report['narrative']=assist(data,narrative_client)
        if redaction=='identifiers' and 'model_metadata' in report['narrative']:
            report['narrative']['model_metadata']={'identity_basis':'Model metadata suppressed by identifiers redaction'}
        if report['narrative']['status']!='ACCEPTED': data['status']='COMPLETE_WITH_LIMITATIONS'
    structure(report)
    payloads={'report.json':canonical(report),'report.html':render(report)}
    manifest=dict(format=FORMAT,report_id=report['report_id'],created_utc=report['created_utc'],
        application_version=__version__,schema=3,derived_data=True,input_mode=data['input_mode'],scope=data['scope'],
        evidence_fingerprint=data['evidence_fingerprint'],investigations=data['investigations'],
        selection=data['selection'],profile=profile,redaction=redaction,status=data['status'],
        deterministic_sha256=digest(data),claim_ids=[c['claim_id'] for c in data['claims']],
        evidence_ids=sorted(data['evidence']),claim_evidence_graph=data['graph'],
        narrative=report['narrative'],outputs={name:hashlib.sha256(raw).hexdigest() for name,raw in payloads.items()},
        integrity_meaning='File consistency only; not authentication or proof of forensic conclusions')
    payloads['manifest.json']=canonical(manifest)
    payloads['checksums.sha256']=''.join(hashlib.sha256(payloads[name]).hexdigest()+'  '+name+'\n' for name in sorted(payloads)).encode()
    if any(len(raw)>MAX_FILE for raw in payloads.values()) or sum(map(len,payloads.values()))>64*1024*1024:
        raise ValueError('Report output size limit')
    # Check current evidence after optional model wait and before publication.
    from .collect import ReportWorker
    if time.monotonic()>=deadline: raise ValueError('Report runtime exhausted')
    with ReportWorker({'case_path':str(case)}) as worker:
        worker.call('check',fingerprint=data['evidence_fingerprint'],seconds=min(45,max(.001,deadline-time.monotonic())))
    staging=Path(tempfile.mkdtemp(prefix='.locard-report-',dir=destination.parent))
    try:
        for name,raw in payloads.items():
            with (staging/name).open('xb') as stream:
                stream.write(raw);stream.flush();os.fsync(stream.fileno())
        inspect(staging)
        if time.monotonic()>=deadline: raise ValueError('Report runtime exhausted')
        safe_path(destination)
        if destination.exists(): raise ValueError('Report destination appeared during generation')
        os.rename(staging,destination)
    finally:
        if staging.exists():
            checked=safe_path(staging)
            if checked.resolve().parent!=destination.parent.resolve() or not checked.name.startswith('.locard-report-'):
                raise ValueError('Unsafe staging cleanup refused')
            shutil.rmtree(checked)
    return dict(status=data['status'],report_id=report['report_id'],output=str(destination),input_mode=data['input_mode'])

def read_payloads(directory):
    directory=safe_path(directory)
    if {p.name for p in directory.iterdir()}!=set(FILES): raise ValueError('Unexpected or missing bundle files')
    payloads={name:read(directory/name,MAX_FILE) for name in FILES}
    if sum(map(len,payloads.values()))>64*1024*1024: raise ValueError('Bundle size limit')
    expected=''.join(hashlib.sha256(payloads[name]).hexdigest()+'  '+name+'\n' for name in sorted(FILES) if name!='checksums.sha256').encode()
    if payloads['checksums.sha256']!=expected: raise ValueError('File integrity failed')
    return payloads

def inspect_payloads(payloads):
    from .model import loads
    report=loads(payloads['report.json']);manifest=loads(payloads['manifest.json'])
    structure(report)
    if set(manifest)!={'format','report_id','created_utc','application_version','schema','derived_data','input_mode','scope',
        'evidence_fingerprint','investigations','selection','profile','redaction','status','deterministic_sha256',
        'claim_ids','evidence_ids','claim_evidence_graph','narrative','outputs','integrity_meaning'}:
        raise ValueError('Unexpected manifest fields')
    if manifest['format']!=FORMAT or manifest['schema']!=3 or manifest['derived_data'] is not True:
        raise ValueError('Invalid manifest format/schema')
    if manifest['claim_ids']!=[c['claim_id'] for c in report['data']['claims']] or manifest['evidence_ids']!=sorted(report['data']['evidence']):
        raise ValueError('Manifest reference mismatch')
    if manifest['outputs']!={name:hashlib.sha256(payloads[name]).hexdigest() for name in ('report.json','report.html')}:
        raise ValueError('Manifest output hash mismatch')
    for key in ('report_id','created_utc','application_version','profile','redaction','narrative'):
        if manifest[key]!=report[key]: raise ValueError('Manifest/report mismatch')
    for key in ('input_mode','scope','evidence_fingerprint','investigations','selection','status'):
        if manifest[key]!=report['data'][key]: raise ValueError('Manifest/data mismatch')
    if manifest['deterministic_sha256']!=digest(report['data']) or manifest['claim_evidence_graph']!=report['data']['graph']:
        raise ValueError('Manifest data digest/graph mismatch')
    # Re-rendering prevents a rehashed HTML file from presenting different facts.
    if render(report)!=payloads['report.html']: raise ValueError('HTML differs from structured report')
    return report,manifest

def inspect(directory): return inspect_payloads(read_payloads(directory))

def validate(directory, *, case=None, transcript_root=None):
    result=dict(file_integrity='NOT_CHECKED',structure='NOT_CHECKED',case_fingerprint='NOT_CHECKED',
                evidence_grounding='NOT_CHECKED',conclusions_truth='NOT_ESTABLISHED',
                caution='Successful validation does not prove forensic conclusions; hashes are not authentication.')
    try: payloads=read_payloads(directory)
    except (ValueError,OSError):
        result['file_integrity']='FAIL';return result
    result['file_integrity']='PASS'
    try: report,manifest=inspect_payloads(payloads)
    except (ValueError,KeyError,TypeError,AttributeError):
        result['structure']='FAIL';return result
    result['structure']='PASS'
    if case is None: return result
    from .collect import ReportWorker
    try:
        with ReportWorker({'case_path':str(case)}) as worker:
            worker.call('check',fingerprint=manifest['evidence_fingerprint'])
    except (ValueError,OSError):
        result['case_fingerprint']='FAIL';return result
    result['case_fingerprint']='PASS'
    data=report['data']
    if data['input_mode']=='investigations' and transcript_root is None:
        result['grounding_requirement']='Original investigation transcripts required';return result
    try:
        rebuilt=apply(build(case,**data['selection'],transcript_root=transcript_root,limits=Limits(**data['limits']),
            metadata={} if report['redaction']=='identifiers' else data['analyst_metadata'],
            include_source_locations=data['source_locations_included']),report['redaction'])
    except (ValueError,OSError):
        result['evidence_grounding']='FAIL';return result
    if report['redaction']=='identifiers': rebuilt['analyst_metadata']=data['analyst_metadata']
    if report['narrative']['status'] not in ('NOT_REQUESTED','ACCEPTED'): rebuilt['status']='COMPLETE_WITH_LIMITATIONS'
    result['evidence_grounding']='PASS' if rebuilt==data else 'FAIL'
    return result

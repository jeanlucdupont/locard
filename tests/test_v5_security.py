import hashlib
import json
import sqlite3
import sys
import pytest
from forensic_assistant.reporting.bundle import generate,inspect,validate
from forensic_assistant.reporting.collect import build,ReportWorker
from forensic_assistant.reporting.model import canonical,digest,claim,graph
from forensic_assistant.reporting.render import render
from forensic_assistant.investigation_ai.controller import run
from test_v4_worker import make_case,config
from test_v4_controller import Scripted,final,tool

def rehash_transcript(directory,transform):
    from forensic_assistant.investigation_ai.transcript import digest as event_digest
    events=[json.loads(line) for line in (directory/'events.jsonl').read_text().splitlines()]
    events=transform(events);chain='0'*64
    for event in events:
        event['previous']=chain;event.pop('hash')
        if event['kind']=='result':event['data']['result_sha256']=event_digest(event['data']['response']['result'])
        event['hash']=event_digest(event);chain=event['hash']
    (directory/'events.jsonl').write_bytes(b'\n'.join(canonical(e) for e in events)+b'\n')
    manifest=json.loads((directory/'manifest.json').read_text());manifest['chain']=chain
    (directory/'manifest.json').write_bytes(canonical(manifest))

def test_rehashed_forged_evidence_is_not_grounded(tmp_path):
    case=tmp_path/'case.db';make_case(case);root=tmp_path/'runs'
    iid=run(config(case),'PowerShell',root,client=Scripted([final]))['investigation_id']
    rehash_transcript(root/iid,lambda events:json.loads(json.dumps(events).replace('powershell.exe','fabricated.exe')))
    with pytest.raises(ValueError,match='grounding'):build(case,investigation_ids=[iid],transcript_root=root)

def test_rehashed_report_distinguishes_grounding_from_integrity(tmp_path):
    case=tmp_path/'case.db';event=make_case(case);out=tmp_path/'report'
    generate(case,out,evidence_ids=[event['id']]);report,manifest=inspect(out)
    data=report['data'];target=next(c for c in data['claims'] if c['category']=='OBSERVED FACT')
    target['assertion']['value']='forged observation'
    replacement=claim(target['category'],target['assertion'],target['evidence_ids'],target['origins'])
    target.clear();target.update(replacement);data['graph']=graph(data['claims'],data['evidence'])
    manifest.update(deterministic_sha256=digest(data),claim_ids=[c['claim_id'] for c in data['claims']],claim_evidence_graph=data['graph'])
    payloads={'report.json':canonical(report),'report.html':render(report)}
    manifest['outputs']={k:hashlib.sha256(v).hexdigest() for k,v in payloads.items()}
    payloads['manifest.json']=canonical(manifest)
    payloads['checksums.sha256']=''.join(hashlib.sha256(payloads[k]).hexdigest()+'  '+k+'\n' for k in sorted(payloads)).encode()
    for name,raw in payloads.items():(out/name).write_bytes(raw)
    result=validate(out,case=case)
    assert result['file_integrity']==result['structure']==result['case_fingerprint']=='PASS'
    assert result['evidence_grounding']=='FAIL' and result['conclusions_truth']=='NOT_ESTABLISHED'

def test_registry_support_timestamps_and_context_conflict(tmp_path):
    from forensic_assistant.database.db import connect
    from forensic_assistant.artifacts.ingest import ingest_artifact
    from forensic_assistant.artifacts.context import bind_context
    from v2_fixtures import registry_file
    case=tmp_path/'case.db';db=connect(case)
    result=ingest_artifact(db,registry_file(tmp_path/'synthetic.hive'),'registry',hostname='first.example')
    assert result['status']=='complete'
    row=db.execute('SELECT evidence_id,file_sha256 FROM evidence_records WHERE artifact_type=? LIMIT 1',('registry_value',)).fetchone()
    with db:bind_context(db,row['file_sha256'],'synthetic.hive',hostname='second.example')
    eid=row['evidence_id'];db.close()
    report=build(case,evidence_ids=[eid])
    support=report['evidence'][eid]['supporting_evidence_ids'][0]
    assert support in report['evidence'] and report['timeline'][0]['evidence_id']==support
    assert any(c['category']=='CONFLICT' for c in report['claims'])
    assert report['graph']['qualification_edges']
    generate(case,tmp_path/'redacted',evidence_ids=[eid],redaction='identifiers')
    assert validate(tmp_path/'redacted',case=case)['evidence_grounding']=='PASS'

def test_engine_relationships_are_regrounded(tmp_path):
    from forensic_assistant.database.db import connect,register_source
    from v1_fixtures import process
    from test_ingest import SHA
    case=tmp_path/'case.db';db=connect(case)
    with db:register_source(db,SHA,1,'synthetic.evtx')
    process(db,1,'20',name='WINWORD.EXE',time='14:29:00')
    child=process(db,2,'24',ppid='20');db.close()
    def finish(messages):
        packet=json.loads(messages[1]['content'])['UNTRUSTED FORENSIC EVIDENCE']
        return {'action':'final','answer':dict(observed=[],relationships=[r['relationship_id'] for r in packet['relationships'][:3]],detections=[],hypotheses=[],unknowns=[])}
    result=run(config(case),'PowerShell',tmp_path/'runs',client=Scripted([tool('process_tree',{'evidence_id':child['id']}),finish]))
    report=build(case,investigation_ids=[result['investigation_id']],transcript_root=tmp_path/'runs')
    assert report['graph']['engine_objects']

@pytest.mark.parametrize('wal',[True,False])
def test_report_worker_kill_timeout_and_writer_cleanup(tmp_path,wal):
    case=tmp_path/'case.db';make_case(case,wal=wal)
    worker=ReportWorker({'case_path':str(case)})
    with pytest.raises(ValueError,match='TIMEOUT'):worker.call('check',seconds=0)
    worker.close()
    worker=ReportWorker({'case_path':str(case)})
    worker.process.kill();worker.process.wait()
    with pytest.raises(ValueError):worker.call('check')
    worker.close()
    db=sqlite3.connect(case,timeout=.2);db.execute("UPDATE events SET command_line='writer completed'");db.commit();db.close()

def test_redaction_does_not_whitelist_hash_shaped_username(tmp_path):
    case=tmp_path/'case.db';event=make_case(case);secret='f'*64
    db=sqlite3.connect(case);db.execute('UPDATE events SET username=?',(secret,));db.commit();db.close()
    generate(case,tmp_path/'report',evidence_ids=[event['id']],redaction='identifiers')
    for path in (tmp_path/'report').iterdir():assert secret.encode() not in path.read_bytes()

@pytest.mark.skipif(sys.platform!='win32',reason='Windows venv launcher lifecycle regression')
def test_timeout_terminates_actual_busy_python_worker(tmp_path):
    import ctypes
    case=tmp_path/'case.db';make_case(case)
    script=tmp_path/'synthetic_worker.py'
    script.write_text('import sys,json,os\nsys.stdin.readline()\nprint(json.dumps({"ready":True,"worker_pid":os.getpid()}),flush=True)\nsys.stdin.readline()\nwhile True: pass\n')
    class BusyWorker(ReportWorker): worker_script=script
    worker=BusyWorker({'case_path':str(case)})
    kernel=ctypes.WinDLL('kernel32');kernel.OpenProcess.restype=ctypes.c_void_p
    kernel.OpenProcess.argtypes=[ctypes.c_ulong,ctypes.c_int,ctypes.c_ulong]
    kernel.WaitForSingleObject.argtypes=[ctypes.c_void_p,ctypes.c_ulong]
    kernel.CloseHandle.argtypes=[ctypes.c_void_p]
    handle=kernel.OpenProcess(0x100000|0x1000,False,worker.worker_pid)
    assert handle
    try:
        with pytest.raises(ValueError,match='TIMEOUT'):worker.call('check',seconds=.15)
        assert kernel.WaitForSingleObject(handle,5000)==0
    finally:
        worker.close();kernel.CloseHandle(handle)

def test_report_wal_pressure_terminates_worker(tmp_path,monkeypatch):
    case=tmp_path/'case.db';make_case(case)
    worker=ReportWorker({'case_path':str(case)})
    sizes=iter((0,65*1024*1024));monkeypatch.setattr(worker,'_wal_size',lambda:next(sizes))
    with pytest.raises(ValueError,match='WAL_PRESSURE'):worker.call('check')
    assert worker.process.poll() is not None;worker.close()

def test_conceptual_semantic_history_needs_no_embedding_model(tmp_path):
    from forensic_assistant.database.db import connect,register_source
    from forensic_assistant.investigation_ai.runner import ForensicWorker
    from v1_fixtures import process
    from test_ingest import SHA
    case=tmp_path/'case.db';db=connect(case)
    with db:register_source(db,SHA,1,'synthetic.evtx')
    process(db,1,'20',name='WINWORD.EXE',time='14:29:00')
    child=process(db,2,'24',ppid='20');db.close()
    class RecordedSemanticFixture(ForensicWorker):
        def call(self,operation,arguments=None,**kwargs):
            if operation!='initial':return super().call(operation,arguments,**kwargs)
            response=super().call('investigate_evidence',{'evidence_id':child['id'],'limit':50},known_ids=[child['id']])
            result=response['result'];result['tool']='initial_retrieval'
            result.update(semantic_used=True,semantic_candidates=[{'evidence_id':child['id'],'score':0.9}],
                          plan={'operation':'conceptual','semantic_coverage':'searched'})
            for record in result['records']:record['retrieval_basis']=['semantic_similarity']
            return response
    def finish(messages):
        packet=json.loads(messages[1]['content'])['UNTRUSTED FORENSIC EVIDENCE']
        return {'action':'final','answer':dict(observed=[],relationships=[r['relationship_id'] for r in packet['relationships'][:3]],detections=[],hypotheses=[],unknowns=[])}
    result=run(config(case),'Conceptual query without a deterministic planner equivalent',tmp_path/'runs',
               client=Scripted([finish]),worker_factory=RecordedSemanticFixture)
    report=build(case,investigation_ids=[result['investigation_id']],transcript_root=tmp_path/'runs')
    assert report['graph']['engine_objects'] and report['methodology']['semantic_retrieval_rerun'] is False

def test_hypothesis_has_no_implied_negative_or_factual_conclusion(tmp_path):
    case=tmp_path/'case.db';make_case(case);root=tmp_path/'runs'
    statement='Synthetic hypothesis that has not been independently established'
    def proposal(messages):
        result=final(messages);eid=result['answer']['observed'][0]['evidence_id']
        result['answer']['hypotheses']=[{'statement':statement,'evidence_ids':[eid],'alternatives':['Synthetic alternative explanation']}]
        result['answer']['unknowns']=['An unverified model question remains']
        return result
    iid=run(config(case),'PowerShell',root,client=Scripted([proposal]))['investigation_id']
    for redaction in ('none','identifiers'):
        output=tmp_path/redaction
        generate(case,output,investigation_ids=[iid],transcript_root=root,redaction=redaction)
        report,_=inspect(output)
        hypothesis=next(c for c in report['data']['claims'] if c['category']=='MODEL/ANALYST HYPOTHESIS')
        assert hypothesis['assertion']['verification']=='UNVERIFIED'
        assert hypothesis['assertion']['contradictions']['status']=='NOT_EVALUATED'
        assert all(e['relation']=='references' for e in report['data']['graph']['edges'] if e['claim_id']==hypothesis['claim_id'])
        html=(output/'report.html').read_text()
        assert statement not in html.split('<h2>Conclusions</h2>')[1].split('</section>')[0]
        assert validate(output,case=case,transcript_root=root)['evidence_grounding']=='PASS'

"""Provider-free temporal discovery, authority, replay and read-only worker tests."""
from contextlib import closing
from copy import deepcopy
import json
import time
import pytest

from forensic_assistant.investigation_ai import autonomous as a, follow_up as f, autonomous_policy as policy
from forensic_assistant.investigation_ai.transcript import load, digest
from forensic_assistant.investigation_ai.runner import ForensicWorker, WorkerError
from forensic_assistant.ai import openai_schema
from test_autonomous_stage_a import setup, grant
from test_compact_disclosure import records, envelope, answer
from test_v4_controller import Scripted
from test_assessment_seed_selection import saved


def discovery_grant(g):
    g = deepcopy(g)
    g.update(contract=f.CONTRACT, follow_up=deepcopy(f.LIMITS), tools=['show_evidence', 'follow_up'])
    return g


def proposal(messages, family='evtx'):
    body = json.loads(messages[1]['content'])
    assert body['controller']['final_only'] is False
    packet = body['UNTRUSTED FORENSIC EVIDENCE']
    for row in packet['records']:
        for item in row['observations']:
            if item[1] == '/timestamps/0/utc':
                return dict(action='tool', tool='follow_up', arguments=dict(evidence_id=row['id'], field=item[1], family=family), reason='Compare recorded activity near the disclosed timestamp.')
    pytest.fail('Timestamp must be disclosed before proposing temporal retrieval')


def final(messages):
    return dict(action='final', answer=answer(json.loads(messages[1]['content'])['UNTRUSTED FORENSIC EVIDENCE']))


def run_mock(tmp_path, actions=None, empty=False):
    config, _, _, _, _ = setup(tmp_path, count=3)
    g = config['_stage_a'] = discovery_grant(config['_stage_a'])
    seed = records()[:3]
    for row in seed:
        row.pop('defender_asr',None);row.pop('interpretation_ids',None)
        if row['source_type']=='evtx':row.update(event_id=7,original_event_data=[dict(name='Message',ordinal=0,value='Neutral activity',truncated=False)])
    extra = deepcopy(seed[1]); extra['id'] = 'EVTX:'+'a'*64+':Offset:77'
    rows = {r['id']:r for r in [*seed, extra]}
    for r in rows.values(): r['source_context'] = {'source_ids':['source-test']}
    view = dict(contract='sqlite-read-view-v1', view_id='a'*32, file_identity=dict(device=1,inode=1))
    calls=[]; closed=[]; retained={}
    class Worker:
        def __init__(self, _): pass
        def close(self): closed.append(True)
        def call(self, name, args=None, **kw):
            calls.append(name)
            if name in ('initial','check'): result=envelope([])
            elif name=='show_evidence':result=envelope([rows[args['evidence_id']]])
            else:
                selected=[] if empty else [extra]
                result=envelope(selected);result['tool']='follow_up'
                result['plan']=dict(f.record_window(g,args,retained),returned_ids=[r['id'] for r in selected],complete=True)
            retained.update((r['id'],r) for r in result['records'])
            return dict(result=result,evidence_state=view,database_changes=0,fingerprint=None,schema=5)
    client=Scripted(actions or [final,proposal,final,final,final,final])
    client.provider_name='openai';client.model_name='synthetic'
    result=a.run(config,g['objective'],tmp_path/'runs',client=client,worker_factory=Worker)
    return result,client,calls,closed,extra


def test_full_mock_pipeline_and_independent_reconstruction(tmp_path):
    result,client,calls,closed,extra=run_mock(tmp_path)
    assert result['follow_up']['executed']==1 and calls.count('follow_up')==1 and closed
    assert result['validated_batches']==3
    assert extra['id'] in {eid for row in result['findings']['observed'] for eid in row['evidence_ids']}
    assert len(client.calls)==4 and result['metrics']['ai_requests']==4
    assert all(sum(len(m['content'].encode()) for m in openai_schema.instruct(call))<=5600 for call in client.calls)
    one=a.reconstruct(tmp_path/'runs',result['investigation_id'])
    two=a.reconstruct(tmp_path/'runs',result['investigation_id'])
    assert one==two and one['findings']==result['findings']
    manifest,events=load(tmp_path/'runs',result['investigation_id'])
    f.validate_journal(manifest,events)
    from forensic_assistant.investigation_ai.recorded import open_history
    assert open_history(tmp_path/'runs',result['investigation_id']).factual_state()
    altered=deepcopy(events)
    next(e for e in altered if e['kind']=='follow_up_proposed')['data']['scope']['source_ids']=['other']
    with pytest.raises(ValueError):f.validate_journal(manifest,altered)


@pytest.mark.parametrize('bad',['invented','source','window','family','pointer'])
def test_untrusted_proposals_cannot_expand_scope(tmp_path,bad):
    def invalid(messages):
        value=proposal(messages)
        if bad=='invented':value['arguments']['evidence_id']='EVTX:'+'e'*64+':Offset:999'
        elif bad=='source':value['arguments']['source_id']='src-other'
        elif bad=='window':value['arguments']['start']='2099-01-01T00:00:00Z'
        elif bad=='family':value['arguments']['family']='registry'
        else:value['arguments']['field']='/objects/0'
        return value
    result,client,calls,closed,_=run_mock(tmp_path,[final,invalid])
    assert result['termination']=='VALIDATION_FAILURE' and result['validated_batches']==1
    assert 'follow_up' not in calls and closed and len(client.calls)==2
    assert a.reconstruct(tmp_path/'runs',result['investigation_id'])['findings']==result['findings']


def test_duplicate_search_stops_without_paid_retry(tmp_path):
    result,client,calls,closed,_=run_mock(tmp_path,[final,proposal,proposal])
    assert result['termination']=='FOLLOW_UP_DUPLICATE'
    assert calls.count('follow_up')==1 and len(client.calls)==3 and closed


def test_empty_is_scoped_and_preserves_prior_findings(tmp_path):
    result,client,calls,closed,_=run_mock(tmp_path,empty=True)
    assert result['termination']=='FOLLOW_UP_EMPTY' and len(client.calls)==2
    assert result['validated_batches']==1 and closed
    assert result['follow_up']['searches'][0]['returned_ids']==[]
    assert 'not the entire' in ' '.join(result['limitations'])


@pytest.mark.parametrize('failure',['validation','cancel','provider'])
def test_failure_after_search_retains_findings_and_cleanup(tmp_path,failure):
    def bad(messages):
        if failure=='cancel':raise KeyboardInterrupt()
        if failure=='provider':raise ValueError('Synthetic backend failure')
        value=final(messages);value['answer']['observed'][0]['field']='/invented'
        return value
    result,client,calls,closed,_=run_mock(tmp_path,[final,proposal,bad])
    assert result['validated_batches']==1 and calls.count('follow_up')==1 and closed
    assert len(client.calls)==3
    assert a.reconstruct(tmp_path/'runs',result['investigation_id'])['findings']==result['findings']


def test_schema_adaptation_and_strict_canonical_contract():
    schema=f.schema()
    assert openai_schema.investigation(schema)
    wire=openai_schema.request_schema('openai',schema)
    assert 'anyOf' in wire['properties']['proposal']
    value=dict(action='tool',tool='follow_up',arguments=dict(evidence_id='EVTX:'+'1'*64+':Offset:1',field='/timestamp_utc',family='mft'),reason='Compare metadata')
    assert f.parse(openai_schema.response('openai',json.dumps({'proposal':value}),schema))==value
    value['arguments']['sql']='SELECT * FROM evidence_records'
    with pytest.raises(ValueError):f.parse(json.dumps(value))


def test_late_window_seed_sampling_is_deterministic(saved):
    from forensic_assistant import assessment_selection as sel, assessment_handoff as handoff
    _,_,assessment=saved
    assessment=deepcopy(assessment)
    assessment['records']={e:r for e,r in assessment['records'].items() if r['artifact']=='browser'}
    ids=sorted(assessment['records'])
    for eid in ids:assessment['records'][eid]['match']['timestamps'][0]['timestamp_utc']='2020-01-01T00:01:00Z'
    assessment['records'][ids[-1]]['match']['timestamps'][0]['timestamp_utc']='2020-01-01T23:30:00Z'
    args=(assessment,handoff.references(assessment),[],'Inspect recorded activity',dict(start='2020-01-01T00:00:00Z',end='2020-01-02T00:00:00Z'))
    one=sel.select(*args,temporal=True);assert one==sel.select(*args,temporal=True)
    pending=set(one[1]['selected_ids']);seen=[]
    for _ in range(6):
        eid=a.choose(pending,{}, {},one[1],seen);seen.append(eid);pending.remove(eid)
    assert ids[-1] in seen


def make_case(path):
    from forensic_assistant.database.db import connect,register_source,insert_events
    from forensic_assistant.database import sources
    from forensic_assistant.ingest.normalize import normalize
    with closing(connect(path)) as db:
        sid=sources.create(db,hostname='neutral-lab',volume_root='C:')
        sha='c'*64;register_source(db,sha,999,'synthetic.evtx')
        items=[]
        # Dense routine morning activity must not consume the late anchor scan.
        for n in range(1105):
            stamp='2026-09-30T00:01:00Z' if n<1100 else f'2026-09-30T23:30:0{n-1100}Z'
            xml=f'<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Synthetic"/><EventID>7</EventID><Channel>Application</Channel><TimeCreated SystemTime="{stamp}"/><Computer>neutral-lab</Computer></System><EventData><Data Name="Message">Neutral activity</Data></EventData></Event>'
            items.append(normalize(xml,sha,'synthetic.evtx',n))
        insert_events(db,items)
        sources.assign(db,sid,[sha],reason='Synthetic test')
        db.commit()
    eid=items[1100].id
    g=discovery_grant(grant(path,[{'id':eid,'source_type':'evtx'}]));g['source_ids']=[sid]
    return g


def test_real_read_only_worker_late_search_bounded_and_no_orphans(tmp_path):
    path=tmp_path/'case.db';g=make_case(path);before=path.read_bytes()
    worker=ForensicWorker(dict(case_path=str(path),semantic_enabled=False,_transaction_view=True,_stage_a=g))
    try:
        initial=worker.call('initial',question=g['objective'])
        seed=worker.call('show_evidence',{'evidence_id':g['evidence_ids'][0]},known_ids=g['evidence_ids'])
        r=seed['result']['records'][0]
        from forensic_assistant.investigation_ai.state import fields
        pointer=next(p for p,v in fields(r) if p=='/timestamp_utc' or p.endswith('/utc'))
        args=dict(evidence_id=r['id'],field=pointer,family='evtx')
        response=worker.call('follow_up',args,known_ids=g['evidence_ids'],seconds=5)
        result=response['result']
        assert len(result['records'])==3 and not result['plan']['complete']
        assert result['plan']['fetched_candidates']==5
        assert all('23:30:' in row.get('timestamp_utc',str(row.get('timestamps'))) for row in result['records'])
        assert response['evidence_state']==initial['evidence_state'] and response['database_changes']==0
        with pytest.raises(WorkerError,match='DUPLICATE'):worker.call('follow_up',args,known_ids=[])
    finally:worker.close()
    assert worker.process.poll() is not None and path.read_bytes()==before


def test_old_grant_rejects_follow_up_and_expiry(tmp_path):
    config,*_=setup(tmp_path)
    args=dict(evidence_id=config['_stage_a']['evidence_ids'][0],field='/timestamps/0/utc',family='browser')
    with pytest.raises(ValueError):policy.operation(config['_stage_a'],config['case_path'],'follow_up',args)
    g=discovery_grant(config['_stage_a']);g['issued']-=301;g['expires']-=301
    with pytest.raises(ValueError,match='EXPIRED'):policy.operation(g,config['case_path'],'follow_up',args)


def test_display_omits_url_query_secrets(tmp_path):
    from forensic_assistant.investigation_ai.presentation import render
    result,*_=run_mock(tmp_path)
    result['findings']['observed'][0]['reported_value']='https://example.invalid/invite?token=secret-value'
    text=render(result)
    assert 'secret-value' not in text and '[query omitted]' in text
    assert 'Follow-up searches: 1' in text and 'Status: Partial' in text


def test_opt_in_authorization_and_cancellation(saved, monkeypatch, capsys):
    from forensic_assistant import assessment_handoff_cli
    from forensic_assistant.ai import backend
    from test_assessment_seed_selection import client
    case,store,assessment=saved
    before=store.path.read_bytes()
    monkeypatch.setattr(backend,'backend',lambda:client(monkeypatch))
    monkeypatch.setattr('forensic_assistant.investigation_ai.supervision.run',lambda *a,**k:pytest.fail('Declined grant cannot start'))
    result=assessment_handoff_cli.execute(case,assessment['id'],'Compare recorded activity',read=lambda _:'n',autonomous=True,follow_up=True)
    assert 'cancelled' in result['message']
    text=capsys.readouterr().out
    assert 'At most 2 searches' in text and '6 total tool calls and 6 model requests' in text
    assert 'show_evidence only, no search' not in text and 'ONLY the selected IDs' not in text
    assert store.path.read_bytes()==before


def test_parser_accepts_single_opt_in():
    from forensic_assistant.cli import build_parser
    args=build_parser().parse_args(['investigation','run','latest','--follow-up','--question','Compare activity'])
    assert args.follow_up is True


def test_workflow_uses_one_exact_grant_not_preliminary_approvals(monkeypatch):
    from forensic_assistant import investigation_workflow as flow
    monkeypatch.setattr('forensic_assistant.assessment_handoff.prepare',lambda *a:dict(assessment_id='saved',limitations=[]))
    monkeypatch.setattr('forensic_assistant.ai.settings.load',lambda:dict(provider='openai',model='synthetic',cloud_acknowledged=True))
    monkeypatch.setattr('forensic_assistant.ai.readiness.status',lambda _:dict(investigation_compatibility='ready'))
    calls=[]
    monkeypatch.setattr(flow.assessment_handoff_cli,'execute',lambda *a,**kw:calls.append(kw) or {})
    flow.run('synthetic','saved','Neutral question',read=lambda _:pytest.fail('No preliminary approval'),display=lambda _:None,follow_up=True)
    assert len(calls)==1 and calls[0]['follow_up'] and calls[0]['autonomous']
    assert not calls[0]['decompose'] and not calls[0]['synthesize']


@pytest.mark.parametrize('family',['browser','prefetch','mft','registry','evtx'])
def test_real_service_artifact_families_and_source_isolation(tmp_path,family):
    from forensic_assistant.database.db import connect,register_source
    from forensic_assistant.database import sources
    from forensic_assistant.database.artifacts import register,add_object,add_timestamp
    from forensic_assistant.investigation_ai.tools import execute
    from test_browser_parser import history
    from test_browser_integration import ingest
    path=tmp_path/'case.db';g=make_case(path)
    with closing(connect(path)) as db:
        sid=g['source_ids'][0]
        if family=='browser':
            source=tmp_path/'History';history(source).close();ingest(db,source,source=sid)
            db.execute("UPDATE evidence_timestamps SET timestamp_utc='2026-09-30T23:30:01.000000000Z' WHERE evidence_id LIKE 'BROWSER:%'")
        elif family!='evtx':
            for n in range(2):
                sha=f'{n+30:064x}';register_source(db,sha,100,'synthetic-artifact')
                suffix='File' if family=='prefetch' else ('KeyOffset:' if family=='registry' else 'Offset:')+str(n)
                eid=family.upper()+':'+sha+':'+suffix
                register(db,dict(evidence_id=eid,source_type=family,artifact_type={'mft':'mft_record','registry':'registry_key','prefetch':'prefetch'}[family],
                    file_sha256=sha,source_file='synthetic-artifact',locator_json='{}',original_json='{}'))
                add_timestamp(db,eid,dict(slot='recorded',timestamp_utc='2026-09-30T23:30:01.000000000Z',source='synthetic',meaning='metadata',normalization_status='normalized'))
                add_object(db,eid,'path','file_path','C:/Synthetic/neutral-tool.dat')
                if family=='mft':db.execute('INSERT INTO mft_records VALUES (?,?,1,1,0,100,NULL,NULL,1024,?,?)',(eid,n,'{}',b''))
                if family=='prefetch':db.execute('INSERT INTO prefetch_records VALUES (?,?,1,1,30,?,?)',(eid,'neutral.exe',b'','{}'))
                if family=='registry':
                    db.execute('INSERT INTO registry_hives VALUES (?,?,?,0,?)',(sha,'SOFTWARE','synthetic','[]'))
                    db.execute('INSERT INTO registry_keys VALUES (?,?,NULL,?)',(eid,'Software\\Neutral'+str(n),n))
                sources.assign(db,sid if n==0 else sources.create(db,hostname='other-source'),[sha],reason='Synthetic membership')
        db.commit();before=list(db.iterdump())
        g['families']=sorted({'evtx',family})
        seed=execute(db,'show_evidence',{'evidence_id':g['evidence_ids'][0]},{'known_ids':g['evidence_ids']})['records'][0]
        from forensic_assistant.investigation_ai.state import fields
        field=next(p for p,v in fields(seed) if p=='/timestamp_utc' or p.endswith('/utc'))
        args=dict(evidence_id=seed['id'],field=field,family=family)
        result=f.search(db,g,args,{seed['id']:seed})
        assert result['records'] and all(r['source_type']==family for r in result['records'])
        assert all(set(r['source_context']['source_ids'])=={sid} for r in result['records'])
        assert list(db.iterdump())==before


def test_exact_window_and_no_free_timestamp(tmp_path):
    config,*_=setup(tmp_path);g=discovery_grant(config['_stage_a'])
    args=dict(evidence_id=g['evidence_ids'][0],field='/timestamps/0/utc',family='browser')
    with pytest.raises(ValueError,match='OUTSIDE_WINDOW'):f.window(g,args,'2026-10-01T00:00:00Z')
    start=f.window(g,args,g['start'])
    from forensic_assistant.retrieval.queries import required_time
    assert start['start']==required_time(g['start'])
    precise=f.window(g,args,'2026-09-30T12:00:00.123456789Z')
    assert precise['start']=='2026-09-30T11:55:00.123456789Z'
    assert precise['end']=='2026-09-30T12:05:00.123456789Z'


def test_search_limit_and_disclosed_field_binding(tmp_path):
    result,client,_,_,_=run_mock(tmp_path)
    manifest,events=load(tmp_path/'runs',result['investigation_id'])
    grant=manifest['authorization']
    exposure=next(e['data']['content'] for e in events if e['kind']=='exposure')
    args=proposal(client.calls[0])['arguments']
    args['field']='/timestamps/31/utc'
    with pytest.raises(ValueError,match='NOT_DISCLOSED'):f.proposed(grant,args,exposure)
    grant['follow_up']['searches']=3
    with pytest.raises(ValueError,match='AUTHORIZATION_INVALID'):f.shape(grant)


def test_worker_enforces_two_search_budget(tmp_path):
    path=tmp_path/'case.db';g=make_case(path);g['families']=list(f.FAMILIES)
    with ForensicWorker(dict(case_path=str(path),semantic_enabled=False,_transaction_view=True,_stage_a=g)) as worker:
        worker.call('initial',question=g['objective'])
        seed=worker.call('show_evidence',{'evidence_id':g['evidence_ids'][0]},known_ids=g['evidence_ids'])['result']['records'][0]
        from forensic_assistant.investigation_ai.state import fields
        field=next(p for p,v in fields(seed) if p=='/timestamp_utc' or p.endswith('/utc'))
        args=dict(evidence_id=seed['id'],field=field,family='evtx')
        worker.call('follow_up',args,known_ids=[])
        assert worker.call('follow_up',{**args,'family':'mft'},known_ids=[])['result']['records']==[]
        with pytest.raises(WorkerError,match='BUDGET'):worker.call('follow_up',{**args,'family':'registry'},known_ids=[])


def test_audit_and_failed_durable_authorization_prevent_dispatch(tmp_path,monkeypatch):
    from forensic_assistant import activity
    from forensic_assistant.investigation_ai.transcript import Transcript
    events=[]
    monkeypatch.setattr(activity,'event',lambda name,*args,**kw:events.append((name,kw)))
    append=Transcript.append
    def fail(self,kind,data,**kwargs):
        if kind=='authorized_operation' and data['tool']=='follow_up':raise OSError('synthetic journal failure')
        return append(self,kind,data,**kwargs)
    monkeypatch.setattr(Transcript,'append',fail)
    result,client,calls,closed,_=run_mock(tmp_path)
    assert result['termination']=='AUDIT_OR_PERSISTENCE_FAILURE' and 'follow_up' not in calls
    assert result['failure_diagnostic']['operation']=='follow_up'
    assert result['validated_batches']==1 and closed and len(client.calls)==2
    assert all(kw['required'] is True for name,kw in events if name.startswith('TOOL_'))
    assert not any(name=='TOOL_APPROVED' and kw['tool']=='follow_up' for name,kw in events)
    assert any(name=='TOOL_REJECTED' and kw['tool']=='follow_up' for name,kw in events)


def test_search_audit_correlates_with_recorded_dispatch(tmp_path,monkeypatch):
    from forensic_assistant import activity
    events=[]
    monkeypatch.setattr(activity,'event',lambda name,*args,**kw:events.append((name,kw)))
    result,_,calls,_,_=run_mock(tmp_path)
    approvals=[kw for name,kw in events if name=='TOOL_APPROVED' and kw['tool']=='follow_up']
    completed=[kw for name,kw in events if name=='TOOL_COMPLETED' and kw['tool']=='follow_up']
    assert len(approvals)==len(completed)==calls.count('follow_up')==1
    assert approvals[0]['investigation_id']==result['investigation_id']
    assert approvals[0]['tool_call_number']==completed[0]['tool_call_number']
    assert approvals[0]['approval']=='configured_policy' and approvals[0]['required']


def test_search_does_not_implicitly_fetch_supporting_records(tmp_path,monkeypatch):
    from forensic_assistant.database.db import connect
    from forensic_assistant.investigation_ai import tools
    from forensic_assistant.retrieval import evidence
    from forensic_assistant.investigation_ai.state import fields
    path=tmp_path/'case.db';g=make_case(path)
    with closing(connect(path)) as db:
        seed=tools.execute(db,'show_evidence',{'evidence_id':g['evidence_ids'][0]},{'known_ids':g['evidence_ids']})['records'][0]
        field=next(p for p,v in fields(seed) if p=='/timestamp_utc' or p.endswith('/utc'))
        original=evidence.get_evidence;seen=[]
        outside='EVTX:'+'f'*64+':Offset:999'
        def linked(db,eid):
            assert eid!=outside
            seen.append(eid);record=original(db,eid)
            record['supporting_evidence_ids']=[outside]
            return record
        monkeypatch.setattr(evidence,'get_evidence',linked)
        monkeypatch.setattr(tools,'get_evidence',lambda *a:pytest.fail('No implicit envelope expansion'))
        result=f.search(db,g,dict(evidence_id=seed['id'],field=field,family='evtx'),{seed['id']:seed})
        assert len(seen)==3 and outside not in {r['id'] for r in result['records']}

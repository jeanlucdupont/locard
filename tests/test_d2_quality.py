import copy
import hashlib
import json
import time
from pathlib import Path
from unittest.mock import patch
import pytest
from forensic_assistant.investigation_ai import d2_quality as q,d2_wire as w,d2,d2_execution as ex,d2_result as ipc,d2_issues,d2_presentation as ui
from forensic_assistant.ai import settings
from test_d2_execution import config,generic_packet
from test_d2_preview import history
from d2_generic_fixtures import scenarios,context,row


def answer(outcome='new_inference',aliases=None):
    abstain=outcome in q.OUTCOMES[2:]
    return dict(v=q.VERSION,o=outcome,a=[] if abstain else [dict(s='The records may describe related activity.',e=aliases or ['O1'],c=[],i=[],a='',u='',d='Compare independently recorded identifiers to distinguish related from unrelated activity.',n='Review independently authorized corroborating fields; they may not be available.')],r='The packet does not justify another inference.' if abstain else '')


def prepared():
    h=history();p=h.preview(exploratory=True)['packets'][0]
    return ex.Prepared(h,p,config(),dict(exploratory=True),profile=q.VERSION)


@pytest.mark.parametrize('name',list(scenarios))
def test_budget_and_lossless(name):
    p=generic_packet(name);old=w.messages(p);new=q.messages(p)
    assert q.expand_view(json.loads(new[1]['content']),p)==p['content']
    old_size=len(w.body(old,config()['model']));size=len(w.body(new,config()['model'],w.schema_for(new)))
    assert size>old_size  # Typed schema and clarified guide; exact sizes tested separately.
    if old_size<=5600:assert size<=5600
    if name=='large_value':assert size==5568
    if old_size>5600:assert size>5600


@pytest.mark.parametrize('outcome',q.OUTCOMES)
def test_outcomes(outcome):
    p=prepared();v=answer(outcome)
    if outcome=='competing_explanations':
        a=copy.deepcopy(v['a'][0]);a['s']='Alternatively the observations may be independent.';v['a'].append(a)
    result=d2.validate_response(p.packet,q.expand_response(json.dumps(v),p.packet),p._response_context)
    assert result['reasoning_outcome']==outcome and result['original_s3_assessment']==p.history._original
    assert len(result['proposals'])==len(v['a'])
    assert all(x['classification']=='mechanically_accepted_unverified' for x in result['proposals'])


@pytest.mark.parametrize('bad',['version','outcome','forced','empty','alias','foreign','execution','causal','absence','tool','contradiction','long','unicode','duplicate','qualification','value','source','packet','raw'])
def test_fail_closed(bad):
    p=prepared();v=answer()
    if bad=='version':v['v']='d2c1'
    elif bad=='outcome':v['o']='proved'
    elif bad=='forced':v['o']='no_material_inference';v['r']='No inference.'
    elif bad=='empty':v['a']=[]
    elif bad=='alias':v['a'][0]['e']=['O999']
    elif bad=='foreign':v['a'][0]['e']=['other:O1']
    elif bad in ('execution','causal','absence','tool'):v[bad]=True
    elif bad=='contradiction':v['r']='Abstention alongside inference.'
    elif bad=='long':v['a'][0]['s']='x'*401
    elif bad=='unicode':v['a'][0]['s']='界'*134
    elif bad=='duplicate':v['a'][0]['e']=['O1','O1']
    elif bad=='qualification':v['qualifications']=[]
    elif bad=='value':v['a'][0]['value']='forged original'
    elif bad=='source':v['source']='forged'
    elif bad=='packet':pass
    else:
        with pytest.raises(ValueError):q.expand_response('{invalid',p.packet)
        return
    with pytest.raises(ValueError):
        raw=q.expand_response(json.dumps(v),p.packet)
        if bad=='packet':
            canonical=json.loads(raw);canonical['packet_digest']='0'*64;raw=json.dumps(canonical)
        d2.validate_response(p.packet,raw,p._response_context)


def test_optional_empty_not_blank():
    v=answer();q.validate(v)
    v['a'][0]['d']=' '
    with pytest.raises(ValueError):q.validate(v)


def test_no_provider_issue_unicode_and_short(monkeypatch):
    monkeypatch.setattr('forensic_assistant.ai.backend.ModelBackend.complete_d2',lambda *a:pytest.fail('provider'))
    for value,question,expected in [('工具.exe','Did 工具.exe run?','exact_technical_referent'),('x','Did "x" run?','exact_technical_referent'),('x','What ran?','unresolved')]:
        ctx,_=context([row('prefetch',200,executable=value)]);ctx.manifest['question']=question;h=history(ctx);preview=h.preview(exploratory=True)
        review=d2_issues.inspect(h,preview,config()['model'])
        assert review==d2_issues.inspect(h,preview,config()['model'])
        assert review['issues'][0]['relevance']==expected
        assert all(r['relevance']!='verified_typed_objective' for r in review['issues'])
        assert len(review['issues'])==len(preview['issues'])


def test_ui_abstention_details():
    p=prepared();v=d2.validate_response(p.packet,q.expand_response(json.dumps(answer('no_material_inference')),p.packet),p._response_context)
    result=dict(status='accepted',validated=v,attempts=1,lookups=0,cleanup='confirmed')
    view=ui.view(result,p);text=ui.render(view)
    assert 'no_material_inference' in text and 'Suggested next examination' in text
    assert view['details']['packet']==p.packet['content']
    assert ui.unique([dict(id='a',slot='si'),dict(id='a',slot='fn')])!=[dict(id='a',slot='si')]
    assert len(ui.unique([dict(id='a',name='x'),dict(id='b',name='x')]))==2


def _child(connection,gate,request):
    original=ex._child
    def complete(client,messages,body_sha256):
        assert w.schema_for(messages)!=q.SCHEMA
        assert len(w.body(messages,client.model_name,w.schema_for(messages)))<=5600
        return dict(text=json.dumps(dict(answer('no_material_inference'),v=w.schema_for(messages)['properties']['v']['enum'][0])),usage={})
    with patch.object(settings,'load',config),patch('forensic_assistant.ai.backend.ModelBackend.complete_d2',complete),patch('socket.socket.connect',side_effect=AssertionError('network')),patch('sqlite3.connect',side_effect=AssertionError('case')):
        original(connection,gate,request)


@pytest.mark.parametrize('response_version,expected_bytes',[(q.VERSION,5455),(q.CURRENT,5453)])
def test_quality_windows_spawn_historical(monkeypatch,response_version,expected_bytes):
    root=Path(r'C:\tmp\locard-diagnostics\6.118-live');rid='6ad0c85499564406aa4d949f3b0e72e5'
    if not (root/rid/'manifest.json').exists():pytest.skip('readable copied fixture unavailable')
    files=[root/rid/n for n in ('manifest.json','events.jsonl')];hashes=lambda:[hashlib.sha256(f.read_bytes()).hexdigest() for f in files];before=hashes()
    p=ex.prepare(root,rid,'d81869143ab5f3a355285bd79802d93912491834bc4f602c0a5fda6fd28739e7',config(),exploratory=True,response_version=response_version)
    assert p.profile==q.VERSION and len(p.body)==expected_bytes
    permit=ex.authorize(p,lambda _:True)
    monkeypatch.setattr(ex,'_child',_child)
    result=ex.execute(permit)
    assert result['status']=='accepted' and result['attempts']==1 and result['lookups']==0
    assert not result['validated']['proposals'] and result['validated']['original_s3_assessment']['status']=='NOT_ASSESSABLE'
    assert result['cleanup']=='confirmed' and result['ipc_result_bytes']+8<=ipc.LIMIT
    print('QUALITY_IPC_BYTES',result['ipc_result_bytes'])
    with pytest.raises(ValueError):ex.execute(permit)
    assert before==hashes()

QUALITY_CASES = {
    'execution':([row('evtx',301,process_name='worker.exe'),row('prefetch',302,executable='WORKER.EXE')],'Process activity is recorded; successful malicious purpose is unestablished.'),
    'persistence':([row('registry',303,objects=[r'HKCU\Software\Microsoft\Windows\CurrentVersion\Run',r'C:\Apps\sync.exe'])],'Configuration is not execution.'),
    'lateral':([row('evtx',304,ip='192.0.2.9',process_name='remote.exe'),row('evtx',305,hostname='other-node',event_id=7045)],'No session or identity bridge establishes movement.'),
    'exfiltration':([row('mft',306,current_path=r'D:\Work\report.csv'),row('browser',307,url='https://upload.invalid/')],'A file and portal do not establish transmission.'),
    'administration':([row('evtx',308,command_line='maintenance.exe --scheduled'),row('registry',309,objects=['MaintenanceWindow'])],'Scheduled-looking activity does not establish benign intent.'),
    'contradictory':([row('registry',310,hostname='host-a',objects=['State','enabled']),row('registry',311,hostname='host-b',objects=['State','disabled'])],'Different source assertions are not automatically the same object.'),
    'incomplete':([row('mft',312,current_path=r'D:\Unknown\tool.exe',coverage_notes=['Process logs unavailable.'])],'Missing coverage cannot prove non-execution.'),
    'unrelated':([row('browser',313,url='https://weather.invalid/'),row('registry',314,objects=['IndependentSetting'])],'Co-presence does not establish a relationship.'),
    'no_conclusion':([row('registry',315,objects=['UnknownSetting'])],'No material inference is justified.'),
}


@pytest.mark.parametrize('case',QUALITY_CASES)
def test_quality_review_fixtures(case):
    rows,caveat=QUALITY_CASES[case];ctx,_=context(rows);h=history(ctx);preview=h.preview(exploratory=True)
    assert preview['packets']
    for packet in preview['packets']:
        assert len(w.body(q.messages(packet),config()['model'],w.schema_for(q.messages(packet))))<=5600
        v=answer('insufficient_packet_support');v['r']=caveat
        result=h.validate(packet,q.expand_response(json.dumps(v),packet),exploratory=True)
        assert not result['proposals'] and result['original_s3_assessment']==h._original
    # This asserts safety/mechanical validity, not a model-quality score.


def test_exact_dedup_preserves_semantics():
    p=prepared();packet=p.packet['content'];leaf=copy.deepcopy(packet['supports'][0])
    packet['supports'].append(leaf)
    view=ui.view(dict(status='rejected'),p)
    total=len(view['established'])+view['established_detail_count']
    baseline=len(packet['interpretations'])+len(packet['supports'])-1
    assert total==baseline
    assert view['details']['packet']['supports']==packet['supports']
    assert ui.unique(['qualification','qualification'])==['qualification']

@pytest.mark.parametrize('failure',['timeout','refusal','malformed'])
def test_quality_provider_failure_no_retry(monkeypatch,failure):
    p=prepared();calls=[]
    class Pipe:
        def __init__(self):self.data=[]
        def send_bytes(self,b):self.data.append(b)
        def close(self):pass
    def complete(*args):
        calls.append(1)
        from forensic_assistant.ai.provider_diagnostics import ProviderFailure
        if failure=='timeout':raise ProviderFailure('timeout','timeout')
        if failure=='refusal':raise ProviderFailure('response_envelope_failed','response_envelope',metadata={'response_envelope':{'envelope_received':True,'rule':'invalid_content_type'}})
        return dict(text='not JSON',usage={})
    monkeypatch.setattr(settings,'load',config);monkeypatch.setattr(ex,'prepare',lambda *a,**k:p)
    monkeypatch.setattr('forensic_assistant.ai.backend.ModelBackend.complete_d2',complete)
    import threading
    gate=threading.Event();gate.set();pipe=Pipe()
    ex._child(pipe,gate,dict(deadline=time.monotonic()+10,binding=ipc.binding(p),config=config(),root='unused',run_id='b'*32,issue='c'*64,exploratory=True,profile=q.VERSION,seal=p.identity()))
    value=ipc.parse(pipe.data[-1],ipc.binding(p))
    assert value['status']=='rejected' and calls==[1]
    assert value['category']=={'timeout':'provider_timeout','refusal':'provider_response_invalid','malformed':'response_schema_validation'}[failure]


def test_canonical_cross_run_and_exact_version():
    p=prepared();raw=json.loads(q.expand_response(json.dumps(answer()),p.packet));raw['request_id']='0'*64
    with pytest.raises(ValueError):d2.validate_response(p.packet,json.dumps(raw),p._response_context)
    assert w.schema_for(p.messages)==p.schema
    assert w.schema_for(w.messages(p.packet))==w.SCHEMA
    with pytest.raises(ValueError):w.expand_response(json.dumps(answer()),p.packet)


def test_preview_context_cannot_mutate_after_authorization():
    p=prepared();permit=ex.authorize(p,lambda _:True);p.packet['content']['supports'][0]['field']['value']='forged'
    with pytest.raises(ValueError):ex.execute(permit)


def test_competing_requires_a_competing_account():
    with pytest.raises(ValueError):q.validate(answer('competing_explanations'))
    v=answer('competing_explanations');v['a'][0]['a']='The records might be independent.'
    q.validate(v)


def test_backend_uses_exact_quality_schema_without_probe(monkeypatch):
    from forensic_assistant.ai.backend import ModelBackend
    p=prepared();calls=[]
    def dispatch(self,messages,schema,**kwargs):
        calls.append((messages,schema,kwargs));return dict(text=json.dumps(answer('no_material_inference')),usage={})
    monkeypatch.setattr(ModelBackend,'_cloud_request',dispatch)
    monkeypatch.setattr(ModelBackend,'prepare',lambda *a,**k:pytest.fail('hidden readiness request'))
    client=ModelBackend(config=config(),timeout=10)
    client.complete_d2(p.messages,hashlib.sha256(p.body).hexdigest())
    assert len(calls)==1 and calls[0][1]==p.schema
    assert calls[0][2]['d2_body_sha256']==hashlib.sha256(p.body).hexdigest()
    assert p.preview()['contract']=='d2-quality-authorized-preview-v1'

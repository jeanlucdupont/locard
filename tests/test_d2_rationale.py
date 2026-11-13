"""Versioned rationale semantics preserve evidence authority and exact wire admission."""
import copy
import hashlib
import json
from unittest.mock import patch
import pytest
from forensic_assistant.investigation_ai import d2_quality as q, d2_execution as ex, d2_wire as w
from forensic_assistant.investigation_ai import d2_cross as x, d2_diagnostics as diag, d2_presentation as ui
from test_d2_cross import prepared as cross_prepared
from test_d2_execution import generic_packet, scenarios, config
from test_d2_preview import history
from test_d2_quality import answer
from test_d2_transport import sdk


def prepared(version=q.CURRENT):
    old=cross_prepared()
    h=x.History(old.history,old.history.question,old.config['model'],version)
    packet=h.preview()['packets'][0]
    return ex.Prepared(h,packet,old.config,old.options,profile=x.VERSION)


def response(outcome='new_inference',reason='',version=q.CURRENT):
    v=answer(outcome);v['v']=version;v['r']=reason
    if outcome=='competing_explanations':v['a'][0]['a']='An independent copy could explain the pathname.'
    return v


@pytest.mark.parametrize('version,outcome,reason,ok',[
    (q.VERSION,'new_inference','',True),(q.VERSION,'new_inference','Qualification.',False),
    (q.CURRENT,'new_inference','',True),(q.CURRENT,'new_inference','Qualification.',True),
    (q.CURRENT,'no_material_inference','Nothing further supported.',True),(q.CURRENT,'no_material_inference','',False),
    (q.CURRENT,'insufficient_packet_support','Missing identifying evidence.',True),
    (q.CURRENT,'competing_explanations','',True),(q.CURRENT,'competing_explanations','The alternatives remain open.',True)])
def test_outcomes(version,outcome,reason,ok):
    p=prepared(version);v=response(outcome,reason,version)
    if not ok:
        with pytest.raises(ValueError) as caught:ex.validate_model_response(p,w.J(v),parent=True)
        d=diag.failure(caught.value,completion='stop',reported={'completion_tokens':950})
        assert d['code']=='outcome_reason'
        assert d['outcome']==outcome and d['account_count_consistent'] is True
        assert d['outcome_rule']==('inference_reason_forbidden' if version==q.VERSION else 'abstention_reason_required')
        assert d['usage_availability']=='reported' and d['completion']=='stop'
        assert reason not in json.dumps(d) if reason else True
    else:
        out,_=ex.validate_model_response(p,w.J(v),parent=True)
        if version==q.CURRENT:assert out['outcome_rationale']==reason and out['response_version']==version
        assert out['original_s3_assessment']==p.history._original


@pytest.mark.parametrize('mutation',['missing_alternative','empty_support','unknown','wrong_namespace','missing_field','long','unicode','blank','nul','malformed','account_count'])
def test_strict_rejections(mutation):
    p=prepared();v=response('competing_explanations')
    if mutation=='missing_alternative':v['a'][0]['a']=''
    if mutation=='empty_support':v['a'][0]['e']=[]
    if mutation=='unknown':v['a'][0]['e']=['O99']
    if mutation=='wrong_namespace':v['a'][0]['e']=['E1']
    if mutation=='missing_field':del v['a'][0]['n']
    if mutation=='long':v['r']='x'*241
    if mutation=='unicode':v['r']='é'*121
    if mutation=='blank':v['r']='   '
    if mutation=='nul':v['r']='a\0b'
    if mutation=='account_count':v['a']=[]
    raw='{' if mutation=='malformed' else w.J(v)
    with pytest.raises(ValueError):ex.validate_model_response(p,raw,parent=True)


def test_rationale_not_support_and_not_semantic_agreement():
    p=prepared();v=response(reason='The proposed account is unsupported and may be wrong.')
    v['a'][0]['e']=['O1','O1']
    result,receipt=ex.validate_model_response(p,w.J(v),parent=True)
    assert receipt['duplicates_removed']==1
    assert result['proposals'][0]['classification']=='mechanically_accepted_unverified'
    rendered=ui.view(dict(status='accepted',validated=result,attempts=1,lookups=0,cleanup='confirmed'),p)
    assert rendered['outcome_rationale']==v['r']
    assert rendered['rationale_classification']=='unverified_model_commentary'
    text=ui.render(rendered)
    assert 'Unverified outcome rationale' in text and v['r'] in text
    v['a'][0]['e']=[]
    with pytest.raises(ValueError):ex.validate_model_response(p,w.J(v),parent=True)


def test_empty_optional_text():
    p=prepared();v=response()
    for k in ('a','u','d','n'):v['a'][0][k]=''
    ex.validate_model_response(p,w.J(v),parent=True)


def test_interpretation_premises():
    h=x.History(history(),'What recorded blocking action and download context are available?',config()['model'],q.CURRENT)
    packet=h.preview()['packets'][0];p=ex.Prepared(h,packet,config(),dict(exploratory=True),profile=x.VERSION)
    i=packet['content']['interpretations'][0]
    refs=[s['alias'] for s in packet['content']['supports'] if s['record_ref']==i['record_ref'] and s['field']['pointer'] in i['premise_pointers']]
    v=response(reason='A tentative comparison.');v['a'][0].update(e=refs,i=[i['alias']])
    ex.validate_model_response(p,w.J(v),parent=True)
    v['a'][0]['e']=refs[:-1]
    with pytest.raises(ValueError,match='INCOMPLETE_INTERPRETATION'):ex.validate_model_response(p,w.J(v),parent=True)


@pytest.mark.parametrize('name',list(scenarios))
def test_single_packet_no_eligibility_regression(name):
    from forensic_assistant.investigation_ai import d2_schema
    p=generic_packet(name)
    old=w.body(q.messages(p),config()['model'],d2_schema.from_packet(p))
    new=w.body(q.messages(p,q.CURRENT),config()['model'],d2_schema.from_packet(p,q.CURRENT))
    assert len(new)==len(old)-2
    assert not (len(old)<=5600<len(new))
    assert q.expand_view(json.loads(q.messages(p,q.CURRENT)[1]['content']),p,q.CURRENT)==p['content']


@pytest.mark.parametrize('mutation',['version','schema','request_policy'])
def test_authorized_identity_cannot_change(mutation):
    p=prepared();permit=ex.authorize(p,lambda _:True)
    if mutation=='version':p.response_version=q.VERSION
    elif mutation=='schema':p.schema['properties']['v']['enum']=[q.VERSION]
    else:p.request_policy='different'
    with pytest.raises(ValueError,match='GRANT'):ex.execute(permit)


def test_old_new_not_substitutable():
    old=prepared(q.VERSION);new=prepared()
    assert old.identity()!=new.identity() and old.body!=new.body
    for p,v in [(old,response()),(new,response(version=q.VERSION))]:
        with pytest.raises(ValueError):ex.validate_model_response(p,w.J(v),parent=True)


@pytest.mark.parametrize('outcome',['valid','reason_failure','refusal','truncated','finish','malformed'])
def test_actual_sdk_new_policy(sdk,monkeypatch,outcome):
    import httpx
    from forensic_assistant.ai import cloud_worker,d2_transport
    p=prepared();v=response(reason='The correspondence remains unverified.')
    if outcome=='reason_failure':v=response('insufficient_packet_support','')
    seen=[]
    def handle(req):
        assert req.content==p.body;seen.append(1)
        msg=dict(role='assistant',content='{' if outcome=='malformed' else w.J(v))
        if outcome=='refusal':msg.update(content=None,refusal='Refused')
        finish='length' if outcome=='truncated' else 'content_filter' if outcome=='finish' else 'stop'
        return httpx.Response(200,json=dict(id='mock',object='chat.completion',created=0,model=p.config['model'],choices=[dict(index=0,message=msg,finish_reason=finish)],usage=dict(prompt_tokens=80,completion_tokens=950,total_tokens=1030)))
    factory=d2_transport.guarded_client
    monkeypatch.setattr(d2_transport,'guarded_client',lambda r:factory(r,httpx.MockTransport(handle)))
    request=dict(provider='openai',model=p.config['model'],messages=p.messages,schema=p.schema,timeout=10,handshake=False,raw_diagnostics=False,final_only=False,d2_body_sha256=hashlib.sha256(p.body).hexdigest())
    def run():
        result=cloud_worker.generate(request,sdk)
        assert result['usage']['completion_tokens']==950
        return ex.validate_model_response(p,result['text'],parent=True)
    if outcome=='valid':assert run()[0]['outcome_rationale']==v['r']
    else:
        with pytest.raises(Exception) as caught:run()
        d=diag.failure(caught.value)
        assert d['code']=={'reason_failure':'outcome_reason','refusal':'provider_refusal','truncated':'output_truncated','finish':'invalid_response_envelope','malformed':'malformed_json'}[outcome]
    assert seen==[1]


def test_historical_exact_body_and_integrity(sdk):
    from pathlib import Path
    import httpx
    from forensic_assistant.ai.d2_transport import guarded_client
    root=Path(r'C:\tmp\locard-diagnostics\6.118-live');rid='6ad0c85499564406aa4d949f3b0e72e5'
    if not (root/rid/'manifest.json').exists():pytest.skip('copied history unavailable')
    files=[root/rid/n for n in ('manifest.json','events.jsonl')]
    before=[hashlib.sha256(f.read_bytes()).hexdigest() for f in files]
    question='What evidence connects the recorded download and subsequent filesystem observations? Which links remain hypotheses and what additional examination would discriminate?'
    old=x.prepare(root,rid,question,config(),response_version=q.VERSION)
    new=x.prepare(root,rid,question,config())
    assert len(old.body)==16268 and len(new.body)==16266
    assert hashlib.sha256(old.body).hexdigest()=='19b7020921b08d47885812c16a92778eb8bb3dd2c51859b93e6ae8035f48c4b5'
    assert old.packet['content']==new.packet['content']
    v=response('competing_explanations','The pathname correspondence merits examination, not an identity conclusion.')
    v['a'][0].update(s='The Browser target and MFT pathname may correspond, but the differing drive representation prevents an identity conclusion.',e=['O1','O12','O9','O11'],a='An independent file or copy could have the same relative pathname.',u='Host and volume identity and synchronized clocks are unestablished; DownloadStart and FN Created have different meanings.',d='Independent volume mappings and matching recovered content would favor correspondence; differing content would favor distinct files.',n='Seek separately authorized archive hashes and download provenance; availability is unknown.')
    result,_=ex.validate_model_response(new,w.J(v),parent=True)
    assert result['outcome_rationale']==v['r'] and result['original_s3_assessment']==new.history._original
    seen=[]
    def handle(req):
        assert req.content==new.body;seen.append(1)
        return httpx.Response(200,json=dict(id='mock',object='chat.completion',created=0,model=config()['model'],choices=[dict(index=0,message=dict(role='assistant',content=w.J(v)),finish_reason='stop')]))
    request=dict(provider='openai',model=new.config['model'],messages=new.messages,schema=new.schema,timeout=10,d2_body_sha256=hashlib.sha256(new.body).hexdigest(),_key='synthetic')
    with guarded_client(request,httpx.MockTransport(handle)) as client:client.chat.completions.create(**json.loads(new.body))
    assert seen==[1] and before==[hashlib.sha256(f.read_bytes()).hexdigest() for f in files]
    print('HISTORICAL_NEW_BODY',hashlib.sha256(new.body).hexdigest(),len(new.body))


@pytest.mark.parametrize('bad',[{'outcome':'private prose'},{'account_count':3},{'account_count_consistent':1},{'root_reason_state':'secret'},{'outcome_rule':'invented'}])
def test_diagnostic_closed_metadata(bad):
    with pytest.raises(ValueError):diag.validate(dict(diag.base(),**bad))


@pytest.mark.parametrize('families',[('browser_only','filesystem_no_evtx'),('registry_persistence','process_service'),('process_service','prefetch_only')])
def test_unrelated_new_cross_packets(families):
    from d2_generic_fixtures import context
    rows=[copy.deepcopy(scenarios[name][0]) for name in families]
    oldh=x.History(history(context(rows)[0]),'Compare the recorded observations.',config()['model'])
    newh=x.History(history(context(rows)[0]),'Compare the recorded observations.',config()['model'],q.CURRENT)
    old=oldh.preview()['packets'][0];new=newh.preview()['packets'][0]
    p=ex.Prepared(newh,new,config(),dict(exploratory=True),profile=x.VERSION)
    assert old['content']==new['content'] and len(p.body)<=16384
    out,_=ex.validate_model_response(p,w.J(response(reason='The observations may be independent.')),parent=True)
    assert out['outcome_rationale']=='The observations may be independent.'

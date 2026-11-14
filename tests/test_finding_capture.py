"""Parent capture integration with no paid providers or live evidence access."""
from copy import deepcopy
import json
from pathlib import Path
import socket
import sqlite3
from unittest.mock import patch

import pytest

from forensic_assistant.investigation_ai import finding_capture as capture, findings as f
from forensic_assistant.investigation_ai import d2_execution as ex, d2_wire as wire, d2_quality as q
from test_findings import source, workspace, prepared, answer


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    monkeypatch.setattr(socket.socket,'connect',lambda *a,**kw:pytest.fail('network prohibited'))
    monkeypatch.setattr(socket,'create_connection',lambda *a,**kw:pytest.fail('network prohibited'))


def result(p, count=1):
    value=answer(p)
    if count==2:
        second=deepcopy(value['a'][0]);second['s']='Independent activity remains an alternative account.'
        value['a'].append(second)
    if count==0:value.update(o='insufficient_packet_support',a=[],r='No adequate comparison support.')
    validated,_=ex.validate_model_response(p,wire.J(value))
    return dict(status='accepted',validated=validated,attempts=1,lookups=0,usage={'completion_tokens':100},cleanup='confirmed',elapsed_seconds=1)


@pytest.mark.parametrize('count',[1,2])
def test_separate_approvals_atomic_capture(workspace,source,monkeypatch,count):
    p=prepared(source);out=result(p,count);calls=[]
    def execute(permit):calls.append('execute');return out
    monkeypatch.setattr(ex,'execute',execute)
    before=[(source[0]/source[1]/n).read_bytes() for n in ('manifest.json','events.jsonl')]
    def approve(offer):calls.append('provider');return True
    def save(offer):
        assert calls==['provider','execute','display']
        assert offer['count']==count and offer['revision']==0
        calls.append('capture');return True
    returned=capture.run(p,approve,directory=workspace.directory,actor='Analyst',capture_confirmation=save,
        display=lambda *a:calls.append('display'))
    assert returned['result'] is out and calls==['provider','execute','display','capture']
    assert returned['capture']['status']=='captured' and returned['capture']['revision']==count
    state=workspace.export();assert len(state['findings'])==count
    for index,finding in enumerate(state['findings']):
        assert finding['state']=='proposed' and finding['reviewed_classification'] is None
        candidate=finding['candidate'];assert candidate['origin']=='ai_proposal'
        assert candidate['ai']['validated']==out['validated']['proposals'][index]
        assert json.loads(candidate['ai']['capsule']['raw'])['r']=='Provisional only.'
        assert candidate['contrary'] and candidate['support'] and candidate['limitations']
        assert all(r['execution']=='unexecuted' for r in candidate['recommendations'])
    assert f.Workspace(workspace.directory).export()==state
    assert before==[(source[0]/source[1]/n).read_bytes() for n in ('manifest.json','events.jsonl')]


@pytest.mark.parametrize('failure',['missing','run','view','invalid','actor'])
def test_preflight_before_paid_authorization(workspace,source,monkeypatch,tmp_path,failure):
    p=prepared(source)
    old=f.Workspace.export
    def state(w):
        value=old(w)
        if failure=='run':value['metadata']['binding']['source']['run_id']='f'*32
        if failure=='view':value['metadata']['binding']['view']['view_id']='f'*32
        if failure=='invalid':value['source_binding_status']='invalid_source_binding'
        return value
    monkeypatch.setattr(f.Workspace,'export',state)
    monkeypatch.setattr(ex,'authorize',lambda *a:pytest.fail('authorization offered'))
    monkeypatch.setattr(ex,'execute',lambda *a:pytest.fail('execution started'))
    with pytest.raises((ValueError,OSError)):
        capture.run(p,lambda _:True,directory=tmp_path/'missing.findings' if failure=='missing' else workspace.directory,
            actor='' if failure=='actor' else 'Analyst',capture_confirmation=lambda _:True,display=lambda *a:None)


def test_provider_decline_still_required(workspace,source,monkeypatch):
    p=prepared(source)
    monkeypatch.setattr(ex,'execute',lambda *a:pytest.fail('unauthorized dispatch'))
    with pytest.raises(ValueError,match='NOT_AUTHORIZED'):
        capture.run(p,lambda _:False,directory=workspace.directory,actor='Analyst',
            capture_confirmation=lambda _:pytest.fail('capture offered'),display=lambda *a:None)
    assert workspace.export()['revision']==0


@pytest.mark.parametrize('approval',[False,None,'yes',1])
def test_decline_requires_true(workspace,source,approval):
    p=prepared(source);c=capture.Capture(p,workspace.directory);before=workspace.export()
    decision=c.finish(result(p),lambda _:approval,actor='Analyst')
    assert decision['status']=='declined' and workspace.export()==before


@pytest.mark.parametrize('status',['rejected','refused','timeout','cancelled','interrupted','truncated'])
def test_no_offer_on_failure(workspace,source,status):
    p=prepared(source);c=capture.Capture(p,workspace.directory)
    out=dict(status=status,usage={'completion_tokens':7},cleanup='unconfirmed',diagnostic={'code':'failure'})
    before=deepcopy(out)
    decision=c.finish(out,lambda _:pytest.fail('capture offered'),actor='Analyst')
    assert decision['status']=='not_eligible' and out==before and workspace.export()['revision']==0


def test_abstention_and_invalid_validated_result(workspace,source):
    p=prepared(source)
    assert capture.Capture(p,workspace.directory).finish(result(p,0),lambda _:pytest.fail('abstention offer'),actor='Analyst')['status']=='no_inferential_findings'
    forged=result(p);forged['validated']['proposals'][0]['dependencies'][0]['evidence_id']='foreign'
    assert capture.Capture(p,workspace.directory).finish(forged,lambda _:pytest.fail('invalid offer'),actor='Analyst')['status']=='failed'
    assert not workspace.export()['findings']


def test_stale_revision_no_retry(workspace,source):
    p=prepared(source);c=capture.Capture(p,workspace.directory)
    from test_findings import register
    def confirm(_):register(workspace,source);return True
    out=c.finish(result(p,2),confirm,actor='Analyst')
    assert out['status']=='conflict' and workspace.export()['revision']==1
    assert workspace.export()['findings'][0]['candidate']['origin']=='analyst_hypothesis'


def test_duplicate_capture_rejected(workspace,source):
    p=prepared(source);out=result(p,2);c=capture.Capture(p,workspace.directory)
    assert c.finish(out,lambda _:True,actor='Analyst')['status']=='captured'
    assert c.finish(out,lambda _:pytest.fail('second offer'),actor='Analyst')['status']=='already_handled'
    assert capture.Capture(p,workspace.directory).finish(out,lambda _:True,actor='Analyst')['status']=='already_captured'
    assert workspace.export()['revision']==2


def test_duplicate_accounts_and_partly_imported_response(workspace,source):
    p=prepared(source);value=answer(p);value['a'].append(deepcopy(value['a'][0]))
    # Canonical D2 validation already rejects identical accounts before capture.
    with pytest.raises(ValueError,match='duplicate items'):
        ex.validate_model_response(p,wire.J(value))
    forged=result(p,2)
    forged['validated']['proposals'][1]=deepcopy(forged['validated']['proposals'][0])
    decision=capture.Capture(p,workspace.directory).finish(forged,
        lambda _:pytest.fail('duplicate accounts offered'),actor='Analyst')
    assert decision['status']=='failed'
    out=result(p,2)
    workspace.import_result(p,out['validated'],0,actor='Analyst',expected_revision=0)
    decision=capture.Capture(p,workspace.directory).finish(out,lambda _:True,actor='Analyst')
    assert decision['status']=='already_captured' and workspace.export()['revision']==1


def test_distinct_response_same_packet_not_duplicate(workspace,source):
    p=prepared(source)
    assert capture.Capture(p,workspace.directory).finish(result(p),lambda _:True,actor='Analyst')['status']=='captured'
    value=answer(p);value['a'][0]['s']='A different provisional explanation merits examination.'
    validated,_=ex.validate_model_response(p,wire.J(value))
    out=capture.Capture(p,workspace.directory).finish(dict(status='accepted',validated=validated),lambda _:True,actor='Analyst')
    assert out['status']=='captured' and workspace.export()['revision']==2


def test_single_packet_capture(workspace,source):
    from test_d2_execution import config
    from forensic_assistant.investigation_ai import d2
    h=d2.open_history(source[0],source[1]);issue=h.preview(exploratory=True)['packets'][0]['content']['issue']['id']
    p=ex.prepare(source[0],source[1],issue,config(),exploratory=True)
    assert capture.Capture(p,workspace.directory).finish(result(p),lambda _:True,actor='Analyst')['status']=='captured'
    assert workspace.export()['findings'][0]['state']=='proposed'


def test_cancel_capture(workspace,source):
    p=prepared(source)
    def cancel(_):raise KeyboardInterrupt()
    assert capture.Capture(p,workspace.directory).finish(result(p),cancel,actor='Analyst')['status']=='cancelled'
    assert not workspace.export()['findings']


def test_bulk_rollback_second_insert(workspace,source,monkeypatch):
    p=prepared(source);out=result(p,2);original=sqlite3.connect
    class Failing:
        def __init__(self,db):self.db=db
        def __getattr__(self,k):return getattr(self.db,k)
        def executemany(self,sql,rows):
            self.db.execute(sql,rows[0]);raise OSError('synthetic disk failure')
    def connect(path,*args,**kwargs):
        db=original(path,*args,**kwargs)
        return Failing(db) if str(path).endswith('?mode=rw') else db
    monkeypatch.setattr(sqlite3,'connect',connect)
    assert capture.Capture(p,workspace.directory).finish(out,lambda _:True,actor='Analyst')['status']=='storage_uncertain'
    assert workspace.export()['revision']==0


def test_store_replaced_during_confirmation(workspace,source):
    p=prepared(source);c=capture.Capture(p,workspace.directory)
    def replace(_):
        with sqlite3.connect(workspace.path) as db:
            metadata=json.loads(db.execute('SELECT value FROM metadata').fetchone()[0]);metadata['id']='c'*32
            db.execute('UPDATE metadata SET value=?',(json.dumps(metadata),))
        return True
    assert c.finish(result(p),replace,actor='Analyst')['status']=='failed'
    assert workspace.export()['revision']==0


_CHILD=ex._child


def sdk_child(connection,gate,request):
    """Spawn-safe actual OpenAI SDK + MockTransport; network prohibited in child."""
    import httpx
    from forensic_assistant.ai import d2_transport, settings
    def forbidden(*a,**kw):raise AssertionError('network prohibited')
    def complete(client,messages,sha):
        schema=wire.schema_for(messages)
        view=json.loads(messages[1]['content']);alias=view['supports'][0][0]
        value=dict(v=request['response_version'],o='new_inference',r='Provisional.',a=[dict(
            s='The records may describe related activity.',e=[alias],c=[],i=[],a='They may be unrelated.',
            u='Clock agreement is unknown.',d='Compare source timestamps.',n='Examine additional process records; availability unknown.')])
        count=[]
        def handle(req):
            count.append(1)
            return httpx.Response(200,json=dict(id='mock',object='chat.completion',created=0,model=client.model_name,
                choices=[dict(index=0,message=dict(role='assistant',content=wire.J(value)),finish_reason='stop')],
                usage=dict(prompt_tokens=1,completion_tokens=20,total_tokens=21)))
        config=dict(provider='openai',model=client.model_name,messages=messages,schema=schema,timeout=10,
                    _key='synthetic-not-a-key',d2_body_sha256=sha)
        with d2_transport.guarded_client(config,httpx.MockTransport(handle)) as sdk:
            response=sdk.chat.completions.create(**json.loads(wire.body(messages,client.model_name,schema)))
        assert count==[1]
        return dict(text=response.choices[0].message.content,finish_reason='stop',usage={'completion_tokens':20})
    with patch.object(settings,'load',lambda:request['config']),patch('forensic_assistant.ai.backend.ModelBackend.complete_d2',complete),patch.object(socket.socket,'connect',forbidden),patch.object(socket,'create_connection',forbidden):
        _CHILD(connection,gate,request)


def test_windows_supervised_sdk_capture(workspace,source,monkeypatch):
    import subprocess
    import sys
    from test_d2_execution import config
    from forensic_assistant.investigation_ai import d2_cross
    p=d2_cross.prepare(source[0],source[1],'Compare the recorded fields and their limitations.',config())
    monkeypatch.setattr(ex,'_child',sdk_child)
    offers=[]
    returned=capture.run(p,lambda _:True,directory=workspace.directory,actor='Synthetic analyst',
        capture_confirmation=lambda offer:offers.append(offer) or True,display=lambda *a:None)
    assert returned['result']['status']=='accepted',returned
    assert returned['result']['attempts']==1 and returned['result']['lookups']==0
    assert returned['result']['cleanup']=='confirmed'
    assert returned['capture']['status']=='captured' and len(offers)==1
    saved=workspace.export()
    assert saved['findings'][0]['state']=='proposed'
    reopened=subprocess.run([sys.executable,'-B','-m','forensic_assistant.investigation_ai.findings',
        str(workspace.directory),'export'],capture_output=True,text=True,check=True)
    assert json.loads(reopened.stdout)==saved
    fid=returned['capture']['finding_ids'][0]
    workspace.review(fid,'accept',actor='Synthetic reviewer',expected_revision=saved['revision'],rationale='Separate test decision.')
    assert workspace.get(fid)['findings'][0]['state']=='accepted'
    print('Provider-free capture demonstration: one mocked SDK request; separate capture approval; '
          'proposed finding reopened in a new process; separate analyst acceptance recorded.')


def test_cli_without_workspace_unchanged(source,monkeypatch,capsys):
    from forensic_assistant.investigation_ai import d2_reasoning as cli, d2_cross
    import sys
    p=prepared(source);out=result(p)
    monkeypatch.setattr(d2_cross,'prepare',lambda *a,**kw:p)
    monkeypatch.setattr('forensic_assistant.ai.settings.load',lambda:p.config)
    monkeypatch.setattr(ex,'execute',lambda permit:out)
    monkeypatch.setattr('builtins.input',lambda _: 'y')
    monkeypatch.setattr(capture,'Capture',lambda *a:pytest.fail('capture initialized'))
    monkeypatch.setattr(sys,'argv',['d2',str(source[0]),source[1],'--cross-artifact','--question','Question','--execute'])
    cli.main();text=capsys.readouterr().out
    assert cli.render(out,p) in text and 'No retries, lookups, fallback or persistence.' in text
    assert 'Register these proposals' not in text


def test_cli_capture_defaults_no(workspace,source,monkeypatch,capsys):
    from forensic_assistant.investigation_ai import d2_reasoning as cli, d2_cross
    import sys
    p=prepared(source);out=result(p);prompts=[]
    monkeypatch.setattr(d2_cross,'prepare',lambda *a,**kw:p)
    monkeypatch.setattr('forensic_assistant.ai.settings.load',lambda:p.config)
    monkeypatch.setattr(ex,'execute',lambda permit:out)
    def input(prompt):prompts.append(prompt);return 'y' if len(prompts)==1 else ''
    monkeypatch.setattr('builtins.input',input)
    monkeypatch.setattr(sys,'argv',['d2',str(source[0]),source[1],'--cross-artifact','--question','Question','--execute',
        '--findings-workspace',str(workspace.directory),'--findings-actor','Synthetic analyst'])
    cli.main();text=capsys.readouterr().out
    assert len(prompts)==2 and prompts[1].endswith('[y/N] ')
    assert 'Capture declined; workspace unchanged.' in text and workspace.export()['revision']==0

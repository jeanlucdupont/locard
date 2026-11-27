"""Provider-free diagnostic observability, real synthetic read-only worker."""
import json
from pathlib import Path
import pytest
from scripts import diagnose_local_provider as diagnostic
from forensic_assistant.conversational_ai.operation_diagnostics import operation_trace,failure_detail
from forensic_assistant.conversational_ai.service import Session,Paused
from test_conversational_ai import setup,reply,call


def test_repeated_failure_trace_and_retention(tmp_path,monkeypatch):
    monkeypatch.setenv('LOCALAPPDATA',str(tmp_path))
    def run(root):
        invalid=reply(calls=[call('memory',{'kind':'state','limit':'wrong'})])
        path,provider,scope=setup(root,[reply(calls=[call('search_evidence',{'artifact':'evtx','limit':1})]),invalid,invalid,invalid])
        before=path.read_bytes();session=Session(scope,provider,lambda _:True)
        try:
            with pytest.raises(Paused,match='REPEATED_TOOL_FAILURE'):session.submit('Synthetic')
        finally:session.close('REPEATED_TOOL_FAILURE')
        trace=operation_trace(session.journal.path)
        assert operation_trace(session.journal.path)==trace
        rows=trace['operations'];assert len(rows)==4
        assert rows[0]['returned_evidence_ids'] and rows[0]['worker_reached']
        assert [r['exact_repeat'] for r in rows]==[False,False,True,True]
        assert all(r['canonical_validation']=='failed' and not r['worker_reached'] for r in rows[1:])
        assert rows[1]['error']['validation_detail']['validation_path']=='request.limit'
        assert rows[1]['feedback_sent_request']==3 and rows[1]['subsequent_response_identity']
        assert rows[3]['feedback_sent_request'] is None
        assert trace['repeated_failure']['identical'] and len(trace['repeated_failure']['contributing_operations'])==3
        assert path.read_bytes()==before and session.worker.process.poll() is not None
        return dict(outcome='REPEATED_TOOL_FAILURE',operation_trace=rows,provider_diagnostics=trace['provider_diagnostics'])
    root=tmp_path/'retained';result=diagnostic.retained(root,run)
    assert result['outcome']=='REPEATED_TOOL_FAILURE' and not diagnostic.successful(result)
    assert list(root.glob('case.db.conversations/*/workspace.db'))
    assert list(root.glob('case.db.conversations/*/manifest.json'))
    assert len(json.loads((root/'operation-trace.json').read_text()))==4
    with pytest.raises((OSError,ValueError)):diagnostic.retained(root,lambda _:None)


def test_worker_rejection_has_safe_reason(tmp_path,monkeypatch):
    monkeypatch.setenv('LOCALAPPDATA',str(tmp_path))
    path,provider,scope=setup(tmp_path,[reply(calls=[call('search_evidence',{'artifact':'evtx','start':'2025-01-01T00:00:00Z'})]),reply('No inference of absence.')])
    session=Session(scope,provider,lambda _:True)
    try:session.submit('Synthetic')
    finally:session.close()
    row=operation_trace(session.journal.path)['operations'][0]
    assert row['canonical_validation']=='passed' and row['worker_reached']
    assert row['error']['stage']=='query'
    assert row['error']['validation_detail']['rule']=='Search cannot expand approved time interval'
    assert row['feedback_sent_request']==2


@pytest.mark.parametrize('outcome',['COMPLETED','PROVIDER_FAILURE','CONTEXT_CAPACITY'])
def test_retained_controlled_outcomes(tmp_path,outcome):
    def run(root):
        (root/'events.jsonl').write_text('synthetic fixture',encoding='utf-8')
        return dict(outcome=outcome,checks={'fixture':True})
    root=tmp_path/'private';result=diagnostic.retained(root,run)
    assert (root/'diagnostic.json').is_file() and (root/'events.jsonl').is_file()
    assert diagnostic.successful(result)==(outcome=='COMPLETED')


def test_retains_unexpected_failure_without_exception_content(tmp_path):
    def fail(root):raise ValueError('secret synthetic payload')
    result=diagnostic.retained(tmp_path/'private',fail)
    assert not diagnostic.successful(result) and 'secret' not in json.dumps(result)
    assert failure_detail(ValueError('secret synthetic payload'))=={}


def test_parity_before_unrelated_argument_validation(monkeypatch):
    class Meter:
        def __init__(self,*args):pass
        def measure(self,*args,**kwargs):
            assert kwargs['choice']=='none'
            return {'input_tokens':7,'fits':True}
        def observe(self,m,u):return {'difference':u['prompt_tokens']-m['input_tokens']}
    class Client:
        model_name='synthetic'
        def conversation_binding(self):return {'endpoint':'synthetic'}
        def converse(self,*args,**kwargs):
            assert kwargs['tool_choice']=='none'
            return dict(usage={'prompt_tokens':7},tool_calls=[call('memory',{'kind':'invalid'})])
    monkeypatch.setattr('forensic_assistant.conversational_ai.local_context.ContextMeter',Meter)
    result=diagnostic.tokenization_probe(Client())
    assert result['checks']['initial_and_tool_parity']
    assert all(r['canonical_arguments']=='invalid' and r['unexpected_tool_calls'] for r in result['rows'])

@pytest.mark.parametrize('outcome',['COMPLETED','PROVIDER_FAILURE','CONTEXT_CAPACITY'])
def test_retained_real_session_outcomes(tmp_path,monkeypatch,outcome):
    from forensic_assistant.ai.backend import ModelBackend
    from forensic_assistant.ai.provider_diagnostics import ProviderFailure
    from forensic_assistant.conversational_ai import local_context
    # Deterministic unsupported metadata capability: no socket or live provider.
    def unavailable(*a,**k):raise ProviderFailure('network_error','provider_request')
    monkeypatch.setattr(local_context,'auxiliary',unavailable)
    client=ModelBackend.local_conversation('http://127.0.0.1:1','synthetic',4096 if outcome=='CONTEXT_CAPACITY' else 32768)
    def respond(*a,**k):
        if outcome=='PROVIDER_FAILURE':raise ProviderFailure('local_grammar_rejected','provider_request')
        return reply('Synthetic response; no forensic conclusion.')
    monkeypatch.setattr(client,'converse',respond)
    root=tmp_path/'private'
    result=diagnostic.retained(root,lambda path:diagnostic.synthetic_investigation(path,client,request_budget=4))
    assert result['outcome']==outcome and all(result['checks'].values())
    journal=Path(result['journal'])
    assert all((journal/name).is_file() for name in ('events.jsonl','manifest.json','workspace.db'))
    assert result['diagnostic_request_ceiling']==4
    assert (root/'case.db').is_file() and (root/'diagnostic.json').is_file()


def test_retained_rejects_traversal_and_existing_file(tmp_path):
    existing=tmp_path/'existing';existing.write_text('preserve',encoding='utf-8')
    for path in (existing,tmp_path/'..'/'redirect'):
        with pytest.raises((OSError,ValueError)):
            diagnostic.retained(path,lambda _:pytest.fail('must not run'))
    assert existing.read_text()=='preserve'


def test_failed_retained_cli_exit(tmp_path,monkeypatch,capsys):
    monkeypatch.setattr(diagnostic,'synthetic_investigation',lambda *a:dict(outcome='REPEATED_TOOL_FAILURE'))
    monkeypatch.setattr('sys.argv',['diagnostic','--endpoint','http://127.0.0.1:1','--model','synthetic','--synthetic-investigation','--output-dir',str(tmp_path/'retained')])
    assert diagnostic.main()==1
    assert json.loads(capsys.readouterr().out)['outcome']=='REPEATED_TOOL_FAILURE'
    assert (tmp_path/'retained'/'diagnostic.json').is_file()

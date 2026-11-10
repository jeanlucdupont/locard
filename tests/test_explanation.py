"""D1a uses only recorded accepted state; synthetic evidence and fake providers."""
from copy import deepcopy
import hashlib
import json
import pytest
from forensic_assistant.investigation_ai import explanation as e, organization as o
from forensic_assistant.investigation_ai.transcript import load, digest, Transcript
from test_synthesis_consumer import execute, setup, reply
from test_organization import rehash


def pages(session):
    cursor=None
    for _ in range(193):
        p=e.page(session,cursor);yield p
        cursor=p['next_cursor']
        if not cursor:return
    pytest.fail('Pagination made no progress')


def test_history_readonly_provider_free_bounded_and_grounded(tmp_path,monkeypatch):
    result,*_=execute(tmp_path);root=tmp_path/'runs';rid=result['investigation_id']
    import sqlite3
    from forensic_assistant.ai.backend import ModelBackend
    def forbidden(*a,**kw):pytest.fail('Provider/database access')
    monkeypatch.setattr(ModelBackend,'complete',forbidden);monkeypatch.setattr(sqlite3,'connect',forbidden)
    paths=[root/rid/'manifest.json',root/rid/'events.jsonl']
    before=[hashlib.sha256(p.read_bytes()).hexdigest() for p in paths]
    session=e.open_history(root,rid)
    views=list(pages(session));again=list(pages(e.open_history(root,rid)))
    assert views==again
    assert views[0]['summary_omitted']==len(session.clauses)-len(views[0]['summary'])
    atoms=[s for p in views for s in p['statements']]
    assert len(atoms)==len({s['id'] for s in atoms})
    assert all(not p['omissions'] for p in views)
    for p in views:
        assert e._size(p)<=16384 and len(p['statements'])<=64
        assert len(e.render(p).encode('utf-8'))<=16384
        body={s['id']:s for s in p['statements']}
        for sid in p['summary']:
            assert sid in body and body[sid]['qualifications']
            assert body[sid]['classification'] in ('recorded_observation','deterministic_interpretation')
    factual=[s for s in atoms if s['classification']=='recorded_observation']
    assert len(factual)==len([c for c in session.factual['clauses'] if c['type']=='observation'])
    for s in factual:
        c=session.clauses[s['source_units'][0]]
        assert s['text']==e._fact_text(c) and s['qualifications']==c['qualifications']
        assert s['dependencies'][0]['value_digest']==digest(c['arguments']['value'])
    assert all(p['question']==result['question'] for p in views)
    assert before==[hashlib.sha256(p.read_bytes()).hexdigest() for p in paths]


@pytest.mark.parametrize('change',['value','view','missing','qualification'])
def test_changed_validated_sources_rejected(tmp_path,change):
    result,*_=execute(tmp_path);session=e.open_history(tmp_path/'runs',result['investigation_id'])
    if change=='value':session.factual['clauses'][0]['arguments']['value']='invented'
    elif change=='view':session.organization['read_view']['view_id']='c'*32
    elif change=='missing':session.factual['clauses'].clear()
    else:session.factual['clauses'][0]['qualifications'].clear()
    with pytest.raises(ValueError):e.page(session)


def test_cursor_binds_exact_revision_and_order(tmp_path):
    result,*_=execute(tmp_path);session=e.open_history(tmp_path/'runs',result['investigation_id'])
    cursor=e.page(session)['next_cursor'];assert cursor
    other=deepcopy(session);other.binding['organization_revision']+=1
    with pytest.raises(ValueError,match='cursor'):e.page(other,cursor)
    with pytest.raises(ValueError):e.page(session,'not-valid-json')
    with pytest.raises(ValueError):e.page({})


def synthetic_session(rows_extra=()):
    from test_synthesis_relationships import clause,factual
    from forensic_assistant.investigation_ai import synthesis as s1
    from test_organization import source
    src=source()
    rows=[clause(r'C:\Admin\update.zip',family='browser',pointer='/target_path',number=1,source='admin-a'),
          clause(r'C:\Admin\update.zip',family='mft',pointer='/objects/0',number=2,source='admin-b'),
          clause('2026-01-01T10:00:00Z',number=3,source='admin-a'),
          clause('2026-01-01T10:00:05Z',number=4,source='admin-b'),
          clause('UpdaterService',family='evtx',pointer='/original_event_data/0/value',name='ServiceName',number=5,source='admin-b')]
    rows.extend(rows_extra)
    facts=factual(*rows);src.view=facts['evidence_state'];src.manifest['evidence_state']=src.view
    reducer=s1._Reducer();reducer.previous='accepted';reducer.batches=1;reducer.finish=lambda:facts
    exposure={'synthetic':'accepted'}
    hypotheses=[dict(statement='Administrative maintenance may explain the staging.',alternatives=['An unapproved installation is also possible.'],evidence_ids=[rows[0]['supports'][0]['evidence_id']])]
    delta=dict(id='accepted',batch=1,disclosure_sha256=digest(exposure),evidence_state=src.view,counters={'ai_requests':1},findings={'hypotheses':hypotheses,'model_proposed_unknowns':['Was the maintenance approved?','Was this particular maintenance approved?']})
    src.analysis(reducer,delta,exposure)
    org=o._Reducer(src,clock=lambda:0);prepared,_=org.prepare({'sequence':1,'hash':'d'*64});org.commit(prepared)
    view=org.state();view.update(state_digest=digest(view),mode='retrospective',incomplete=False,limitations=['Synthetic recorded view'])
    manifest={**src.manifest,'chain':'d'*64}
    return e._Session(e._TOKEN,manifest,facts,view)


def test_benign_multisource_no_attack_or_identity_inference():
    session=synthetic_session();views=list(pages(session));atoms=[s for p in views for s in p['statements']]
    assert len([s for s in atoms if s['classification']=='unverified_hypothesis'])==1
    h=next(s for s in atoms if s['classification']=='unverified_hypothesis')
    assert h['metadata']['support_granularity']=='record_only'
    assert h['metadata']['alternatives']==['An unapproved installation is also possible.']
    assert 'pointer' not in h['dependencies'][0]
    questions=[s for s in atoms if s['classification']=='unresolved_question']
    assert any(s['text']=='Was the maintenance approved?' for s in questions)
    assert any(s['text']=='Was this particular maintenance approved?' for s in questions)
    rel=next(s for s in atoms if s['classification']=='validated_relationship' and s['metadata']['predicate']=='recorded_time_before')
    assert rel['metadata']['semantics']['physical_event_order']=='not established'
    assert rel['metadata']['semantics']['left']['clock_skew']=='unknown'
    assert len({tuple(s['dependencies'][0]['context']['source_context']['source_ids']) for s in atoms if s['classification']=='recorded_observation'})==2
    assert not any('attack' in s['text'] for s in atoms if s['classification']=='recorded_observation')


def test_utf8_oversized_atom_is_omitted_not_truncated(monkeypatch):
    session=synthetic_session();original=session._statement
    def oversized(section,identity):
        s=original(section,identity);s['text']='界'*6000;return s
    monkeypatch.setattr(session,'_statement',oversized)
    p=e.page(session)
    assert not p['statements'] and p['omissions'] and not p['page_complete']
    assert e._size(p)<=16384


def test_assembly_admission_limit():
    session=synthetic_session()
    # Test only the bounded planner; duplicate candidates are never a grounding input.
    session.candidates=[('coverage','coverage')]*250
    session.binding['ordering']=digest(session.candidates)
    result=list(pages(session))
    assert sum(len(p['statements']) for p in result)<=192
    assert result[-1]['assembly_limit_omitted']==58


@pytest.mark.parametrize('failure',['later','after_b2','final_anchor','final_checkpoint','cancel_later'])
def test_c1_prospective_failure_gate(tmp_path,monkeypatch,failure):
    original=Transcript.append;committed=[];b2_seen=[];cancelled=[]
    def append(self,kind,data,terminal=False):
        if kind=='synthesis_decision' and data['status']=='accepted':b2_seen.append(data)
        fail=(failure in ('later','cancel_later') and kind=='organization_checkpoint' and len(committed)==1 or
              failure=='after_b2' and kind=='organization_checkpoint' and bool(b2_seen) or
              failure=='final_anchor' and kind=='organization_final' or
              failure=='final_checkpoint' and kind=='organization_checkpoint' and data['final'])
        if fail and not (failure=='cancel_later' and cancelled):
            if failure=='cancel_later':
                cancelled.append(True);raise KeyboardInterrupt()
            raise OSError('injected C1 append failure')
        value=original(self,kind,data,terminal)
        if kind=='organization_checkpoint':committed.append(deepcopy(data))
        return value
    monkeypatch.setattr(Transcript,'append',append)
    result,client,seen,closed=execute(tmp_path)
    assert committed and closed and len(client.calls)<=9
    assert len([x for x in seen if x[0]=='show_evidence'])<=6
    assert result['organization']['digest']==committed[-1]['result_digest']
    view=o.reconstruct(tmp_path/'runs',result['investigation_id'])
    assert view['state_digest']==committed[-1]['result_digest']
    if failure!='cancel_later':assert view['incomplete']
    else:assert result['primary_termination']=='ANALYST_CANCELLED'
    assert result['state']['steps']<=10
    if failure=='after_b2':assert result['synthesis']['accepted']


def test_rejected_analysis_excluded_from_c1(tmp_path):
    from forensic_assistant.investigation_ai import autonomous as a
    config,worker,client,seen,closed=setup(tmp_path);actions=list(client.actions)
    def invalid(messages):
        out=actions[2](messages);out['answer']['unknowns']=['x'*10000];return out
    client.actions=iter([actions[0],actions[1],invalid,reply,reply])
    result=a.run(config,config['_stage_a']['objective'],tmp_path/'runs',client=client,worker_factory=worker)
    assert result['validated_batches']==1 and len(client.calls)==5
    view=o.reconstruct(tmp_path/'runs',result['investigation_id'])
    assert view['coverage']['validated_batches']==1
    _,events=load(tmp_path/'runs',result['investigation_id'])
    ids={x['data']['id'] for x in events if x['kind']=='validated_delta'}
    assert all(l['delta_id'] in ids for entity in view['entities'] if entity['kind']=='finding' for d in entity['dependencies'] for l in d['lineage'])

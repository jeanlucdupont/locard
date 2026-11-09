"""B1 local previews: synthetic original projections, no case or providers."""
from copy import deepcopy
import json

import pytest

from forensic_assistant.investigation_ai import packets as p, synthesis as s, relationships as r
from forensic_assistant.investigation_ai import decomposition as d
from forensic_assistant.investigation_ai.state import State, Budget, encoded
from forensic_assistant.investigation_ai.transcript import digest
from test_factual_clauses import batch, VIEW
from test_compact_disclosure import records
from test_question_decomposition import objective, proposal, configure, run


def context(rows=None, question='What recorded download and blocking metadata is present?', mapping=None):
    rows = deepcopy(rows if rows is not None else records())
    for row in rows:
        row['source_context'] = {'source_ids':row.get('source_context',{}).get('source_ids',['synthetic-source']), 'basis':'analyst supplied'}
    reducer = s._Reducer()
    state = State(Budget())
    accepted = set()
    previous = None
    for i, row in enumerate(rows):
        current, delta, exposure = batch([row], number=i+1, previous=previous)
        reducer.consume(current, delta, exposure)
        state.records.update(current.records)
        state.exposed.update(current.exposed)
        accepted.add((delta['id'], delta['disclosure_sha256'], delta['batch']))
        previous = delta['id']
    factual = reducer.finish()
    manifest = dict(question=question, evidence_state=VIEW, authorization=dict(
        contract='investigation-authorization-v1', id='grant', source_ids=sorted({sid for row in rows for sid in row['source_context']['source_ids']}),
        evidence_ids=[row['id'] for row in rows], families=sorted({row['source_type'] for row in rows})))
    return p.Context(state, factual, r._build(factual), manifest, mapping, accepted)


def test_earlier_supports_and_no_ledger_mutation():
    ctx=context()
    before=deepcopy(ctx.state.__dict__)
    result=p.plan(ctx)
    assert result['packets'] and len(result['packets'])<=2
    assert result['counts']['support_unavailable']==0
    assert result['counts']['actually_disclosed_records']==0
    assert result['counts']['provider_requests']==result['counts']['evidence_lookups']==0
    assert ctx.state.__dict__==before
    assert p.validate_preview(ctx,result)
    for packet in result['packets']:
        assert packet['actually_disclosed'] is False
        assert packet['content_bytes']==sum(len(m['content'].encode('utf-8')) for m in packet['messages'])<=5600
        assert packet['digest']==digest(packet['messages'])
        for leaf in packet['content']['supports']:
            assert leaf['source_ref'] in packet['content']['sources']
            assert leaf['lineage_ref'] in packet['content']['lineages']
            assert leaf['evidence_id'] in ctx.state.records
            assert leaf['field']['value'] is not None


@pytest.mark.parametrize('mutation',['value','alias','lineage','bytes','qualification','membership','digest'])
def test_preview_forgery_requires_original_reconstruction(mutation):
    ctx=context([records()[0]])
    result=p.plan(ctx)
    packet=result['packets'][0]
    if mutation=='value':packet['content']['supports'][0]['field']['value']='invented'
    elif mutation=='alias':packet['content']['supports'][0]['source_ref']='missing'
    elif mutation=='lineage':packet['content']['lineages'].clear()
    elif mutation=='bytes':packet['content_bytes']=1
    elif mutation=='qualification':packet['content']['qualifications']=[]
    elif mutation=='membership':packet['represented_supports']=[]
    else:packet['digest']='0'*64
    with pytest.raises(ValueError):p.validate_preview(ctx,result)


@pytest.mark.parametrize('change',['replace','missing','source'])
def test_exact_historical_projection_not_replaced(change):
    ctx=context([records()[0]])
    eid=next(iter(ctx.state.records))
    if change=='missing':ctx.state.records.clear();ctx.state.exposed.clear()
    elif change=='source':ctx.state.records[eid]['source_context']['source_ids']=['different']
    else:ctx.state.records[eid]['target_path']='changed'
    result=p.plan(ctx)
    assert result['status']=='no_supported_packet'
    assert result['counts']['support_unavailable']==len(ctx.factual['clauses'])


@pytest.mark.parametrize('change',['epoch','grant_source','lineage','clause','relationship'])
def test_invalid_trusted_context_rejected(change):
    ctx=context()
    if change=='epoch':ctx.manifest['evidence_state']=dict(VIEW,view_id='b'*32)
    elif change=='grant_source':ctx.manifest['authorization']['source_ids']=['other']
    elif change=='lineage':ctx.accepted.clear()
    elif change=='clause':ctx.factual['clauses'][0]['contract']='unknown'
    else:ctx.related['relationships'][0]['endpoints'][0]='unknown'
    with pytest.raises((ValueError,KeyError)):p.plan(ctx)


def test_atomic_interpretation_and_relationship_closure():
    ctx=context()
    meter=p.Meter(p.Limits(),lambda:0)
    clauses={c['id']:c for c in ctx.factual['clauses']}
    hydrated={cid:p._rehydrate(c,ctx,meter) for cid,c in clauses.items()}
    interpreted=next(c for c in clauses.values() if c['type']=='deterministic_interpretation')
    bundle=p._bundle(interpreted,clauses,hydrated,{})
    assert {x['field']['pointer'] for x in bundle['leaves']}=={'/provider','/channel','/event_id','/defender_asr'}
    assert any('does not establish successful' in q for q in bundle['qualifications'])
    for edge in ctx.related['relationships']:
        bundle=p._bundle(edge,clauses,hydrated,{})
        assert set(edge['endpoints'])<=set(bundle['clauses'])
        assert set(edge['assumptions'])<=set(bundle['qualifications'])
        missing=deepcopy(hydrated);missing[edge['endpoints'][0]]=None
        assert p._bundle(edge,clauses,missing,{}) is None


def test_oversize_atomic_omission_empty_and_support_budgets():
    ctx=context()
    result=p.plan(ctx,limits=p.Limits(content_bytes=200))
    assert result['status']=='no_supported_packet'
    assert result['selections'][0]['omitted_counts']['byte_budget']>0
    result=p.plan(ctx,limits=p.Limits(resolutions=1))
    assert result['planning_stop']=='support_resolution_budget'
    assert result['counts']['support_resolutions']==1
    assert p.plan(context([]))['status']=='no_supported_packet'
    result=p.plan(ctx,limits=p.Limits(candidates=1,observations=1))
    assert all(s['examined']<=1 for s in result['selections'])
    assert all(len(x['content']['supports'])<=1 for x in result['packets'])
    assert result['selections'][0]['unassessed']>0


def test_deadline_is_bounded_result():
    ticks=iter([0,6])
    result=p.plan(context(),_clock=lambda:next(ticks))
    assert result['planning_stop']=='planning_time' and not result['packets']


def test_determinism_unicode_and_input_order():
    rows=[records()[0]];rows[0]['target_path']='C:\\資料\\é😀.zip'
    ctx=context(rows)
    first=p.plan(ctx)
    ctx.factual['clauses'].reverse()
    ctx.related=r._build(ctx.factual)
    assert p.plan(ctx)==first
    assert '\\u' in first['packets'][0]['messages'][1]['content']
    assert len(first['packets'][0]['content']['supports'])>0
    assert json.loads(first['packets'][0]['messages'][1]['content'])==first['packets'][0]['content']


@pytest.mark.parametrize('literal',['execute','the PowerShell script'])
def test_invalid_script_binding_is_preserved_not_repaired(literal):
    question='Did '+literal+' happen?'
    mapping=d.validate(proposal(objective(question,'execution_outcome',literal,'value')),question)
    ctx=context(question=question,mapping=mapping)
    result=p.plan(ctx)
    assert result['bindings'][0]['status']=='not_a_validated_technical_referent'
    assert result['historical_decomposition']==mapping


def test_exact_event_binding_and_ambiguous_occurrences():
    question='Was event 1121 recorded?'
    mapping=d.validate(proposal(objective(question)),question)
    ctx=context([records()[1]],question,mapping)
    assert p.plan(ctx)['bindings'][0]['status']=='resolved_within_declared_candidates'
    rows=[records()[1],deepcopy(records()[1])];rows[1]['id']=rows[1]['id']+'x'
    rows[1]['source_context']={'source_ids':['another-source']}
    ctx=context(rows,question,mapping)
    assert p.plan(ctx)['bindings'][0]['status']=='ambiguous'


def test_reconstruct_s4_keeps_original_assessment_and_bytes(tmp_path,monkeypatch):
    config,worker,client,_,_=configure(tmp_path,count=1)
    completed=run(tmp_path,config,worker,client)
    identity=completed['investigation_id']
    folder=tmp_path/'runs'/identity
    before={f.name:f.read_bytes() for f in folder.iterdir() if f.is_file()}
    expected=d.reconstruct(tmp_path/'runs',identity)
    import sqlite3, socket
    monkeypatch.setattr(sqlite3,'connect',lambda *a,**k:pytest.fail('Case access'))
    monkeypatch.setattr(socket,'socket',lambda *a,**k:pytest.fail('Provider/network access'))
    result=p.reconstruct(tmp_path/'runs',identity)
    assert result['original_s3_assessment']==expected['original_assessment']
    assert result['counts']['provider_requests']==0
    assert before=={f.name:f.read_bytes() for f in folder.iterdir() if f.is_file()}


def test_binding_incomplete_unavailable_and_generic_unresolved():
    question='Was event 1121 recorded?'
    mapping=d.validate(proposal(objective(question)),question)
    ctx=context([records()[1]],question,mapping)
    meter=p.Meter(p.Limits(),lambda:0)
    assert p._bindings(ctx,{},meter)[0]['status']=='incomplete_candidates'
    assert p._bindings(ctx,{c['id']:None for c in ctx.factual['clauses']},meter)[0]['status']=='support_unavailable'
    item=objective(question,'execution_outcome',None)
    item['unresolved']=[{'name':'value','role':'the PowerShell script'}]
    ctx.mapping=d.validate(proposal(item),question)
    assert p.plan(ctx)['bindings'][0]['status']=='unsupported_role'


def test_hypotheses_never_become_original_support():
    ctx=context([records()[0]])
    before=p.plan(ctx)
    ctx.factual['hypotheses']=[{'statement':'Invented successful execution', 'evidence_ids':[]}]
    ctx.related=r._build(ctx.factual)
    assert p.plan(ctx)==before


def test_projection_version_and_cycle_fail_closed():
    ctx=context()
    ctx.factual['clauses'][0]['lineage'][0]['projection_contract']='future'
    ctx.related=r._build(ctx.factual)
    with pytest.raises(ValueError,match='projection contract'):p.plan(ctx)
    ctx=context()
    ctx.related['chronology']['graph']['unresolved_cycle_or_dependent_nodes']=['cycle']
    with pytest.raises(ValueError):p.plan(ctx)


def test_large_synthetic_collection_keeps_shared_bounds():
    rows=records()
    for row in rows:
        row['timestamps']=[dict(utc=f'2026-09-30T12:00:{i:02d}Z',slot=str(i),type='recorded',meaning='recorded') for i in range(20)]
    ctx=context(rows)
    result=p.plan(ctx)
    assert result['counts']['known_clauses']>20
    assert result['counts']['support_resolutions']<=512
    assert len(result['packets'])<=2
    for packet in result['packets']:
        assert packet['content_bytes']<=5600
        assert len(packet['content']['supports'])<=12
        assert len(packet['content']['interpretations'])<=4
    assert all(s['examined']<=192 for s in result['selections'])


def test_no_recency_tiebreaker():
    ctx=context()
    result=p.plan(ctx)
    represented={s['evidence_id'] for packet in result['packets'] for s in packet['represented_supports']}
    # Earlier Browser support is not evicted just because the sixth batch is newer.
    assert records()[0]['id'] in represented

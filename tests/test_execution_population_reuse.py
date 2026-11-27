"""6.183 synthetic read-view reuse, compact disclosure and worker regressions."""
import copy
import json
import time
import pytest
from forensic_assistant.database.db import connect
from forensic_assistant.investigation_ai.case import ReadView
from forensic_assistant.conversational_ai.tools import Tools
from forensic_assistant.detections import execution
from forensic_assistant.detections.execution_cache import PopulationCache
from test_execution_discovery import populate
from test_security_discovery import event,SECURITY,START,END


@pytest.fixture(autouse=True)
def private(tmp_path,monkeypatch):monkeypatch.setenv('LOCALAPPDATA',str(tmp_path))


def normalized(result):return {k:v for k,v in result.items() if k!='population_id'}


def test_compatible_views_equal_fresh_without_rescanning(tmp_path,monkeypatch):
    path,sid,scope,*_=populate(tmp_path,100)
    view=ReadView(path,float('inf'));tools=Tools(view.db,scope,read_view=view)
    original=execution.build_population;builds=[]
    def build(*a,**k):builds.append(1);return original(*a,**k)
    monkeypatch.setattr(execution,'build_population',build)
    before=path.read_bytes()
    try:
        first=tools.execute('discover_execution_behaviors',{})
        population_id=tools.computation['population_id']
        gid=first['records'][0]['group_id']
        cases=[{},dict(offset=1),dict(category_filter=first['categories'][0]['category_filter']),
               dict(feature='nested_interpreter'),dict(group_id=gid),dict(presentation='detailed'),
               dict(executable='cmd.exe'),dict(parent='explorer.exe')]
        for args in cases:
            reused=tools.execute('discover_execution_behaviors',args)
            assert tools.computation['cache_hit']
            fresh=Tools(view.db,scope).execute('discover_execution_behaviors',args)
            assert normalized(reused)==fresh
            assert tools.computation['population_id']==population_id
        assert len(builds)==1+len(cases) # fresh controls only; compatible calls did not scan
        assert first==tools.execute('discover_execution_behaviors',{})
        assert first['coverage']['records_processed']==103
    finally:view.close()
    assert path.read_bytes()==before


@pytest.mark.parametrize('change',[{'mode':'exact'},{'hostname':'other'},{'artifact':'evtx'},
                                    {'start':'2026-09-20T12:00:00Z'}])
def test_membership_keys_do_not_reuse(tmp_path,change):
    path,sid,scope,*_=populate(tmp_path,2)
    # Select a valid strictly narrower window regardless of fixture date.
    if 'start' in change:change={'start':scope['start'][:11]+'00:00:01.000000000Z'}
    view=ReadView(path,float('inf'));tools=Tools(view.db,scope,read_view=view)
    try:
        first=tools.execute('discover_execution_behaviors',{})
        population_id=tools.computation['population_id']
        changed=tools.execute('discover_execution_behaviors',change)
        assert not tools.computation['cache_hit'] and population_id!=tools.computation['population_id']
    finally:view.close()


@pytest.mark.parametrize('version',['VERSION','RANKING_VERSION'])
def test_algorithm_versions_invalidate(tmp_path,monkeypatch,version):
    path,sid,scope,*_=populate(tmp_path,1);view=ReadView(path,float('inf'));tools=Tools(view.db,scope,read_view=view)
    try:
        tools.execute('discover_execution_behaviors',{})
        monkeypatch.setattr(execution,version,'changed-version')
        tools.execute('discover_execution_behaviors',{})
        assert not tools.computation['cache_hit']
    finally:view.close()


@pytest.mark.parametrize('damage',['scope','epoch','database','closed'])
def test_authority_changes_fail_closed(tmp_path,damage):
    path,sid,scope,*_=populate(tmp_path,1);view=ReadView(path,float('inf'));tools=Tools(view.db,scope,read_view=view)
    try:
        tools.execute('discover_execution_behaviors',{})
        if damage=='scope':tools.scope=copy.deepcopy(scope);tools.scope['source_ids'].append('unauthorized')
        elif damage=='epoch':view.state['view_id']='changed'
        elif damage=='database':tools.db=object()
        else:view.close()
        with pytest.raises((ValueError,AttributeError)):tools.execute('discover_execution_behaviors',{})
        assert not tools.population_cache.entries
    finally:view.close()


def test_eviction_oversize_and_cancelled_construction(tmp_path,monkeypatch):
    path,sid,scope,*_=populate(tmp_path,30);view=ReadView(path,float('inf'));tools=Tools(view.db,scope,read_view=view)
    try:
        expected=tools.execute('discover_execution_behaviors',{})
        size=tools.population_cache.bytes
        tools.population_cache.budget=size+1
        tools.execute('discover_execution_behaviors',{'mode':'exact'})
        assert tools.population_cache.evictions==1
        assert tools.execute('discover_execution_behaviors',{})==expected
        assert not tools.computation['cache_hit']
        tools.population_cache.clear();tools.population_cache.budget=1
        assert tools.execute('discover_execution_behaviors',{})==expected
        assert not tools.population_cache.entries and not tools.computation['retained']
        tools.population_cache.budget=size*2
        original=execution.build_population
        def fail(*a,**k):original(*a,**k);raise KeyboardInterrupt()
        monkeypatch.setattr(execution,'build_population',fail)
        with pytest.raises(KeyboardInterrupt):tools.execute('discover_execution_behaviors',{})
        assert not tools.population_cache.entries
        monkeypatch.setattr(execution,'build_population',original)
        assert tools.execute('discover_execution_behaviors',{})==expected
        assert tools.computation['retained']
    finally:view.close()


def test_compact_preview_not_verification_authority(tmp_path):
    path,sid,scope,*_=populate(tmp_path,2);view=ReadView(path,float('inf'));tools=Tools(view.db,scope,read_view=view)
    try:
        r=tools.execute('discover_execution_behaviors',{'feature':'nested_interpreter'})
        row=r['records'][0]
        host=r['shared']['host_contexts'][row['host_context']]
        assert host['host_basis']=='analyst-supplied' and host['context_host']['value']=='lab'
        f=next(f for f in row['previews'] if f['name']=='command')
        args=dict(evidence_id=row['evidence_id'],field=f['field'],value_json=json.dumps(f['value']))
        with pytest.raises(ValueError):tools.execute('verify_observation',args)
        page=tools.execute('show_evidence',{'evidence_id':row['evidence_id']})
        while not any(x['field']==f['field'] for x in page['fields']):
            assert page['next_offset'] is not None
            page=tools.execute('show_evidence',{'evidence_id':row['evidence_id'],'offset':page['next_offset']})
        assert tools.execute('verify_observation',args)['verified']
    finally:view.close()


def varied(tmp_path,n=100):
    path,sid,scope,*_=populate(tmp_path,0);db=connect(path)
    for i in range(n):event(db,100+i,4688,SECURITY,'Security',{'NewProcessName':'worker.exe','CommandLine':f'worker.exe task{i}.txt','ParentProcessName':'services.exe'})
    db.commit();db.close();return path,sid,scope


def test_compact_density_pagination_and_lossless_detailed_selection(tmp_path):
    path,sid,scope=varied(tmp_path);view=ReadView(path,float('inf'));tools=Tools(view.db,scope,read_view=view)
    try:
        compact=tools.execute('discover_execution_behaviors',{'limit':10})
        detailed=tools.execute('discover_execution_behaviors',{'limit':10,'presentation':'detailed'})
        assert len(compact['records'])>len(detailed['records'])
        assert len(execution.wire(compact))<=12000 and len(execution.wire(detailed))<=12000
        assert sum(c['groups'] for c in compact['categories'])==compact['coverage']['eligible_groups']
        seen=[];offset=0
        while True:
            r=tools.execute('discover_execution_behaviors',{'offset':offset})
            seen.extend(x['group_id'] for x in r['records'])
            if r['next_offset'] is None:break
            assert r['next_offset']>offset;offset=r['next_offset']
        assert len(set(seen))==len(seen)==103
    finally:view.close()


def test_oversized_caveat_is_explicit_and_advances(tmp_path,monkeypatch):
    from forensic_assistant.detections.execution_observations import Population
    path,sid,scope,*_=populate(tmp_path,1);view=ReadView(path,float('inf'));tools=Tools(view.db,scope,read_view=view)
    original=Population.project
    def project(*a,**k):
        obs=original(*a,**k)
        if obs:obs['limitations'].append('Mandatory qualification '+('x'*13000))
        return obs
    monkeypatch.setattr(Population,'project',project)
    try:
        r=tools.execute('discover_execution_behaviors',{})
        assert not r['records'] and r['next_offset']==1 and not r['coverage']['presentation_complete']
        eid=r['omitted_candidates'][0]['evidence_id']
        assert tools.execute('show_evidence',{'evidence_id':eid})['evidence_id']==eid
        assert len(execution.wire(r))<=12000
    finally:view.close()


def test_worker_sequence_replay_and_repeated_disclosure(tmp_path):
    from forensic_assistant.conversational_ai.service import Session,notebook
    from forensic_assistant.conversational_ai.provider import ScriptedProvider
    from test_conversational_ai import reply,call,last
    path,sid,scope,*_=populate(tmp_path,5)
    def narrow(messages):return reply(calls=[call('discover_execution_behaviors',{'category_filter':last(messages)['categories'][0]['category_filter']})])
    provider=ScriptedProvider([reply(calls=[call('discover_execution_behaviors',{})]),narrow,
        reply(calls=[call('discover_execution_behaviors',{})]),reply('These candidates remain investigative leads.')])
    session=Session(scope,provider,lambda _:True)
    try:session.submit('Explore the recorded behavior categories.')
    finally:session.close()
    assert session.used['behavioral_populations_constructed']==1
    assert session.used['behavioral_populations_reused']==2
    assert session.used['successful_forensic_operations']==3
    saved=notebook(str(path)+'.conversations',session.journal.id)
    assert saved==notebook(str(path)+'.conversations',session.journal.id)
    computations=[e['data'] for e in saved['events'] if e['kind']=='behavioral_computation']
    assert [c['cache_hit'] for c in computations]==[False,True,True]
    assert len({c['population_id'] for c in computations})==1
    results=[e['data']['result'] for e in saved['events'] if e['kind']=='tool_result']
    assert session.used['evidence_bytes']>sum(len(execution.wire(r)) for r in results)
    assert session.worker.process.poll() is not None


def test_long_unicode_and_redacted_previews(tmp_path,monkeypatch):
    monkeypatch.setenv('OPENAI_API_KEY','sk-'+('a'*48))
    path,sid,scope,*_=populate(tmp_path,0);db=connect(path)
    eid=event(db,800,4688,SECURITY,'Security',{'CommandLine':'worker.exe '+('résumé '*500)+' --api-key sk-'+('a'*48)})
    db.commit();db.close();view=ReadView(path,float('inf'));tools=Tools(view.db,scope,read_view=view)
    try:
        r=tools.execute('discover_execution_behaviors',{'limit':10})
        f=next(f for row in r['records'] if row['evidence_id']==eid for f in row['previews'] if f['name']=='command')
        assert f['truncated'] and f['redacted']
        assert 'sk-'+('a'*48) not in execution.wire(r).decode()
        with pytest.raises(ValueError):tools.execute('verify_observation',dict(evidence_id=eid,field=f['field'],value_json=json.dumps(f['value'])))
    finally:view.close()


def test_distinct_authorized_sources(tmp_path):
    from forensic_assistant.database import sources
    from forensic_assistant.database.db import register_source
    from forensic_assistant.conversational_ai.contracts import authorize,FAMILIES
    path,sid,scope,*_=populate(tmp_path,1);db=connect(path)
    other=sources.create(db,hostname='other')
    register_source(db,'b'*64,10,'other.evtx');sources.assign(db,other,['b'*64],reason='Synthetic')
    event(db,1,4688,SECURITY,'Security',{'CommandLine':'other.exe'},sha='b'*64)
    db.commit();db.close()
    scope=authorize(path,[sid,other],START,END,list(FAMILIES),'openai','scripted')
    view=ReadView(path,float('inf'));tools=Tools(view.db,scope,read_view=view)
    try:
        a=tools.execute('discover_execution_behaviors',{'source_id':sid});identity=tools.computation['population_id']
        b=tools.execute('discover_execution_behaviors',{'source_id':other})
        assert not tools.computation['cache_hit'] and identity!=tools.computation['population_id']
        assert not {r['evidence_id'] for r in a['records']} & {r['evidence_id'] for r in b['records']}
    finally:view.close()


def test_provider_free_sequence_script(tmp_path):
    import subprocess,sys
    from pathlib import Path
    path,sid,scope,*_=populate(tmp_path,1);before=path.read_bytes()
    output=subprocess.check_output([sys.executable,str(Path(__file__).resolve().parents[1]/'scripts/discover_execution_behaviors.py'),
        '--db',str(path),'--source',sid,'--start',START,'--end',END,'--sequence','--compare-fresh','--json'],text=True)
    result=json.loads(output)
    assert result['repeat_equal'] and len(result['operations'])==7
    assert all(c['equal'] for c in result['fresh_comparisons'])
    assert [o['computation']['cache_hit'] for o in result['operations']]==[False,True,True,True,True,True,True]
    assert path.read_bytes()==before


def test_cli_numerical_progress(tmp_path):
    from forensic_assistant.cli import build_parser
    from forensic_assistant.conversational_ai.cli import run
    from forensic_assistant.conversational_ai.provider import ScriptedProvider
    from test_conversational_ai import reply,call
    path,sid,scope,*_=populate(tmp_path,5)
    provider=ScriptedProvider([reply(calls=[call('discover_execution_behaviors',{})]),
        reply(calls=[call('discover_execution_behaviors',{'offset':1})]),reply('Review leads and alternatives.')])
    args=build_parser().parse_args(['--db',str(path),'investigation','chat','--source',sid,'--start',START,'--end',END])
    answers=iter(['Explore recorded behavior','y','/exit']);output=[]
    assert run(args,read=lambda _:next(answers),write=output.append,provider=provider)==0
    assert any('8 records;' in line and 'groups.' in line for line in output)
    assert any('reused' in line and '8 records;' in line for line in output)


def test_small_user_command_category_remains_discoverable(tmp_path):
    from forensic_assistant.artifacts.ingest import ingest_artifact
    from forensic_assistant.database import sources
    from forensic_assistant.conversational_ai.contracts import authorize,FAMILIES
    from v2_fixtures import registry_file
    path,sid,scope,*_=populate(tmp_path,100);db=connect(path)
    assert ingest_artifact(db,registry_file(tmp_path/'NTUSER.DAT',target='reviewer.exe document.txt'),'registry')['inserted']
    # Construct retained synthetic RunMRU context without case-specific indicators.
    db.execute("UPDATE registry_keys SET key_path='Software\\Synthetic\\RunMRU' WHERE key_path LIKE '%\\Run'")
    sources.assign(db,sid,[r[0] for r in db.execute("SELECT DISTINCT file_sha256 FROM evidence_records WHERE source_type='registry'")],reason='Synthetic')
    db.commit();db.close()
    scope=authorize(path,[sid],'2010-01-01T00:00:00Z','2030-01-01T00:00:00Z',list(FAMILIES),'openai','scripted')
    view=ReadView(path,float('inf'));tools=Tools(view.db,scope,read_view=view)
    try:
        r=tools.execute('discover_execution_behaviors',{})
        category=next(c for c in r['categories'] if c['category_filter']=='user_entered_command')
        assert category['groups']==2 and category['with_commands']==1
        narrowed=tools.execute('discover_execution_behaviors',{'category_filter':'user_entered_command'})
        assert tools.computation['cache_hit']
        assert all(x['kind']=='user_entered_command' for x in narrowed['records'])
        assert any('not individual value creation or execution' in limitation for x in narrowed['records'] for limitation in x['limitations'])
        assert normalized(narrowed)==Tools(view.db,scope).execute('discover_execution_behaviors',{'category_filter':'user_entered_command'})
    finally:view.close()

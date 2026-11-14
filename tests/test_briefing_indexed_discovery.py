"""6.90 indexed discovery, scope-safe continuation and same-view scheduling."""
from contextlib import closing
import json
import time
import pytest
from forensic_assistant import briefing as b
from forensic_assistant.database.db import connect
from forensic_assistant.database.artifacts import add_object
from forensic_assistant.retrieval.evidence import EvidenceQueries
from forensic_assistant.retrieval import object_discovery, evtx_content
from test_briefing_cross_artifact import artifact, Worker, run
from test_briefing import START, END
from test_evtx_content import add


@pytest.mark.parametrize('path',[r'C:\ProgramData\baje.ps1',r'\ProgramData\baje.ps1',r'C:\PROGRA~3\BAJE.PS1'])
def test_path_to_indexed_candidate_preserves_variants(path):
    with closing(connect(':memory:')) as db:
        eid=artifact(db,'mft');pf=artifact(db,'prefetch')
        add_object(db,eid,'short','file_path',r'\PROGRA~3\baje.ps1')
        add_object(db,eid,'full','file_path',r'\ProgramData\baje.ps1')
        add_object(db,pf,'volume','referenced_file',r'\VOLUME{synthetic}\PROGRAMDATA\BAJE.PS1')
        db.commit();before=list(db.iterdump());traces=[];db.set_trace_callback(traces.append)
        packet=run(db,path)
        assert packet['discovery']['counts']['returned_matches']==2
        assert set(packet['handoff']['evidence_ids'])=={eid,pf}
        assert packet['inputs']['original']==path
        assert packet['discovery']['outcomes'][0]['indicator']==packet['leads'][0]['occurrences'][0]['original']
        values=[f['value'] for r in packet['discovery']['outcomes'] for m in r['matches'] for f in m['matched_fields']]
        assert r'\PROGRA~3\baje.ps1' in values and r'\VOLUME{synthetic}\PROGRAMDATA\BAJE.PS1' in values
        assert not any('SELECT count(*) FROM (SELECT t.evidence_id' in sql for sql in traces)
        plan=db.execute('EXPLAIN QUERY PLAN SELECT DISTINCT evidence_id FROM evidence_objects WHERE basename=? AND evidence_id>? ORDER BY evidence_id LIMIT ?',('baje.ps1','',1001)).fetchall()
        assert any('object_basename' in r[3] for r in plan)
        assert list(db.iterdump())==before
        assert b.query_for(packet['leads'][0],'mft',START,END)['path']==packet['leads'][0]['occurrences'][0]['original']


def test_alias_not_invented_and_duplicate_slots_not_records():
    with closing(connect(':memory:')) as db:
        eid=artifact(db,'mft',filename='script~1.ps1')
        add_object(db,eid,'other','file_path',r'\Temp\script~1.ps1');db.commit()
        assert run(db,'script.ps1')['discovery']['counts']['returned_matches']==0
        result=EvidenceQueries(db).search(artifact='mft',object_basename='script~1.ps1',start=START,end=END,limit=10)
        assert len(result.records)==1 and result.records[0]['id']==eid


def test_failure_continues_only_with_valid_same_transaction():
    from forensic_assistant.investigation_ai.runner import WorkerError
    with closing(connect(':memory:')) as db:
        add(db)
        for family in ('mft','prefetch','registry','browser'):artifact(db,family)
        class Failure(Worker):
            def call(self,name,args=None,**kwargs):
                if name=='briefing_search' and args['artifact']=='mft':raise WorkerError('synthetic failure')
                return super().call(name,args,**kwargs)
        p=run(db,worker=Failure(db))
        assert p['metrics']['attempted_searches']==5
        assert p['discovery']['counts']['failed']==1 and p['discovery']['counts']['match']==4
        class Dead(Failure):
            def call(self,name,args=None,**kwargs):
                if name=='check':raise WorkerError('Worker unavailable')
                return super().call(name,args,**kwargs)
        p=run(db,worker=Dead(db))
        assert p['metrics']['attempted_searches']==1
        assert p['discovery']['counts']['not_searched']==4
        assert not p['discovery']['integrity_verified']


def test_soft_time_bound_retains_later_family_coverage(monkeypatch):
    monkeypatch.setattr(object_discovery,'SECONDS',0)
    with closing(connect(':memory:')) as db:
        artifact(db,'mft');add(db)
        p=run(db)
        assert p['metrics']['attempted_searches']==2
        assert next(r for r in p['discovery']['outcomes'] if r['artifact']=='mft')['status']=='truncated'
        assert next(r for r in p['discovery']['outcomes'] if r['artifact']=='evtx')['status']=='match'


@pytest.mark.parametrize('family',['mft','evtx'])
def test_explicit_continuation_no_repeats_and_scope_binding(family,monkeypatch):
    with closing(connect(':memory:')) as db:
        if family=='mft':
            for n in range(12):artifact(db,family,n)
        else:
            monkeypatch.setattr(evtx_content,'CANDIDATES',1)
            add(db,0,data=[('File','absent.exe')]);add(db,1)
        p=run(db)
        row=next(r for r in p['discovery']['outcomes'] if r['artifact']==family)
        token=row['continuation'];first={r['evidence_id'] for r in row['matches']}
        q=b.extract('baje.ps1');lead=q['leads'][0]['id']
        b.discover(q,'synthetic.db',[lead],'all',START,END,continuation=token,worker_factory=lambda _:Worker(db))
        resumed=next(r for r in q['discovery']['outcomes'] if r['artifact']==family)
        assert resumed['status']=='match' and not first.intersection(r['evidence_id'] for r in resumed['matches'])
        assert q['metrics']['attempted_searches']==1
        with pytest.raises(ValueError,match='continuation'):
            b.discover(b.extract('baje.ps1'),'other.db',[lead],'all',START,END,continuation=token,worker_factory=lambda _:pytest.fail('invalid scope'))
        changed=b.extract('baje.ps1');changed['saved_briefing']={'revision':2}
        with pytest.raises(ValueError,match='continuation'):
            b.discover(changed,'synthetic.db',[lead],'all',START,END,continuation=token,worker_factory=lambda _:pytest.fail('invalid revision'))


def test_object_candidate_limit(monkeypatch):
    with closing(connect(':memory:')) as db:
        for n in range(3):artifact(db,'mft',n)
        monkeypatch.setattr(object_discovery,'CANDIDATES',1)
        p=run(db)
        row=next(r for r in p['discovery']['outcomes'] if r['artifact']=='mft')
        assert row['search_coverage']['examined']==1 and row['status']=='truncated' and row['continuation']


def test_before_after_synthetic_performance():
    with closing(connect(':memory:')) as db:
        for n in range(1500):artifact(db,'mft',n,filename='baje.ps1' if n==1499 else f'unrelated-{n}.dat')
        at=time.perf_counter();old=EvidenceQueries(db).search(artifact='mft',path=r'C:\Synthetic\baje.ps1',start=START,end=END,limit=10);before=time.perf_counter()-at
        at=time.perf_counter();new=EvidenceQueries(db).search(artifact='mft',object_basename='baje.ps1',start=START,end=END,limit=10);after=time.perf_counter()-at
        assert [r['id'] for r in old.records]==[r['id'] for r in new.records]
        assert new.object_search['examined']==1
        print(f'1500-record synthetic: old {before:.6f}s; indexed {after:.6f}s; same single evidence ID; one candidate')


def test_registry_value_retains_inherited_timestamp():
    from forensic_assistant.database.artifacts import register
    with closing(connect(':memory:')) as db:
        key=artifact(db,'registry');eid=key+':value'
        register(db,dict(evidence_id=eid,source_type='registry',artifact_type='registry_value',
                        file_sha256='b'*64,source_file='synthetic-artifact',locator_json='{}'))
        db.execute('INSERT INTO registry_values VALUES (?,?,?,1,?,?,2)',(eid,key,'Run',b'x',json.dumps('baje.ps1')))
        add_object(db,eid,'target','persistence_target',r'C:\Temp\baje.ps1');db.commit()
        result=EvidenceQueries(db).search(artifact='registry',object_basename='baje.ps1',start=START,end=END,limit=10)
        record=next(r for r in result.records if r['id']==eid)
        assert record['timestamps'][0]['inherited_from_key']
        assert record['supporting_evidence_ids']==[key]


def test_continuation_requires_explicit_scope_in_cli():
    from forensic_assistant.cli import build_parser
    from forensic_assistant.briefing_cli import run as cli_run
    arguments=build_parser().parse_args(['investigation','briefing','inspect','--text','baje.ps1','--discovery-after','bad'])
    with pytest.raises(ValueError,match='requires --discover'):
        cli_run(arguments)

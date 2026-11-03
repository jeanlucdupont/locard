"""Synthetic cross-family discovery through existing queries, never a provider."""
from contextlib import closing
import copy
import json
import time
import pytest
from forensic_assistant import briefing as b, briefing_cli as cli, briefing_discovery as cross
from forensic_assistant.database.db import connect, register_source
from forensic_assistant.database.artifacts import register, add_object, add_timestamp
from test_briefing import START, END, MemoryWorker
from test_evtx_content import add
from test_briefing_persistence import store, args, value


def artifact(db, family, number=1, filename='baje.ps1'):
    sha = 'b'*64
    register_source(db,sha,100,'synthetic-artifact')
    eid=f'{family.upper()}:{sha}:{number}'
    register(db,dict(evidence_id=eid,source_type=family,artifact_type={'mft':'mft_record','registry':'registry_key','browser':'browser_download','prefetch':'prefetch'}[family],
        file_sha256=sha,source_file='synthetic-artifact',locator_json='{}',
        original_json=json.dumps(dict(url='https://example.org/'+filename,title='Synthetic download',url_chain=[]))))
    add_timestamp(db,eid,dict(slot='recorded',timestamp_utc='2026-09-30T12:00:00.000000Z',source='synthetic',meaning='metadata',normalization_status='normalized'))
    add_object(db,eid,'path','download_target' if family=='browser' else 'file_path','C:/Synthetic/'+filename)
    if family=='mft':
        db.execute('INSERT INTO mft_records VALUES (?,?,1,1,0,100,NULL,NULL,1024,?,?)',(eid,number,'{}',b''))
    elif family=='prefetch':
        db.execute('INSERT INTO prefetch_records VALUES (?, ?,1,1,30,?,?)',(eid,filename,b'','{}'))
    elif family=='registry':
        db.execute('INSERT OR IGNORE INTO registry_hives VALUES (?,?,?,0,?)',(sha,'SOFTWARE','synthetic','[]'))
        db.execute('INSERT INTO registry_keys VALUES (?,?,NULL,?)',(eid,'Software\\Synthetic'+str(number),number))
    db.commit()
    return eid


class Worker(MemoryWorker):
    def call(self,name,args=None,**kwargs):
        self.calls.append(name)
        if name=='initial':return dict(result=dict(available_artifacts=cross.available(self.db)),evidence_state={'synthetic':True})
        if name=='check':return {'result':{'checked':True}}
        return {'result':b.execute_query(self.db,args,cross=True)}


def run(db,text='baje.ps1',ids=None,worker=None):
    packet=b.extract(text)
    ids=ids or [lead['id'] for lead in packet['leads']]
    b.discover(packet,'synthetic.db',ids,'all',START,END,worker_factory=lambda _:worker or Worker(db))
    return packet


def test_five_families_same_indicator_read_only_and_render():
    with closing(connect(':memory:')) as db:
        expected={add(db),*(artifact(db,f) for f in b.ARTIFACTS if f!='evtx')}
        before=list(db.iterdump());at=time.perf_counter()
        packet=run(db)
        elapsed=time.perf_counter()-at
        outcomes=packet['discovery']['outcomes']
        assert [r['artifact'] for r in outcomes]==list(b.ARTIFACTS)
        assert {r['status'] for r in outcomes}=={'match'}
        assert set(packet['handoff']['evidence_ids'])==expected
        assert list(db.iterdump())==before
        for row in outcomes:
            match=row['matches'][0]
            assert match['source_file'] and match['timestamp_utc'] and match['matched_fields']
            assert 'baje.ps1' in match['matched_fields'][0]['value']
        human=cli.render(packet)
        assert all(eid in human for eid in expected)
        assert 'not proof of execution' in human and 'Totals:' in human
        assert cli.render(packet,details=True)==human
        print(f'five-family synthetic discovery: {elapsed:.6f}s; {packet["metrics"]["evidence_packet_bytes"]} aggregate bytes')


def test_multiple_leads_fair_query_budget_and_determinism():
    with closing(connect(':memory:')) as db:
        add(db)
        for f in b.ARTIFACTS[1:]:artifact(db,f)
        p=run(db,'baje.ps1 absent.exe')
        q=run(db,'baje.ps1 absent.exe')
        assert p['discovery']['outcomes']==q['discovery']['outcomes']
        assert p['metrics']['attempted_searches']==6
        assert p['discovery']['counts']['not_searched']==4
        assert p['discovery']['counts']['no_match']==3
        assert [x['lead_id'] for x in p['discovery']['queries'][:2]]==[r['id'] for r in p['leads']]
        assert len(p['handoff']['evidence_ids'])<=60


def test_unavailable_unsupported_and_no_match_are_distinct():
    with closing(connect(':memory:')) as db:
        artifact(db,'mft')
        packet=run(db,'absent.exe example.org')
        rows=packet['discovery']['outcomes']
        assert sum(r['status']=='unavailable' for r in rows)==8
        assert sum(r['status']=='unsupported' for r in rows)==1
        assert sum(r['status']=='no_match' for r in rows)==1
        assert packet['metrics']['attempted_searches']==1


def test_empty_case_does_not_search():
    with closing(connect(':memory:')) as db:
        w=Worker(db);p=run(db,worker=w)
        assert w.calls==['initial','check'] and w.closed
        assert p['discovery']['counts']['unavailable']==5


@pytest.mark.parametrize('ids',[[],['fake'],['x']*7])
def test_invalid_approvals_no_worker(ids):
    with pytest.raises(ValueError):
        b.discover(b.extract('baje.ps1'),'unused',ids,'all',START,END,worker_factory=lambda _:pytest.fail('worker'))


def test_window_rejected_before_worker():
    p=b.extract('baje.ps1')
    with pytest.raises(ValueError):
        b.discover(p,'unused',[p['leads'][0]['id']],'all',START,'2026-10-02T00:00:00Z',worker_factory=lambda _:pytest.fail('worker'))


def test_revision_mismatch_all(store):
    first=store.save(value('baje.ps1'),None)['revisions'][-1]
    store.save(value('new.ps1'),first['digest'])
    with pytest.raises(ValueError,match='revision'):
        cli.run(args(store,'--analyze','--deterministic','--discover','--artifact','all','--revision','1','--approve','fake','--start',START,'--end',END))


def test_sql_injection_remains_literal_and_result_limit():
    with closing(connect(':memory:')) as db:
        for n in range(12):artifact(db,'mft',n)
        p=run(db)
        row=next(r for r in p['discovery']['outcomes'] if r['artifact']=='mft')
        assert row['status']=='truncated' and len(row['matches'])==10
        result=b.execute_query(db,dict(artifact='mft',path="x' OR 1=1 --.exe",start=START,end=END,limit=10),cross=True)
        assert result['matches']==[] and cross.available(db)==['mft']


def test_worker_failure_check_and_payload_budget():
    from forensic_assistant.investigation_ai.runner import WorkerError
    with closing(connect(':memory:')) as db:
        add(db)
        class Failed(Worker):
            def call(self,name,args=None,**kwargs):
                if name=='briefing_search':raise WorkerError('TOOL_TIMEOUT')
                return super().call(name,args,**kwargs)
        w=Failed(db);p=run(db,worker=w)
        assert p['discovery']['counts']['failed']==1 and 'check' in w.calls and w.closed
        class Large(Worker):
            def call(self,name,args=None,**kwargs):
                result=super().call(name,args,**kwargs)
                if name=='briefing_search':result['result']['extra']='x'*200000
                return result
        p=run(db,worker=Large(db))
        assert not p['discovery']['queries'] and p['discovery']['counts']['truncated']==1


def test_actual_worker_and_database_unchanged(tmp_path):
    path=tmp_path/'case.db'
    with closing(connect(path)) as db:
        add(db);artifact(db,'mft')
    before=path.read_bytes();p=b.extract('baje.ps1')
    b.discover(p,path,[p['leads'][0]['id']],'all',START,END)
    assert p['discovery']['counts']['match']==2
    assert p['discovery']['integrity_verified']
    assert path.read_bytes()==before


def test_domain_routes_evtx_browser_and_source_projection():
    with closing(connect(':memory:')) as db:
        add(db,data=[('URL','https://example.org/report')])
        artifact(db,'browser')
        p=run(db,'example.org')
        assert [r['artifact'] for r in p['discovery']['outcomes'] if r['status']=='match']==['evtx','browser']
        assert all(r['matches'][0]['matched_fields'] for r in p['discovery']['outcomes'] if r['status']=='match')


def test_candidate_bound_is_truncated_not_absence(monkeypatch):
    from forensic_assistant.retrieval import evtx_content
    monkeypatch.setattr(evtx_content,'CANDIDATES',1)
    with closing(connect(':memory:')) as db:
        add(db,0,data=[('File','other.exe')]);add(db,1)
        p=run(db)
        row=p['discovery']['outcomes'][0]
        assert row['status']=='truncated' and row['matches']==[]
        assert not row['content_search']['complete']


def test_cancellation_closes_worker():
    class Cancelled(Worker):
        def call(self,name,args=None,**kwargs):
            if name=='briefing_search':raise KeyboardInterrupt
            return super().call(name,args,**kwargs)
    with closing(connect(':memory:')) as db:
        add(db);w=Cancelled(db)
        with pytest.raises(KeyboardInterrupt):run(db,worker=w)
        assert w.closed


def test_time_budget_stops_before_second_lookup(monkeypatch):
    class Clock:
        now=0
    monkeypatch.setattr(cross.time,'monotonic',lambda:Clock.now)
    class Slow(Worker):
        def call(self,name,args=None,**kwargs):
            result=super().call(name,args,**kwargs)
            if name=='briefing_search':Clock.now=86
            return result
    with closing(connect(':memory:')) as db:
        add(db);artifact(db,'mft');p=run(db,worker=Slow(db))
        assert p['metrics']['attempted_searches']==1
        assert next(r for r in p['discovery']['outcomes'] if r['artifact']=='mft')['status']=='not_searched'


def test_summary_editorial_and_narratives_unchanged():
    from test_briefing_summary_review import make,read
    from forensic_assistant import briefing_canonical as c
    p,proposal=make(['bad-ref'],'Unverified editable account.')
    accepted=c.review(proposal,read(['accept','y']))
    packet=b.extract('baje.ps1')
    packet['accepted_canonical']=accepted['document']
    packet['accepted_canonical_provenance']=accepted['original_provenance']
    before=copy.deepcopy(packet)
    with closing(connect(':memory:')) as db:
        b.discover(packet,'synthetic.db',[packet['leads'][0]['id']],'all',START,END,worker_factory=lambda _:Worker(db))
    for key in ('inputs','leads','accepted_canonical','accepted_canonical_provenance'):
        assert packet[key]==before[key]


def test_synthetic_scale_performance():
    with closing(connect(':memory:')) as db:
        for n in range(250):add(db,n)
        for f in b.ARTIFACTS[1:]:
            for n in range(25):artifact(db,f,n)
        at=time.perf_counter();packet=run(db);elapsed=time.perf_counter()-at
        assert packet['metrics']['attempted_searches']==5
        assert packet['discovery']['counts']['returned_matches']==50
        assert all(r['status']=='truncated' for r in packet['discovery']['outcomes'])
        assert packet['metrics']['evidence_packet_bytes']<=192*1024
        print(f'350-record synthetic discovery: {elapsed:.6f}s; 5 queries; 50 matches; {packet["metrics"]["evidence_packet_bytes"]} budgeted bytes')

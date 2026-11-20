"""Neutral synthetic discovery: no incident-specific indicators or providers."""
from contextlib import closing
import json
import pytest
from forensic_assistant import assessment as a, assessment_cli as cli, assessment_discovery as discovery
from forensic_assistant import briefing_entities as entities
from forensic_assistant.briefing_semantics import technical
from forensic_assistant.database.db import connect
from forensic_assistant.database import sources
from forensic_assistant.assessment_store import AssessmentStore
from forensic_assistant.briefing_store import Store
from test_assessment import accepted, arguments, factory
from test_briefing_cross_artifact import artifact
from test_browser_parser import history
from test_browser_integration import ingest as browser_ingest

START='2019-12-31T18:00:00-06:00'
END='2020-01-01T18:00:00-06:00'


@pytest.fixture
def neutral(tmp_path):
    case=tmp_path/'case.db'
    with closing(connect(case)) as db:
        with db:sid=sources.create(db,hostname='lab-node-7',volume_root='C:')
        for family in ('mft','prefetch','registry'):artifact(db,family,filename='notes.txt')
        with db:
            sources.assign(db,sid,['b'*64],reason='Synthetic source membership')
            db.execute("UPDATE evidence_timestamps SET timestamp_utc='2020-01-01T12:00:00.000000Z'")
        source=tmp_path/'History';history(source).close()
        browser_ingest(db,source,source=sid)
    revision=accepted(case,values=())
    return case,sid,revision


def test_displayed_exclusions_and_unknown(neutral):
    case,sid,revision=neutral
    p=a.plan(revision,AssessmentStore(case).identity,list(a.briefing.ARTIFACTS),START,END,source_id=sid)
    text=a.plan_text(p)
    for lead in p['leads']:
        assert lead['id'] in text
        assert a.exclusion_ids(p,lead['id'])=={lead['id']}
        assert a.exclusion_ids(p,lead['id'].swapcase())=={lead['id']}
    with pytest.raises(ValueError,match='Valid IDs:'):a.exclusion_ids(p,'A-not-an-id')
    with pytest.raises(ValueError):a.exclusion_ids(p,p['leads'][0]['id'][:-1])
    assert a.plan(revision,AssessmentStore(case).identity,list(a.briefing.ARTIFACTS),START,END,source_id=sid)==p


@pytest.mark.parametrize('word',['on','during','with','activity'])
def test_narrative_roles_not_hostnames(word):
    assert not entities.candidates('Investigate the computer '+word+' the specified date.')[1]
    with pytest.raises(ValueError):technical('hostname',word)


def test_valid_hostnames():
    assert technical('hostname','LAB-NODE-7')=='lab-node-7'
    assert entities.candidates('Hostname: atlas')[1]
    assert not entities.candidates('The computer suspicious activity')[1]


def test_source_scoped_date_only_application(neutral,monkeypatch):
    case,sid,_=neutral
    events=[]
    from forensic_assistant import activity
    monkeypatch.setattr(activity,'event',lambda action,outcome='success',**fields:events.append((action,outcome,fields)))
    before=case.read_bytes()
    with closing(connect(case)) as db:
        result=cli.run(arguments(case,'assess','--source',sid,'--start',START,'--end',END,answers=['','yes']),worker_factory=factory(db))
    assert result['integrity_verified']
    assert {r['artifact'] for r in result['records'].values()}=={'mft','prefetch','registry','browser'}
    assert result['plan']['source_id']==sid
    assert result['metrics']['queries']==5  # EVTX routes are unavailable.
    assert all(r['query']['source_id']==sid for r in result['rows'])
    assert all(sid in r['source_context']['source_ids'] for r in result['records'].values())
    assert result['authorization']['plan_digest']==a.digest(result['plan'])
    lookups=[fields for action,outcome,fields in events if action=='BRIEFING_LOOKUP' and outcome=='pending']
    assert len(lookups)==5
    assert all(item['scope']['source_id']==sid for item in lookups)
    assert all(item['scope']['start']=='2020-01-01T00:00:00Z' and item['scope']['end']=='2020-01-02T00:00:00Z' for item in lookups)
    assert case.read_bytes()==before
    assert json.loads(json.dumps(result))==result


def test_decline_and_unknown_id_no_execution(neutral):
    case,sid,_=neutral
    with closing(connect(case)) as db:
        result=cli.run(arguments(case,'assess','--source',sid,'--start',START,'--end',END,answers=['','n']),worker_factory=factory(db))
        assert 'cancelled' in result['message']
        assert not AssessmentStore(case).root.exists()


def test_displayed_search_is_excluded_from_execution(neutral):
    case,sid,revision=neutral
    p=a.plan(revision,AssessmentStore(case).identity,list(a.briefing.ARTIFACTS),'2020-01-01T00:00:00Z','2020-01-02T00:00:00Z',source_id=sid)
    excluded=next(r['lead_id'] for r in p['rows'] if r['artifact']=='mft')
    with closing(connect(case)) as db:
        result=cli.run(arguments(case,'assess','--source',sid,'--start',START,'--end',END,answers=[excluded.swapcase(),'yes']),worker_factory=factory(db))
    assert all(row['lead_id']!=excluded for row in result['rows'])
    assert all(record['artifact']!='mft' for record in result['records'].values())


def test_neutral_evtx_routes(neutral):
    from forensic_assistant.database.db import register_source,insert_events
    from forensic_assistant.ingest.normalize import normalize
    case,sid,_=neutral
    xml='<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Sysmon"/><EventID>1</EventID><Channel>Microsoft-Windows-Sysmon/Operational</Channel><TimeCreated SystemTime="2020-01-01T12:00:00Z"/><Computer>lab-node-7</Computer></System><EventData><Data Name="Image">C:\\Tools\\editor.exe</Data><Data Name="CommandLine">editor.exe notes.txt</Data></EventData></Event>'
    with closing(connect(case)) as db:
        with db:
            register_source(db,'c'*64,len(xml),'synthetic.evtx')
            event=normalize(xml,'c'*64,'synthetic.evtx',0)
            insert_events(db,[event])
            sources.assign(db,sid,['c'*64],reason='Synthetic source membership')
        for purpose in ('recorded_events','process_context'):
            result=discovery.search(db,dict(time_discovery=True,source_id=sid,artifact='evtx',purpose=purpose,start=START,end=END,limit=10))
            assert [r['evidence_id'] for r in result['matches']]==[event.id]
        with pytest.raises(ValueError,match='no searches executed'):
            cli.run(arguments(case,'assess','--source',sid,'--start',START,'--end',END,answers=['wrong']),worker_factory=factory(db))
        assert not AssessmentStore(case).root.exists()


def test_boundaries_missing_times_and_wrong_source(neutral):
    case,sid,_=neutral
    args=dict(time_discovery=True,source_id=sid,artifact='mft',purpose='file_metadata',start=START,end=END,limit=10)
    with closing(connect(case)) as db:
        with db:db.execute("UPDATE evidence_timestamps SET timestamp_utc='2020-01-02T00:00:00.000000Z' WHERE evidence_id LIKE 'MFT:%'")
        assert not discovery.search(db,args)['matches']
        with db:db.execute("UPDATE evidence_timestamps SET timestamp_utc='2020-01-01T00:00:00.000000Z' WHERE evidence_id LIKE 'MFT:%'")
        assert len(discovery.search(db,args)['matches'])==1
        with db:other=sources.create(db,hostname='other-node-8')
        assert not discovery.search(db,{**args,'source_id':other})['matches']
        with db:db.execute("UPDATE evidence_timestamps SET timestamp_utc=NULL WHERE evidence_id LIKE 'MFT:%'")
        empty=discovery.search(db,args)
        assert not empty['matches'] and any('Missing/ambiguous' in n for n in empty['limitations'])
        with pytest.raises(ValueError):discovery.search(db,{**args,'start':'2020-01-01'})


def test_bounded_continuation_and_query_plan(neutral,monkeypatch):
    case,sid,_=neutral
    args=dict(time_discovery=True,source_id=sid,artifact='mft',purpose='file_metadata',start=START,end=END,limit=10)
    with closing(connect(case)) as db:
        for n in range(2,8):artifact(db,'mft',number=n,filename='notes.txt')
        with db:db.execute("UPDATE evidence_timestamps SET timestamp_utc='2020-01-01T12:00:00.000000Z'")
        monkeypatch.setattr(discovery,'CANDIDATES',2)
        first=discovery.search(db,args)
        assert first['time_search']['examined']==2 and not first['time_search']['complete']
        cursor=first['time_search']['next_cursor'];assert cursor
        second=discovery.search(db,{**args,'time_after':cursor})
        assert {r['evidence_id'] for r in first['matches']}.isdisjoint(r['evidence_id'] for r in second['matches'])
        with pytest.raises(ValueError):discovery.search(db,{**args,'end':'2020-01-01T23:00:00Z','time_after':cursor})
        plan=db.execute('EXPLAIN QUERY PLAN SELECT t.timestamp_utc,t.evidence_id,t.slot FROM evidence_timestamps t INDEXED BY artifact_time CROSS JOIN evidence_records e ON e.evidence_id=t.evidence_id WHERE t.timestamp_utc>=? AND t.timestamp_utc<? AND e.source_type=? ORDER BY t.timestamp_utc,t.evidence_id,t.slot LIMIT 1001',('2020','2021','mft')).fetchall()
        assert any('artifact_time' in r[3] for r in plan)
        assert not any('TEMP B-TREE' in r[3] for r in plan)

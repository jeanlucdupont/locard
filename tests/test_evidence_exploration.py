"""6.149 provider-free exploration boundaries and source aggregate equivalence."""
import copy
import sqlite3
from contextlib import closing
from types import SimpleNamespace
import pytest
from forensic_assistant.cli import build_parser
from forensic_assistant.cli_time import absolute_utc
from forensic_assistant.database.db import connect,register_source
from forensic_assistant.database import sources
from forensic_assistant import source_cli,v2_cli,workflow_cli,terminal as t

@pytest.fixture(autouse=True)
def isolated(tmp_path,monkeypatch):
    monkeypatch.setenv('LOCALAPPDATA',str(tmp_path/'app'))
    monkeypatch.setenv('USERPROFILE',str(tmp_path/'user'))
    monkeypatch.setattr('forensic_assistant.ai.backend.ModelBackend.complete',lambda *a,**k:pytest.fail('provider call'))


def test_source_aggregates_preserve_membership_and_bounded_hosts():
    with closing(connect(':memory:')) as db:
        with db:
            a=sources.create(db,automatic=True);b=sources.create(db,name='Lab',hostname='asserted')
            register_source(db,'a'*64,1,'synthetic');register_source(db,'b'*64,1,'unassigned')
            sources.assign(db,a,['a'*64],reason='one');sources.assign(db,b,['a'*64],reason='two')
            for i in range(110):
                db.execute('INSERT INTO evidence_records(evidence_id,source_type,artifact_type,file_sha256,source_file,locator_json,extractor_version,warnings_json,original_json,hostname) VALUES (?,?,?,?,?,?,?,?,?,?)',(str(i),'mft','mft_record','a'*64,'synthetic','{}','test','[]','{}',f'host{i:03}'))
        before='\n'.join(db.iterdump())
        page=sources.listing(db)
        for row in page['sources']:
            sid=row['source_id']
            old_artifacts=dict(db.execute('SELECT e.source_type,count(*) FROM evidence_records e JOIN ('+sources.record_membership(db)+') m USING(evidence_id) WHERE m.source_id=? GROUP BY e.source_type',(sid,)))
            old_hosts=[r[0] for r in db.execute('SELECT DISTINCT e.hostname FROM evidence_records e JOIN ('+sources.record_membership(db)+') m USING(evidence_id) WHERE m.source_id=? AND e.hostname IS NOT NULL ORDER BY e.hostname LIMIT 101',(sid,))]
            assert row['artifacts']==old_artifacts and row['artifact_hostnames']==old_hosts[:100]
            assert row['host_conflict'] and row['artifact_hostnames_truncated'] and row['ambiguous_files']==1
            assert sources.detail(db,sid)['evidence_count']==110
        assert sources.coverage(db)['unassigned_files']==1
        assert before=='\n'.join(db.iterdump())
        shown=source_cli.render_list(page)
        assert 'Unnamed source' in shown and a not in shown
        assert a in source_cli.render_list(page,ids=True)
        row=page['sources'][0]
        assert row['source_id'] not in source_cli.render_show(sources.detail(db,row['source_id']))
        assert row['source_id'] in source_cli.render_show(sources.detail(db,row['source_id']),details=True)


def test_status_default_details_json_no_evidence_mutation(monkeypatch):
    from forensic_assistant.retrieval import status_display as display
    with closing(connect(':memory:')) as db:
        with db:
            db.execute("INSERT INTO ingestion_runs(source_file,started_utc,status,error_count) VALUES ('synthetic','2026','partial',1)")
            db.execute("INSERT INTO ingestion_errors(run_id,stage,message) VALUES (1,'parse','raw parser diagnostic')")
        before='\n'.join(db.iterdump())
        args=build_parser().parse_args(['case','status','--json']);result,_=v2_cli.dispatch(db,args)
        assert result['ingestion_errors'][0]['message']=='raw parser diagnostic'
        full=copy.deepcopy(result)
        normal=display.render(result,'C:/synthetic/case.db',display.context(db,verbose=False))
        assert 'raw parser diagnostic' not in normal and 'Recorded ingestion errors:' in normal
        assert 'raw parser diagnostic' in display.render(result,'C:/synthetic/case.db',display.context(db),verbose=True)
        assert result==full
        monkeypatch.setattr(display,'error_details',lambda *a:pytest.fail('unused error details'))
        v2_cli.dispatch(db,build_parser().parse_args(['case','status']),presentation={})
        assert before=='\n'.join(db.iterdump())


def test_case_listing_metadata_only_details():
    value={'cases':[dict(name='Lab',path='C:/lab/case.db',origin='legacy',status='discovered; not validated')]}
    before=copy.deepcopy(value)
    plain=workflow_cli.render(value)
    assert 'Legacy' not in plain and 'C:/' not in plain and 'Discovery' not in plain
    details=workflow_cli.render(value,details=True)
    assert 'Location:' in details and 'C:/lab/case.db' in details and 'not validated' not in details
    assert value==before


def test_source_selection_exact_id_and_cancellation(tmp_path,monkeypatch,capsys):
    from forensic_assistant.interactive.sources import prepare
    path=tmp_path/'case.db'
    with closing(connect(path)) as db:
        with db:
            a=sources.create(db,name='Same');b=sources.create(db,name='Same')
        ids=[r['source_id'] for r in sources.listing(db)['sources']]
    shell=SimpleNamespace(active=path,reader=SimpleNamespace(read=lambda prompt:'2'))
    args=build_parser(interactive=True).parse_args(['evidence','source','show'])
    assert prepare(shell,args) and args.source_id==ids[1]
    shell.reader.read=lambda prompt:''
    args=build_parser(interactive=True).parse_args(['evidence','source','show'])
    assert not prepare(shell,args) and args.source_id is None
    shell.reader.read=lambda prompt:'3'
    with pytest.raises(ValueError,match='displayed source page'):prepare(shell,args)
    args.json=True
    with pytest.raises(ValueError,match='exact source ID'):prepare(shell,args)


@pytest.mark.parametrize('value,expected',[
 ('2026-09-30','2026-09-30T00:00:00Z'),('2026-09-30T03','2026-09-30T03:00:00Z'),
 ('2026-09-30T03:00','2026-09-30T03:00:00Z'),('2026-09-30T03:00:00','2026-09-30T03:00:00Z'),
 ('2026-09-30T03:00Z','2026-09-30T03:00:00Z'),('2026-09-30T03:00-05:00','2026-09-30T08:00:00Z'),
 ('2026-09-30T00:03','2026-09-30T00:03:00Z'),('2026-09-30T03:00:00.123456789-05:00','2026-09-30T08:00:00.123456789Z')])
def test_cli_time(value,expected):
    assert absolute_utc(value)==expected
    args=build_parser().parse_args(['evidence','search','--start',value])
    assert args.start==expected

@pytest.mark.parametrize('value',['2026-02-30','2026-01-01T24','2026-01-01T02:61','2026-01-01T00:00+01:99','2026-01-01T00:00:60','03:00','2026-01-01T00:00:01.1234567890'])
def test_invalid_time(value):
    with pytest.raises(ValueError):absolute_utc(value)


def test_boundary_only_normalization():
    from forensic_assistant.model import utc_timestamp
    from forensic_assistant.retrieval.queries import required_time
    assert utc_timestamp('2026-09-30')[1]=='invalid'
    with pytest.raises(ValueError):required_time('2026-09-30')
    args=build_parser().parse_args(['evidence','timeline','--start','2026-09-30','--end','2026-10-01'])
    assert required_time(args.start)=='2026-09-30T00:00:00.000000000Z'
    assert required_time(args.end)=='2026-10-01T00:00:00.000000000Z'


def test_evtx_fallback_and_exact_timeline():
    from forensic_assistant.retrieval.presentation import human_detail
    from forensic_assistant.retrieval.mixed_display import compact_timeline
    r=dict(id='synthetic',source_type='evtx',artifact_type=None,provider='Other provider',event_id=4624,timestamp_utc='2026-09-30T00:00:00.123456789Z',timestamp={'slot':'Event.SystemTime'},warnings=[])
    before=copy.deepcopy(r)
    assert human_detail(r)=='Other provider — Event 4624'
    assert 'logon' not in human_detail(r)
    result=dict(records=[r,dict(r,timestamp={'slot':'Another slot'})],total=2,offset=0,truncated=False)
    text=compact_timeline(result,width=160)
    assert text.count('2026-09-30 00:00:00.123456789')==1 and 'Other provider — Event 4624' in text
    assert r==before


def test_warning_dedup_scope():
    from forensic_assistant.retrieval.search_display import render
    warning='Source volume was live and not frozen.'
    def record(n,sha):return dict(id=str(n),source_type='mft',detail={'record_number':n,'sequence_number':1,'allocated':True,'file_size':10,'names':[]},warnings=[warning],source={'sha256':sha,'acquisitions':[{'run_id':1}]},context={})
    result=dict(records=[record(1,'a'),record(2,'a'),record(3,'b')],total=715426,offset=0)
    before=copy.deepcopy(result);text=render(result)
    assert text.count(warning)==2 and 'Rows 1, 2:' in text and 'Row 3:' in text
    assert 'Showing 3 of 715,426' in text and result==before

def test_original_evtx_fallback_across_views_and_time_boundary():
    from test_evtx_content import add
    from forensic_assistant.retrieval.evidence import get_evidence,EvidenceQueries
    from forensic_assistant.retrieval import search_display,show_display,mixed_display
    with closing(connect(':memory:')) as db:
        eid=add(db,provider='Synthetic-Storage',event_id=549,data=[])
        before='\n'.join(db.iterdump())
        record=get_evidence(db,eid)
        assert record['kind'] is None
        text=search_display.render(EvidenceQueries(db).search().as_dict(),width=180)
        assert 'Synthetic-Storage — Event 549' in text
        assert 'Synthetic-Storage — Event 549' in show_display.render(record)
        args=build_parser(interactive=True).parse_args(['evidence','timeline','--start','2026-09-30T14:05:47','--end','2026-09-30T14:05:47'])
        result,_=v2_cli.dispatch(db,args)
        assert result['records'] and 'Synthetic-Storage — Event 549' in mixed_display.compact_timeline(result,width=180)
        assert before=='\n'.join(db.iterdump())


def test_progress_roles_and_new_options():
    assert t.STYLES['progress']=='96'
    assert build_parser().parse_args(['case','status','--details']).details
    assert build_parser().parse_args(['evidence','source','show','source-id','--details']).details
    assert build_parser().parse_args(['evidence','timeline','--details','--start','2026-01-01','--end','2026-01-02']).details

"""Irregular disposable evidence through the real supervised SQLite worker."""
import json
import sqlite3
from pathlib import Path
import pytest
from forensic_assistant.investigation_ai import autonomous, supervision, worker_diagnostics as d
from forensic_assistant.investigation_ai.transcript import load
from forensic_assistant.llm.client import LocalClient
from test_extended_search_reliability import configured, scripted_child


def irregular_child(connection, gate, request):
    # Reuse the real child with the scripted provider, adding two distinct context
    # calls before the third search without changing production allocations.
    from test_extended_search_reliability import scripted_child
    scripted_child(connection,gate,request)


@pytest.mark.parametrize('variant,location,exception',[
    ('optional',None,None),
    ('timestamp','CANDIDATE_ORDERING','ValueError'),
    ('mismatch','SEARCH_RESULT_VALIDATION','ValueError'),
    ('locator','EVIDENCE_HYDRATION','JSONDecodeError'),
    ('projection','EVIDENCE_PROJECTION','KeyError'),
    ('restoration','PROGRESS_HANDLER_RESTORATION','TypeError'),
    ('serialization','WORKER_RESPONSE_SERIALIZATION','TypeError'),
])
def test_irregular_third_search(tmp_path,monkeypatch,variant,location,exception):
    config=configured(tmp_path)
    config['_test_extra_context']=True
    with sqlite3.connect(config['case_path']) as db:
        db.execute('UPDATE events SET event_data_json=? WHERE id=?',(json.dumps([{'name':'SubjectUserName','value':'Synthetic actor'}]),config['_test_seed']))
        eid=db.execute("SELECT evidence_id FROM evidence_timestamps WHERE timestamp_utc LIKE '2026-09-30T13:00:07%' LIMIT 1").fetchone()[0]
        if variant=='timestamp':
            db.execute('UPDATE evidence_timestamps SET timestamp_utc=? WHERE evidence_id=?',('2026-09-30T13:00:07-invalid',eid))
        elif variant=='mismatch':
            db.execute('UPDATE events SET timestamp_utc=? WHERE id=?',('2026-09-30T18:00:00Z',eid))
        elif variant=='locator':
            db.execute('UPDATE evidence_records SET locator_json=? WHERE evidence_id=?',('SECRET invalid JSON',eid))
        else:
            db.execute('UPDATE events SET command_line=NULL, process_name=NULL,event_data_json=? WHERE id=?',
                (json.dumps([{'name':'Odd','value':None},{'name':'Odd','value':'x'*9000},17,{'name':'Unexpected','value':{'nested':True}}]),eid))
    if variant in ('projection','restoration','serialization'):
        shim=tmp_path/'worker_shim.py'
        source_root=str(Path(__file__).resolve().parents[1])
        mutation={
            'projection':"  def fail(*a,**k):raise KeyError('SECRET projection')\n  tools.compact=fail\n",
            'restoration':"  old=ReadView.deadline\n  def fail(self,value):\n   ReadView.deadline=old\n   raise TypeError('SECRET restoration')\n  ReadView.deadline=fail\n",
            'serialization':"  result['synthetic_bad_value']={object()}\n",
        }[variant]
        before_search=mutation if variant=='projection' else ''
        after_search=mutation if variant!='projection' else ''
        shim.write_text('import sys\n'+f'sys.path.insert(0,{source_root!r})\n'+
            'from forensic_assistant.investigation_ai import worker,follow_up,tools\n'+
            'from forensic_assistant.investigation_ai.case import ReadView\noriginal=follow_up._search\ncount=0\n'+
            'def search(*a,**k):\n global count\n count+=1\n'+
            (' if count==3:\n'+before_search if before_search else '')+
            ' result=original(*a,**k)\n'+(' if count==3:\n'+after_search if after_search else '')+
            ' return result\nfollow_up._search=search\nworker.serve()\n')
        config['_test_worker_script']=str(shim)
    before=Path(config['case_path']).read_bytes()
    monkeypatch.setattr(supervision,'_child',irregular_child)
    result=supervision.run(config,config['_stage_a']['objective'],tmp_path/'runs',client=LocalClient())
    assert result['follow_up']['executed']==3, result.get('failure_diagnostic')
    assert result['follow_up']['context_completed']==5, result
    assert result['startup_diagnostic']['cleanup_confirmed']
    if location:
        detail=result['failure_diagnostic']['worker']
        assert detail['location']==location
        assert detail['exception_class']==exception
        assert detail['deadline_exceeded'] is False
        assert detail['counts']['candidates_fetched']>0
        assert detail['category']==('WORKER_PROTOCOL_ERROR' if variant=='serialization' else 'WORKER_INTERNAL_ERROR' if variant in ('projection','restoration') else 'SEARCH_DATA_VALIDATION_FAILURE')
        assert result['validated_batches']==1 and len(result['work_batches'])==1
        assert result['termination']=='WORKER_FAILURE'  # Final read-view check succeeded.
        assert result['follow_up']['completed']==2
        from forensic_assistant.investigation_ai.presentation import render
        text=render(result)
        assert location in text and exception in text and 'SECRET' not in text
    else:
        assert result['validated_batches']==2, result.get('failure_diagnostic')
    assert Path(config['case_path']).read_bytes()==before
    one=autonomous.reconstruct(tmp_path/'runs',result['investigation_id'])
    assert one==autonomous.reconstruct(tmp_path/'runs',result['investigation_id'])
    assert one['findings']==result['findings']
    _,events=load(tmp_path/'runs',result['investigation_id'])
    assert 'SECRET invalid JSON' not in json.dumps(events)


@pytest.mark.parametrize('location',d.LOCATIONS)
def test_location_allowlist_and_cleanup_preserves_origin(location):
    trace=d.Trace()
    try:
        try:
            with trace.at(location):raise KeyError('SECRET evidence')
        finally:
            with trace.at('PROGRESS_HANDLER_RESTORATION'):pass
    except KeyError as exc:
        value=d.classify(exc,'temporal_search',False,trace)
    d.validate(value)
    assert value['location']==location and value['exception_class']=='KeyError'
    assert 'SECRET' not in json.dumps(value)
    for key,bad in [('location','SECRET'),('exception_class','SecretClass'),('counts',{'SECRET':1})]:
        with pytest.raises(ValueError):d.validate({**value,key:bad})
    d.validate(d.detail('WORKER_INTERNAL_ERROR','temporal_search'))


def test_restoration_failure_takes_own_location():
    trace=d.Trace()
    try:
        try:
            with trace.at('EVIDENCE_PROJECTION'):raise KeyError('SECRET')
        finally:
            with trace.at('PROGRESS_HANDLER_RESTORATION'):raise TypeError('SECRET cleanup')
    except TypeError as exc:detail=d.classify(exc,'temporal_search',False,trace)
    assert detail['location']=='PROGRESS_HANDLER_RESTORATION'
    assert detail['exception_class']=='TypeError'


def test_browser_candidates_and_source_exclusions(tmp_path,monkeypatch):
    from contextlib import closing
    from datetime import datetime,timezone
    from forensic_assistant.database.db import connect
    from test_browser_parser import history
    from test_browser_integration import ingest
    config=configured(tmp_path)
    source=tmp_path/'History'
    stamp=int((datetime(2026,9,30,13,0,2,tzinfo=timezone.utc)-datetime(1601,1,1,tzinfo=timezone.utc)).total_seconds()*1000000)
    with closing(history(source)) as db:
        db.execute('UPDATE visits SET visit_time=?',(stamp,))
        db.execute('UPDATE downloads SET start_time=?,end_time=?,referrer=NULL',(stamp,stamp+1000000))
        db.commit()
    with closing(connect(config['case_path'])) as db:
        assert ingest(db,source,source=config['_stage_a']['source_ids'][0])['inserted']==2
        assert ingest(db,source,product='edge',profile='OutsideScope',host='other')['inserted']==2
    config['_stage_a']['families']=['browser','evtx']
    config['_test_family']='browser'
    before=Path(config['case_path']).read_bytes()
    monkeypatch.setattr(supervision,'_child',irregular_child)
    result=supervision.run(config,config['_stage_a']['objective'],tmp_path/'runs',client=LocalClient())
    assert result['validated_batches']==2, result.get('failure_diagnostic')
    assert result['follow_up']['executed']==3
    last=result['follow_up']['searches'][-1]
    assert len(last['returned_ids'])==2
    assert last['fetched_candidates']>=4
    assert all(eid.startswith('BROWSER:') for eid in last['returned_ids'])
    assert result['startup_diagnostic']['cleanup_confirmed']
    assert Path(config['case_path']).read_bytes()==before
    one=autonomous.reconstruct(tmp_path/'runs',result['investigation_id'])
    assert one==autonomous.reconstruct(tmp_path/'runs',result['investigation_id'])

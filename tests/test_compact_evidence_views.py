"""Presentation-only regression checks using synthetic evidence."""
import copy
import json
from contextlib import closing
import pytest
from forensic_assistant import source_cli,terminal,output
from forensic_assistant.cli import main
from forensic_assistant.database.db import connect
from forensic_assistant.database import sources
from forensic_assistant.retrieval.evidence import get_evidence
from forensic_assistant.retrieval.search_display import render as search
from forensic_assistant.retrieval.show_display import render as show
from forensic_assistant.retrieval.layout import pagination
from test_output_ux import case
from test_source_path_selection import make_case
from test_cli_presentation_cleanup import source_rows


@pytest.mark.parametrize('count,total,offset,expected',[(1,1,0,''),(0,0,0,''),(35,35,0,''),(10,19,0,'Showing 10 of 19'),(10,83,10,'Showing 11\u201320 of 83'),(0,19,30,'Showing 0 of 19')])
def test_pagination(count,total,offset,expected):assert pagination(count,total,offset)==expected


def test_prefetch_summary_and_unchanged_structures(case,capsys):
    path,eid,_=case;before=path.read_bytes()
    with closing(connect(path)) as db:
        expected=get_evidence(db,eid);raw=get_evidence(db,eid,True)
    assert main(['--db',str(path),'show',eid])==0
    text=capsys.readouterr().out
    for value in (eid,'SHA-256','Recorded run count: 5','Referenced files: 220','Showing 5 of 220','REFERENCE_ONLY_004','2 of 2 slots populated','not necessarily executed','not a content hash'):
        assert value in text
    assert 'REFERENCE_ONLY_005' not in text
    for flag,data in [('--json',expected),('--raw',raw)]:
        assert main(['--db',str(path),'show',eid,flag])==0
        assert json.loads(capsys.readouterr().out)==data
    assert path.read_bytes()==before


@pytest.mark.parametrize('kind,detail,expected',[
    ('mft',dict(record_number=42,sequence_number=3,allocated=1,names=[dict(filename='sample.txt')]),'Record number: 42'),
    ('registry',dict(key_path='Software\\Synthetic',value_name='Run',value_type=1,value_data='sample.exe'),'Value data: sample.exe'),
    ('evtx',{},'Event id: 4688')])
def test_artifact_show(kind,detail,expected):
    record=dict(id=kind+':synthetic',source_type=kind,detail=detail,event_id=4688,context={},warnings=['Parser quality warning'],timestamps=[dict(slot='missing',timestamp_utc=None),dict(slot='present',timestamp_utc='2020-01-01T00:00:00.123456789Z',inherited_from_key=kind=='registry')])
    before=copy.deepcopy(record);text=show(record)
    assert expected in text and 'Parser quality warning' in text and '1 of 2 slots populated' in text
    assert 'missing:' not in text and '00:00:00.123' in text
    if kind=='registry':assert 'not the value' in text
    assert record==before


@pytest.mark.parametrize('width',[40,80,120])
@pytest.mark.parametrize('ids',[False,True])
def test_search_table_width_ids_paths_precision(case,width,ids):
    with closing(connect(case[0])) as db:r=get_evidence(db,case[1])
    r['objects']=[dict(role='executable_path_candidate',original='C:\\'+'long directory\\'*12+'SYSTEM32\\APP.EXE')]
    r['objects_truncated']=False;r['timestamps'][0]['timestamp_utc']='2020-09-19T05:08:43.031392300Z'
    other=copy.deepcopy(r);other['context']['hostname']='other-host';other['id']='PREFETCH:other:File'
    result=dict(records=[r,other],total=19,offset=0);before=copy.deepcopy(result)
    text=search(result,width=width,ids=ids)
    assert 'LAST RUN (UTC)' in text and '05:08:43.031' in text and '031392300' not in text
    assert 'Showing 2 of 19' in text and 'other-host' in text
    assert (r['id'] in text)==ids and 'Host basis' not in text and 'SEARCH RESULTS' not in text
    if not ids:assert max(map(len,text.splitlines()))<=width
    assert terminal.SGR.sub('',search(result,terminal.Palette(True),width=width,ids=ids))==text
    assert result==before


def test_source_list_noise_and_help(capsys):
    text=source_cli.render_list(source_rows())
    for forbidden in ('SOURCES','abbreviations','Showing','offset','more:'):assert forbidden not in text
    with pytest.raises(SystemExit):main(['source','list','--help'])
    assert 'abbreviations' in capsys.readouterr().out


def test_source_summary_overlapping_assignment_details(tmp_path,capsys):
    path=tmp_path/'case.db';sid,hashes=make_case(path)
    with closing(connect(path)) as db:
        with db:
            sources.assign(db,sid,hashes[:1],reason='First reviewed subset')
            sources.assign(db,sid,hashes[:3],reason='Second reviewed subset')
        expected=sources.detail(db,sid)
    before=path.read_bytes();base=['--db',str(path),'source','show',sid]
    assert main(base)==0;text=capsys.readouterr().out
    assert 'Distinct source files: 3' in text and 'assignment-to-file links: 4' in text
    assert 'Retrospective assignments: 2' in text and 'Assertion revisions: 1' in text
    assert hashes[0] not in text and sid in text and 'synthetic-host' in text
    for flag in ('--details','--json'):
        assert main(base+[flag])==0
        assert json.loads(capsys.readouterr().out)==expected
    assert path.read_bytes()==before


@pytest.mark.parametrize('command',['show','source'])
def test_new_summaries_pager_files(case,tmp_path,monkeypatch,capsys,command):
    if command=='show':base=['--db',str(case[0]),'show',case[1]]
    else:
        path=tmp_path/'other.db';sid,_=make_case(path);base=['--db',str(path),'source','show',sid]
    captured=[];monkeypatch.setattr(output,'page',lambda stream,palette=None:captured.append(stream.read()))
    assert main(base+['--page'])==0
    target=tmp_path/'summary.txt'
    for flag in ('--output','--append'):assert main(base+[flag,str(target)])==0
    data=target.read_text(encoding='utf-8')
    assert data==captured[0]+'\n'+captured[0] and '\x1b' not in data

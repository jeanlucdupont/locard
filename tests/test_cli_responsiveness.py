"""6.148: synthetic status equivalence and presentation lifecycle only."""
import copy
import io
import time
from types import SimpleNamespace
from contextlib import closing
import pytest
from forensic_assistant import terminal as t, terminal_activity as ui, workflow_cli, session_recording as sr
from forensic_assistant.database.db import connect
from forensic_assistant.artifacts.userassist import timeline_cte, timeline_count
from forensic_assistant.cli import build_parser
from forensic_assistant import v2_cli
from test_terminal_activity import terminal, wait_for


def test_aligned_fields_semantics_and_narrow_layout():
    def view(color,width):
        p=t.Palette(color)
        return t.aligned_lines([t.field('Short','one',p),t.field('Long label','two words '*8,p,role='warning')],width=width)
    wide=view(False,60)
    assert wide.splitlines()[0].index('one')==wide.splitlines()[1].index('two')
    assert t.SGR.sub('',view(True,60))==wide
    assert all(len(line)<=60 for line in wide.splitlines())
    assert view(False,20).splitlines()[:2]==['Short:','  one']
    assert '\x1b' not in t.aligned_lines([t.field('Label','\x1b[31munsafe')])


def test_case_list_details_preserve_data():
    value={'cases':[dict(name='A',origin='legacy',path='C:/synthetic/A/case.db',status='discovered; not validated'),dict(name='A',origin='registered',path='C:/other/case.db',status='missing')]}
    before=copy.deepcopy(value)
    plain=workflow_cli.render(value)
    assert 'C:/' not in plain and 'not validated' not in plain
    assert plain.count('A ')==2 and 'missing' in plain
    details=workflow_cli.render(value,details=True)
    assert 'C:/synthetic/A/case.db' in details and 'discovered; not validated' in details
    assert value==before
    args=build_parser().parse_args(['case','list','--details','--json'])
    assert args.details and args.json


def test_limitation_brown_and_fallback(monkeypatch):
    from forensic_assistant.retrieval.status_display import render
    monkeypatch.setenv('COLORTERM','truecolor')
    for count in [0,5]:
        result={'artifact_counts':{'mft':count}}
        details=dict(runs={},dirty_hives=0,hive_warnings=[],error_summaries=[])
        output=render(result,'synthetic',details,t.Palette(True))
        assert '\x1b[38;5;136m  ' in output
        assert '\x1b[97mLimitations' in output
        assert t.SGR.sub('',output)==render(result,'synthetic',details)
    monkeypatch.delenv('COLORTERM');monkeypatch.delenv('WT_SESSION',raising=False);monkeypatch.setenv('TERM','dumb')
    assert t.Palette(True)('forensic_note','note')=='\x1b[37mnote\x1b[0m'


def test_audit_summary_no_redundant_success_and_errors_visible():
    value=dict(activity=dict(valid=True,exists=True),sessions=[dict(session_id='s',integrity='verified',limitations=['policy'])])
    before=copy.deepcopy(value)
    text=sr.integrity_summary(value)
    assert 'No integrity failures' not in text and 'Recording limitations' not in text
    assert value==before
    value['sessions'][0]['integrity']='corrupt'
    assert 'Integrity verification failed' in sr.integrity_summary(value)


def test_delayed_operation_and_nested_owner(terminal):
    with ui.operation('Fast') as fast:
        assert fast.delay==.5
    assert not terminal.getvalue()
    with ui.ActivityIndicator('Outer',delay=.01) as outer:
        wait_for(lambda:bool(terminal.getvalue()))
        with ui.operation('Inner') as inner:
            assert inner._thread is None
        assert outer._thread.is_alive()
    assert terminal.getvalue().endswith('\r\x1b[K')


def test_frames_suppress_recording(terminal,monkeypatch):
    states=[]
    def frame(*args):
        states.append(sr.SUPPRESS.get());return True
    monkeypatch.setattr(ui,'replace_progress_line',frame)
    with ui.ActivityIndicator('Work',delay=.01):
        wait_for(lambda:bool(states))
    assert all(states) and len(states)>=2


@pytest.mark.parametrize('version',[3,5])
def test_timestamp_count_equivalence_with_legacy_userassist(tmp_path,version):
    from v2_fixtures import registry_file
    from test_userassist import RAW_NAME,binary
    from forensic_assistant.artifacts.ingest import ingest_artifact
    with closing(connect(':memory:')) as db:
        assert timeline_count(db)==0
        hive=registry_file(tmp_path/'synthetic.DAT',userassist=[(RAW_NAME,3,binary(version))],userassist_version=version)
        assert ingest_artifact(db,hive,'registry')['status']=='complete'
        args=build_parser().parse_args(['case','status','--json'])
        for legacy in [False,True]:
            if legacy:
                db.execute("DELETE FROM evidence_timestamps WHERE slot='UserAssist.LastExecution'")
            before='\n'.join(db.iterdump())
            old=db.execute(timeline_cte(db)+'SELECT count(*) FROM locard_times WHERE timestamp_utc IS NOT NULL').fetchone()[0]
            assert timeline_count(db)==old
            assert v2_cli.dispatch(db,args)[0]['timeline_observations']==old
            assert '\n'.join(db.iterdump())==before

def test_ascii_fallback_and_thread_start_failure(terminal,monkeypatch):
    monkeypatch.setattr(t,'supports_unicode',lambda *a:False)
    with ui.ActivityIndicator('ASCII',delay=.01):
        wait_for(lambda:'| ASCII' in terminal.getvalue())
    monkeypatch.setattr(ui.threading.Thread,'start',lambda self:(_ for _ in ()).throw(RuntimeError('unavailable')))
    with ui.operation('Unavailable') as indicator:
        assert indicator._thread is None and not indicator._owns_line
    assert not ui._OWNER.locked()


def test_current_recording_failure_remains_visible():
    token=sr.ACTIVE.set(SimpleNamespace(broken=True,segment='s',head={}))
    try:
        text=sr.integrity_summary(dict(activity=dict(valid=True,exists=True),sessions=[]))
        assert 'Current session recording failed' in text
    finally:
        sr.ACTIVE.reset(token)

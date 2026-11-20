"""Ingestion presentation uses synthetic results, clocks and history only."""
import copy
import io
import json
from types import SimpleNamespace

import pytest

from forensic_assistant import activity, v2_cli
from forensic_assistant.database.db import connect
from forensic_assistant.ingest import presentation as view
from forensic_assistant.retrieval import status_display
from forensic_assistant.terminal import Palette, SGR


def row(status='partial', inserted=918450, errors=2451):
    return dict(source_type='mft', status=status, inserted=inserted, errors=errors, duplicates=0,
                acquisition={'source_state': 'live mounted volume; not frozen', 'elapsed_seconds':8},
                limitation='Legacy combined operational failure and acquisition message')


@pytest.mark.parametrize('seconds,text', [(None,'unavailable'), (0,'0s'), (8.99,'8s'),
    (272,'4m 32s'), (4685,'1h 18m 05s'), (9258,'2h 34m 18s')])
def test_duration(seconds,text):
    assert view.duration(seconds) == text


@pytest.mark.parametrize('status,retained,role', [('complete',12,'success'), ('partial',12,'warning'),
    ('partial',0,'warning'), ('failed',0,'error'), ('failed',12,'error'), ('cancelled',12,'warning')])
def test_structured_outcome_roles_and_unchanged_data(status,retained,role):
    value = dict(results=[row(status,retained)], elapsed_seconds=9258)
    before = copy.deepcopy(value)
    p = Palette(True)
    text = view.render(value,p)
    assert p(role,view.outcome(status,retained)) in text
    assert p('value',f'{retained:,}') in text
    assert p('error','2,451') in text
    assert p('value','2h 34m 18s') in text
    assert 'Acquisition time:' in SGR.sub('',text)
    assert 'Legacy combined' not in text
    assert p('heading','MFT INGESTION') in text
    assert value == before
    assert SGR.sub('',text) == view.render(value)


def test_native_partial_does_not_claim_failure_or_explain_cause():
    result = dict(results=[row()],elapsed_seconds=8)
    text = view.render(result)
    assert '918,450' in text and '2,451' in text and 'Partial' in text
    assert 'failed' not in text.lower()
    assert 'live' in text and 'coverage is incomplete' in text
    assert 'corrupt' not in text and 'lost records' not in text
    assert 'Elapsed time:' in text


@pytest.mark.parametrize('exc', [KeyboardInterrupt(), EOFError(), ValueError('synthetic failure'),
                               activity.AuditError('completion failed')])
def test_exception_and_cancellation_duration(exc,capsys):
    view.interrupted(exc,272)
    text = capsys.readouterr().err
    assert '4m 32s' in text
    assert 'Completed' not in text
    assert ('Uncertain' in text) == isinstance(exc,activity.AuditError)


@pytest.mark.parametrize('status', ['complete','partial','failed'])
def test_dispatch_monotonic_and_json_additive(monkeypatch,status):
    clock = [100]
    monkeypatch.setattr(view,'time',SimpleNamespace(monotonic=lambda:clock[0]))
    rows = [row(status,0 if status=='failed' else 12)]
    def ingest(*args):
        clock[0] += 272.7
        return rows
    monkeypatch.setattr(v2_cli,'ingest_sources',ingest)
    db = connect(':memory:')
    try:
        value,code = v2_cli.dispatch(db,SimpleNamespace(command='ingest-mft'))
        assert value['results'] is rows
        assert value['elapsed_seconds'] == 272.7
        assert code == (0 if status=='complete' else 1)
        assert value['status'] == ('complete' if status=='complete' else 'incomplete')
        assert '\x1b' not in json.dumps(value)
    finally: db.close()


@pytest.mark.parametrize('exc', [KeyboardInterrupt(), activity.AuditError('failed completion'), OSError('failed')])
def test_command_failure_reports_time_once_and_propagates(monkeypatch,capsys,exc):
    from forensic_assistant import cli
    clock=[10]
    monkeypatch.setattr(view,'time',SimpleNamespace(monotonic=lambda:clock[0]))
    def body(*a,**k):
        clock[0]=70
        raise exc
    monkeypatch.setattr(cli,'_dispatch_command_body',body)
    args=SimpleNamespace(command='ingest-mft',json=True)
    with pytest.raises(type(exc)):
        cli._dispatch_command(args)
    output=capsys.readouterr()
    assert output.out == '' and output.err.count('Elapsed time:')==1
    assert '1m 00s' in output.err and '\x1b' not in output.err
    assert not hasattr(args,'_ingestion_timer')


@pytest.mark.parametrize('retry_status', ['complete','partial'])
def test_recorded_failure_then_retry_stays_historical_and_read_only(retry_status):
    from forensic_assistant.cli import build_parser
    db=connect(':memory:')
    try:
        with db:
            for status,message in [('failed','ValueError: Parser worker timed out; staged output rejected'),
                                   (retry_status,'EOFError:')]:
                run=db.execute('INSERT INTO ingestion_runs(source_file,started_utc,status,error_count) VALUES (?,?,?,?)',
                               ('synthetic','2026',status,1)).lastrowid
                db.execute("INSERT INTO artifact_runs VALUES (?,'mft','synthetic','1','1',NULL,?)",
                           (run,json.dumps({'acquisition':{'source_state':'live mounted volume; not frozen'}})))
                db.execute('INSERT INTO ingestion_errors(run_id,stage,message) VALUES (?,?,?)',(run,'parse',message))
        before='\n'.join(db.iterdump())
        result,_=v2_cli.dispatch(db,build_parser().parse_args(['case','status','--json']))
        original=copy.deepcopy(result)
        context=status_display.context(db)
        normal=status_display.render(result,'synthetic',context)
        assert 'EOFError' not in normal and 'timed out' not in normal
        assert 'lost records' not in normal and 'live' in normal
        text=status_display.render(result,'synthetic',context,Palette(True),verbose=True)
        diagnostics=text.split('Ingestion diagnostics',1)[1]
        assert 'EOFError:' in diagnostics and 'ValueError: Parser worker timed out' in diagnostics
        assert '\x1b[31m' not in diagnostics and '\x1b[33m' not in diagnostics
        assert 'unavailable (not recorded)' in diagnostics
        assert result==original and '\n'.join(db.iterdump())==before
    finally:db.close()


def test_guided_uses_same_limitations_and_outcome_roles():
    from forensic_assistant.interactive import setup,setup_display
    progress=setup.Progress(); progress(None,'mft',row())
    assert set(progress.limitations)==set(view.limitations(row()))
    text=setup_display.category_line('mft',progress,Palette(True))
    assert Palette(True)('warning','partial') in text
    assert '918,450 records retained' in text


def test_alignment_and_unavailable_duration():
    text=view.render(dict(results=[row()]))
    assert 'unavailable' in text
    # Labels keep their own colon, values align in the shared field formatter.
    fields=[line for line in text.splitlines() if line.startswith(('Records retained','Duplicates:','Recorded errors:'))]
    assert len({line.index(':')+1+len(line.split(':',1)[1])-len(line.split(':',1)[1].lstrip()) for line in fields})==1


@pytest.mark.parametrize('error', [KeyboardInterrupt, OSError, activity.AuditError])
def test_guided_exception_elapsed_and_prior_case_preserved(tmp_path,monkeypatch,capsys,error):
    from forensic_assistant.interactive import setup
    from test_add_evidence import manual
    from test_interactive_shell import Input
    from forensic_assistant.interactive.shell import Shell
    from forensic_assistant.interactive.state import State
    from v2_fixtures import mft_file
    target=tmp_path/'case.db';connect(target).close()
    shell=Shell(State(None),Input(),no_color=True)
    shell.activate(target)
    (tmp_path/'evidence').mkdir()
    source=mft_file(tmp_path/'evidence'/'MFT')
    original=source.read_bytes()
    shell.reader=Input(*manual(source))
    clock=[100]
    monkeypatch.setattr(setup,'monotonic',lambda:clock[0])
    def fail(*a,**kw):
        clock[0]=372
        raise error('synthetic interruption')
    monkeypatch.setattr(setup,'execute',fail)
    try:
        assert not setup.add_evidence(shell)
        text=capsys.readouterr().out
        assert text.count('Elapsed time:')==1 and '4m 32s' in text
        assert shell.active == target.resolve() and source.read_bytes()==original
        assert ('outcome uncertain' in text) == (error is activity.AuditError)
    finally:
        shell.audit.end()


def test_forensic_note_uses_existing_brown_role(monkeypatch):
    monkeypatch.setenv('COLORTERM','truecolor')
    text=view.render(dict(results=[row()],elapsed_seconds=8),Palette(True))
    assert '\x1b[38;5;136m  Source volume was live' in text
    assert '\x1b[31m' not in text.split('Limitations', 1)[1]


def test_acquisition_failure_is_operational_not_forensic_note():
    value=dict(results=[dict(source_type='mft',status='failed',inserted=0,duplicates=0,errors=1,
                            acquisition_error='access denied',limitation='Administrator access required')])
    text=view.render(value,Palette(True))
    assert Palette(True)('error','Administrator access required') in text
    assert 'Limitations' not in text

from contextlib import closing
from pathlib import Path
import sqlite3
import pytest
from forensic_assistant.interactive import creation
from forensic_assistant.interactive.shell import Shell
from forensic_assistant.interactive.state import State
from forensic_assistant.database.db import connect
from test_interactive_shell import Input, case
from v2_fixtures import mft_file, prefetch_file, registry_file


def wizard(tmp_path, *tail, missing=False):
    source=tmp_path/'evidence';source.mkdir()
    target=tmp_path/('nested/case.db' if missing else 'case.db')
    reader=Input(str(target),*(['yes'] if missing else []),str(source),'e','','','','','yes',*tail)
    return Shell(State(None),reader),target,source


@pytest.mark.parametrize('name',['case.db','space name.db','résumé.db'])
def test_exclusive_initialization(tmp_path,name,monkeypatch):
    monkeypatch.chdir(tmp_path)
    target=creation.initialize(Path(name))
    assert creation.validate(target)==tmp_path/name
    original=target.read_bytes()
    with pytest.raises(FileExistsError):creation.initialize(target)
    assert target.read_bytes()==original
    assert not list(tmp_path.glob('.locard-init-*'))


def test_publication_race_preserves_competing_file(tmp_path,monkeypatch):
    target=tmp_path/'case.db';original=creation.validate
    def race(path):
        result=original(path);target.write_bytes(b'competing file');return result
    monkeypatch.setattr(creation,'validate',race)
    with pytest.raises(FileExistsError):creation.initialize(target)
    assert target.read_bytes()==b'competing file'
    assert not list(tmp_path.glob('.locard-init-*'))


@pytest.mark.parametrize('error',[OSError('unwritable'),KeyboardInterrupt()])
def test_failed_initialization_retains_requested_parents(tmp_path,monkeypatch,error):
    target=tmp_path/'requested'/'nested'/'case.db'
    def fail(*args,**kwargs):raise error
    monkeypatch.setattr(creation,'connect',fail)
    with pytest.raises(type(error)):creation.initialize(target,True)
    assert target.parent.is_dir() and not target.exists()
    assert not list(target.parent.iterdir())


@pytest.mark.parametrize('cancel',['n','',KeyboardInterrupt(),EOFError()])
def test_before_confirmation_no_filesystem_changes(tmp_path,cancel):
    source=tmp_path/'evidence';source.mkdir();target=tmp_path/'new'/'case.db'
    shell=Shell(State(None),Input(str(target),'yes',str(source),'e','','','',cancel))
    assert not creation.create(shell)
    assert not target.parent.exists() and shell.active is None and not shell.state.recent


def test_decline_missing_parent_returns_destination(tmp_path):
    shell=Shell(State(None),Input(str(tmp_path/'new'/'case.db'),'n',''))
    assert not creation.create(shell) and not (tmp_path/'new').exists()
    assert shell.reader.prompts[-1].startswith('New database')


def test_empty_case_first_run_and_recent(tmp_path):
    shell,target,source=wizard(tmp_path,missing=True)
    lines=['1',str(target),'yes',str(source),'e','','','','','yes','exit']
    shell=Shell(State(tmp_path/'ui.json'),Input(*lines))
    assert shell.run()==0 and shell.active==target
    assert State(shell.state.path).load().recent==[str(target)]
    assert any(p.startswith('locard[nested/case.db]') for p in shell.reader.prompts)


@pytest.mark.parametrize('kind',['file','directory','database'])
def test_existing_destination_never_modified(tmp_path,kind):
    target=tmp_path/'existing'
    if kind=='directory':target.mkdir()
    elif kind=='database':connect(target).close()
    else:target.write_bytes(b'unrelated file')
    before=target.read_bytes() if target.is_file() else None
    shell=Shell(State(None),Input(str(target),'yes' if kind=='database' else ''))
    assert creation.create(shell)==(kind=='database')
    assert not target.is_file() or target.read_bytes()==before


def test_evidence_tree_cannot_contain_case(tmp_path):
    with pytest.raises(ValueError):creation.source_path(tmp_path,tmp_path/'case.db')


@pytest.mark.parametrize('source_kind',['missing','unsupported','empty'])
def test_invalid_or_empty_sources_no_implicit_creation(tmp_path,source_kind):
    source=tmp_path/'evidence'
    if source_kind=='empty':source.mkdir()
    elif source_kind=='unsupported':source.write_text('ordinary text')
    target=tmp_path/'case.db'
    shell=Shell(State(None),Input(str(target),str(source),'c' if source_kind=='empty' else ''))
    assert not creation.create(shell) and not target.exists()


def test_mixed_real_parsers_and_additional_ingestion(tmp_path,capsys):
    source=tmp_path/'evidence';source.mkdir()
    mft_file(source/'mft');prefetch_file(source/'program.pf');registry_file(source/'hive')
    before={p.name:p.read_bytes() for p in source.iterdir()}
    target=tmp_path/'case.db'
    shell=Shell(State(None),Input('1',str(target),str(source),'Workstation','TESTHOST','TestUser','C:','yes',
                                 f'ingest-all "{source}"','1','exit'))
    assert shell.run()==0 and shell.active==target
    with closing(connect(target,existing_only=True)) as db:
        assert {r[0] for r in db.execute('SELECT DISTINCT source_type FROM evidence_records')}=={'mft','prefetch','registry'}
        assert db.execute('SELECT count(*) FROM ingestion_runs').fetchone()[0]==6
    assert before=={p.name:p.read_bytes() for p in source.iterdir()}
    assert 'Stored evidence records' in capsys.readouterr().out


@pytest.mark.parametrize('failure',[OSError('discovery failed'),KeyboardInterrupt()])
def test_failure_after_commits_preserves_old_case_and_evidence(tmp_path,monkeypatch,capsys,failure):
    source=tmp_path/'evidence';source.mkdir();artifact=mft_file(source/'mft')
    old=case(tmp_path,'old.db');target=tmp_path/'new.db'
    shell=Shell(State(None),Input(str(target),str(source),'','','','','yes','n'));shell.activate(old)
    discover=creation.v2_cli.discover
    calls=0
    def fail_later(*args,**kwargs):
        nonlocal calls
        calls+=1
        yield from discover(*args,**kwargs)
        if calls>1:raise failure
    monkeypatch.setattr(creation.v2_cli,'discover',fail_later)
    assert not creation.create(shell) and shell.active==old and shell.state.recent==[str(old)]
    with closing(connect(target,existing_only=True)) as db:
        assert db.execute('SELECT count(*) FROM evidence_records').fetchone()[0]>0
    assert 'not rolled back' in capsys.readouterr().out


def test_partial_artifact_failure_activates_with_limitations(tmp_path,capsys):
    source=tmp_path/'evidence';source.mkdir();mft_file(source/'a-mft')
    (source/'z-bad-hive').write_bytes(b'regf'+bytes(100))
    target=tmp_path/'new.db'
    shell=Shell(State(None),Input(str(target),str(source),'','','','','yes'))
    assert creation.create(shell) and shell.active==target
    assert 'completed with errors/limitations' in capsys.readouterr().out


def test_case_new_cancel_retains_case(tmp_path):
    old=case(tmp_path)
    shell=Shell(State(None),Input(str(old),'case new','','case','n','','exit'))
    assert shell.run()==0 and shell.active==old


def test_first_run_open_menu(tmp_path):
    old=case(tmp_path)
    shell=Shell(State(None),Input('2','', '2',str(old),'exit'))
    assert shell.run()==0 and shell.active==old


def test_initialization_exception_closes_connection(tmp_path,monkeypatch):
    import forensic_assistant.database.db as database
    def fail(db):raise KeyboardInterrupt()
    monkeypatch.setattr(database,'upgrade',fail)
    target=tmp_path/'failed.db'
    with pytest.raises(KeyboardInterrupt):database.connect(target)
    target.unlink()  # Windows refuses deletion if SQLite still holds the file.


@pytest.mark.parametrize('phase',range(8))
def test_cancel_each_prepublication_input(tmp_path,phase):
    source=tmp_path/'evidence';source.mkdir();mft_file(source/'mft')
    target=tmp_path/'new'/'case.db';old=case(tmp_path,'old.db')
    lines=[str(target),'yes',str(source),'','','','','yes']
    lines[phase]=KeyboardInterrupt()
    shell=Shell(State(None),Input(*lines));shell.activate(old)
    assert not creation.create(shell) and shell.active==old
    assert not target.parent.exists() and shell.state.recent==[str(old)]


@pytest.mark.parametrize('kind',['evtx','mft','prefetch','registry'])
def test_parser_cancel_records_interruption_without_activation(tmp_path,monkeypatch,kind):
    from functools import partial
    source=tmp_path/'artifact'
    if kind=='evtx':source.write_bytes(b'ElfFile\x00'+bytes(100))
    else:dict(mft=mft_file,prefetch=prefetch_file,registry=registry_file)[kind](source)
    def cancel(*args,**kwargs):raise KeyboardInterrupt()
    if kind=='evtx':monkeypatch.setattr(creation.v2_cli,'ingest_file',partial(creation.v2_cli.ingest_file,reader=cancel))
    else:monkeypatch.setattr(creation.v2_cli,'ingest_artifact',partial(creation.v2_cli.ingest_artifact,runner=cancel))
    old=case(tmp_path,'old.db');target=tmp_path/'new.db'
    shell=Shell(State(None),Input(str(target),str(source),'','','','','yes'));shell.activate(old)
    assert not creation.create(shell) and shell.active==old
    with closing(connect(target,existing_only=True)) as db:
        row=db.execute('SELECT * FROM ingestion_runs').fetchone()
        assert row['status']=='interrupted' and row['finished_utc'] and row['inserted_count']==0


def test_timeout_does_not_activate_failed_case(tmp_path,monkeypatch,capsys):
    from functools import partial
    source=mft_file(tmp_path/'mft');target=tmp_path/'new.db'
    def timeout(*args,**kwargs):raise ValueError('Parser time limit exceeded')
    monkeypatch.setattr(creation.v2_cli,'ingest_artifact',partial(creation.v2_cli.ingest_artifact,runner=timeout))
    shell=Shell(State(None),Input(str(target),str(source),'','','','','yes','c'))
    assert not creation.create(shell) and shell.active is None and not shell.state.recent
    with closing(connect(target,existing_only=True)) as db:
        assert db.execute('SELECT status FROM ingestion_runs').fetchone()[0]=='failed'
    assert 'Parser time limit exceeded' in capsys.readouterr().out


def test_cancel_immediately_after_publication_reports_retained_database(tmp_path,monkeypatch,capsys):
    shell,target,source=wizard(tmp_path)
    original=creation.os.rename
    def publish_then_interrupt(*args):original(*args);raise KeyboardInterrupt()
    if creation.os.name!='nt':pytest.skip('Windows rename gate')
    monkeypatch.setattr(creation.os,'rename',publish_then_interrupt)
    assert not creation.create(shell) and shell.active is None and not shell.state.recent
    assert creation.validate(target)==target
    assert 'Database retained:' in capsys.readouterr().out


def test_unconfirmed_cleanup_failure_is_fatal(tmp_path,monkeypatch):
    source=mft_file(tmp_path/'mft');target=tmp_path/'new.db'
    def fail(*args,**kwargs):raise RuntimeError('Worker cleanup unconfirmed')
    monkeypatch.setattr(creation.v2_cli,'ingest_sources',fail)
    shell=Shell(State(None),Input(str(target),str(source),'','','','','yes'))
    with pytest.raises(RuntimeError,match='cleanup'):creation.create(shell)
    assert shell.active is None and not shell.state.recent


def test_source_disappears_after_preflight_can_activate_empty_explicitly(tmp_path,monkeypatch,capsys):
    source=tmp_path/'evidence';source.mkdir();artifact=mft_file(source/'mft')
    target=tmp_path/'new.db'
    def confirm():artifact.unlink();return 'yes'
    shell=Shell(State(None),Input(str(target),str(source),'','','','',confirm,'e'))
    assert creation.create(shell) and shell.active==target
    assert 'No supported artifacts remained' in capsys.readouterr().out


def test_directory_race_to_file_preserved(tmp_path,monkeypatch):
    target=tmp_path/'new'/'case.db';original=Path.mkdir
    def race(self,*args,**kwargs):
        if self==target.parent:self.write_bytes(b'competing file')
        return original(self,*args,**kwargs)
    monkeypatch.setattr(Path,'mkdir',race)
    with pytest.raises(FileExistsError):creation.initialize(target,True)
    assert target.parent.read_bytes()==b'competing file'


def test_back_leaves_filesystem_unchanged(tmp_path):
    shell,target,source=wizard(tmp_path)
    shell.reader=Input(str(target),str(source),'e','','','','','b','')
    assert not creation.create(shell) and not target.exists()


def test_unreadable_preflight_never_creates(tmp_path,monkeypatch):
    source=tmp_path/'evidence';source.mkdir();target=tmp_path/'case.db'
    def deny(*args):raise PermissionError('source denied')
    monkeypatch.setattr(creation,'preflight',deny)
    shell=Shell(State(None),Input(str(target),str(source),''))
    assert not creation.create(shell) and not target.exists()


def test_active_case_stays_old_through_ingestion(tmp_path,monkeypatch):
    source=mft_file(tmp_path/'mft');old=case(tmp_path,'old.db');target=tmp_path/'new.db'
    shell=Shell(State(None),Input(str(target),str(source),'','','','','yes'));shell.activate(old)
    original=creation.v2_cli.ingest_sources
    def check(*args,**kwargs):
        assert shell.active==old and shell.state.recent==[str(old)]
        return original(*args,**kwargs)
    monkeypatch.setattr(creation.v2_cli,'ingest_sources',check)
    assert creation.create(shell) and shell.active==target
    assert shell.state.recent==[str(target),str(old)]


def test_retry_source_does_not_hide_previous_failures(tmp_path,capsys):
    bad=tmp_path/'bad';bad.write_bytes(b'regf'+bytes(100))
    good=mft_file(tmp_path/'mft');target=tmp_path/'case.db'
    shell=Shell(State(None),Input(str(target),str(bad),'','','','','yes','a',str(good),'yes'))
    assert creation.create(shell) and shell.active==target
    output=capsys.readouterr().out
    assert 'completed with errors/limitations' in output
    assert 'Ingestion completed successfully.' not in output


def test_cancel_initialization_reports_retained_directories(tmp_path,monkeypatch,capsys):
    shell,target,source=wizard(tmp_path,missing=True)
    def cancel(*args,**kwargs):raise KeyboardInterrupt()
    monkeypatch.setattr(creation,'connect',cancel)
    assert not creation.create(shell) and target.parent.is_dir() and not target.exists()
    assert 'directories already created are retained' in capsys.readouterr().out

"""Small synthetic cases only; no provider or analyst case access."""
from contextlib import closing
import hashlib
import json
from pathlib import Path
import shutil
import sqlite3
import pytest
from forensic_assistant import case_management as cm
from forensic_assistant.database.db import connect
from forensic_assistant.briefing_store import Store, content, FIELDS
from forensic_assistant.assessment_store import AssessmentStore
from forensic_assistant.cli import build_parser

@pytest.fixture(autouse=True)
def locations(tmp_path, monkeypatch):
    monkeypatch.setenv('LOCALAPPDATA', str(tmp_path/'app'))
    monkeypatch.setenv('USERPROFILE',str(tmp_path/'user'))


def dbfile(path):
    with closing(connect(path)):pass
    return path


def briefing(path):
    s=Store(path)
    return s.save(content(dict.fromkeys(FIELDS,''),'Synthetic analyst text.'),None)


def test_defaults_configuration_and_legacy(tmp_path):
    assert cm.root()==tmp_path/'user/Locard/Cases'
    old=dbfile(tmp_path/'app/Locard/cases/14/case.db')
    digest=hashlib.sha256(old.read_bytes()).hexdigest()
    cm.set_root(tmp_path/'custom')
    assert cm.root()==tmp_path/'custom'
    assert cm.resolve('14')==old
    assert cm.discover()[0]['origin']=='legacy'
    assert hashlib.sha256(old.read_bytes()).hexdigest()==digest
    assert json.loads(cm.config_path().read_text())['root']==str(tmp_path/'custom')

@pytest.mark.parametrize('value',['','.', '..','a/b','a\\b','C:\\a','bad?','bad.','bad ','CON','con.txt','LPT1','com¹','.hidden','a\x00b'])
def test_reject_names(value):
    with pytest.raises(ValueError):cm.name(value)


def test_discovery_no_database_open_and_ambiguity(tmp_path,monkeypatch):
    a=dbfile(cm.root()/'14/case.db')
    b=dbfile(tmp_path/'app/Locard/cases/14/case.db')
    monkeypatch.setattr(sqlite3,'connect',lambda *a,**k:pytest.fail('discovery opened SQLite'))
    assert len(cm.discover())==2
    with pytest.raises(ValueError,match='AMBIGUOUS'):cm.resolve('14')
    with pytest.raises(ValueError,match='NOT_FOUND'):cm.resolve('missing')
    assert a.exists() and b.exists()


def test_register_unregister_and_identity_refusal(tmp_path):
    p=dbfile(tmp_path/'external/case.db');briefing(p)
    before=p.read_bytes()
    cm.register('External',p.parent)
    assert cm.resolve('external')==p
    with pytest.raises(ValueError,match='EXISTS'):cm.register('EXTERNAL',p)
    cm.unregister('EXTERNAL')
    assert p.read_bytes()==before and Store(p).load()
    copied=tmp_path/'copied';shutil.copytree(p.parent,copied)
    with pytest.raises(ValueError,match='CASE_IDENTITY_MISMATCH'):cm.register('Copy',copied)
    assert (copied/'case.db.briefing/state.json').is_file()


def test_creation_collision_and_no_accidental_open(tmp_path):
    p=cm.create('Incident-001')
    assert cm.resolve('incident-001')==p
    with pytest.raises(ValueError,match='EXISTS'):cm.create('INCIDENT-001')
    absent=tmp_path/'missing.db'
    with pytest.raises(ValueError):cm.resolve(str(absent))
    assert not absent.exists()


def populate(p):
    with closing(connect(p)) as db:
        with db:
            db.execute("INSERT INTO evidence_files VALUES ('abc',12,'synthetic')")
            db.execute("INSERT INTO source_locations VALUES ('abc','D:/original/source.evtx')")
            db.execute("INSERT INTO ingestion_runs (id,source_file,started_utc,finished_utc,status,error_count) VALUES (1,'D:/original/source.evtx','start','end','partial',1)")
            db.execute("INSERT INTO ingestion_errors (run_id,stage,message) VALUES (1,'decode','Synthetic limitation')")
    return p


def test_clone_wal_and_fresh_context(tmp_path):
    source=populate(cm.create('Original'));briefing(source)
    sidecar=Path(str(source)+'.investigations');sidecar.mkdir();(sidecar/'untouched').write_text('synthetic')
    with closing(sqlite3.connect(source)) as live:
        live.execute('PRAGMA journal_mode=WAL')
        live.execute("INSERT INTO evidence_files VALUES ('wal',23,'wal-commit')");live.commit()
        before=list(live.iterdump())
        result=cm.clone('Original','Clone')
        clone=Path(result['path'])
        with closing(sqlite3.connect(clone)) as copied:
            assert list(copied.iterdump())==before
        assert list(live.iterdump())==before
    assert Store(source).load() and Store(clone).load() is None
    assert AssessmentStore(clone).history()==[]
    assert not Path(str(clone)+'.investigations').exists()
    assert (sidecar/'untouched').read_text()=='synthetic'
    assert result['origin']['external_evidence_copied'] is False
    assert result['origin']['source_reference_sample']==['D:/original/source.evtx']
    assert source.stat().st_ino!=clone.stat().st_ino
    assert cm.resolve('Clone')==clone

@pytest.mark.parametrize('failure',['space','cancel','timeout','busy','schema','overlap'])
def test_clone_fail_closed(tmp_path,monkeypatch,failure):
    p=populate(cm.create('Source'))
    if failure=='busy':
        with sqlite3.connect(p) as db:db.execute("UPDATE ingestion_runs SET finished_utc=NULL,status='running'")
    if failure=='schema':
        with sqlite3.connect(p) as db:db.execute('CREATE TABLE unexpected_history (value TEXT)')
    if failure=='space':monkeypatch.setattr(shutil,'disk_usage',lambda _:type('Disk',(),{'free':0})())
    if failure=='overlap':monkeypatch.setattr(cm,'root',lambda:p.parent)
    before=p.read_bytes()
    def cancel(*args):raise KeyboardInterrupt()
    with pytest.raises((ValueError,KeyboardInterrupt,sqlite3.OperationalError,TimeoutError)):
        cm.clone('Source' if failure!='overlap' else str(p),'Copy',seconds=-1 if failure=='timeout' else 30,progress=cancel if failure=='cancel' else None)
    assert p.read_bytes()==before
    assert not (cm.root()/'Copy/case.db').exists()


def test_source_corruption_rejected(tmp_path):
    p=tmp_path/'invalid.db';p.write_bytes(b'not SQLite')
    with pytest.raises((ValueError,sqlite3.DatabaseError)):cm.clone(str(p),'InvalidClone')
    assert not (cm.root()/'InvalidClone/case.db').exists()


def test_redirect_and_root_inside_case_rejected(tmp_path):
    original=cm.create('Original')
    with pytest.raises(ValueError,match='CASE_ROOT_INVALID'):cm.set_root(original.parent/'nested')
    link=tmp_path/'redirect'
    try:link.symlink_to(original.parent,target_is_directory=True)
    except OSError:pytest.skip('Symlink privilege unavailable')
    with pytest.raises(ValueError):cm.resolve(str(link))


def test_cli_paths_and_confirmation(tmp_path):
    from forensic_assistant.case_cli import run
    parser=build_parser()
    for words in ('case list','case open 14','case new Named','case root','case root set C:\\Cases','case register Name C:\\Cases\\Name','case unregister Name','case clone A B'):
        assert parser.parse_args(words.split()).workflow.startswith('case-')
    args=parser.parse_args(['case','root','set',str(tmp_path/'other')])
    assert run(args,read=lambda p:'n')['status']=='cancelled'
    assert not (tmp_path/'other').exists()
    with pytest.raises(ValueError,match='confirmation required'):run(args)


def test_briefing_error_categories(tmp_path):
    p=cm.create('Original');briefing(p);s=Store(p)
    initial=s.path.read_bytes();value=json.loads(initial)
    for update,code in [({'format':99},'SCHEMA_UNSUPPORTED'),({'case':{}},'IDENTITY_MISMATCH')]:
        s.path.write_text(json.dumps({**value,**update}))
        with pytest.raises(ValueError,match=code):s.load()
    s.path.write_bytes(initial)
    changed=json.loads(initial);changed['revisions'][0]['content']['narrative']='tampered'
    s.path.write_text(json.dumps(changed))
    with pytest.raises(ValueError,match='INTEGRITY_FAILURE'):s.load()
    s.path.unlink()
    with pytest.raises(ValueError,match='SIDECAR_MISSING'):s.load()


def test_shell_named_open_and_menu(tmp_path,monkeypatch):
    from forensic_assistant.interactive.shell import Shell
    from forensic_assistant.interactive.state import State
    from test_interactive_shell import Input
    p=cm.create('14')
    shell=Shell(State(None),Input('#1'))
    monkeypatch.setattr(shell,'activate',lambda path:setattr(shell,'active',path))
    assert shell.choose() and shell.active==p
    assert shell.choose('14')

def test_actual_mft_evidence_ids_and_history_preserved(tmp_path):
    from forensic_assistant import v2_cli,activity
    from forensic_assistant.briefing_store import digest
    from v2_fixtures import mft_file
    p=cm.create('MFT');artifact=mft_file(tmp_path/'synthetic.mft')
    with closing(connect(p,existing_only=True)) as db:
        result,code=v2_cli.dispatch(db,build_parser().parse_args(['evidence','ingest','mft',str(artifact)]))
        assert code==0,result
        original=list(db.iterdump())
        ids=[r[0] for r in db.execute('SELECT evidence_id FROM evidence_records')]
        assert ids
    briefing(p)
    store=AssessmentStore(p);plan={'revision':1}
    saved=dict(id='a'*32,case=store.identity,kind='case_assessment',created='synthetic',status='complete',plan=plan,authorization={'plan_digest':digest(plan)})
    store.save_assessment(saved)
    session=activity.Session(p);session.start();session.end('synthetic')
    audit=activity.sidecar(p).read_bytes()
    result=cm.clone('MFT','MFT-copy')
    q=Path(result['path'])
    with closing(sqlite3.connect(q)) as db:
        assert list(db.iterdump())==original
        assert [r[0] for r in db.execute('SELECT evidence_id FROM evidence_records')]==ids
    assert store.load('a'*32)==saved
    assert activity.sidecar(p).read_bytes()==audit
    assert activity.inspect(activity.sidecar(p),1)['valid']
    assert not activity.sidecar(q).exists()
    assert AssessmentStore(q).history()==[]


def test_wal_concurrent_later_commit_not_mixed(tmp_path):
    p=cm.create('Source')
    with closing(sqlite3.connect(p)) as writer:
        writer.execute('PRAGMA journal_mode=WAL')
        writer.execute("INSERT INTO evidence_files VALUES ('before',1,'t')");writer.commit()
        changed=[]
        def update(*args):
            if not changed:
                writer.execute("INSERT INTO evidence_files VALUES ('later',2,'t')");writer.commit();changed.append(True)
        q=Path(cm.clone('Source','Snapshot',progress=update)['path'])
        with closing(sqlite3.connect(q)) as copy:
            assert copy.execute('SELECT sha256 FROM evidence_files').fetchall()==[('before',)]
        assert writer.execute('SELECT count(*) FROM evidence_files').fetchone()[0]==2


def test_clone_publication_failure_preserves_rival(tmp_path,monkeypatch):
    p=cm.create('Source');before=p.read_bytes()
    def rival(staged,target):
        Path(target).write_bytes(b'competing file')
        raise FileExistsError('synthetic race')
    monkeypatch.setattr(cm.os,'link',rival)
    with pytest.warns(RuntimeWarning,match='CLEANUP_LIMITATION'):
        with pytest.raises(FileExistsError):cm.clone('Source','Rival')
    assert (cm.root()/'Rival/case.db').read_bytes()==b'competing file'
    assert p.read_bytes()==before


def test_bounded_discovery_and_config_failure(tmp_path,monkeypatch):
    cm.create('One');cm.create('Two')
    monkeypatch.setattr(cm,'MAX_CASES',1)
    with pytest.raises(ValueError,match='DISCOVERY_LIMIT'):cm.discover()
    cm.config_path().parent.mkdir(parents=True,exist_ok=True)
    cm.config_path().write_text('{invalid')
    before=cm.config_path().read_bytes()
    with pytest.raises(ValueError):cm.set_root(tmp_path/'new')
    assert cm.config_path().read_bytes()==before

def test_fresh_clone_first_use_commands(tmp_path,monkeypatch):
    from forensic_assistant import workflow_cli,briefing_cli,investigation_workflow as flow
    p=cm.create('Original');q=Path(cm.clone('Original','Fresh')['path'])
    parser=build_parser()
    shown=briefing_cli.run(parser.parse_args(['--db',str(q),'investigation','briefing','show']))
    assert 'No saved briefing' in shown['message']
    assert workflow_cli.run(parser.parse_args(['--db',str(q),'investigation','list']))['assessments']==[]
    value=content(dict.fromkeys(FIELDS,''),'A new analyst account; not evidence.')
    monkeypatch.setattr(flow.briefing_workflow,'edit',lambda *args:value)
    monkeypatch.setattr(flow.assessment_cli,'assess',lambda *a,**k:pytest.fail('unapproved or unstructured assessment'))
    answers=iter(['','yes'])
    result=flow.start(q,read=lambda _:next(answers),display=lambda _:None)
    assert result['status']=='briefing_saved'
    assert Store(q).load()['revisions'][0]['content']==value
    assert Store(p).load() is None

def test_registered_file_replacement_is_not_silent_rebinding(tmp_path):
    p=dbfile(tmp_path/'external/case.db')
    cm.register('Pinned',p)
    replacement=dbfile(tmp_path/'replacement.db')
    replacement.replace(p)
    assert 'identity changed' in next(e for e in cm.discover() if e['name']=='Pinned')['status']
    with pytest.raises(ValueError,match='CASE_IDENTITY_MISMATCH'):cm.resolve('Pinned')


def test_configuration_lock_refuses_concurrent_mutation(tmp_path):
    cm.config_path().parent.mkdir(parents=True)
    lock=cm.config_path().with_suffix('.lock');lock.write_text('owned by another operation')
    with pytest.raises(ValueError,match='CASE_CONFIG_BUSY'):cm.set_root(tmp_path/'root')
    assert lock.read_text()=='owned by another operation'

def test_cli_clone_confirmation_and_root_race(tmp_path):
    from forensic_assistant.case_cli import run
    cm.create('Original');parser=build_parser()
    args=parser.parse_args(['case','clone','Original','Copy'])
    assert run(args,read=lambda _: 'n')['status']=='cancelled'
    assert not (cm.root()/'Copy').exists()
    original_root=cm.root()
    def move_root(_):
        cm.set_root(tmp_path/'changed')
        return 'yes'
    with pytest.raises(ValueError,match='DESTINATION_CHANGED'):run(args,read=move_root)
    assert not (original_root/'Copy').exists()
    cm.set_root(original_root)
    result=run(args,read=lambda _: 'yes')
    assert Path(result['path']).is_file()

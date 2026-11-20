"""Synthetic immutable ingestion through the production service and subprocesses."""
from contextlib import closing
import json
from pathlib import Path
import sqlite3
import pytest
from forensic_assistant import activity
from forensic_assistant.artifacts import browser, sqlite_immutable, ingest
from forensic_assistant.database.db import connect
from forensic_assistant.database import sources
from forensic_assistant.database.browser import provenance
from test_browser_parser import history
from test_browser_integration import ingest as application_ingest
from test_sqlite_recovery import audited, captured, hot
from test_browser_journal import persist


def indeterminate(path):
    Path(str(path)+'-journal').write_bytes(bytes.fromhex('000000000000000000000000eae2c6ed000007de0000020000001000')+bytes(1024))


@pytest.mark.parametrize('state,retained', [('presync',2),('extra-pages',2),('empty',0),
    ('missing-visits',1),('bad-row',1),('damaged-table',1)])
def test_application_best_effort(tmp_path,audited,state,retained):
    source=tmp_path/'History'
    with closing(history(source)) as db:
        if state=='empty': db.executescript('DELETE FROM visits; DELETE FROM downloads; DELETE FROM downloads_url_chains; DELETE FROM urls;')
        if state=='missing-visits': db.execute('DROP TABLE visits');db.commit()
        if state=='bad-row': db.execute("UPDATE visits SET visit_time='invalid'");db.commit()
        if state=='damaged-table':
            page=db.execute("SELECT rootpage FROM sqlite_master WHERE name='downloads'").fetchone()[0]
    if state=='extra-pages':
        with source.open('ab') as out: out.write(bytes(8192))
    if state=='damaged-table':
        with source.open('r+b') as out: out.seek((page-1)*4096);out.write(bytes(4096))
    indeterminate(source)
    before=captured(source)
    case,case_path=audited
    with case: sid=sources.create(case,hostname='synthetic')
    first=application_ingest(case,source,'edge','Default',source=sid)
    assert first['status']=='partial',first
    assert first['inserted']==retained,first
    proof=first['extraction']
    assert proof['mode']=='best_effort_immutable' and proof['recovery_applied'] is False
    assert proof['derived']==proof['original_manifest']['']
    assert proof['journal_classification']=='journal_indeterminate'
    assert proof['transactional_consistency']=='not_established'
    assert captured(source)==before
    if state=='damaged-table':
        assert proof['validation']['quick_check']=='failed'
        assert proof['tables']['downloads']=='iteration_failed'
    if state=='bad-row': assert proof['counts']['rejected']==1
    if state=='empty': assert proof['empty_readable'] and first['errors']==0
    if state=='extra-pages': assert proof['header']['physical_pages']>proof['header']['declared_pages']
    if retained:
        eid=case.execute('SELECT evidence_id FROM evidence_records LIMIT 1').fetchone()[0]
        members,occurrences=provenance(case,eid)
        assert members[0]['source_id']==sid
        assert occurrences[0]['parameters']['extraction']['mode']=='best_effort_immutable'
        second=application_ingest(case,source,'edge','Default',source=sid)
        assert second['status']=='partial' and second['inserted']==0 and second['duplicates']==retained
    assert case.execute('SELECT count(*) FROM sources').fetchone()[0]==1
    assert activity.inspect(activity.sidecar(case_path))['valid']
    events=[json.loads(x) for x in activity.sidecar(case_path).read_text().splitlines()]
    assert any(x['action']=='SQLITE_IMMUTABLE_EXTRACT' and x['phase']=='complete' for x in events)
    assert not any(x['action']=='SQLITE_RECOVERY' for x in events)
    assert '\x1b' not in json.dumps(first)
    from forensic_assistant.ingest.presentation import render
    from forensic_assistant.terminal import Palette
    text=render(dict(results=[first]),Palette(False))
    assert 'Best-effort immutable' in text and 'Limitations' in text


@pytest.mark.parametrize('state',['ordinary','inactive','hot','wal'])
def test_existing_modes_application(tmp_path,audited,state):
    source=tmp_path/'History'
    writer=None
    if state=='hot':hot(source)
    elif state=='inactive':persist(source)
    else:writer=history(source,wal=state=='wal')
    try:
        before=captured(source)
        db,_=audited
        result=application_ingest(db,source,'edge','Default')
        assert result['status']=='complete' and result['inserted']==2,result
        assert 'extraction' not in result
        assert result['extraction_mode']==('recovered' if state=='hot' else 'normal')
        assert captured(source)==before
    finally:
        if writer:writer.close()


@pytest.mark.parametrize('phase',['prepare','intent','complete','cleanup'])
def test_audit_failure_prevents_publication(tmp_path,audited,monkeypatch,phase):
    source=tmp_path/'History';history(source).close();indeterminate(source)
    db,_=audited;session=activity.CURRENT.get();original=session.record
    def record(action,*a,**k):
        if ((phase=='prepare' and action=='SQLITE_IMMUTABLE_PREPARE' and k.get('phase')=='complete')
            or (phase in ('intent','complete') and action=='SQLITE_IMMUTABLE_EXTRACT' and k.get('phase')==phase)
            or phase=='cleanup' and action=='SQLITE_IMMUTABLE_CLEANUP'):
            raise activity.AuditError('synthetic audit failure')
        return original(action,*a,**k)
    monkeypatch.setattr(session,'record',record)
    result=application_ingest(db,source,'edge','Default')
    assert result['status']=='failed'
    assert db.execute('SELECT count(*) FROM evidence_records').fetchone()[0]==0


def test_immutable_connection_only(tmp_path,monkeypatch):
    source=tmp_path/'History';history(source).close()
    original=sqlite3.connect;uris=[]
    def connection(database,**kwargs):
        uris.append(database)
        assert database.endswith('?mode=ro&immutable=1') and kwargs['uri']
        return original(database,**kwargs)
    monkeypatch.setattr(sqlite3,'connect',connection)
    with closing(sqlite_immutable.connection(source)) as db:
        with pytest.raises(sqlite3.OperationalError):db.execute('CREATE TABLE forbidden(x)')
    assert len(uris)==1


def test_open_failure_no_writable_fallback(tmp_path,monkeypatch):
    attempts=[]
    def reject(*a,**k):attempts.append(a);raise sqlite3.OperationalError('synthetic')
    monkeypatch.setattr(sqlite3,'connect',reject)
    with pytest.raises(sqlite3.OperationalError):sqlite_immutable.connection(tmp_path/'History')
    assert len(attempts)==1


def test_invalid_header_rejected(tmp_path,audited):
    source=tmp_path/'History';source.write_bytes(b'bad'*4096);indeterminate(source)
    db,_=audited
    result=application_ingest(db,source,'edge','Default')
    assert result['status']=='failed' and result['inserted']==0
    assert result['extraction_mode']=='unknown'  # Preparation never returned an established mode.


def test_iteration_failure_keeps_other_table(tmp_path,monkeypatch):
    from forensic_assistant.artifacts import browser_best_effort as parser
    source=tmp_path/'History';history(source).close()
    real=sqlite_immutable.connection
    class Proxy:
        def __init__(self):self.db=real(source)
        def close(self):self.db.close()
        def set_authorizer(self,*a):return self.db.set_authorizer(*a)
        def execute(self,sql,*a):
            cursor=self.db.execute(sql,*a)
            if 'FROM visits v' in sql:
                def broken():
                    yield next(cursor)
                    raise sqlite3.DatabaseError('synthetic iteration corruption')
                return broken()
            return cursor
    monkeypatch.setattr(parser,'connection',lambda p:Proxy())
    proof=dict(mode=sqlite_immutable.MODE,limitations=list(sqlite_immutable.LIMITATIONS))
    rows=list(parser.parse(source,'edge','Default','BROWSERCTX:test',proof))
    assert len([r for r in rows if 'record' in r])==2
    assert proof['tables']['visits']=='iteration_failed'
    assert proof['all_supported_tables_read'] is False


def test_ignored_companion_changes_do_not_duplicate_main_records(tmp_path,audited):
    source=tmp_path/'History';history(source).close();indeterminate(source)
    db,_=audited
    with db:sid=sources.create(db,hostname='synthetic')
    first=application_ingest(db,source,'edge','Default',source=sid)
    journal=Path(str(source)+'-journal')
    raw=bytearray(journal.read_bytes());raw[12]^=1;journal.write_bytes(raw)
    second=application_ingest(db,source,'edge','Default',source=sid)
    assert first['inserted']==2 and second['inserted']==0 and second['duplicates']==2
    assert first['extraction']['original_manifest']!=second['extraction']['original_manifest']


def test_missing_all_required_structure_failed(tmp_path,audited):
    source=tmp_path/'History'
    with closing(sqlite3.connect(source)) as db:db.execute('CREATE TABLE unrelated(id INTEGER PRIMARY KEY)')
    indeterminate(source);db,_=audited
    result=application_ingest(db,source,'edge','Default')
    assert result['status']=='failed' and not result['extraction'].get('empty_readable')


def test_missing_wal_main_only_coverage(tmp_path,audited):
    live=tmp_path/'live';live.mkdir();source=tmp_path/'History'
    with closing(history(live/'History',wal=True)) as writer:
        writer.execute('PRAGMA wal_checkpoint(TRUNCATE)')
        writer.execute('INSERT INTO visits VALUES(2,1,13222310400123456,1)');writer.commit()
        source.write_bytes((live/'History').read_bytes())
        Path(str(source)+'-shm').write_bytes((live/'History-shm').read_bytes())
    before=captured(source);db,_=audited
    result=application_ingest(db,source,'edge','Default')
    assert result['status']=='partial' and result['inserted']==2,result
    assert result['extraction']['journal_classification']=='missing_required_companion'
    assert result['extraction']['recovery_applied'] is False
    assert captured(source)==before


@pytest.mark.parametrize('cancel',[False,True])
def test_immutable_worker_timeout_cancellation_cleanup(tmp_path,audited,monkeypatch,cancel):
    from test_evtx_worker import assert_gone
    source=tmp_path/'History';history(source).close();indeterminate(source)
    original=ingest.subprocess.Popen;processes=[];paths=[]
    code="""import runpy,time
from forensic_assistant.artifacts import sqlite_immutable as s
def hang(*a): time.sleep(60)
s.prepare_worker=hang
runpy.run_module('forensic_assistant.artifacts.worker',run_name='__main__')
"""
    def launch(args,**kwargs):
        if 'sqlite_immutable' in args:
            paths.append(Path(args[6]))
            p=original([args[0],'-c',code,*args[3:]],**kwargs);processes.append(p);return p
        return original(args,**kwargs)
    monkeypatch.setattr(ingest.subprocess,'Popen',launch)
    monkeypatch.setattr(sqlite_immutable.safe,'TIMEOUT',1)
    sleep=ingest.time.sleep
    def waiting(seconds):
        if cancel and processes:raise KeyboardInterrupt
        sleep(seconds)
    monkeypatch.setattr(ingest.time,'sleep',waiting)
    db,_=audited
    if cancel:
        with pytest.raises(KeyboardInterrupt):application_ingest(db,source,'edge','Default')
    else:assert application_ingest(db,source,'edge','Default')['status']=='failed'
    assert db.execute('SELECT count(*) FROM evidence_records').fetchone()[0]==0
    assert paths and all(not p.parent.exists() for p in paths)
    for p in processes:assert p.poll() is not None;assert_gone(p.pid)

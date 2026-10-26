"""Synthetic cases only: WAL consistency, isolation, exact fingerprints and cleanup."""
import os
from pathlib import Path
import sqlite3
import subprocess
import time

import pytest

from forensic_assistant.investigation_ai import snapshot, controller, supervision
from forensic_assistant.investigation_ai.case import open_readonly, read_transaction
from forensic_assistant.investigation_ai.lifecycle import CleanupError
from forensic_assistant.investigation_ai.state import Budget
from forensic_assistant.investigation_ai.transcript import load
from forensic_assistant.semantic.documents import fingerprint
from test_v4_worker import make_case, config
from test_v4_controller import Scripted, tool, final
from test_investigation_hardening import local_model
from forensic_assistant.llm.client import LocalClient


def test_wal_copy_is_one_transaction_and_releases_reader(tmp_path):
    path = tmp_path / 'case.db'
    event = make_case(path)
    writer = sqlite3.connect(path)
    writer.execute('PRAGMA wal_autocheckpoint=0')
    writer.execute("UPDATE events SET process_name='before.exe'")
    writer.commit()
    assert Path(str(path) + '-wal').stat().st_size > 0
    source = open_readonly(path)
    try:
        with snapshot.SnapshotDirectory() as directory:
            with read_transaction(source):
                expected = fingerprint(source)
                writer.execute("UPDATE events SET process_name='after.exe'")
                writer.commit()
                target, size = snapshot.create(source, directory.path, time.monotonic() + 10)
            copy = open_readonly(target)
            try:
                assert fingerprint(copy) == expected
                assert copy.execute('SELECT process_name FROM events WHERE id=?', (event['id'],)).fetchone()[0] == 'before.exe'
                with pytest.raises(sqlite3.DatabaseError):
                    copy.execute("UPDATE events SET process_name='forbidden'")
                assert copy.total_changes == 0
                assert size == target.stat().st_size
            finally:
                copy.close()
            assert fingerprint(source) != expected
            assert writer.execute('PRAGMA wal_checkpoint(TRUNCATE)').fetchone() == (0, 0, 0)
        assert not directory.path.exists()
    finally:
        source.close()
        writer.close()


@pytest.mark.parametrize('dry_run,count', [(True, 0), (False, 0)])
def test_transaction_identity_without_content_digest(tmp_path, dry_run, count):
    path = tmp_path / 'case.db'
    event = make_case(path)
    db = open_readonly(path)
    try:
        expected = fingerprint(db)
    finally:
        db.close()
    result = controller.run(config(path), 'PowerShell', tmp_path / 'runs',
        client=Scripted([tool('show_evidence', {'evidence_id': event['id']})]),
        budget=Budget(steps=1), dry_run=dry_run, approval=lambda *_: True)
    assert result['evidence_fingerprint'] is None
    assert result['evidence_state']['contract'] == 'sqlite-read-view-v1'
    metrics = result['metrics']['integrity']
    assert metrics['fingerprint_count'] == count
    assert metrics['live_case_matches'] is None and metrics['strategy'] == 'sqlite_read_view_v1'
    assert metrics['transaction_seconds'] > 0 and metrics['fingerprint_seconds'] == 0
    assert result['state']['accepted_calls'] == int(not dry_run)
    manifest, _ = load(tmp_path / 'runs', result['investigation_id'])
    assert manifest['evidence_fingerprint'] is None
    assert manifest['evidence_state'] == result['evidence_state']


def test_mutation_stays_in_original_view_without_claiming_live_equality(tmp_path):
    path = tmp_path / 'case.db'
    event = make_case(path)
    def mutate(messages):
        db = sqlite3.connect(path)
        db.execute("UPDATE events SET process_name='changed.exe'")
        db.commit()
        db.close()
        return tool('show_evidence', {'evidence_id': event['id']})
    result = controller.run(config(path), 'PowerShell', tmp_path / 'runs',
        client=Scripted([mutate]), budget=Budget(steps=1), approval=lambda *_: True)
    assert result['termination'] == 'BUDGET_EXHAUSTED'
    assert result['metrics']['integrity']['live_case_matches'] is None
    assert result['metrics']['integrity']['fingerprint_count'] == 0
    _, events = load(tmp_path / 'runs', result['investigation_id'])
    records = next(e['data']['response']['result']['records'] for e in events if e['kind'] == 'result')
    assert records[0]['process_name'] == 'powershell.exe'
    assert any('only the pinned investigation read view' in s for s in result['limitations'])
    assert not any(e['kind'] == 'validated_final' for e in events)


def test_no_cross_investigation_or_case_cache(tmp_path):
    paths = [tmp_path / (name + '.db') for name in ('first', 'second')]
    for path in paths:
        make_case(path)
    values = []
    for number, path in enumerate((paths[0], paths[1], paths[0])):
        db = sqlite3.connect(path)
        db.execute('UPDATE events SET command_line=?', (str(number),))
        db.commit(); db.close()
        result = controller.run(config(path), 'PowerShell', tmp_path / 'runs',
            client=Scripted([final]), dry_run=True)
        values.append(result['evidence_state']['view_id'])
        assert result['metrics']['integrity']['fingerprint_count'] == 0
    assert len(set(values)) == 3


@pytest.mark.skipif(os.name != 'nt', reason='Windows DACL and sharing gate')
def test_private_dacl_and_file_write_pin(tmp_path):
    with snapshot.SnapshotDirectory() as directory:
        import ctypes as c
        from ctypes import wintypes as w
        adv = c.WinDLL('advapi32', use_last_error=True)
        kernel = c.WinDLL('kernel32', use_last_error=True)
        kernel.LocalFree.argtypes = [w.HLOCAL]
        adv.GetNamedSecurityInfoW.argtypes = [w.LPWSTR, c.c_int, w.DWORD, w.LPVOID,
            w.LPVOID, w.LPVOID, w.LPVOID, c.POINTER(w.LPVOID)]
        adv.ConvertSecurityDescriptorToStringSecurityDescriptorW.argtypes = [w.LPVOID,
            w.DWORD, w.DWORD, c.POINTER(w.LPWSTR), w.LPVOID]
        descriptor, text = w.LPVOID(), w.LPWSTR()
        try:
            assert adv.GetNamedSecurityInfoW(str(directory.path), 1, 4, None, None, None, None, c.byref(descriptor)) == 0
            assert adv.ConvertSecurityDescriptorToStringSecurityDescriptorW(descriptor, 1, 4, c.byref(text), None)
            acl = text.value
            assert 'D:P' in acl and acl.count('(A;') == 2 and ';;;SY)' in acl
            assert ';;;WD)' not in acl and ';;;BU)' not in acl and ';;;AU)' not in acl
        finally:
            if descriptor: kernel.LocalFree(descriptor)
            if text: kernel.LocalFree(c.cast(text, w.HLOCAL))
        target = directory.path / 'snapshot.db'
        target.write_bytes(b'private synthetic bytes')
        pin = snapshot.SnapshotFile(target)
        try:
            with pytest.raises(OSError):
                target.write_bytes(b'overwrite')
            with pytest.raises(OSError):
                target.unlink()
        finally:
            pin.close()


def test_timeout_and_collision_cleanup(tmp_path):
    source = sqlite3.connect(':memory:')
    source.execute('CREATE TABLE example(a)')
    with snapshot.SnapshotDirectory() as directory:
        with pytest.raises(TimeoutError):
            snapshot.create(source, directory.path, time.monotonic() - 1)
        with pytest.raises(FileExistsError):
            snapshot.create(source, directory.path, time.monotonic() + 10)
    assert not directory.path.exists()
    source.close()


def blocked_snapshot_child(connection, gate, request):
    gate.wait()
    assert '_snapshot_dir' not in request['config']
    time.sleep(30)


def test_abnormal_controller_termination_cleans_snapshot(tmp_path, monkeypatch):
    path = tmp_path / 'case.db'
    make_case(path)
    monkeypatch.setattr(snapshot.tempfile, 'gettempdir', lambda: str(tmp_path))
    monkeypatch.setattr(supervision, '_child', blocked_snapshot_child)
    # This deliberately blocked controller tests snapshot cleanup, not runtime startup.
    from forensic_assistant.llm.client import LocalClient
    result = supervision.run(config(path), 'Inspect', tmp_path / 'runs',
                             client=LocalClient(), budget=Budget(seconds=1))
    assert result['termination'] == 'STARTUP_TIMEOUT'
    assert not list(tmp_path.glob('locard-investigation-*'))


@pytest.mark.parametrize('failure', [KeyboardInterrupt(), ValueError('synthetic model failure')])
def test_failure_and_cancel_delete_copy(tmp_path, monkeypatch, failure):
    path = tmp_path / 'case.db'
    make_case(path)
    monkeypatch.setattr(snapshot.tempfile, 'gettempdir', lambda: str(tmp_path))
    class Client:
        def complete(self, *args):
            assert not list(tmp_path.glob('locard-investigation-*/snapshot.db'))
            raise failure
    result = controller.run(config(path), 'PowerShell', tmp_path / 'runs', client=Client())
    assert result['termination'] in ('USER_SCOPE_REACHED', 'MODEL_FAILURE')
    assert not list(tmp_path.glob('locard-investigation-*'))


def test_cleanup_failure_surfaces(tmp_path, monkeypatch):
    path = tmp_path / 'case.db'
    make_case(path)
    from forensic_assistant.investigation_ai.runner import ForensicWorker
    original = ForensicWorker.close
    def failed(self):
        original(self)
        raise CleanupError('CLEANUP_LIMITATION: synthetic cleanup uncertainty')
    monkeypatch.setattr(ForensicWorker, 'close', failed)
    with pytest.raises(CleanupError, match='CLEANUP_LIMITATION'):
        controller.run(config(path), 'PowerShell', tmp_path / 'runs', client=Scripted([final]), dry_run=True)


def test_snapshot_proof_never_crosses_connections_or_lifetime(tmp_path):
    path = tmp_path / 'case.db'
    make_case(path)
    source = open_readonly(path)
    with snapshot.SnapshotDirectory() as directory:
        target, _ = snapshot.create(source, directory.path, time.monotonic() + 10)
        guard = snapshot.SnapshotFile(target)
        db = open_readonly(target)
        try:
            with read_transaction(db):
                proof = snapshot.SnapshotFingerprint(db, guard, fingerprint(db))
                assert proof.value(db) == fingerprint(db)
                with pytest.raises(ValueError):
                    proof.value(source)
            with pytest.raises(ValueError):
                proof.value(db)
            with read_transaction(source), pytest.raises(ValueError):
                snapshot.SnapshotFingerprint(source, guard, 'untrusted')
        finally:
            db.close(); guard.close(); source.close()


def test_semantic_snapshot_reuses_exact_fingerprint_and_still_rejects_stale_index(tmp_path, monkeypatch):
    from forensic_assistant.semantic import index
    from test_v3_index import FakeModel
    path = tmp_path / 'case.db'
    make_case(path)
    source = open_readonly(path)
    root = tmp_path / 'index'
    index.build(source, root, FakeModel())
    with snapshot.SnapshotDirectory() as directory:
        target, _ = snapshot.create(source, directory.path, time.monotonic() + 10)
        guard = snapshot.SnapshotFile(target)
        db = open_readonly(target)
        try:
            with read_transaction(db):
                proof = snapshot.SnapshotFingerprint(db, guard, fingerprint(db))
                monkeypatch.setattr(index, 'fingerprint', lambda _: pytest.fail('Redundant full fingerprint'))
                found = index.search(db, root, FakeModel(), 'process execution', _snapshot_proof=proof)
                assert found['results']
                with pytest.raises(ValueError, match='Invalid private snapshot proof'):
                    index.search(db, root, FakeModel(), 'process execution', _snapshot_proof=proof.fingerprint)
                original = index._manifest
                def stale(root):
                    path, manifest = original(root)
                    return path, {**manifest, 'database_fingerprint': '0' * 64}
                monkeypatch.setattr(index, '_manifest', stale)
                with pytest.raises(ValueError, match='stale'):
                    index.search(db, root, FakeModel(), 'process execution', _snapshot_proof=proof)
        finally:
            db.close(); guard.close(); source.close()


def test_model_cannot_supply_snapshot_proof():
    from forensic_assistant.investigation_ai.contracts import arguments
    with pytest.raises(ValueError, match='unknown parameter'):
        arguments('semantic_search', {'query': 'execution', '_snapshot_proof': 'forged'})


@pytest.mark.skipif(os.name != 'nt', reason='Windows junction gate')
def test_reparse_temporary_parent_is_rejected(tmp_path, monkeypatch):
    target = tmp_path / 'target'
    target.mkdir()
    redirect = tmp_path / 'redirect'
    subprocess.run(['cmd.exe', '/c', 'mklink', '/J', str(redirect), str(target)],
                   check=True, capture_output=True)
    try:
        monkeypatch.setattr(snapshot.tempfile, 'gettempdir', lambda: str(redirect))
        with pytest.raises(ValueError, match='redirection'):
            snapshot.SnapshotDirectory()
        assert not list(target.iterdir())
    finally:
        redirect.rmdir()

"""New read-view contracts are not cryptographic case-equality assertions."""
import io
import json
from pathlib import Path
import sqlite3
import time
import pytest
from forensic_assistant.investigation_ai import controller, transcript, worker
from forensic_assistant.investigation_ai.case import ReadView, ReadViewFingerprint
from test_v4_worker import make_case, config
from test_v4_controller import Scripted, final


def test_worker_initial_and_completion_never_hash_normal_view(tmp_path, monkeypatch):
    from forensic_assistant.artifacts import worker as artifact_worker
    from forensic_assistant.semantic import documents, index
    path = tmp_path/'case.db'
    make_case(path)
    def forbidden(*args):
        pytest.fail('Unexpected whole-case fingerprint')
    monkeypatch.setattr(worker, 'fingerprint', forbidden)
    monkeypatch.setattr(documents, 'fingerprint', forbidden)
    monkeypatch.setattr(artifact_worker, 'limit_memory', lambda: None)
    messages = [{'config':{**config(path), '_transaction_view':True}}]
    messages += [{'operation':op,'seconds':30,'question':'PowerShell','expected_fingerprint':None,
                  'arguments':{},'known_ids':[]} for op in ('initial','check')]
    incoming = io.TextIOWrapper(io.BytesIO(('\n'.join(json.dumps(m) for m in messages)+'\n').encode()))
    outgoing = io.TextIOWrapper(io.BytesIO(), encoding='utf-8')
    monkeypatch.setattr(worker.sys, 'stdin', incoming)
    monkeypatch.setattr(worker.sys, 'stdout', outgoing)
    worker.serve()
    outgoing.flush()
    records = [json.loads(line) for line in outgoing.buffer.getvalue().splitlines()]
    assert not any('error' in r for r in records), records
    initial, check = [r for r in records if 'result' in r]
    assert initial['evidence_state'] == check['evidence_state']
    assert initial['fingerprint'] is check['fingerprint'] is None
    assert check['integrity']['fingerprint_count'] == 0
    assert check['database_changes'] == 0


def test_lazy_semantic_fingerprint_is_exact_and_once_per_view(tmp_path, monkeypatch):
    from forensic_assistant.semantic import documents, index
    from test_v3_index import FakeModel
    from forensic_assistant.investigation_ai.case import open_readonly
    path = tmp_path/'case.db'
    make_case(path)
    source = open_readonly(path)
    try:
        index.build(source, tmp_path/'index', FakeModel())
    finally:
        source.close()
    original = documents.fingerprint
    calls = []
    def counted(db):
        calls.append(db)
        return original(db)
    monkeypatch.setattr(documents, 'fingerprint', counted)
    for changed in (False, True):
        if changed:
            with sqlite3.connect(path) as writer:
                writer.execute("UPDATE events SET raw_xml='changed retained raw bytes'")
        view = ReadView(path, time.monotonic()+30)
        try:
            proof = ReadViewFingerprint(view)
            assert view.fingerprint is None
            if changed:
                with pytest.raises(ValueError, match='stale'):
                    index.search(view.db, tmp_path/'index', FakeModel(), 'execution', _read_view_proof=proof)
            else:
                for _ in range(2):
                    assert index.search(view.db, tmp_path/'index', FakeModel(), 'execution', _read_view_proof=proof)['results']
                assert proof.value(view.db) == original(view.db)
            assert view.fingerprint_count == 1
        finally:
            view.close()
    assert len(calls) == 2


def test_new_transcript_inspection_supported_but_exact_replay_report_refused(tmp_path):
    from forensic_assistant.investigation_ai.replay import replay
    from forensic_assistant.reporting.transcripts import load as report_load
    path = tmp_path/'case.db'
    make_case(path)
    root = tmp_path/'runs'
    result = controller.run(config(path), 'PowerShell', root, client=Scripted([final]))
    iid = result['investigation_id']
    manifest, events = transcript.load(root, iid)
    assert manifest['evidence_fingerprint'] is None
    assert manifest['evidence_state'] == result['evidence_state']
    assert result['termination'] == 'ANSWER_SUPPORTED'
    assert result['metrics']['integrity_status'] == 'view_validated'
    for call in (lambda: replay(config(path), root, iid), lambda: report_load(root, iid)):
        with pytest.raises(ValueError, match='fingerprint-backed transcript'):
            call()
    # Content-chain verification remains required even without a case digest.
    file = root/iid/'events.jsonl'
    raw = file.read_text()
    file.write_text(raw.replace('PowerShell','Changed',1))
    if file.read_text() == raw:
        file.write_text(raw.replace('database_changes":0','database_changes":1',1))
    with pytest.raises(ValueError, match='integrity'):
        transcript.load(root, iid)


@pytest.mark.parametrize('action', ['replace','delete'])
def test_actual_file_identity_changes_or_os_prevents_them(tmp_path, action):
    path = tmp_path/'case.db'
    make_case(path, wal=False)
    replacement = tmp_path/'replacement.db'
    make_case(replacement, wal=False)
    view = ReadView(path, time.monotonic()+30)
    try:
        try:
            if action == 'replace':
                replacement.replace(path)
            else:
                path.unlink()
        except PermissionError:
            # Windows can prevent deletion/replacement of an open SQLite file.
            view.check_identity()
        else:
            with pytest.raises(ValueError, match='EVIDENCE_STATE_CHANGED'):
                view.check_identity()
    finally:
        view.close()


def test_transaction_reset_is_not_a_valid_completion(tmp_path):
    path = tmp_path/'case.db'
    make_case(path)
    view = ReadView(path, time.monotonic()+30)
    view.close()
    with pytest.raises(ValueError, match='read transaction unavailable'):
        view.check_identity()


def test_concurrent_insert_does_not_enter_pinned_view(tmp_path):
    from v1_fixtures import process
    path = tmp_path/'case.db'
    first = make_case(path)
    view = ReadView(path, time.monotonic()+30)
    try:
        with sqlite3.connect(path) as writer:
            writer.row_factory = sqlite3.Row
            second = process(writer, 2, '24')
        assert [r[0] for r in view.db.execute('SELECT id FROM events')] == [first['id']]
        view.check_identity()  # WAL changes are safe, not a whole-case equality claim.
        assert view.fingerprint is None
    finally:
        view.close()
    with sqlite3.connect(path) as live:
        assert {r[0] for r in live.execute('SELECT id FROM events')} == {first['id'], second['id']}

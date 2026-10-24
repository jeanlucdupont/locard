"""Native/extracted convergence, provenance and failure isolation; synthetic MFT."""
import ctypes
import hashlib
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from forensic_assistant.artifacts import native_mft, ntfs_acquisition as ntfs
from forensic_assistant.database.db import connect
from forensic_assistant.database import sources
from forensic_assistant import v2_cli
from forensic_assistant.retrieval.evidence import get_evidence
from v2_fixtures import mft_file

pytestmark = pytest.mark.skipif(os.name != 'nt', reason='Windows native-volume integration')


@pytest.fixture
def native(monkeypatch, tmp_path):
    original = mft_file(tmp_path / 'extracted').read_bytes()
    seen = []
    def acquire(volume, destination, **kwargs):
        seen.append(Path(destination))
        Path(destination).write_bytes(original)
        return dict(source=r'\\.\E:', sha256=hashlib.sha256(original).hexdigest(),
                    bytes_written=len(original), logical_size=len(original),
                    started_utc='2026-01-01T00:00:00+00:00', finished_utc='2026-01-01T00:00:01+00:00',
                    method='native read-only NTFS', limitations=[ntfs.LIVE_LIMITATION])
    monkeypatch.setattr(ntfs, 'acquire', acquire)
    monkeypatch.setattr(ntfs, 'volume_id', lambda path: 'source' if str(path).upper().startswith('E:') else 'case-volume')
    monkeypatch.setattr(native_mft, 'check_storage', lambda *args: None)
    return original, seen


def args():
    return SimpleNamespace(command='ingest-mft', path='E:', source=None, source_name=None,
                           hostname=None, user=None, volume_root=None, parser_timeout=300, record_size=None)


def test_native_and_extracted_same_records_and_source_batch(native, tmp_path):
    from forensic_assistant.artifacts.ingest import ingest_artifact
    raw, seen = native
    db = connect(':memory:')
    try:
        result = v2_cli.ingest_sources(db, args())[0]
        assert result['status'] == 'complete' and result['inserted'] == 3
        assert result['limitation'] == ntfs.LIVE_LIMITATION
        assert seen and all(not p.parent.exists() for p in seen)
        assert [r[0] for r in db.execute('SELECT source_file FROM source_locations')] == ['E:\\$MFT']
        assert {r[0] for r in db.execute('SELECT source_file FROM evidence_records')} == {'E:\\$MFT'}
        row = db.execute('SELECT * FROM ingestion_runs').fetchone()
        assert row['source_file'] == 'E:\\$MFT' and row['batch_id']
        sha = hashlib.sha256(raw).hexdigest()
        assert len(sources.memberships(db, sha)) == 1
        eid = db.execute('SELECT evidence_id FROM evidence_records LIMIT 1').fetchone()[0]
        shown = get_evidence(db, eid)
        assert ntfs.LIVE_LIMITATION in shown['warnings']
        assert shown['source']['acquisitions'][0]['metadata']['sha256'] == sha
        assert shown['source']['acquisitions'][0]['batch_id'] == row['batch_id']
        extracted = tmp_path / '$MFT'; extracted.write_bytes(raw)
        again = ingest_artifact(db, extracted, 'mft')
        assert again['inserted'] == 0 and again['duplicates'] == 3
        assert {r[0] for r in db.execute('SELECT evidence_id FROM evidence_records')} == {
            f'MFT:{sha}:Offset:{offset}' for offset in (0, 5120, 6144)}
    finally: db.close()


@pytest.mark.parametrize('error,category', [
    (PermissionError('denied'), 'administrator privileges required'),
    (ntfs.AcquisitionError('Non-NTFS volume'), 'non-NTFS source'),
    (ntfs.AcquisitionError('Unsupported $ATTRIBUTE_LIST'), 'unsupported NTFS structure'),
    (ntfs.AcquisitionError('Source changed during acquisition'), 'source changed/inconsistent'),
    (ntfs.AcquisitionError('Invalid USA bounds/count'), 'acquisition metadata validation failure'),
    (OSError('device read error'), 'raw-volume access/read failure'),
])
def test_acquisition_failures_persist_without_evidence(native, monkeypatch, error, category):
    seen = []
    def fail(volume, destination, **kw):
        seen.append(Path(destination).parent)
        raise error
    monkeypatch.setattr(ntfs, 'acquire', fail)
    db = connect(':memory:')
    try:
        result = v2_cli.ingest_sources(db, args())[0]
        assert result['status'] == 'failed' and result['acquisition_error'] == category
        assert result['inserted'] == 0 and result['errors'] == 1
        assert db.execute('SELECT count(*) FROM evidence_records').fetchone()[0] == 0
        assert db.execute('SELECT stage FROM ingestion_errors').fetchone()[0] == 'acquire'
        assert db.execute('SELECT status FROM ingestion_batches').fetchone()[0] == 'failed'
        assert all(not p.exists() for p in seen)
    finally: db.close()


def test_cancellation_records_run_and_cleans(native, monkeypatch):
    seen = []
    def cancel(volume, destination, **kw):
        seen.append(Path(destination).parent)
        Path(destination).write_bytes(b'partial synthetic')
        raise KeyboardInterrupt
    monkeypatch.setattr(ntfs, 'acquire', cancel)
    db = connect(':memory:')
    try:
        with pytest.raises(KeyboardInterrupt): v2_cli.ingest_sources(db, args())
        assert db.execute('SELECT status FROM ingestion_runs').fetchone()[0] == 'cancelled'
        assert db.execute('SELECT status FROM ingestion_batches').fetchone()[0] == 'cancelled'
        assert all(not p.exists() for p in seen)
    finally: db.close()


def test_parser_failure_retains_acquisition_metadata(native, monkeypatch):
    # Existing parser containment failure is distinct from acquisition failure.
    from forensic_assistant.artifacts import ingest as pipeline
    original = pipeline.ingest_artifact
    def fail(*args, **kw):
        def runner(*a, **k): raise ValueError('synthetic parser failure')
        return original(*args, **kw, runner=runner)
    monkeypatch.setattr(pipeline, 'ingest_artifact', fail)
    db = connect(':memory:')
    try:
        result = v2_cli.ingest_sources(db, args())[0]
        assert result['status'] == 'failed'
        assert 'acquisition_error' not in result
        assert json.loads(db.execute('SELECT parameters_json FROM artifact_runs').fetchone()[0])['acquisition']['sha256']
        assert all(not p.parent.exists() for p in native[1])
    finally: db.close()


def test_raw_open_flags_and_handle_cleanup(monkeypatch):
    calls = []
    class Function:
        def __init__(self, fn): self.fn = fn
        def __call__(self, *args): return self.fn(*args)
    def ioctl(handle, code, inp, n, output, size, returned, overlap):
        assert code == 0x7405C
        ctypes.cast(output, ctypes.POINTER(ctypes.c_longlong))[0] = 1000000
        ctypes.cast(returned, ctypes.POINTER(ctypes.c_ulong))[0] = 8
        return 1
    kernel = SimpleNamespace(
        CreateFileW=Function(lambda *a: calls.append(('open', a)) or 123),
        CloseHandle=Function(lambda h: calls.append(('close', h)) or 1),
        SetFilePointerEx=Function(lambda *a: 1), ReadFile=Function(lambda *a: 1),
        DeviceIoControl=Function(ioctl))
    monkeypatch.setattr(ctypes, 'WinDLL', lambda *a, **k: kernel)
    reader = ntfs.RawVolume('E:')
    reader.close()
    values = calls[0][1]
    assert values[0] == r'\\.\E:' and values[1] == 0x80000000 and values[2] == 3
    assert values[4] == 3 and values[5] == 0
    assert calls[-1] == ('close', 123)


def test_discovery_native_candidate_and_failure(monkeypatch, tmp_path):
    from forensic_assistant.interactive import discovery
    monkeypatch.setattr(ntfs, 'mounted_volume', lambda value: 'E:' if Path(value) == tmp_path else None)
    monkeypatch.setattr(ntfs, 'probe', lambda value: {})
    # input_path should still use the real synthetic directory in this test.
    monkeypatch.setattr(discovery, 'input_path', lambda value: Path(value))
    inventory = discovery.scan(tmp_path)
    assert inventory.candidates[0].native_volume == 'E:'
    assert inventory.candidates[0].access == 'native read-only NTFS'
    def denied(value): raise PermissionError('denied')
    monkeypatch.setattr(ntfs, 'probe', denied)
    candidate = discovery.scan(tmp_path).candidates[0]
    assert candidate.access == 'requires extraction' and candidate.native_volume is None
    assert 'administrator privileges' in candidate.access_reason


def test_candidate_root_validation_not_filesystem_mft(monkeypatch):
    from forensic_assistant.interactive import discovery
    seen = []
    monkeypatch.setattr(discovery, 'input_path', lambda p: seen.append(p) or Path(p))
    item = discovery.Candidate(Path('E:/$MFT'), 'mft', native_volume='E:')
    assert discovery.candidate_path(item) == 'E:'
    assert seen == ['E:\\']


def test_temp_guard_never_probes_source(monkeypatch):
    import tempfile
    monkeypatch.setattr(tempfile, 'tempdir', None)
    monkeypatch.setenv('TEMP', 'E:\\')
    monkeypatch.setattr(tempfile, 'gettempdir', lambda: pytest.fail('Must not write-probe temp candidates'))
    monkeypatch.setattr(ntfs, 'volume_id', lambda p: 'source')
    db = connect(':memory:')
    try:
        with pytest.raises(ValueError, match='source volume'): native_mft.check_storage(db, 'E:')
    finally: db.close()


def test_guided_native_ingestion_uses_compact_success(native, tmp_path, monkeypatch, capsys):
    from forensic_assistant.interactive import discovery, setup
    from forensic_assistant import activity
    from forensic_assistant.terminal import Palette
    target = tmp_path / 'case.db'
    connect(target).close()
    item = discovery.Candidate(tmp_path / 'source' / '$MFT', 'mft', native_volume='E:')
    plan = setup.Plan('Synthetic', '', '', target, items=[item])
    monkeypatch.setattr(discovery, 'candidate_path', lambda c: 'E:')
    session = activity.Session(target)
    try:
        with activity.bind(session):
            outcomes = setup.execute(plan, session, Palette())
        assert outcomes == {'mft': 'complete'}
        text = capsys.readouterr().out
        assert 'Failed:' not in text and ntfs.LIVE_LIMITATION in text
        assert 'LCN' not in text and 'runlist' not in text
    finally: session.end()


def test_scripted_volume_discovery_once_and_no_file_shortcut(monkeypatch):
    from forensic_assistant.artifacts import ingest as pipeline
    monkeypatch.setattr(Path, 'exists', lambda p: True)
    monkeypatch.setattr(Path, 'is_file', lambda p: False)
    monkeypatch.setattr(pipeline.os, 'walk', lambda *a, **k: [('E:\\', [], ['$MFT'])])
    monkeypatch.setattr(pipeline, 'identify', lambda *a, **k: pytest.fail('Must not open E:\\$MFT'))
    assert list(pipeline.discover('E:', 'mft')) == [('E:', 'mft')]
    assert list(pipeline.discover('E:')) == [('E:', 'mft')]
    assert ntfs.mounted_volume('E:\\$MFT') is None


def test_storage_rejection_precedes_batch_and_audit(monkeypatch):
    from forensic_assistant import activity
    def reject(*a): raise ValueError('source volume storage rejected')
    monkeypatch.setattr(native_mft, 'check_storage', reject)
    monkeypatch.setattr(activity, 'mutation', lambda *a, **k: pytest.fail('Audit mutation before storage validation'))
    db = connect(':memory:')
    try:
        with pytest.raises(ValueError, match='source volume'): v2_cli.ingest_sources(db, args())
        assert db.execute('SELECT count(*) FROM ingestion_batches').fetchone()[0] == 0
    finally: db.close()


@pytest.mark.parametrize('structured', [False, True])
def test_native_cli_summary_or_explicit_json(native, tmp_path, capsys, structured):
    from forensic_assistant.cli import main
    target = tmp_path / 'case.db'
    connect(target).close()
    command = ['--db', str(target), 'ingest', 'mft', 'E:']
    if structured: command.append('--json')
    assert main(command) == 0
    text = capsys.readouterr().out
    if structured:
        result = json.loads(text)
        assert result['results'][0]['acquisition']['sha256']
    else:
        assert 'mft: complete | 3 records | 0 errors' in text
        assert ntfs.LIVE_LIMITATION in text
        assert 'sha256' not in text and 'acquisition' not in text.splitlines()[0]


def test_cli_rejects_source_case_before_creation_or_audit(tmp_path, monkeypatch):
    from forensic_assistant import activity
    from forensic_assistant.cli import main
    monkeypatch.setattr(ntfs, 'volume_id', lambda path: 'same-source-volume')
    monkeypatch.setattr(activity, 'Command', lambda *a: pytest.fail('Audit setup must not occur'))
    target = tmp_path / 'not-created' / 'case.db'
    assert main(['--db', str(target), 'ingest', 'mft', 'E:']) == 2
    assert not target.parent.exists()

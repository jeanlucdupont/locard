"""Acquire a derived temporary MFT, then reuse ordinary artifact ingestion."""
from pathlib import Path
import tempfile
import uuid
import os

from . import ntfs_acquisition as ntfs
from forensic_assistant.database.db import now
from forensic_assistant.database.artifacts import dump
from forensic_assistant.ingest.observation import emit


def check_case_path(case, volume):
    """Run before CLI case creation or audit attachment, not only before parsing."""
    if str(case) == ':memory:':
        return
    parent = Path(case).resolve().parent
    while not parent.exists() and parent != parent.parent:
        parent = parent.parent
    if ntfs.volume_id(parent) == ntfs.volume_id(volume + '\\'):
        raise ValueError('Case database must not be on the native acquisition source volume')


def check_storage(db, volume):
    """Reject case/temp storage on the source before creating anything."""
    source = ntfs.volume_id(volume + '\\')
    for row in db.execute('PRAGMA database_list'):
        if row[2] and ntfs.volume_id(Path(row[2]).parent) == source:
            raise ValueError('Case database must not be on the native acquisition source volume')
    # gettempdir() may test candidate directories by writing a probe file.
    # Select without that probe, then validate before any temporary creation.
    configured = tempfile.tempdir or os.environ.get('TEMP') or os.environ.get('TMP')
    if configured is None and os.name == 'nt':
        import ctypes
        buffer = ctypes.create_unicode_buffer(32768)
        count = ctypes.windll.kernel32.GetTempPathW(len(buffer), buffer)
        if not 0 < count < len(buffer):
            raise OSError('Cannot determine safe acquisition staging directory')
        configured = buffer.value
    temp = Path(configured or '/tmp')
    # This validates ancestors and volume identity without creating a file.
    ntfs.destination_check(temp / ('.locard-native-check-' + uuid.uuid4().hex), source)
    return temp


def failed_run(db, volume, started, exc, batch_id, cancelled=False):
    category, reason = ('cancelled', 'Native MFT acquisition cancelled') if cancelled else ntfs.failure_reason(exc)
    status = 'cancelled' if cancelled else 'failed'
    label = volume + '\\$MFT'
    metadata = dict(source='\\\\.\\' + volume, method='native read-only NTFS',
                    started_utc=started, finished_utc=now(), status=status,
                    failure_category=category, limitations=[ntfs.LIVE_LIMITATION])
    with db:
        run = db.execute('INSERT INTO ingestion_runs(source_file,started_utc,finished_utc,status,error_count,batch_id) VALUES (?,?,?,?,?,?)',
                         (label, started, now(), status, 1, batch_id)).lastrowid
        db.execute('INSERT INTO artifact_runs VALUES (?,?,?,?,?,?,?)',
                   (run, 'mft', 'native-ntfs-acquisition', '1', '1', None, dump({'acquisition': metadata})))
        db.execute('INSERT INTO ingestion_errors(run_id,stage,message) VALUES (?,?,?)',
                   (run, 'acquire', category + ': ' + reason))
    return dict(run_id=run, source_file=label, source_type='mft', status=status,
                inserted=0, duplicates=0, errors=1, acquisition_error=category, limitation=reason)


def ingest(db, volume, *, batch_id=None, timeout=300, record_size=None):
    from .ingest import ingest_artifact
    storage = check_storage(db, volume)
    started = now()
    try:
        with tempfile.TemporaryDirectory(prefix='locard-native-mft-', dir=storage) as directory:
            path = Path(directory) / '$MFT'
            emit(parser_stage='native read-only NTFS acquisition', current_path=volume + '\\$MFT')
            try:
                metadata = ntfs.acquire(volume, path, write_metadata=False)
                metadata.update(artifact='$MFT', storage='temporary derived acquisition; removed after ingestion',
                                source_state='live mounted volume; not frozen')
            except KeyboardInterrupt as exc:
                failed_run(db, volume, started, exc, batch_id, cancelled=True)
                raise
            except (OSError, ValueError) as exc:
                return failed_run(db, volume, started, exc, batch_id)
            emit(parser_stage='hashing acquired MFT')
            result = ingest_artifact(db, path, 'mft', batch_id=batch_id, timeout=timeout,
                                     record_size=record_size, acquisition=metadata,
                                     source_label=volume + '\\$MFT')
            result['limitation'] = ntfs.LIVE_LIMITATION
            if result['status'] != 'complete':
                phase = ('Acquired MFT failed integrity validation' if result['status'] == 'changed'
                         else 'MFT parsing failed or was incomplete after successful native acquisition')
                result['limitation'] = phase + '. ' + ntfs.LIVE_LIMITATION
            result['acquisition'] = metadata
            return result
    except KeyboardInterrupt:
        raise

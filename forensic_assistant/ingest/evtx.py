"""Read-only parsing, disk-backed staging, and auditable ingestion outcomes."""
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path
import hashlib
import json
from forensic_assistant.ingest.validation import identifier_note, LABEL
import os
import tempfile
from forensic_assistant.database.db import connect, insert_events, register_source, now
from forensic_assistant.ingest.normalize import normalize
from forensic_assistant.model import NormalizedEvent


@dataclass
class ParsedRecord:
    offset: int | None
    record_id: int | None = None
    xml: str | None = None
    error: str | None = None
    diagnostics: dict | None = None


def digest(path):
    sha = hashlib.sha256()
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            sha.update(block)
    return sha.hexdigest()


def records(path, *, timeout=300):
    from forensic_assistant.ingest.evtx_recovery import read_records
    yield from read_records(path, timeout=timeout)


def ingest_file(db, path, batch_size=500, reader=records, reporter=None, *, batch_id=None, timeout=300):
    if batch_size < 1:
        raise ValueError("Batch size must be positive")
    path = Path(path).resolve()
    import importlib.metadata
    parser_metadata = {
        'parser_name': 'python-evtx',
        'parser_version': importlib.metadata.version('python-evtx')
    } if reader is records else {}
    run_id = None
    errors = 0
    identifier_discrepancies = 0
    diagnostics = []

    def report(stage, message, offset=None, record_id=None, diagnostic=None):
        nonlocal errors
        errors += 1
        with db:
            error_id = db.execute(
                "INSERT INTO ingestion_errors(run_id,record_offset,record_id,stage,message) VALUES (?,?,?,?,?)",
                (run_id, offset, record_id, stage, message)
            ).lastrowid
            if diagnostic is not None:
                diagnostics.append((error_id, diagnostic))
                db.execute("INSERT INTO artifact_errors VALUES (?,?)", (error_id, json.dumps(diagnostic)))
        if reporter:
            reporter(f"{path} offset={offset} record={record_id}: {stage}: {message}")

    inserted = duplicates = 0
    status = "failed"
    try:
        with db:
            run_id = db.execute(
                "INSERT INTO ingestion_runs(source_file,started_utc,status) VALUES (?, ?, ?)",
                (str(path), now(), "running")
            ).lastrowid
            if batch_id is not None:
                db.execute('UPDATE ingestion_runs SET batch_id=? WHERE id=?', (batch_id, run_id))
        before = digest(path)
        size = path.stat().st_size
        with tempfile.TemporaryDirectory(prefix="locard-stage-") as temp:
            with closing(connect(Path(temp) / "stage.db")) as stage:
                with stage:
                    register_source(stage, before, size, str(path))
                batch = []
                try:
                    for record in (records(path, timeout=timeout) if reader is records else reader(path)):
                        if record.error:
                            report("parse", record.error, record.offset, record.record_id, record.diagnostics)
                            continue
                        try:
                            event = normalize(record.xml, before, str(path), record.offset)
                            if record.record_id is not None and event.record_id != record.record_id:
                                if event.record_id is not None and event.record_id >= 0:
                                    notes = json.loads(event.normalization_warnings_json)
                                    notes.append(identifier_note(record.record_id, event.record_id, record.offset))
                                    event.normalization_warnings_json = json.dumps(notes)
                                    identifier_discrepancies += 1
                                else:
                                    report(
                                        "normalize",
                                        "XML EventRecordID missing or invalid; EVTX record-header identifier=" + str(record.record_id),
                                        record.offset,
                                        record.record_id
                                    )
                            batch.append(event)
                            if len(batch) >= batch_size:
                                with stage:
                                    insert_events(stage, batch, **parser_metadata)
                                batch.clear()
                        except Exception as exc:
                            report("normalize", f"{type(exc).__name__}: {exc}", record.offset, record.record_id)
                except Exception as exc:
                    report("parse", f"File iteration stopped: {type(exc).__name__}: {exc}")
                with db:
                    for error_id, diagnostic in diagnostics:
                        db.execute("UPDATE artifact_errors SET locator_json=? WHERE error_id=?",
                                   (json.dumps(diagnostic), error_id))
                with stage:
                    insert_events(stage, batch, **parser_metadata)
                if digest(path) != before or path.stat().st_size != size:
                    report("integrity", "Source changed during ingestion; staged records rejected")
                    status = "changed"
                else:
                    with db:
                        register_source(db, before, size, str(path))
                        cursor = stage.execute("SELECT * FROM events ORDER BY record_offset")
                        while rows := cursor.fetchmany(batch_size):
                            count = insert_events(db, [NormalizedEvent(**dict(row)) for row in rows], **parser_metadata)
                            inserted += count
                            duplicates += len(rows) - count
                        db.execute("UPDATE ingestion_runs SET file_sha256=? WHERE id=?", (before, run_id))
                    status = "partial" if errors else "complete"
        with db:
            db.execute(
                "UPDATE ingestion_runs SET finished_utc=?,status=?,inserted_count=?,duplicate_count=?,error_count=? WHERE id=?",
                (now(), status, inserted, duplicates, errors, run_id)
            )
    except KeyboardInterrupt:
        from forensic_assistant.ingest.interruption import record_interruption
        record_interruption(db, run_id, inserted, duplicates)
        raise
    except Exception as exc:
        db.rollback()
        if run_id is None:
            raise
        published = db.execute('SELECT file_sha256 FROM ingestion_runs WHERE id=?', (run_id,)).fetchone()
        if not published:
            raise
        if published[0] is None:
            inserted = duplicates = 0
        status = 'partial' if published[0] is not None else 'failed'
        report("file", f"{type(exc).__name__}: {exc}")
        with db:
            db.execute(
                "UPDATE ingestion_runs SET finished_utc=?,status=?,inserted_count=?,duplicate_count=?,error_count=? WHERE id=?",
                (now(), status, inserted, duplicates, errors, run_id)
            )
    return {
        "run_id": run_id,
        "source_file": str(path),
        "status": status,
        "inserted": inserted,
        "duplicates": duplicates,
        "errors": errors,
        "validation_notes": {LABEL: identifier_discrepancies} if identifier_discrepancies else {}
    }


def discover(path):
    path = Path(path)
    if not path.exists():
        raise ValueError(f"Evidence path does not exist: {path}")
    if path.is_file():
        if path.suffix.lower() != ".evtx":
            raise ValueError("Expected an .evtx file")
        yield path
        return
    def fail(error):
        raise error
    for root, dirs, files in os.walk(path, onerror=fail, followlinks=False):
        dirs.sort()
        for name in sorted(files):
            if name.lower().endswith(".evtx"):
                yield Path(root) / name

"""Read-only parsing, disk-backed staging, and auditable ingestion outcomes."""
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path
import hashlib
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


def digest(path):
    sha = hashlib.sha256()
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            sha.update(block)
    return sha.hexdigest()


def records(path):
    from Evtx.Evtx import Evtx
    with Evtx(str(path)) as log:
        header = log.get_file_header()
        if not header.verify():
            yield ParsedRecord(0, error="File header verification failed")
        seen_chunks = 0
        for chunk in log.chunks():
            seen_chunks += 1
            end = chunk.offset() + 512
            try:
                if not chunk.verify():
                    yield ParsedRecord(chunk.offset(), error="Chunk checksum/header verification failed")
                for record in chunk.records():
                    offset = record.offset()
                    record_id = None
                    try:
                        end = offset + record.length()
                        record_id = record.record_num()
                        if not record.verify():
                            yield ParsedRecord(offset, record_id, error="Record size verification failed")
                        yield ParsedRecord(offset, record_id, xml=record.xml())
                    except Exception as exc:
                        yield ParsedRecord(offset, record_id, error=f"{type(exc).__name__}: {exc}")
                if end != chunk.offset() + chunk.next_record_offset():
                    yield ParsedRecord(end, error="Parser stopped before the declared end of chunk; records may be missing")
            except Exception as exc:
                yield ParsedRecord(end, error=f"Chunk iteration failed: {exc}")
        if seen_chunks != header.chunk_count():
            yield ParsedRecord(None, error="File truncated: fewer chunks than declared")


def ingest_file(db, path, batch_size=500, reader=records, reporter=None):
    if batch_size < 1:
        raise ValueError("Batch size must be positive")
    path = Path(path).resolve()
    import importlib.metadata
    parser_metadata={'parser_name':'python-evtx','parser_version':importlib.metadata.version('python-evtx')} if reader is records else {}
    with db:
        run_id = db.execute("INSERT INTO ingestion_runs(source_file,started_utc,status) VALUES (?, ?, ?)",
                            (str(path), now(), "running")).lastrowid
    errors = 0

    def report(stage, message, offset=None, record_id=None):
        nonlocal errors
        errors += 1
        with db:
            db.execute("INSERT INTO ingestion_errors(run_id,record_offset,record_id,stage,message) VALUES (?,?,?,?,?)",
                       (run_id, offset, record_id, stage, message))
        if reporter:
            reporter(f"{path} offset={offset} record={record_id}: {stage}: {message}")

    inserted = duplicates = 0
    status = "failed"
    try:
        before = digest(path)
        size = path.stat().st_size
        with tempfile.TemporaryDirectory(prefix="locard-stage-") as temp:
            with closing(connect(Path(temp) / "stage.db")) as stage:
                with stage:
                    register_source(stage, before, size, str(path))
                batch = []
                try:
                    for record in reader(path):
                        if record.error:
                            report("parse", record.error, record.offset, record.record_id)
                            continue
                        try:
                            event = normalize(record.xml, before, str(path), record.offset)
                            if record.record_id is not None and event.record_id != record.record_id:
                                report("normalize", "XML EventRecordID differs from binary record number", record.offset, record.record_id)
                            batch.append(event)
                            if len(batch) >= batch_size:
                                with stage:
                                    insert_events(stage, batch,**parser_metadata)
                                batch.clear()
                        except Exception as exc:
                            report("normalize", f"{type(exc).__name__}: {exc}", record.offset, record.record_id)
                except Exception as exc:
                    report("parse", f"File iteration stopped: {type(exc).__name__}: {exc}")
                with stage:
                    insert_events(stage, batch,**parser_metadata)
                if digest(path) != before or path.stat().st_size != size:
                    report("integrity", "Source changed during ingestion; staged records rejected")
                    status = "changed"
                else:
                    with db:
                        register_source(db, before, size, str(path))
                        cursor = stage.execute("SELECT * FROM events ORDER BY record_offset")
                        while rows := cursor.fetchmany(batch_size):
                            count = insert_events(db, [NormalizedEvent(**dict(row)) for row in rows],**parser_metadata)
                            inserted += count
                            duplicates += len(rows) - count
                        db.execute("UPDATE ingestion_runs SET file_sha256=? WHERE id=?", (before, run_id))
                    status = "partial" if errors else "complete"
    except Exception as exc:
        inserted = duplicates = 0
        report("file", f"{type(exc).__name__}: {exc}")
    with db:
        db.execute("UPDATE ingestion_runs SET finished_utc=?,status=?,inserted_count=?,duplicate_count=?,error_count=? WHERE id=?",
                   (now(), status, inserted, duplicates, errors, run_id))
    return {"run_id": run_id, "source_file": str(path), "status": status,
            "inserted": inserted, "duplicates": duplicates, "errors": errors}


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

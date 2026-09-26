"""Record graceful interruption without undoing or misdescribing prior commits."""
from forensic_assistant.database.db import now


def record_interruption(db, run_id, inserted, duplicates):
    db.rollback()
    # The source hash is published in the same transaction as current-file rows.
    row = db.execute('SELECT file_sha256 FROM ingestion_runs WHERE id=?',(run_id,)).fetchone()
    if row is None: return  # Interrupted before the run record was committed.
    published = row[0] is not None
    if not published: inserted=duplicates=0
    message = ('Interrupted. Current-file publication '+('was committed' if published else 'was not committed')+
               '; previously completed ingestion runs remain committed.')
    with db:
        db.execute('INSERT INTO ingestion_errors(run_id,stage,message) VALUES (?,?,?)',(run_id,'interruption',message))
        db.execute("UPDATE ingestion_runs SET finished_utc=?,status='interrupted',inserted_count=?,duplicate_count=?,error_count=(SELECT count(*) FROM ingestion_errors WHERE run_id=?) WHERE id=?",
                   (now(),inserted,duplicates,run_id,run_id))

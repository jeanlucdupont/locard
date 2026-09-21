"""Explicit synthetic gate for the rejected full-investigation snapshot design."""
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import time

def reader(path):
    db=sqlite3.connect(Path(path).resolve().as_uri()+'?mode=ro',uri=True)
    db.execute('PRAGMA query_only=ON');db.execute('BEGIN')
    print(db.execute('SELECT count(*) FROM gate').fetchone()[0],flush=True)
    for line in sys.stdin:
        if line.strip()=='count':print(db.execute('SELECT count(*) FROM gate').fetchone()[0],flush=True)
        else:break
    db.rollback();db.close()

def validate(root):
    root=Path(root);root.mkdir(parents=True);path=root/'synthetic.db'
    writer=sqlite3.connect(path,timeout=1)
    writer.execute('PRAGMA journal_mode=WAL')
    writer.execute('CREATE TABLE gate(id INTEGER PRIMARY KEY,value BLOB)')
    writer.execute('INSERT INTO gate(value) VALUES (?)',(b'initial',));writer.commit()
    children=[];times=[]
    try:
        for _ in range(2):
            child=subprocess.Popen([sys.executable,__file__,'reader',str(path)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,text=True,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
            children.append(child);assert int(child.stdout.readline())==1
        for _ in range(24):
            started=time.perf_counter()
            writer.executemany('INSERT INTO gate(value) VALUES (?)',[(bytes(65536),)]*64);writer.commit()
            times.append(time.perf_counter()-started)
        retained=Path(str(path)+'-wal').stat().st_size
        blocked=writer.execute('PRAGMA wal_checkpoint(PASSIVE)').fetchone()
        children[0].stdin.write('count\n');children[0].stdin.flush()
        snapshot_count=int(children[0].stdout.readline())
        children[0].stdin.write('close\n');children[0].stdin.flush();children[0].wait(timeout=5)
        started=time.perf_counter();children[1].kill();children[1].wait(timeout=5)
        recovered=writer.execute('PRAGMA wal_checkpoint(TRUNCATE)').fetchone()
        result={'writer_max_seconds':max(times),'retained_wal_bytes':retained,'checkpoint_while_reading':blocked,
            'snapshot_rows':snapshot_count,'live_rows':writer.execute('SELECT count(*) FROM gate').fetchone()[0],
            'forced_termination_cleanup_seconds':time.perf_counter()-started,'checkpoint_after_exit':recovered,
            'long_snapshot_gate':'REJECT' if retained>64*1024*1024 else 'within WAL allowance'}
    finally:
        for child in children:
            if child.poll() is None:child.kill();child.wait(timeout=5)
            for stream in (child.stdin,child.stdout,child.stderr):stream.close()
        writer.close()
    path=root/'rollback.db';writer=sqlite3.connect(path,timeout=.15)
    writer.execute('CREATE TABLE gate(id INTEGER)');writer.execute('INSERT INTO gate VALUES (1)');writer.commit()
    reader_db=sqlite3.connect(path);reader_db.execute('BEGIN');reader_db.execute('SELECT * FROM gate').fetchall()
    try:
        try:writer.execute('INSERT INTO gate VALUES (2)');writer.commit();result['rollback_writer_blocked']=False
        except sqlite3.OperationalError:result['rollback_writer_blocked']=True;writer.rollback()
    finally:reader_db.rollback();reader_db.close();writer.close()
    return result

if __name__=='__main__':
    if len(sys.argv)==3 and sys.argv[1]=='reader':reader(sys.argv[2])
    elif len(sys.argv)==2:print(json.dumps(validate(sys.argv[1]),indent=2))
    else:raise SystemExit('Usage: python tests/v4_snapshot_validation.py NEW_OUTPUT_DIRECTORY')

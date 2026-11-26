"""Provider-free Defender inventory and explicit transactional timestamp repair."""
import argparse
import json
from pathlib import Path
import sqlite3
import sys
import time
import uuid
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from forensic_assistant.artifacts.defender_maintenance import population,repair
from forensic_assistant.artifacts.sqlite_recovery import regular
from forensic_assistant.interactive.case import check_structure,open_existing
from forensic_assistant import activity


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--db',required=True);p.add_argument('--source',required=True)
    mode=p.add_mutually_exclusive_group();mode.add_argument('--preview',action='store_true');mode.add_argument('--apply',action='store_true')
    p.add_argument('--confirm',action='store_true',help='Explicitly authorize derived-data mutation; required with --apply')
    p.add_argument('--time-policy',default='format-utc');p.add_argument('--examples',type=int,default=3)
    a=p.parse_args()
    if a.apply!=a.confirm:p.error('--apply and --confirm must be used together')
    path=Path(a.db).absolute();regular(path);started=time.monotonic();last=[started]
    def progress(count):
        if time.monotonic()-last[0]>5:
            print(f'Verifying/reparsing retained Defender bytes: {count} records; {time.monotonic()-started:.0f}s elapsed',file=sys.stderr,flush=True);last[0]=time.monotonic()
    db=open_existing(path) if a.apply else sqlite3.connect(path.as_uri()+'?mode=ro',uri=True,timeout=.2)
    db.row_factory=sqlite3.Row
    try:
        db.execute('PRAGMA trusted_schema=OFF');check_structure(db)
        if a.apply:
            session=activity.Session(path);session.start();operation_id=uuid.uuid4().hex
            try:
                with activity.bind(session),activity.mutation('DEFENDER_NORMALIZATION_REPAIR',source_id=a.source,policy=a.time_policy,repair_id=operation_id) as receipt:
                    result=repair(db,a.source,policy=a.time_policy,apply=True,progress=progress,operation_id=operation_id);receipt.update({k:v for k,v in result.items() if k!='operation_id'})
            finally:session.end()
        elif a.preview:result=repair(db,a.source,policy=a.time_policy,progress=progress)
        else:
            db.execute('BEGIN');result=population(db,a.source,a.examples);db.rollback()
        print(json.dumps(result,ensure_ascii=True,indent=2));return 0
    except KeyboardInterrupt:
        db.rollback();print('Cancelled; uncommitted repair rolled back. Inspect the maintenance receipt if cancellation occurred during commit.',file=sys.stderr);return 130
    except (ValueError,OSError,sqlite3.Error) as exc:
        db.rollback();print(type(exc).__name__+': '+str(exc),file=sys.stderr);return 2
    finally:db.close()

if __name__=='__main__':raise SystemExit(main())

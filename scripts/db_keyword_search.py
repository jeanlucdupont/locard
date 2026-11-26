"""Independent read-only SQLite literal search. No Locard retrieval imports."""
import argparse
from contextlib import closing
from collections import Counter
import csv
import json
from pathlib import Path
import sqlite3
import sys
import time


def quote(name):return '"'+name.replace('"','""')+'"'


def open_readonly(path):
    db=sqlite3.connect(Path(path).absolute().as_uri()+'?mode=ro',uri=True,timeout=.2)
    db.enable_load_extension(False);db.execute('PRAGMA query_only=ON');db.execute('PRAGMA trusted_schema=OFF')
    def authorize(action,a,b,*rest):
        if action in (sqlite3.SQLITE_SELECT,sqlite3.SQLITE_READ,sqlite3.SQLITE_FUNCTION):return sqlite3.SQLITE_OK
        if action==sqlite3.SQLITE_PRAGMA and a in ('table_xinfo','table_info'):return sqlite3.SQLITE_OK
        return sqlite3.SQLITE_DENY
    db.execute('BEGIN')  # One read transaction across every table; never a live mixed-state scan.
    db.set_authorizer(authorize)
    return db


def search(db,keywords,*,examples=3,seconds=None,check=lambda:None,progress=lambda value:None):
    if not keywords or any(not isinstance(k,str) or not k for k in keywords):raise ValueError('Nonempty literal keywords required')
    if not 0<=examples<=20 or seconds is not None and seconds<=0:raise ValueError('Invalid output/time bounds')
    keywords=list(dict.fromkeys(keywords));folded=[s.casefold() for s in keywords];started=time.monotonic();last=started
    result=dict(contract='independent-keyword-search-v1',complete=True,tables=[],errors=[],keywords=keywords,
                matching='Python Unicode casefold literal substring, without Unicode normalization; counts are matching cells, not occurrences or unique events',
                limitations=['BLOBs are counted but not decoded; compressed/encoded payloads and binary content are not searched.',
                  'JSON is searched as stored text, not decoded strings; escaped Unicode and Base64 may not match decoded text.',
                  'Views are not evaluated; all enumerated tables including virtual/internal tables are attempted.',
                  'Duplicate and derived representations count separately; counts are not unique evidence records.'])
    def stop():
        check()
        if seconds is not None and time.monotonic()-started>=seconds:raise TimeoutError('Analyst time budget reached')
    # Interrupt long SQLite reads cooperatively; Python traversal checks independently.
    db.set_progress_handler(lambda:int(seconds is not None and time.monotonic()-started>=seconds),1000)
    try:
        names=[r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")]
        result['tables_enumerated']=len(names)
        for name in names:
            stop();table=dict(name=name,complete=False,rows=0,text_cells=0,binary_cells=0,matches=[],error=None);result['tables'].append(table)
            counts=Counter();samples={};columns=[]
            try:
                columns=[r for r in db.execute('PRAGMA table_xinfo('+quote(name)+')') if r[6]!=1]
                column_names=[r[1] for r in columns];keys=[r[1] for r in sorted(columns,key=lambda x:x[5]) if r[5]]
                if not columns:raise ValueError('No readable columns')
                key_indexes=[column_names.index(k) for k in keys]
                sql='SELECT '+','.join(map(quote,column_names))+' FROM '+quote(name)
                if keys:sql+=' ORDER BY '+','.join(map(quote,keys))
                for row in db.execute(sql):
                    stop();table['rows']+=1
                    identity={column_names[i]:str(row[i])[:256] for i in key_indexes} if keys else {'scan_ordinal':table['rows'],'stable_identifier':False}
                    for col,value in zip(column_names,row):
                        if isinstance(value,bytes):table['binary_cells']+=1;continue
                        if not isinstance(value,str):continue
                        table['text_cells']+=1;fold=value.casefold()
                        for index,term in enumerate(folded):
                            if term not in fold:continue
                            token=(index,col);counts[token]+=1
                            bucket=samples.setdefault(token,[])
                            if len(bucket)<examples:bucket.append(dict(identity=identity,text=value[:512],truncated=len(value)>512))
                    if time.monotonic()-last>=1:
                        progress(dict(table=name,rows=table['rows'],elapsed_seconds=time.monotonic()-started));last=time.monotonic()
                table['complete']=True
            except (sqlite3.Error,ValueError) as exc:
                table['error']=type(exc).__name__+': '+str(exc);result['errors'].append(dict(table=name,error=table['error']));result['complete']=False
                stop()
            finally:
                table['matches']=[dict(keyword=keywords[i],column=c,count=n,examples=samples[(i,c)]) for (i,c),n in sorted(counts.items())]
                table['columns_attempted']=[c[1] for c in columns]
        result['tables_scanned']=len(result['tables'])
    except (KeyboardInterrupt,TimeoutError,sqlite3.Error) as exc:
        result['complete']=False;result['errors'].append(dict(error=type(exc).__name__+': '+str(exc)))
    finally:db.set_progress_handler(None,0)
    result['elapsed_seconds']=time.monotonic()-started
    result['counts_complete']=result['complete'];return result


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--db',required=True);p.add_argument('--keyword',action='append',required=True)
    p.add_argument('--examples',type=int,default=3);p.add_argument('--seconds',type=float);p.add_argument('--format',choices=('human','json','csv'),default='human')
    a=p.parse_args()
    try:
        with closing(open_readonly(a.db)) as db:
            result=search(db,a.keyword,examples=a.examples,seconds=a.seconds,progress=lambda e:print(json.dumps(e,ensure_ascii=True),file=sys.stderr,flush=True))
    except (sqlite3.Error,OSError,ValueError) as exc:
        print(json.dumps(dict(complete=False,error=type(exc).__name__+': '+str(exc))),file=sys.stderr);return 2
    if a.format=='json':print(json.dumps(result,ensure_ascii=True,indent=2))
    elif a.format=='csv':
        out=csv.writer(sys.stdout);out.writerow(['table','column','keyword','matching_cells','table_complete','examples_json'])
        for t in result['tables']:
            for m in t['matches']:out.writerow([json.dumps(t['name'],ensure_ascii=True),json.dumps(m['column'],ensure_ascii=True),json.dumps(m['keyword'],ensure_ascii=True),m['count'],t['complete'],json.dumps(m['examples'],ensure_ascii=True)])
        print(json.dumps({k:v for k,v in result.items() if k!='tables'},ensure_ascii=True),file=sys.stderr)
    else:
        # JSON quoting prevents control sequences from untrusted identifiers/content.
        for t in result['tables']:
            print(json.dumps(t,ensure_ascii=True))
        print(json.dumps({k:v for k,v in result.items() if k!='tables'},ensure_ascii=True))
    return 0 if result['complete'] else 2

if __name__=='__main__':raise SystemExit(main())

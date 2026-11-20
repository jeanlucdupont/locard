"""Bounded independent Browser table reads; normalizers and record IDs are shared."""
from contextlib import closing
import sqlite3
from .browser import TABLES, STATES, pack, timestamp
from .sqlite_immutable import connection


def parse(path, product, profile, context, extraction):
    counts = extraction['counts'] = dict(extracted=0,rejected=0)
    coverage = extraction['tables'] = {}
    extraction['all_supported_tables_read'] = False
    warnings = list(extraction['limitations'])
    warnings.append('Best-effort immutable main-file extraction; database-level uncertainty does not establish that an individual event is false.')
    with closing(connection(path)) as db:
        definitions=db.execute("SELECT name,type,sql FROM sqlite_master WHERE name IN ('urls','visits','downloads','downloads_url_chains')").fetchall()
        if any(r['type']!='table' or 'VIRTUAL' in (r['sql'] or '').upper() for r in definitions):
            raise ValueError('Unsupported Chromium History schema: executable table/view refused')
        columns={}
        for table in TABLES:
            try:
                layout=list(db.execute('PRAGMA table_info('+table+')'))
                columns[table]={r['name'] for r in layout}
                coverage[table]='pending' if layout else 'absent'
                if table!='downloads_url_chains' and layout and [r['name'] for r in layout if r['pk']]!=['id']:
                    columns[table]=set();coverage[table]='unsupported_identity'
            except sqlite3.Error:
                columns[table]=set();coverage[table]='unreadable_schema'
        required={'urls':{'id','url'},'visits':{'id','url','visit_time'},
                  'downloads':{'id','start_time'},'downloads_url_chains':{'id','chain_index','url'}}
        for table,names in required.items():
            if columns[table] and not names<=columns[table]:
                columns[table]=set();coverage[table]='unsupported_columns'
        for table in TABLES:
            if coverage[table] != 'pending':
                warnings.append('Browser table '+table+': '+coverage[table]+'.')
        if 'full_path' in columns['downloads'] and not {'target_path','current_path'} & columns['downloads']:
            columns['downloads']=set();coverage['downloads']='unsupported_legacy_epoch'
        db.set_authorizer(lambda action,a,b,c,d: sqlite3.SQLITE_OK if action in
                          (sqlite3.SQLITE_SELECT,sqlite3.SQLITE_READ) else sqlite3.SQLITE_DENY)
        def error(table,reason,row_id=None,rejected=False):
            if rejected: counts['rejected']+=1
            return dict(error=reason,locator=dict(table=table,row_id=row_id,extraction_mode=extraction['mode']))
        def field(table,alias,name,output=None):
            return (alias+'.'+name if name in columns[table] else 'NULL')+' AS '+(output or name)
        def valid(detail,kind):
            if type(detail['id']) is not int: raise ValueError('Invalid Browser row identity')
            required_time='visit_time' if kind=='visit' else 'start_time'
            if type(detail[required_time]) is not int or detail[required_time]<0:
                raise ValueError('Invalid required Browser timestamp field')
            if kind=='visit' and (type(detail['url_row_id']) is not int or not isinstance(detail['url'],str) or not detail['url']):
                raise ValueError('Invalid or missing required Browser URL reference')
            for name in ('url','title','target_path','current_path','full_path','referrer','mime_type'):
                value=detail.get(name)
                if value is not None and (not isinstance(value,str) or '\0' in value):
                    raise ValueError('Invalid Browser text field: '+name)
            for name in ('transition','url_visit_count','url_typed_count','received_bytes','total_bytes','state','danger_type','end_time'):
                if detail.get(name) is not None and type(detail[name]) is not int:
                    raise ValueError('Invalid Browser numeric field: '+name)
        if columns['urls'] and columns['visits']:
            fields=['v.id','v.url AS url_row_id','v.visit_time','u.url']
            fields += [field('urls','u',n,'url_'+n if n.endswith('count') else n) for n in ('title','visit_count','typed_count')]
            fields += [field('visits','v','transition')]
            try:
                for row in db.execute('SELECT '+','.join(fields)+' FROM visits v LEFT JOIN urls u ON u.id=v.url ORDER BY v.id'):
                    detail=dict(row)
                    try:
                        valid(detail,'visit')
                        record=pack(detail,'visit',[timestamp(row['visit_time'],'Browser.VisitTime')],warnings,product,profile,context)
                    except ValueError as exc:
                        yield error('visits',str(exc),row['id'],True);continue
                    counts['extracted']+=1;yield record
                coverage['visits']='read';coverage['urls']='read_referenced_rows'
            except sqlite3.Error as exc:
                coverage['visits']='iteration_failed'
                yield error('visits','SQLite visit iteration failed: '+type(exc).__name__)
        else:
            coverage['visits']='unavailable_required_structure'
            yield error('visits','Visit table or required URL structure unavailable; visits not extracted')
        if columns['downloads']:
            names=('target_path','current_path','full_path','url','referrer','mime_type','received_bytes','total_bytes','state','danger_type','end_time')
            try:
                for row in db.execute('SELECT d.id,d.start_time,'+','.join(field('downloads','d',n) for n in names)+' FROM downloads d ORDER BY d.id'):
                    detail=dict(row)
                    try:
                        valid(detail,'download')
                        urls=[]
                        if columns['downloads_url_chains']:
                            for chain in db.execute('SELECT chain_index,url FROM downloads_url_chains WHERE id=? ORDER BY chain_index,url LIMIT 1001',(row['id'],)):
                                if type(chain['chain_index']) is not int or chain['chain_index']<0 or not isinstance(chain['url'],str) or '\0' in chain['url']:
                                    raise ValueError('Invalid Browser download URL chain')
                                urls.append(dict(chain))
                            if len(urls)>1000: raise ValueError('Download URL chain exceeds 1000-entry bound')
                        detail['url_chain']=urls;detail['state_name']=STATES.get(detail['state'],'unknown')
                        record=pack(detail,'download',[timestamp(row['start_time'],'Browser.DownloadStart'),timestamp(row['end_time'],'Browser.DownloadEnd')],warnings,product,profile,context)
                    except (ValueError,sqlite3.Error) as exc:
                        if isinstance(exc,sqlite3.Error): coverage['downloads_url_chains']='iteration_failed'
                        yield error('downloads',str(exc) if isinstance(exc,ValueError) else 'SQLite URL-chain query failed',row['id'],True);continue
                    counts['extracted']+=1;yield record
                coverage['downloads']='read'
                if coverage['downloads_url_chains']=='pending': coverage['downloads_url_chains']='read_referenced_rows'
            except sqlite3.Error as exc:
                coverage['downloads']='iteration_failed'
                yield error('downloads','SQLite download iteration failed: '+type(exc).__name__)
        elif coverage['downloads']!='absent':
            yield error('downloads','Download schema unsupported; downloads not extracted')
        if coverage['downloads_url_chains'] not in ('read_referenced_rows','absent'):
            yield error('downloads_url_chains','Download URL-chain coverage incomplete')
        extraction['all_supported_tables_read']=all(v in ('read','read_referenced_rows','absent') for v in coverage.values())
        extraction['record_scope']='Supported visit/download queries; URL tables read for referenced rows only'
        if not extraction['all_supported_tables_read']:
            extraction['limitations'].append('Some supported Browser tables or queries were not fully read.')
        extraction['empty_readable']=counts['extracted']==0 and counts['rejected']==0 and extraction['all_supported_tables_read']

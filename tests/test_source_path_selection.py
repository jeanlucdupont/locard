"""Entirely synthetic historical records; paths are not filesystem fixtures."""
from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import pytest
from forensic_assistant.cli import main,build_parser
from forensic_assistant import source_cli,v2_cli,terminal,output
from forensic_assistant.database import sources,migrations,source_selection
from forensic_assistant.database.db import connect,register_source
from forensic_assistant.database.artifacts import register,add_timestamp,add_object
from forensic_assistant.semantic.documents import fingerprint
from forensic_assistant.retrieval.evidence import EvidenceQueries,get_evidence
from test_sources_model import connect as legacy

ROOT=r'C:\Evidence\PC01\Prefetch collection'


def populate(db,count=3):
    hashes=[]
    with db:
        for i in range(count+1):
            raw=f'Synthetic Prefetch record {i}'.encode();sha=hashlib.sha256(raw).hexdigest();hashes.append(sha)
            path=(ROOT if i<count else r'C:\Evidence\PC010\Prefetch collection')+f'\\APP{i}.pf'
            eid='PREFETCH:'+sha+':File'
            register_source(db,sha,len(raw),path)
            register(db,dict(evidence_id=eid,source_type='prefetch',artifact_type='prefetch_file',file_sha256=sha,source_file=path,locator_json='{}'))
            db.execute('INSERT INTO prefetch_records VALUES (?,?,?,?,?,?,?)',(eid,f'APP{i}.EXE',1,1,30,raw,'[]'))
            add_object(db,eid,'executable','executable_name',f'APP{i}.EXE')
            add_timestamp(db,eid,dict(slot='run:0',timestamp_utc='2020-01-01T00:00:00.000000000Z',source='Prefetch LastRun',meaning='recorded execution',normalization_status='normalized'))
            db.execute('INSERT INTO ingestion_runs(source_file,file_sha256,started_utc,finished_utc,status,inserted_count) VALUES (?,?,?,?,?,?)',
                       (path,sha,'2020-01-01','2020-01-01','complete',1))
    return hashes


def make_case(path,count=3):
    with closing(legacy(path)) as db:hashes=populate(db,count)
    migrations.migrate(path)
    with closing(connect(path)) as db:
        with db:sid=sources.create(db,name='Synthetic lab',hostname='synthetic-host')
    return sid,hashes


def args(sid,*selectors):
    return build_parser().parse_args(['source','assign',sid,*selectors,'--reason','Analyst reviewed historical collection'])


@pytest.mark.parametrize('path,count',[(ROOT,3),(ROOT+'\\',3),(ROOT.upper().replace('\\','/'),3),
                                     (ROOT+'\\APP1.pf',1),(r'C:\Evidence\PC01',3)])
def test_path_comparison_no_filesystem(tmp_path,monkeypatch,path,count):
    case=tmp_path/'case.db';sid,hashes=make_case(case)
    with closing(connect(case)) as db:
        def forbidden(*a,**kw):raise AssertionError('Filesystem selection forbidden')
        with monkeypatch.context() as m:
            for name in ('glob','rglob','resolve','iterdir'):m.setattr(Path,name,forbidden)
            m.setattr(os,'scandir',forbidden);m.setattr(os,'listdir',forbidden)
            selected=source_selection.select(db,paths=[path])
        assert len(selected['file_hashes'])==count and hashes[-1] not in selected['file_hashes']


def test_unc_and_exact_prefix():
    key=source_selection.path_key
    assert key(r'\\SERVER\Share\Folder'+'\\')==key('//server/share/folder')
    assert key(r'C:\Evidence\PC01')!=key(r'C:\Evidence\PC010')
    assert key('C:\\Straße')!=key('C:\\Strasse') # Do not merge distinct lexical paths via casefold.


@pytest.mark.parametrize('path',['', 'relative/file.pf','C:relative','C:',r'\Evidence\PC01',
    ROOT+'\\..',ROOT+'\\*.pf',ROOT+'\\?.pf',ROOT+'\\file:stream',ROOT+'\\name.',
    '\\\\?\\C:\\Evidence',ROOT+'\x00'])
def test_malformed_paths(path):
    with pytest.raises(ValueError):source_selection.path_key(path)


def test_union_dedup_and_literal_brackets(tmp_path):
    sid,hashes=make_case(tmp_path/'case.db')
    with closing(connect(tmp_path/'case.db')) as db:
        with db:register_source(db,hashes[0],1,ROOT+'\\[abc].pf')
        selection=source_selection.select(db,[hashes[0],hashes[0].upper(),hashes[-1]],
                                         [ROOT,ROOT,ROOT.upper(),ROOT+'\\APP0.pf'])
        assert selection['file_hashes']==sorted(hashes)
        assert source_selection.select(db,paths=[ROOT+'\\[abc].pf'])['file_hashes']==[hashes[0]]


def test_preview_apply_196_migration_integrity_and_correlations(tmp_path):
    path=tmp_path/'case.db';sid,hashes=make_case(path,196)
    with closing(connect(path)) as db:
        immutable={table:[tuple(r) for r in db.execute('SELECT * FROM '+table)] for table in
                   ('evidence_files','evidence_records','prefetch_records','ingestion_runs','source_locations','evidence_timestamps')}
        before=fingerprint(db);a=args(sid,'--path',ROOT)
        preview=source_cli.dispatch(db,a);p=preview['preview']
        assert fingerprint(db)==before and not preview['applied']
        assert p['files']==p['evidence_records']==196 and p['artifact_types']=={'prefetch_file':196}
        assert p['source']['source_id']==sid and p['source']['hostname']=='synthetic-host'
        assert p['existing_provenance']['unassigned']==196 and p['basis']=='retrospective analyst assignment'
        a.yes=True;a.confirmation_fingerprint=preview['confirmation_fingerprint']
        applied=source_cli.dispatch(db,a);assert applied['scope']==p
        aid=applied['result']['assignment_id'];detail=sources.detail(db,sid)
        assert detail['files']==detail['evidence_count']==196 and detail['artifacts']=={'prefetch':196}
        row=detail['retrospective_assignments']['records'][0]
        assert row['assignment_id']==aid and row['reason']==a.reason and row['recorded_utc']
        assert row['basis'].startswith('retrospective analyst assignment; recorded-path selection ')
        assert json.loads(row['basis'].split('recorded-path selection ',1)[1])['paths']==[ROOT]
        assert detail['retrospective_files']['total']==196 and detail['retrospective_files']['truncated']
        assert detail['batches']==0 and sources.coverage(db)['unassigned_files']==1
        for table,values in immutable.items():assert [tuple(r) for r in db.execute('SELECT * FROM '+table)]==values
        assert all(r[0] is None for r in db.execute('SELECT batch_id FROM ingestion_runs'))
        assert EvidenceQueries(db).search(source_id=sid,limit=1000).total==196
        anchor='PREFETCH:'+hashes[0]+':File'
        around=build_parser().parse_args(['around',anchor,'--timestamp-slot','run:0','--limit','1000'])
        result,_=v2_cli.dispatch(db,around)
        assert len(result['records'])==196
        assert 'PREFETCH:'+hashes[-1]+':File' not in {r['id'] for r in result['records']}
        assert get_evidence(db,'PREFETCH:'+hashes[-1]+':File')['context']['source_ids']==[]


def test_existing_occurrences_ambiguity_and_duplicates(tmp_path):
    path=tmp_path/'case.db';sid,hashes=make_case(path)
    with closing(connect(path)) as db:
        with db:
            other=sources.create(db,hostname='other-host')
            sources.assign(db,sid,[hashes[0]],reason='Existing')
            sources.assign(db,other,[hashes[1],hashes[2]],reason='Other')
            sources.assign(db,sid,[hashes[2]],reason='Legitimate second source')
            register_source(db,hashes[0],1,r'D:\Other collection\Same.pf')
        a=args(sid,'--path',ROOT,'--path',ROOT,'--file-hash',hashes[0])
        p=source_cli.dispatch(db,a)['preview']['existing_provenance']
        assert p==dict(unassigned=0,already_assigned_here=2,assigned_to_other_sources=2,ambiguous=1,multiple_recorded_locations=1)
        a.yes=True;result=source_cli.dispatch(db,a)
        assert db.execute('SELECT count(*) FROM source_assignment_files WHERE assignment_id=?',(result['result']['assignment_id'],)).fetchone()[0]==3
        assert {s['source_id'] for s in sources.memberships(db,hashes[1])}=={sid,other}
        assert get_evidence(db,'PREFETCH:'+hashes[1]+':File')['host_key'] is None


def test_errors_schema3_and_race(tmp_path):
    path=tmp_path/'case.db';sid,hashes=make_case(path)
    with closing(connect(path)) as db:
        before=fingerprint(db)
        for a in (args(sid),args(sid,'--path',r'C:\Not recorded'),args(sid,'--file-hash','bad'),
                  args(sid,'--file-hash','f'*64),args('missing','--path',ROOT)):
            with pytest.raises(ValueError):source_cli.dispatch(db,a)
            assert fingerprint(db)==before
        a=args(sid,'--path',ROOT);preview=source_cli.dispatch(db,a)
        with db:register_source(db,hashes[-1],1,ROOT+'\\late.pf')
        a.yes=True;a.confirmation_fingerprint=preview['confirmation_fingerprint']
        with pytest.raises(ValueError,match='changed'):source_cli.dispatch(db,a)
        assert sources.summary(db,sid)['files']==0
        a.confirmation_fingerprint=None
        assert source_cli.dispatch(db,a)['scope']['files']==4 # Unpinned --yes reports the actual current scope.
    with closing(legacy(':memory:')) as db:
        with pytest.raises(ValueError,match='schema 4'):source_cli.dispatch(db,args('missing','--path',ROOT))
        assert db.execute('PRAGMA user_version').fetchone()[0]==3


def test_hash_only_compatibility(tmp_path):
    path=tmp_path/'case.db';sid,hashes=make_case(path)
    with closing(connect(path)) as db:
        a=args(sid,'--file-hash',hashes[0],'--file-hash',hashes[0]);a.yes=True
        result=source_cli.dispatch(db,a)
        assert result['scope']['file_hashes']==[hashes[0]]
        assert sources.detail(db,sid)['retrospective_assignments']['records'][0]['basis']=='retrospective analyst assignment'


def test_selection_bounds_and_atomic_failure(tmp_path,monkeypatch):
    path=tmp_path/'case.db';sid,hashes=make_case(path)
    with closing(connect(path)) as db:
        assert source_selection.select(db,hashes=[hashes[0]]*1001)['file_hashes']==[hashes[0]]
        with pytest.raises(ValueError,match='at most'):source_selection.select(db,paths=[ROOT]*101)
        before=fingerprint(db);original=sources.assign
        def fail(*a,**kw):
            original(*a,**kw);raise ValueError('Injected assignment failure')
        monkeypatch.setattr(sources,'assign',fail)
        a=args(sid,'--path',ROOT);a.yes=True
        with pytest.raises(ValueError,match='Injected'):source_cli.dispatch(db,a)
        assert fingerprint(db)==before
        with db:
            db.executemany('INSERT INTO source_locations VALUES (?,?)',[(hashes[0],ROOT+f'\\alias-{i}.pf') for i in range(10001)])
        with pytest.raises(ValueError,match='exceeds'):source_selection.select(db,paths=[ROOT])


def test_cli_token_same_state_and_missing_selector(tmp_path,capsys):
    path=tmp_path/'case.db';sid,hashes=make_case(path)
    base=['--db',str(path),'source','assign',sid,'--reason','Reviewed','--json']
    assert main(base)==2;assert 'at least one' in capsys.readouterr().err
    assert main(base+['--path',ROOT])==0
    preview=json.loads(capsys.readouterr().out)
    before=path.read_bytes()
    assert main(base+['--path',ROOT])==0;capsys.readouterr()
    assert path.read_bytes()==before
    assert main(base+['--path',ROOT,'--yes','--confirmation-fingerprint',preview['confirmation_fingerprint']])==0
    applied=json.loads(capsys.readouterr().out)
    assert applied['scope']==preview['preview'] and applied['applied']


def test_output_modes_and_interactive_confirmation(tmp_path,monkeypatch,capsys):
    from forensic_assistant.interactive.shell import Shell
    from forensic_assistant.interactive.state import State
    from test_interactive_shell import Input
    path=tmp_path/'case.db';sid,hashes=make_case(path);target=tmp_path/'preview.txt'
    base=['--db',str(path),'source','assign',sid,'--path',ROOT,'--reason','Reviewed']
    monkeypatch.delenv('NO_COLOR',raising=False);monkeypatch.setattr(terminal,'capable',lambda stream:True)
    assert main(base)==0;colored=capsys.readouterr().out
    assert 'Distinct file hashes: 3' in colored and hashes[0] not in colored
    assert main(base+['--no-color'])==0;plain=capsys.readouterr().out
    assert terminal.SGR.sub('',colored)==plain
    pages=[];monkeypatch.setattr(output,'page',lambda stream:pages.append(stream.read()))
    assert main(base+['--page'])==0 and pages[0]==colored
    assert main(base+['--output',str(target)])==0
    assert main(base+['--append',str(target)])==0
    assert target.read_text(encoding='utf-8')==plain+'\n'+plain
    capsys.readouterr()
    assert main(base+['--json'])==0
    data=json.loads(capsys.readouterr().out);assert data['preview']['file_hashes']==sorted(hashes[:-1])
    assert '\x1b' not in json.dumps(data)
    command=f'source assign {sid} --path "{ROOT}" --reason Reviewed'
    assert Shell(State(None),Input(str(path),command,'n','exit')).run()==0
    with closing(connect(path)) as db:assert sources.summary(db,sid)['files']==0
    assert Shell(State(None),Input(str(path),command,'yes','exit')).run()==0
    with closing(connect(path)) as db:assert sources.summary(db,sid)['files']==3

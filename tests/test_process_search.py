import json
from contextlib import closing
import pytest
from forensic_assistant.cli import main, build_parser
from forensic_assistant.database.db import connect
from forensic_assistant.database.artifacts import add_object
from forensic_assistant.artifacts.ingest import ingest_artifact
from forensic_assistant.retrieval.evidence import EvidenceQueries
from v2_fixtures import prefetch_file, evtx_process, mft_file, registry_file


@pytest.fixture(scope='module')
def case(tmp_path_factory):
    root=tmp_path_factory.mktemp('process-search'); path=root/'case.db'
    with closing(connect(path)) as db:
        for name in ('POWERSHELL.EXE','POWERCFG.EXE','POWERPNT.EXE','CMD.EXE','SLUI.EXE','FOO.EXE','TOOL.COM','POWER%.EXE','POWER_.EXE'):
            result=ingest_artifact(db,prefetch_file(root/name,name=name),'prefetch',hostname='lab')
            assert result['status']=='complete'
        foo=db.execute("SELECT evidence_id FROM prefetch_records WHERE executable='FOO.EXE'").fetchone()[0]
        with db:
            add_object(db,foo,'unrelated','referenced_file',r'C:\Temp\POWERSHELL.EXE')
            # Even a path-candidate object cannot replace Prefetch's own identity.
            add_object(db,foo,'unrelated-candidate','executable_path_candidate',r'C:\Temp\POWERSHELL.EXE')
        evtx_process(db,path=r'C:\Temp\POWERSHELL.EXE',parent=r'C:\Temp\CMD.EXE',host='lab')
        evtx_process(db,offset=2,path=r'C:\Temp\TOOL.COM',host='lab')
        for kind,maker in (('mft',mft_file),('registry',registry_file)):
            assert ingest_artifact(db,maker(root/kind),kind,hostname='lab')['status']=='complete'
    return path


def search(case,capsys,*flags):
    before=case.read_bytes()
    assert main(['--db',str(case),'search','--json',*flags])==0
    data=json.loads(capsys.readouterr().out)
    assert case.read_bytes()==before
    assert set(data)=={'records','total','limit','offset','truncated','count_unit','caution'}
    return data


@pytest.mark.parametrize('query,expected',[
    ('powershell','POWERSHELL.EXE'),('powershell.exe','POWERSHELL.EXE'),('POWERSHELL','POWERSHELL.EXE'),
    ('POWERSHELL.EXE','POWERSHELL.EXE'),('PowerShell','POWERSHELL.EXE'),
    ('cmd','CMD.EXE'),('cmd.exe','CMD.EXE'),('CMD.EXE','CMD.EXE'),('slui','SLUI.EXE'),('slui.exe','SLUI.EXE'),
    ('tool.com','TOOL.COM'),('TOOL.COM','TOOL.COM'),('power%','POWER%.EXE'),('power_','POWER_.EXE')])
def test_exact_prefetch(case,capsys,query,expected):
    data=search(case,capsys,'--artifact','prefetch','--process',query)
    assert data['total']==1 and data['records'][0]['detail']['executable']==expected


@pytest.mark.parametrize('query',['power','powershel','tool','powershell.*','powershell?','powershell.exe.extra'])
def test_no_implicit_partial_or_nonexe_expansion(case,capsys,query):
    assert search(case,capsys,'--artifact','prefetch','--process',query)['total']==0


@pytest.mark.parametrize('query',['power','POWER','Power'])
def test_explicit_substring_identity_only(case,capsys,query):
    data=search(case,capsys,'--artifact','prefetch','--process-contains',query)
    names={r['detail']['executable'] for r in data['records']}
    assert names=={'POWERSHELL.EXE','POWERCFG.EXE','POWERPNT.EXE','POWER%.EXE','POWER_.EXE'}
    assert 'FOO.EXE' not in names


@pytest.mark.parametrize('query,expected',[
    ('%',{'POWER%.EXE'}),('_',{'POWER_.EXE'}),('power.*',set()),('power?',set()),
    ("' OR 1=1 --",set()),('Temp',set()),('C:\\',set())])
def test_contains_is_literal_basename(case,capsys,query,expected):
    data=search(case,capsys,'--artifact','prefetch','--process-contains',query)
    assert {r['detail']['executable'] for r in data['records']}==expected


def test_evtx_identity_and_other_filters(case,capsys):
    for flags in (['--process','powershell'],['--process','POWERSHELL.EXE'],['--process-contains','Power']):
        data=search(case,capsys,'--artifact','evtx',*flags,'--hostname','lab','--event-id','4688','--kind','processes')
        assert data['total']==1
        assert data['records'][0]['process_name']==r'C:\Temp\POWERSHELL.EXE'
    assert search(case,capsys,'--artifact','evtx','--process','cmd')['total']==0  # Parent only.
    assert search(case,capsys,'--artifact','evtx','--process','tool.com')['total']==1
    assert search(case,capsys,'--artifact','evtx','--process','powershell','--hostname','other')['total']==0
    assert search(case,capsys,'--process','powershell','--user','absent')['total']==0
    assert search(case,capsys,'--process-contains','power','--ip','192.0.2.1')['total']==0


def test_existing_full_path_and_path_filter(case,capsys):
    assert search(case,capsys,'--artifact','evtx','--process',r'C:\Temp\POWERSHELL.EXE')['total']==1
    assert search(case,capsys,'--artifact','evtx','--process',r'C:\Other\POWERSHELL.EXE')['total']==0
    assert search(case,capsys,'--artifact','evtx','--process',r'C:\Temp\powershell')['total']==0
    # --path still searches references; --process does not turn a reference into identity.
    names={r['detail']['executable'] for r in search(case,capsys,'--artifact','prefetch','--path','powershell.exe')['records']}
    assert 'FOO.EXE' in names
    data=search(case,capsys,'--artifact','prefetch','--process',r'C:\Temp\POWERSHELL.EXE')
    assert all(r['detail']['executable']!='FOO.EXE' for r in data['records'])


def test_existing_mft_and_registry_roles(case,capsys):
    for kind in ('mft','registry'):
        exact=search(case,capsys,'--artifact',kind,'--process','payload.exe')
        bare=search(case,capsys,'--artifact',kind,'--process','payload')
        partial=search(case,capsys,'--artifact',kind,'--process-contains','pay')
        assert exact['total']>0
        assert {r['id'] for r in exact['records']}=={r['id'] for r in bare['records']}=={r['id'] for r in partial['records']}


def test_limits_and_legacy_callers_unchanged(case,capsys):
    data=search(case,capsys,'--artifact','prefetch','--process-contains','power','--limit','2','--offset','1')
    assert data['total']==5 and len(data['records'])==2 and data['truncated'] and data['offset']==1
    with closing(connect(case)) as db:
        q=EvidenceQueries(db)
        assert q.search(artifact='prefetch',process='powershell').total==0
        assert q.search(artifact='prefetch',process_exact='powershell').total==1
        with pytest.raises(ValueError,match='mutually exclusive'):q.search(process_exact='x',process_contains='x')


def test_options_exclusive_and_help(capsys):
    with pytest.raises(SystemExit) as exc:
        build_parser().parse_args(['search','--process','powershell','--process-contains','power'])
    assert exc.value.code==2
    capsys.readouterr()
    with pytest.raises(SystemExit):main(['search','--help'])
    help=' '.join(capsys.readouterr().out.split())
    assert '--process-contains PROCESS' in help and '.exe may be omitted' in help and 'no wildcards' in help


@pytest.mark.parametrize('flag',['--process','--process-contains'])
def test_empty_rejected(case,capsys,flag):
    assert main(['--db',str(case),'search',flag,''])==2
    assert 'must not be empty' in capsys.readouterr().err


def test_extensionless_identity_is_retained():
    with closing(connect(':memory:')) as db:
        evtx_process(db,path=r'C:\Tools\power')
        evtx_process(db,offset=2,path=r'C:\Tools\power.exe')
        evtx_process(db,offset=3,path=r'C:\Tools\tool.com')
        q=EvidenceQueries(db)
        assert q.search(process_exact='power').total==2
        assert q.search(process_exact='power.exe').total==1
        assert q.search(process_exact='tool.com').total==1


def test_interactive_uses_shared_search(case,capsys):
    from forensic_assistant.interactive.shell import Shell
    from forensic_assistant.interactive.state import State
    from test_interactive_shell import Input
    shell=Shell(State(None),Input(str(case),'search --artifact prefetch --process powershell',
                                 'search --artifact prefetch --process-contains power','exit'))
    assert shell.run()==0 and shell.last_status==0
    text=capsys.readouterr().out
    assert 'Showing' not in text and 'LAST RUN (UTC)' in text

from forensic_assistant.artifacts.paths import normalize_path,executable_reference
from forensic_assistant.artifacts.times import filetime
from forensic_assistant.artifacts.context import bind_context,effective_context
from v1_fixtures import database,add


def test_path_comparison_preserves_uncertainty():
    assert normalize_path('"C:/Temp/X.exe"')['normalized']=='c:\\temp\\x.exe'
    assert normalize_path(r'\??\C:\Temp\X.exe')['normalized']==r'c:\temp\x.exe'
    assert normalize_path(r'%TEMP%\X.exe')['kind']=='unexpanded'
    assert normalize_path(r'C:\a\..\x.exe')['normalized'] is None
    assert normalize_path(r'\Device\HarddiskVolume2\x.exe')['kind']=='device'
    assert executable_reference('"C:\\Program Files\\x.exe" /arg')==r'C:\Program Files\x.exe'
    assert executable_reference(r'C:\Program Files\x.exe /arg') is None
    assert normalize_path(r'C:\a\x.exe')['normalized']!=normalize_path(r'C:\b\x.exe')['normalized']
    assert normalize_path('C:\\Temp\\x.exe ')['normalized'] is None
    assert normalize_path(r'\??\UNC\server\share\x.exe')['normalized']==r'\\server\share\x.exe'


def test_filetime_precision_and_invalid():
    a=filetime(132042381048777787,'run:0','Prefetch LastRun','execution timestamp')
    assert a['timestamp_utc'].endswith('.877778700Z') and a['precision_ns']==100
    assert filetime(0,'x','x','x')['normalization_status']=='missing'
    assert filetime(2**64,'x','x','x')['normalization_status']=='invalid'


def test_conflicting_source_assertions_do_not_overwrite():
    db=database();e=add(db,1)
    bind_context(db,e['file_sha256'],'copy',hostname='other')
    record=dict(db.execute('SELECT * FROM evidence_records').fetchone())
    result=effective_context(db,record)
    assert result['hostname'] is None and 'hostname' in result['conflicts']
    assert record['hostname']=='pc.example'

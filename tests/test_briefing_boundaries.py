"""Narrative span and discovery safety; no case evidence or provider calls."""
import pytest
from forensic_assistant import briefing as b
from test_briefing import START,END


def leads(text,kind):return [r for r in b.extract(text)['leads'] if r['type']==kind]


@pytest.mark.parametrize('text',['9:30','09:30','14:05:47','999.2.3.4','hello:abcd','1234:5678'])
def test_not_ip(text):
    assert not leads(text,'ipv4') and not leads(text,'ipv6')


@pytest.mark.parametrize('text,kind', [('192.0.2.1','ipv4'),('2001:db8::1','ipv6'),('::1','ipv6'),('::ffff:192.0.2.1','ipv6'),('2001:db8:0:0:0:0:2:1','ipv6')])
def test_valid_ip(text,kind):
    rows=leads(text,kind);assert len(rows)==1 and rows[0]['occurrences'][0]['original']==text
    assert b.query_for(rows[0],'evtx',START,END)['ip']==rows[0]['normalized']


@pytest.mark.parametrize('suffix',[' was blocked.\n',' was launched through WMI',', was launched through WMI','.',')'])
def test_unquoted_path_boundary(suffix):
    path=r'C:\ProgramData\baje.ps1'
    rows=leads('Reported '+path+suffix,'windows_path')
    assert len(rows)==1 and rows[0]['occurrences'][0]['original']==path and rows[0]['classification']=='exact'
    assert b.query_for(rows[0],'mft',START,END)['path']==path


@pytest.mark.parametrize('path',[r'C:\Program Files\Example App\sample.exe',r'\\server\share\sample.exe',r'C:\folder\long name.pdf'])
def test_space_and_unc_paths(path):
    for text in ('"'+path+'"',path+' was blocked.'):
        row=leads(text,'windows_path')[0]
        assert row['occurrences'][0]['original']==path and row['classification']=='exact'
        assert b.query_for(row,'mft',START,END)['path']==path


@pytest.mark.parametrize('text',[r'C:\folder\unknown destination for review',r'C:\sample.ps1 backup.exe','C:\\incomplete\\'])
def test_ambiguous_path_not_queried(text):
    row=leads(text,'windows_path')[0]
    assert row['classification']=='ambiguous'
    assert b.query_for(row,'mft',START,END) is None


@pytest.mark.parametrize('name,delimiter',[
 ('free printable five crowns score sheet pdf.zip','"{}"'),
 ('free printable five crowns score sheet pdf.lnk','({})'),
 ('qon[1].wsc','{}'),('baje.ps1','{}'),('powershell.exe','{}'),
 ('Résumé final [1].zip','"{}"')])
def test_full_filename(name,delimiter):
    text='Reported '+delimiter.format(name)+'\r\n'
    rows=leads(text,'filename')
    assert len(rows)==1 and rows[0]['occurrences'][0]['original']==name
    assert b.query_for(rows[0],'mft',START,END)['path']==name


def test_no_nested_activity_or_domains_and_independent_technology():
    text=r'C:\ProgramData\domain.org\powershell.exe was blocked. PowerShell WMI Defender https://example.org/page'
    packet=b.extract(text)
    assert {r['normalized'] for r in packet['leads'] if r['type']=='domain'}=={'example.org'}
    assert {r['normalized'] for r in packet['leads'] if r['type']=='term'}=={'PowerShell','WMI','Defender'}
    assert not [r for r in packet['leads'] if r['type']=='filename']


def test_spans_duplicates_and_approximate_time():
    text='Morning around 9:30. September 30, 2026. Timezone unknown.\r\n"long name.zip"\n"long name.zip"'
    packet=b.extract(text)
    for row in packet['leads']:
        for occurrence in row['occurrences']:
            assert text[occurrence['start']:occurrence['end']]==occurrence['original']
    row=next(r for r in packet['leads'] if r['type']=='ambiguous_time')
    assert row['normalized']=='09:30' and row['classification']=='approximate'
    assert b.query_for(row,'evtx',START,END) is None
    assert len(leads(text,'filename')[0]['occurrences'])==2


def test_forged_invalid_ip_and_prose_path_rejected():
    row=leads('192.0.2.1','ipv4')[0];row['normalized']='9:30';row['occurrences'][0]['original']='9:30'
    assert b.query_for(row,'evtx',START,END) is None
    row=leads(r'C:\sample.ps1 was blocked','windows_path')[0]
    row['occurrences'][0]['original']+= ' was blocked'
    assert b.query_for(row,'mft',START,END) is None


def test_after_ai_budget_new_details_are_retained_and_assessed(capsys):
    from test_briefing_interview import run,ask
    responses=['Initial report', 'unknown', 'unknown', 'unknown', 'unknown', 'unknown', 'unknown',
               'Additional script final.ps1 was reported.', 'save']
    topics=['time','people','systems','alerts','objective','discovery']
    questions=['When did this occur?','Who was involved?','Which device was involved?',
               'What alert was reported?','What should be established?','How was this noticed?']
    result,fake,metrics=run(responses,[ask(t,q) for t,q in zip(topics,questions)])
    assert len(fake.calls)==6
    assert result['interviews'][0]['turns'][-1]['answer']=='Additional script final.ps1 was reported.'
    assert metrics['information_assessment']['topics']['indicators']['state']=='supplied_hint'
    output=capsys.readouterr().out
    assert output.count('Interview question budget reached')==1
    assert 'Added. Type done to review and save' in output
    from forensic_assistant.briefing_store import sources
    packet=b.extract_inputs(sources({'content':result}))
    assert any(r['normalized']=='final.ps1' for r in packet['leads'])


@pytest.mark.parametrize('text,kind',[('192.0.2.1.','ipv4'),('[2001:db8::1].','ipv6')])
def test_address_sentence_punctuation(text,kind):
    row=leads(text,kind)[0]
    assert row['classification']=='exact' and not row['occurrences'][0]['original'].endswith('.')


@pytest.mark.parametrize('text',['9:30 AM','9:30PM','14:05:47','09:30 timezone unknown'])
def test_realistic_clock_expressions(text):
    assert leads(text,'ambiguous_time') and not leads(text,'ipv6')

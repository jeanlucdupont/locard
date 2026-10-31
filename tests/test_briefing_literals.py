"""Concrete indicators versus generic terminology; synthetic interpretations only."""
import json
import pytest
from forensic_assistant import briefing as b, briefing_cli
from forensic_assistant.briefing_literals import literals, unsupported
from test_briefing import Fake, item


BASE='PowerShell and WMI activity, a shortcut and baje.ps1 were reported.'


@pytest.mark.parametrize('text',[
    'Investigate whether WMI initiated PowerShell.',
    'Could the reported shortcut have initiated the activity?',
    'Investigate whether persistence was established.',
    'PowerShell may have been launched through WMI.',
    'What command-line or process-creation evidence is available?',
    'What user activity preceded the script?',
    'Was there follow-up activity?', 'Search for BAJE.PS1.', 'No evidence confirms execution.'])
def test_supported_terms(text):
    p=b.extract(BASE);proposal={**item(BASE),'category':'question','text':text}
    b.interpret(p,Fake({'items':[proposal]}))
    assert p['ai_status']=='success' and p['ai_items'][0]['verification']=='UNVERIFIED AI INTERPRETATION'
    assert 'discovery' not in p


@pytest.mark.parametrize('text,kind',[
    ('Did the script contact 203.0.113.25?','ipv4'),('The script contacted 203.0.113.25.','ipv4'),
    ('Search for invented.exe.','filename'),('Did example.org receive traffic?','domain'),
    (r'The attacker used C:\Temp\payload.exe.','windows_path'),
    (r'Could HKCU\Software\Evil be persistence?','registry_path'),
    ('Inspect Event 1121.','event_id'),('Check Event ID 4624.','event_id'),
    ('Could LAB-009 be involved?','hostname'),('Inspect host command-line.','hostname'),
    ('Inspect "follow-up".','hostname'),('Was user named intruder involved?','username'),
    ('Did powershell -enc QUJD run?','command_line'),('Inspect '+('a'*64)+'.','hash'),
    ('Did 2001:db8::1 receive traffic?','ipv6')])
def test_invented_indicators_still_rejected(text,kind):
    p=b.extract(BASE);proposal={**item(BASE),'category':'question','text':text}
    b.interpret(p,Fake({'items':[proposal]}))
    rejected=p['ai_error']['rejected_items'][0]
    assert rejected['rule']=='unsupported_technical_literal' and kind in rejected['literal_types']
    assert text not in json.dumps(rejected)
    assert kind in briefing_cli.render(p)


@pytest.mark.parametrize('source,text',[
    ('Contact 203.0.113.25.','Could 203.0.113.25 be relevant?'),
    ('Recorded Event ID 1121.','Inspect Event 1121.'),
    (r'"C:\Temp\payload.exe"',r'Inspect C:\TEMP\PAYLOAD.EXE.'),
    (r'HKCU\Software\Test',r'Inspect hkcu\software\test.'),
    ('échantillon.exe','Search for ÉCHANTILLON.EXE.'),
    ('example.org','Inspect EXAMPLE.ORG.'),
    ('2001:db8::1','Inspect 2001:DB8::1.'),
    ('a'*64,'Inspect '+('A'*64)+'.')])
def test_source_normalizations(source,text):
    p=b.extract(source)
    assert not unsupported(text,p['inputs'],p['source_units'])


def test_supported_elsewhere_is_not_supported_in_cited_source():
    p=b.extract(BASE+'\n\n203.0.113.25')
    assert unsupported('Inspect 203.0.113.25.',p['inputs'],p['source_units'][:1])
    assert not unsupported('Inspect 203.0.113.25.',p['inputs'],p['source_units'])


def test_partial_and_proof_language_not_a_finding():
    text=BASE+' Event ID 1121 was reported.';p=b.extract(text)
    values=[{**item(text),'category':'question','text':'Could WMI have initiated PowerShell?'},
            {**item(text),'text':'Defender Event 1121 confirms execution.'}]
    b.interpret(p,Fake({'items':values}))
    assert p['ai_status']=='partial' and len(p['ai_items'])==1
    assert p['ai_error']['rejected_items'][0]['rule']=='unsupported_factual_conclusion'
    assert 'handoff' not in p


def test_terms_do_not_hide_explicit_attribution():
    assert ('hostname','follow-up') in literals('hostname: follow-up')
    assert any(k=='username' for k,v in literals('user named activity'))

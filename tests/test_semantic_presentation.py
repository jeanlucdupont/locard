"""Semantic presentation uses synthetic metadata and disposable session records."""
import argparse
import io
import json
from types import SimpleNamespace
import pytest
from forensic_assistant import terminal as t, session_recording as sr
from forensic_assistant.cli_parser import LocardParser, semantic_help
from forensic_assistant.cli import build_parser, main
from forensic_assistant.interactive.help import catalog


def test_roles_and_counterexamples(monkeypatch):
    monkeypatch.delenv('WT_SESSION', raising=False)
    monkeypatch.setenv('TERM', 'ansi')
    monkeypatch.delenv('COLORTERM', raising=False)
    spans = [t.TextSpan('Failed: ', 'label'), t.TextSpan('0', 'value'),
             t.TextSpan(' ERROR', 'syntax'), t.TextSpan(' not checked', 'unknown'),
             t.TextSpan(' Forensic note: missing failed records', 'forensic_note'),
             t.TextSpan(' malicious activity hypothesis', 'label')]
    plain = t.render_spans(spans)
    colored = t.render_spans(spans, t.Palette(True))
    assert t.SGR.sub('', colored) == plain
    assert '\x1b[32m' not in colored and '\x1b[31m' not in colored
    assert '\x1b[33m' not in colored
    for role in ('value','command','syntax','question','forensic_note','heading','label','success','warning','error','unknown','punctuation'):
        assert t.render_spans([t.TextSpan('x', role)], t.Palette(True)).startswith('\x1b[')
    assert t.render_spans([t.TextSpan('x', 'unknown-role')]) == 'x'


def test_controls_and_immutability():
    span = t.TextSpan('\x1b[31mfoo\r\x00\u202e café', 'value')
    plain = t.render_spans([span])
    assert '\x1b' not in plain and '\r' not in plain and '\u202e' not in plain
    assert 'café' in plain
    assert t.SGR.sub('', t.render_spans([span], t.Palette(True))) == plain
    with pytest.raises(AttributeError): span.text = 'changed'


def example():
    p = LocardParser(prog='synthetic', description='Long explanation.\nSecond line retained.')
    p.add_argument('SESSION')
    p.add_argument('--severity', choices=['INFO','WARNING','ERROR'], required=True, help='Select a severity')
    p.add_argument('--limit', type=int, default=3, help='Limit (default: %(default)s)')
    p.add_argument('--hidden', help=argparse.SUPPRESS)
    group = p.add_mutually_exclusive_group(required=True)
    group.add_argument('--left', action='store_true')
    group.add_argument('--right', action='store_true')
    return p


def test_help_metadata_and_validation():
    p=example()
    spans=semantic_help(p)
    plain=t.render_spans(spans)
    colored=t.render_spans(spans,t.Palette(True))
    assert t.SGR.sub('', colored)==plain
    for item in ['SESSION','--severity {INFO,WARNING,ERROR}','default: 3','Second line retained.','(--left | --right)']:
        assert item in plain
    assert '--hidden' not in plain
    assert not any(t.STYLES[s.role] in ('35','95','32','33') for s in spans)
    assert p.parse_args(['s','--severity','ERROR','--left']).severity=='ERROR'
    with pytest.raises(SystemExit): p.parse_args(['s','--severity','WRONG','--left'])


@pytest.mark.parametrize('flag', ['--no-color','--json'])
def test_help_policy(flag, monkeypatch):
    monkeypatch.setattr(t,'capable',lambda s:True)
    monkeypatch.delenv('NO_COLOR',raising=False)
    p=build_parser()
    # Nested print_help receives inherited global policy, before argparse exits.
    out=io.StringIO()
    monkeypatch.setattr('sys.stdout',out)
    with pytest.raises(SystemExit):p.parse_args(['settings','version',flag,'--help'])
    assert '\x1b' not in out.getvalue()


def test_catalog_and_every_nested_help(monkeypatch):
    from forensic_assistant.cli_parser import parser_tree
    p=build_parser()
    for parser in parser_tree(p):
        if hasattr(parser,'color'): assert parser.color is False
        text=t.render_spans(semantic_help(parser))
        assert 'usage:' in text and '\x1b' not in text
    text=catalog(p,t.Palette(True),all_commands=True)
    assert '\x1b[35m' not in text
    assert 'settings version' in t.SGR.sub('',text)


def test_recording_plain_bound_and_redaction(tmp_path,monkeypatch):
    monkeypatch.setenv('LOCALAPPDATA',str(tmp_path))
    monkeypatch.setenv('USERPROFILE',str(tmp_path/'user'))
    monkeypatch.setattr(sr,'OUTPUT_BYTES',12)
    out=io.StringIO()
    with sr.execution([]) as rec:
        path=rec.path
        t.write_spans([t.TextSpan('abcdef\n','value')],palette=t.Palette(True),stream=out)
        sr.output('\x1b[31mghijklmnop\x1b[0m')
        assert rec.output_bytes==12 and rec.omitted_bytes==5
    rows=[sr.activity.decode(line) for line in path.read_bytes().splitlines(keepends=True)]
    recorded=''.join(r['data']['text'] for r in rows if r['action']=='output')
    assert recorded=='abcdef\nghijk'
    assert '\x1b' not in recorded and out.getvalue().count('abcdef')==1
    assert sr.verify()['sessions'][0]['integrity']=='verified'


def test_version_human_and_json(tmp_path,monkeypatch,capsys):
    monkeypatch.setenv('LOCALAPPDATA',str(tmp_path))
    monkeypatch.setenv('USERPROFILE',str(tmp_path/'user'))
    with pytest.raises(SystemExit) as exc:
        main(['--version-details'])
    assert exc.value.code == 0
    data=json.loads(capsys.readouterr().out)
    from forensic_assistant.workflow_cli import render
    from forensic_assistant import __version__
    assert data['application_version'] == __version__
    data = {'application_version': __version__}
    assert t.SGR.sub('',render(data,t.Palette(True)))==render(data)
    assert set(data)=={'application_version'}


def test_semantic_prompt_editor():
    from forensic_assistant.interactive.console import edit
    import time
    prompt=t.shell_prompt('café',t.Palette(True))
    out=io.StringIO()
    result=edit(iter(['a','b','LEFT','\b','c','\r']),prompt=prompt,output=out)
    assert result=='cb'
    assert '\x1b[96m' in out.getvalue()
    assert '[café]> ' == t.SGR.sub('',prompt)


@pytest.mark.parametrize('color', [True, False])
def test_help_current_stream_and_preferences(color, monkeypatch):
    monkeypatch.setattr(t, 'capable', lambda stream: color)
    monkeypatch.delenv('NO_COLOR', raising=False)
    out=io.StringIO()
    p=example()
    p.print_help(out)
    assert ('\x1b' in out.getvalue()) == color
    monkeypatch.setenv('NO_COLOR','')
    out.seek(0);out.truncate()
    p.print_help(out)
    assert '\x1b' not in out.getvalue()


def test_recording_secret_and_split_stream(tmp_path,monkeypatch):
    monkeypatch.setenv('LOCALAPPDATA',str(tmp_path))
    monkeypatch.setenv('USERPROFILE',str(tmp_path/'user'))
    with sr.execution([]) as rec:
        path=rec.path
        rec.redactor.values.add('synthetic-secret')
        rec.stream('\x1b[3','stdout')
        rec.stream('1msecret=synthetic-secret\x1b[0m\n','stdout')
        t.write_spans([t.TextSpan('synthetic-secret\n','value')],palette=t.Palette(True),stream=io.StringIO())
    rows=[sr.activity.decode(line) for line in path.read_bytes().splitlines(keepends=True)]
    text=''.join(r['data']['text'] for r in rows if r['action']=='output')
    assert '\x1b' not in text and 'synthetic-secret' not in text
    assert '<redacted>' in text
    assert sr.verify()['sessions'][0]['integrity']=='verified'


@pytest.mark.parametrize('launcher',['direct','module','console','pwsh','powershell'])
def test_help_entrypoints(launcher,tmp_path):
    import os, subprocess, sys, shutil
    from pathlib import Path
    root=Path(__file__).resolve().parents[1]
    commands={'direct':[sys.executable,str(root/'locard.py')],
              'module':[sys.executable,'-m','forensic_assistant.cli'],
              'console':[str(Path(sys.executable).parent/'locard.exe')]}
    if launcher in ('pwsh','powershell'):
        executable=shutil.which(launcher)
        if not executable:pytest.skip('Shell not installed')
        commands[launcher]=[executable,'-NoProfile','-File',str(root/'locard.ps1')]
    env=dict(os.environ,LOCALAPPDATA=str(tmp_path),USERPROFILE=str(tmp_path/'user'),FORCE_COLOR='1',PYTHON_COLORS='1')
    result=subprocess.run(commands[launcher]+['evidence','source','list','--help'],capture_output=True,env=env,timeout=30)
    assert result.returncode==0, result.stderr.decode(errors='replace')
    assert b'usage:' in result.stdout and b'--json' in result.stdout
    assert b'\x1b' not in result.stdout+result.stderr


def test_case_root_human_json_unchanged(tmp_path,monkeypatch,capsys):
    monkeypatch.setenv('LOCALAPPDATA',str(tmp_path))
    monkeypatch.setenv('USERPROFILE',str(tmp_path/'user'))
    monkeypatch.setattr('forensic_assistant.case_management.root',lambda: tmp_path/'cases')
    assert main(['case','root','--json'])==0
    value=json.loads(capsys.readouterr().out)
    assert set(value)=={'root','effect'}
    from forensic_assistant.workflow_cli import render
    assert t.SGR.sub('',render(value,t.Palette(True)))==render(value)
    assert str(tmp_path/'cases') in render(value)
    assert 'existing cases are not moved' in render(value)


def test_no_color_policy_does_not_stick(monkeypatch):
    p=LocardParser()
    p.add_argument('--no-color',action='store_true')
    p.parse_args(['--no-color'])
    assert p._help_no_color
    p.parse_args([])
    assert not p._help_no_color

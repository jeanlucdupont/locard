"""Provider-free semantic migration checks, using bounded synthetic values."""
import ast
import io
import os
from pathlib import Path
from types import SimpleNamespace
import pytest
from forensic_assistant import terminal as t, session_recording as sr
from forensic_assistant.cli_parser import LocardParser, semantic_help


def test_prompt_and_help_columns(monkeypatch):
    p=LocardParser(prog='locard synthetic')
    p.add_argument('--json',action='store_true',help='Structured output')
    p.add_argument('--severity',choices=['INFO','WARNING','ERROR'],help='Select recorded severity; not an application failure')
    for width in (42,100):
        monkeypatch.setattr('shutil.get_terminal_size',lambda:os.terminal_size((width,30)))
        spans=semantic_help(p)
        plain=t.render_spans(spans)
        assert t.SGR.sub('',t.render_spans(spans,t.Palette(True)))==plain
        assert '--json' in plain and 'Structured output' in plain
        if width==100:assert any('--json' in line and 'Structured output' in line for line in plain.splitlines())
        assert 'ERROR' in plain
    assert t.shell_prompt('case',t.Palette(True))==t.Palette(True)('shell_prompt','[case]> ')


def test_role_retirement_and_neutral_json():
    old={'key','string_value','number_value','boolean_value','secondary_text','prompt','ai_prompt','inactive','evidence_id'}
    assert not old.intersection(t.STYLES)
    for p in Path('forensic_assistant').rglob('*.py'):
        tree=ast.parse(p.read_text(encoding='utf-8-sig'))
        for node in ast.walk(tree):
            if isinstance(node,ast.Call) and isinstance(node.func,ast.Name) and node.func.id=='palette' and node.args and isinstance(node.args[0],ast.Constant):
                assert node.args[0].value not in old, str(p)+':'+str(node.lineno)
    assert '\x1b' not in t.render_json({'ERROR':0,'name':'suspicious'},t.Palette(True))


def test_ai_and_case_views(monkeypatch):
    from forensic_assistant.ai.cli import render
    from forensic_assistant.workflow_cli import render as workflow
    monkeypatch.setattr(t,'capable',lambda stream:True)
    monkeypatch.delenv('NO_COLOR',raising=False)
    text=render(dict(provider='OpenAI',model='synthetic',configuration='configured_ready',connection_readiness='not_checked',configuration_detail=''))
    assert 'Details:' not in text
    assert t.Palette(True)('success','configured ready') in text
    assert t.Palette(True)('unknown','not_checked') in text
    assert t.Palette(True)('value','OpenAI') in text
    clone=dict(path='C:/synthetic/case.db',origin=dict(source='C:/synthetic/original.db',clone_id='example'))
    plain=workflow(clone)
    colored=workflow(clone,t.Palette(True))
    assert t.SGR.sub('',colored)==plain
    assert 'Case clone created.' in plain and clone['path'] in plain


def test_table_spans_and_forensic_event():
    from forensic_assistant.retrieval.layout import table
    from forensic_assistant.retrieval.analyst_display import EVENT_LABELS
    assert EVENT_LABELS['failed_logon'][1]=='value'
    rows=[[t.TextSpan('0','value'),t.TextSpan('not checked','unknown')]]
    kw=dict(minimums=[1,5],maximums=[8,20],roles=['value','value'],width=60)
    plain=table(['Failed','State'],rows,t.Palette(),**kw)
    color=table(['Failed','State'],rows,t.Palette(True),**kw)
    assert [t.SGR.sub('',x) for x in color]==plain
    assert '\x1b[32m' not in ''.join(color) and '\x1b[31m' not in ''.join(color)


def test_question_capture_and_session_color(tmp_path,monkeypatch):
    monkeypatch.setenv('LOCALAPPDATA',str(tmp_path))
    monkeypatch.setenv('USERPROFILE',str(tmp_path/'user'))
    monkeypatch.delenv('NO_COLOR',raising=False)
    monkeypatch.setattr(t,'capable',lambda stream:True)
    prompts=[]
    class Reader:
        def read(self,prompt,**kwargs):prompts.append(prompt);return 'y'
    settings=SimpleNamespace(no_color=False)
    with sr.execution([]) as rec:
        path=rec.path
        reader=sr.ReaderProxy(Reader(),presentation=settings)
        assert reader.read('Confirm? [y/N]: ')=='y'
        settings.no_color=True
        assert reader.read('Confirm? [y/N]: ')=='y'
    assert '\x1b[94m' in prompts[0] and '\x1b' not in prompts[1]
    rows=[sr.activity.decode(x) for x in path.read_bytes().splitlines(keepends=True)]
    assert len([r for r in rows if r['action']=='prompt'])==2
    assert len([r for r in rows if r['action']=='input'])==2
    assert all(r['data']['text']=='Confirm? [y/N]: ' for r in rows if r['action']=='prompt')
    assert sr.verify()['sessions'][0]['integrity']=='verified'


def test_report_view_preserves_mapping():
    from forensic_assistant.reporting.recorded import render_result
    value=dict(file_integrity='PASS',structure='PASS',source_binding='NOT_CHECKED',semantic_truth='NOT_CERTIFIED',content_digest='exact')
    before=dict(value)
    text=render_result(value,SimpleNamespace(no_color=True))
    assert value==before and 'exact' in text and 'NOT_CHECKED' in text
    assert '\x1b' not in text


def test_findings_history_is_human_and_unverified():
    from forensic_assistant.workflow_cli import render
    value = {'decisions': {'revision': 1, 'source_binding_status': 'bound',
        'history': [{'finding_id': 'F-example', 'action': 'accept', 'actor': 'Analyst'}]}}
    import copy
    before = copy.deepcopy(value)
    plain = render(value)
    colored = render(value, t.Palette(True))
    assert t.SGR.sub('', colored) == plain
    assert 'F-example' in plain and 'Analyst' in plain
    assert 'not forensic verification' in plain and value == before


def test_recorded_result_mode_defaults():
    from forensic_assistant.cli import build_parser
    words = ['report', 'verify-history', 'synthetic.json']
    assert build_parser(interactive=False).parse_args(words).json
    assert not build_parser(interactive=True).parse_args(words).json
    assert build_parser(interactive=True).parse_args(words+['--json']).json
    assert not build_parser(interactive=False).parse_args(words+['--text']).json

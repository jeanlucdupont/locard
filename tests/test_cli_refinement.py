"""6.147 human projections and help routing; synthetic, provider-free."""
import argparse
import copy
import os
from types import SimpleNamespace
import pytest
from forensic_assistant import terminal as t, session_recording as sr
from forensic_assistant.cli import build_parser
from forensic_assistant.cli_parser import semantic_help, InvalidArguments, UnknownCommand
from forensic_assistant.interactive.help import catalog, contextual_help

@pytest.fixture(autouse=True)
def isolated(tmp_path,monkeypatch):
    monkeypatch.setenv('LOCALAPPDATA',str(tmp_path/'app'))
    monkeypatch.setenv('USERPROFILE',str(tmp_path/'user'))
    monkeypatch.delenv('NO_COLOR',raising=False)
    monkeypatch.setattr('forensic_assistant.ai.backend.ModelBackend.complete',lambda *a,**k:pytest.fail('provider request'))


def test_catalog_and_inventory():
    from scripts.help_inventory import collect,quality
    text=catalog(build_parser(interactive=True))
    assert 'Ask AI' in text and 'AI proposals' not in text and 'Use help' not in text
    assert not [r for r in quality(collect()) if r['issue']=='empty']
    for row in collect():
        assert 'Diagnostic, resource or output controls' not in row['text']
        assert 'Read-only examination by default' not in row['text']
    assert '--authorize-diagnostic' in str(collect())


@pytest.mark.parametrize('width',[42,80,160])
def test_width_groups_and_error_roles(width,monkeypatch):
    monkeypatch.setattr('shutil.get_terminal_size',lambda:os.terminal_size((width,30)))
    p=build_parser(interactive=True)
    text=contextual_help(p,['case'])
    assert 'List available cases' in text
    if width>=80:assert any('list' in line and 'List available cases' in line for line in text.splitlines())
    assert 'Options:' in contextual_help(p,['case','list'])
    assert 'Advanced options:' in contextual_help(p,['evidence','search'])
    with pytest.raises(InvalidArguments) as exc:p.parse_args(['case','clone'])
    spans=exc.value.spans
    colored=t.render_spans(spans,t.Palette(True));plain=t.render_spans(spans)
    assert t.SGR.sub('',colored)==plain
    assert t.Palette(True)('error','Invalid arguments.\n') in colored
    assert any(s.text=='usage: ' and s.role=='label' for s in spans)
    assert all(s.role!='error' for s in spans[1:])


def test_contextual_help_never_dispatches(tmp_path,monkeypatch,capsys):
    from forensic_assistant.interactive.shell import Shell
    from forensic_assistant.interactive.state import State
    from test_interactive_shell import Input,case
    monkeypatch.setattr('forensic_assistant.ai.cli.offer_setup',lambda *a:None)
    monkeypatch.setattr('forensic_assistant.ai.readiness.present',lambda *a:None)
    monkeypatch.setattr('forensic_assistant.cli.dispatch',lambda *a,**k:pytest.fail('help dispatched'))
    path=case(tmp_path);before=path.read_bytes()
    reader=Input(str(path),'? case','case ?','? evidence search','evidence search ?',
                 '? investigation findings','investigation findings ?','case absent ?','quit')
    shell=Shell(State(None),reader,no_color=True)
    assert shell.run()==0 and path.read_bytes()==before
    text=capsys.readouterr().out
    assert text.count('usage: case ')==2
    assert text.count('usage: evidence search ')==2
    assert ' '.join(text.split()).count('usage: investigation findings ')==2
    assert 'Unknown help path:' in text
    with pytest.raises(UnknownCommand):contextual_help(build_parser(interactive=True),['case','clone','anything'])


@pytest.mark.parametrize('state,word,role',[('configured_ready','configured','success'),('not_configured','not configured','warning'),('configured_invalid','invalid configuration','error'),('other','unknown','unknown')])
def test_ai_views(state,word,role,monkeypatch):
    from forensic_assistant.ai.cli import render
    monkeypatch.setattr(t,'capable',lambda stream:True)
    value=dict(provider='OpenAI',model='synthetic',configuration=state,api_key='configured',integration='available',connection_readiness='not checked',model_readiness='not checked',locard_compatibility='not checked')
    before=copy.deepcopy(value)
    startup=render(value,startup=True)
    assert t.Palette(True)(role,word) in startup
    assert len(t.SGR.sub('',startup).splitlines())==4
    assert 'API key' not in startup and 'Integration' not in startup and 'Connection' not in startup
    full=render(value,SimpleNamespace(ai_command='status'))
    assert 'Model compatibility' in full and t.Palette(True)('unknown','not checked') in full
    assert value==before
    assert '\x1b' not in render(value,SimpleNamespace(ai_command='status',no_color=True))


def test_startup_no_provider(monkeypatch,capsys):
    from forensic_assistant.ai import readiness,settings
    monkeypatch.setattr('socket.socket',lambda *a,**k:pytest.fail('network'))
    monkeypatch.setattr('forensic_assistant.ai.runtime.acquire',lambda *a,**k:pytest.fail('runtime started'))
    config={**settings.defaults(),'provider':'openai','model':'synthetic'}
    readiness.present(config,SimpleNamespace(no_color=True))
    assert 'AI Provider' in capsys.readouterr().out


@pytest.mark.parametrize('count',[0,3])
def test_case_status_neutral_values_and_qualifications(count):
    from forensic_assistant.retrieval.status_display import render
    result=dict(artifact_counts={'mft':count},timeline_observations=count*2,caution='Missing events do not establish absence of activity. Auditing and supplied logs may be incomplete.')
    details=dict(runs={},dirty_hives=1,hive_warnings=[],error_summaries=[])
    before=copy.deepcopy(result)
    color=render(result,'C:/synthetic/case.db',details,t.Palette(True))
    plain=render(result,'C:/synthetic/case.db',details)
    assert t.SGR.sub('',color)==plain and result==before
    assert 'No evidence has been ingested.' in plain if not count else 'absence of matching evidence records' in plain
    assert 'Dirty Registry hives' in plain and 'Missing events' not in plain
    assert t.Palette(True)('value', '0') in color and 'Failed:' in plain


def test_audit_summary_classification_and_unchanged_json(monkeypatch):
    rows=[dict(session_id=str(i),integrity=state,head_hash='h',limitations=['audit_review_not_recursively_recorded']) for i,state in enumerate(['verified','verified','incomplete','incomplete','corrupt','missing','unverifiable'])]
    value=dict(activity=dict(valid=True,exists=True),sessions=rows)
    before=copy.deepcopy(value)
    token=sr.ACTIVE.set(SimpleNamespace(segment='2',head={'entry_hash':'h'},broken=False))
    try:text=' '.join(sr.integrity_summary(value).split())
    finally:sr.ACTIVE.reset(token)
    assert 'Verified sessions: 2' in text and 'Active sessions (this process): 1' in text
    assert 'Incomplete sessions (state unknown): 1' in text and 'Integrity failures: 3' in text
    assert 'audit_review_not_recursively_recorded' not in text and value==before
    assert 'state is not established' in text
    assert 'Active sessions (this process): 0' in ' '.join(sr.integrity_summary(value).split())


def test_live_audit_summary_keeps_recording(tmp_path):
    with sr.execution([]) as recorder:
        before=sr.verify()
        text=' '.join(sr.integrity_summary(before).split())
        assert 'Active sessions (this process): 1' in text
    after=sr.verify()
    assert after['valid'] and after['sessions'][0]['integrity']=='verified'
    assert 'Verified sessions: 1' in ' '.join(sr.integrity_summary(after).split())

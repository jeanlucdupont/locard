import io
import json
from pathlib import Path
import pytest
from forensic_assistant.cli import main
from forensic_assistant.database.db import connect
from forensic_assistant.interactive.shell import Shell, split
from forensic_assistant.interactive.state import State
from forensic_assistant.interactive.console import edit


class Input:
    def __init__(self,*lines):self.lines=iter(lines);self.prompts=[];self.cleared=0
    def read(self,prompt,**kwargs):
        self.prompts.append(prompt)
        value=next(self.lines,EOFError())
        if isinstance(value,BaseException):raise value
        if callable(value):return value()
        return value
    def clear(self):self.cleared+=1


def case(tmp_path,name='case é.db'):
    path=tmp_path/name;path.parent.mkdir(parents=True,exist_ok=True);connect(path).close();return path


@pytest.mark.parametrize('text,expected',[
    ('ask "two words"',['ask','two words']),
    (r'case "C:\Case files\case.db"',['case',r'C:\Case files\case.db']),
    (r'ask "C:\"',['ask','C:\\']),
    ('ask "say ""hello"""',['ask','say "hello"']),
    ("ask ''",['ask','']),
    (r'case "\\server\share\a.db"',['case',r'\\server\share\a.db']),
])
def test_quoting(text,expected):assert split(text)==expected


@pytest.mark.parametrize('text',['ask "unfinished','status;exit','status | whoami','status\nexit'])
def test_reject_shell_syntax(text):
    with pytest.raises(ValueError):split(text)


def test_requires_valid_case_before_prompt_and_remembers(tmp_path,capsys):
    good=case(tmp_path);missing=tmp_path/'missing.db';state=State(tmp_path/'ui.json')
    reader=Input(str(missing),str(good),'status','exit')
    before=good.read_bytes()
    assert Shell(state,reader).run()==0
    assert 'Cannot select' in capsys.readouterr().out
    assert reader.prompts[:2]==['Database path or recent number (Enter cancels): ']*2
    assert not missing.exists() and good.read_bytes()==before
    assert State(state.path).load().recent==[str(good.resolve())]


@pytest.mark.parametrize('response',['', 'n'])
def test_remembered_accept_or_decline(tmp_path,response):
    a=case(tmp_path,'a.db');b=case(tmp_path,'b.db');state=State(None);state.remember(a)
    reader=Input(response,*([str(b)] if response=='n' else []),'exit')
    shell=Shell(state,reader);assert shell.run()==0
    assert shell.active==(b if response=='n' else a)


@pytest.mark.parametrize('remembered',['missing','invalid','legacy'])
def test_unusable_remembered_path_reselects(tmp_path,remembered):
    old=tmp_path/'old.db'
    if remembered=='invalid':old.write_bytes(b'bad')
    if remembered=='legacy':
        db=connect(old);db.execute('PRAGMA user_version=1');db.close()
    good=case(tmp_path);state=State(None);state.remember(old)
    reader=Input(str(good),'exit');shell=Shell(state,reader)
    assert shell.run()==0 and shell.active==good
    assert not any(p.startswith('Use this database?') for p in reader.prompts)


@pytest.mark.parametrize('cancel',['',EOFError(),KeyboardInterrupt(),'exit'])
def test_startup_can_exit_without_main_prompt(tmp_path,cancel):
    reader=Input(cancel);assert Shell(State(None),reader).run()==0
    assert not any(p.startswith('locard[') for p in reader.prompts)


def test_switch_isolates_defaults_and_preserves_report_case_semantics(tmp_path,monkeypatch):
    a=case(tmp_path,'A/a.db');b=case(tmp_path,'B/b.db');seen=[]
    def dispatch(args,**kwargs):seen.append((vars(args),kwargs));return 0
    monkeypatch.setattr('forensic_assistant.cli.dispatch',dispatch)
    reader=Input(str(a),'semantic status --index custom-index',f'case "{b}"','semantic status',
                 'investigate-ai "question" --no-semantic','report validate bundle','exit')
    shell=Shell(State(None),reader);assert shell.run()==0
    assert [v[0]['db'] for v in seen]==[str(a),str(b),str(b),str(b)]
    assert seen[0][0]['index']=='custom-index' and seen[1][0]['index'] is None
    assert seen[2][0]['transcripts'] is None and seen[2][0]['semantic_index'] is None
    assert seen[3][0]['case'] is None
    assert all(v[1]=={'existing_only':True} for v in seen)
    assert reader.cleared>=3


def test_errors_help_interrupt_cancel_switch_and_eof(tmp_path,capsys):
    a=case(tmp_path)
    reader=Input(str(a),'bogus','show not-an-id','ask "','help report validate','case','',
                 KeyboardInterrupt(),'status',EOFError())
    shell=Shell(State(None),reader);assert shell.run()==0 and shell.active==a
    captured=capsys.readouterr();assert '--case' in captured.out and 'invalid choice' in captured.err


def test_disappearing_active_case_never_recreated(tmp_path):
    a=case(tmp_path);b=case(tmp_path,'b.db')
    def remove():a.unlink();return 'status'
    reader=Input(str(a),remove,str(b),'exit')
    shell=Shell(State(None),reader);assert shell.run()==0 and shell.active==b and not a.exists()


def test_db_override_blocked_and_unexpected_failure_visible(tmp_path,monkeypatch):
    a=case(tmp_path);b=tmp_path/'missing.db'
    def fail(*args,**kwargs):raise RuntimeError('internal fault')
    monkeypatch.setattr('forensic_assistant.cli.dispatch',fail)
    reader=Input(str(a),f'--db "{b}" status','status')
    with pytest.raises(RuntimeError,match='internal fault'):Shell(State(None),reader).run()
    assert not b.exists() and reader.cleared>=2


def test_redirected_bare_cli_and_scripted_cli(tmp_path,capsys):
    assert main([])==2
    path=case(tmp_path)
    assert main(['--db',str(path),'status'])==0
    with pytest.raises(SystemExit) as result:main(['--help'])
    assert result.value.code==0


def test_memory_only_editor_navigation_and_timeout():
    assert edit(iter(['UP','\r']),history=['status'],output=io.StringIO())=='status'
    assert edit(iter(['UP','DOWN','x','\r']),history=['status'],output=io.StringIO())=='x'
    with pytest.raises(TimeoutError):edit(iter('partial'),output=io.StringIO())
    with pytest.raises(KeyboardInterrupt):edit(iter(['\x03']),output=io.StringIO())
    with pytest.raises(ValueError,match='discarded'):edit(iter('statuslong\r'),output=io.StringIO(),limit=6)

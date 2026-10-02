import io
import json
import os
import pytest
from forensic_assistant import terminal, output
from forensic_assistant.interactive.console import edit
from forensic_assistant.interactive.shell import Shell
from forensic_assistant.interactive.state import State
from test_interactive_shell import Input, case
from test_output_ux import Terminal


@pytest.fixture
def color(monkeypatch):
    monkeypatch.delenv('NO_COLOR',raising=False)
    monkeypatch.setattr(terminal,'capable',lambda stream:True)


def test_prompt_switch_toggle_session_and_dispatch(tmp_path,monkeypatch,capsys,color):
    a=case(tmp_path,'A/a.db'); b=case(tmp_path,'B/b.db');seen=[]
    monkeypatch.setattr('forensic_assistant.cli.dispatch',lambda args,**kw:seen.append(args) or 0)
    reader=Input(str(a),'color','color off','status',f'case "{b}"','color on',
                 'investigate-ai question --no-semantic','status --no-color','status','quit')
    state=State(None);shell=Shell(state,reader)
    assert shell.run()==0
    prompts=[p for p in reader.prompts if 'locard[' in p]
    assert prompts[0]=='\x1b[97mlocard[A/a.db]> \x1b[0m'
    assert prompts[2]=='locard[A/a.db]> '
    assert prompts[4]=='locard[B/b.db]> '
    assert prompts[5]=='\x1b[97mlocard[B/b.db]> \x1b[0m'
    assert [a.no_color for a in seen]==[True,False,True,False]
    assert seen[1].command=='investigate-ai'
    assert 'Color: on' in capsys.readouterr().out
    assert Shell(state).no_color is False
    assert not hasattr(state,'no_color')


@pytest.mark.parametrize('no_color_env',[False,True])
def test_effective_color_constraints(tmp_path,monkeypatch,capsys,no_color_env):
    if no_color_env:monkeypatch.setenv('NO_COLOR','')
    else:monkeypatch.delenv('NO_COLOR',raising=False)
    monkeypatch.setattr(terminal,'capable',lambda stream:no_color_env)
    reader=Input(str(case(tmp_path)),'color','color on','color','exit')
    assert Shell(State(None),reader).run()==0
    assert all('\x1b' not in p for p in reader.prompts)
    text=capsys.readouterr().out
    assert text.count('Color: off')==2
    assert ('NO_COLOR is set' if no_color_env else 'terminal does not support styling') in text


def test_prompt_editor_redraw_resets_before_typed_input(color,monkeypatch):
    monkeypatch.setattr('shutil.get_terminal_size',lambda:os.terminal_size((40,24)))
    prompt=terminal.Palette(True)('prompt','locard[A/a.db]> ')
    colored=io.StringIO();plain=io.StringIO()
    keys=list('status')+['LEFT','DELETE','s','\r']
    assert edit(keys,output=colored,prompt=prompt)==edit(keys,output=plain,prompt=terminal.SGR.sub('',prompt))
    assert terminal.SGR.sub('',colored.getvalue())==plain.getvalue()
    assert '\x1b[97mlocard[A/a.db]> \x1b[0mstatus' in colored.getvalue()
    assert '\\x1b' not in colored.getvalue()


def test_clear_no_external_process_and_usage(tmp_path,monkeypatch,capsys,color):
    def forbidden(*args,**kw):raise AssertionError('External process')
    monkeypatch.setattr('subprocess.Popen',forbidden);monkeypatch.setattr(os,'system',forbidden)
    stream=Terminal();assert terminal.clear_screen(stream)
    assert stream.getvalue()=='\x1b[2J\x1b[H'
    assert not terminal.clear_screen(io.StringIO())
    cleared=[];monkeypatch.setattr(terminal,'clear_screen',lambda:cleared.append(True) or True)
    reader=Input(str(case(tmp_path)),'cls extra','color wrong','color on extra','help cls','help color',
                 'help','cls','status | whoami','$(whoami)','exit')
    assert Shell(State(None),reader).run()==0
    text=capsys.readouterr().out
    assert 'Usage: cls' in text and 'Usage: color [on|off]' in text
    assert 'No shell execution' not in text and 'Locard Forensics' in text and 'color [on|off]' in text
    assert cleared==[True]


def test_color_output_json_files_and_pager(tmp_path,monkeypatch,capsys,color):
    path=case(tmp_path); dest=tmp_path/'status.txt';paged=[]
    monkeypatch.setattr(output,'page',lambda stream:paged.append(stream.read()))
    reader=Input(str(path),'color on','status --page','color off','status --page',
                 'color on',f'status --output "{dest}"',f'status --append "{dest}"',
                 'status --json','exit')
    assert Shell(State(None),reader).run()==0
    assert '\x1b[' in paged[0] and '\x1b' not in paged[1]
    assert terminal.SGR.sub('',paged[0])==paged[1]
    text=dest.read_text(encoding='utf-8')
    assert text==paged[1]+'\n'+paged[1] and '\x1b' not in text
    stdout=capsys.readouterr().out
    structured=stdout[stdout.index('{'):]
    assert '\x1b' not in structured and json.loads(structured)['schema_version']==4


@pytest.mark.skipif(os.name!='nt',reason='Windows console API')
def test_native_clear_viewport(monkeypatch):
    import ctypes
    import msvcrt
    calls=[]
    class Function:
        def __init__(self,fn):self.fn=fn
        def __call__(self,*args):return self.fn(*args)
    class Kernel:
        def __init__(self):
            self.GetConsoleScreenBufferInfo=Function(self.info)
            self.FillConsoleOutputCharacterW=Function(lambda h,c,n,p,w:calls.append(('characters',p.x,p.y,n)) or 1)
            self.FillConsoleOutputAttribute=Function(lambda h,c,n,p,w:calls.append(('attributes',p.x,p.y,n)) or 1)
            self.SetConsoleCursorPosition=Function(lambda h,p:calls.append(('cursor',p.x,p.y)) or 1)
        def info(self,h,ptr):
            ptr._obj.window.left=2;ptr._obj.window.right=5
            ptr._obj.window.top=3;ptr._obj.window.bottom=4
            return 1
    monkeypatch.setattr(ctypes,'WinDLL',lambda *a,**kw:Kernel())
    monkeypatch.setattr(msvcrt,'get_osfhandle',lambda fd:123)
    class Stream(Terminal):
        def fileno(self):return 1
    assert terminal.clear_windows(Stream())
    assert calls==[('characters',2,3,4),('attributes',2,3,4),('characters',2,4,4),('attributes',2,4,4),('cursor',2,3)]


def test_shell_help_keeps_direct_option_discoverable(tmp_path,capsys):
    from forensic_assistant.cli import build_parser
    reader=Input(str(case(tmp_path)),'help status','help report validate','exit')
    assert Shell(State(None),reader).run()==0
    assert '--no-color' not in capsys.readouterr().out
    with pytest.raises(SystemExit):build_parser().parse_args(['status','--help'])
    assert '--no-color' in capsys.readouterr().out

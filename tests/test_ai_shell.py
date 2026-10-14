"""Synthetic cases only; advisory text is never a command or evidence."""
import json

import pytest

from forensic_assistant import __version__, activity
from forensic_assistant.interactive import advisory
from forensic_assistant.interactive.shell import Shell, Mode
from forensic_assistant.interactive.state import State
from forensic_assistant.terminal import Palette
from test_interactive_shell import Input, case


@pytest.fixture
def model(monkeypatch):
    calls = []
    class Client:
        def __init__(self, **kwargs):
            self.timeout = kwargs['timeout']
        def complete(self, messages, schema):
            calls.append((messages, schema))
            return json.dumps({'goal': None, 'assessment': [], 'steps': [{'text': 'Locate the file.', 'commands': ['search --path example.exe']}], 'cautions': ['Individual records have not been inspected.']})
    monkeypatch.setattr(advisory, 'LocalClient', Client)
    return calls


def run_shell(tmp_path, *commands, no_color=True):
    database = case(tmp_path)
    reader = Input(str(database), *commands, 'exit')
    shell = Shell(State(None), reader, no_color=no_color)
    before = database.read_bytes()
    assert shell.run() == 0
    assert database.read_bytes() == before
    return shell, reader, database


@pytest.mark.parametrize('no_color', [False, True])
def test_modes_and_prompt_styles(tmp_path, monkeypatch, model, no_color):
    monkeypatch.delenv('NO_COLOR', raising=False)
    monkeypatch.setattr('forensic_assistant.terminal.capable', lambda _: True)
    fresh = Shell(State(None))
    assert fresh.mode is Mode.EXPERT
    shell, reader, _ = run_shell(tmp_path, 'ai', 'expert', no_color=no_color)
    assert shell.mode is Mode.EXPERT and not model
    prompts = reader.prompts[1:]
    assert prompts == [Palette(not no_color)('prompt', '[case é.db]> '),
                       Palette(not no_color)('ai_prompt', '[case é.db]# '),
                       Palette(not no_color)('prompt', '[case é.db]> ')]


def test_no_color_environment_still_distinguishes_modes(tmp_path, monkeypatch, model):
    monkeypatch.setenv('NO_COLOR', '1')
    monkeypatch.setattr('forensic_assistant.terminal.capable', lambda _: True)
    _, reader, _ = run_shell(tmp_path, 'ai', no_color=False)
    assert reader.prompts[1:] == ['[case é.db]> ', '[case é.db]# ']
    assert not model


@pytest.mark.parametrize('line,expected', [
    ('! test', 'test'), ('!test', 'test'), (' \t! test', 'test'),
    ('! Explain !important', 'Explain !important'), ('!!test', '!test'),
    ('!  two spaces  ', ' two spaces  '), ('!\ttab', '\ttab'),
    ('! Why "unclosed | & < > ; \\path?', 'Why "unclosed | & < > ; \\path?'),
])
def test_exact_natural_language_routing(tmp_path, model, line, expected):
    shell, _, _ = run_shell(tmp_path, 'ai', line)
    assert len(model) == 1 and shell.mode is Mode.AI
    supplied = json.loads(model[0][0][1]['content'])['case_context']
    assert json.loads(model[0][0][2]['content'])['request'] == expected
    assert supplied['case_name'] == 'case é.db'
    assert supplied['locard_version'] == __version__ and supplied['mode'] == 'AI'
    assert supplied['case_context_available'] is True and supplied['individual_records_inspected'] is False and supplied['forensic_conclusions_reached'] is False and supplied['artifact_inventory'] == dict.fromkeys(('evtx', 'mft', 'prefetch', 'registry', 'browser'), 0)
    assert str(tmp_path) not in model[0][0][1]['content']


@pytest.mark.parametrize('command', ['status', 'semantic status', 'search --path example.exe'])
@pytest.mark.parametrize('mode', ['expert', 'ai'])
def test_commands_use_same_dispatcher(tmp_path, monkeypatch, model, command, mode):
    dispatched = []
    def dispatch(args, **kwargs):
        dispatched.append((args.command, kwargs))
        return 0
    monkeypatch.setattr('forensic_assistant.cli.dispatch', dispatch)
    shell, _, _ = run_shell(tmp_path, mode, command)
    assert dispatched == [(command.split()[0], {'existing_only': True})]
    assert shell.mode is (Mode.AI if mode == 'ai' else Mode.EXPERT)
    assert not model


@pytest.mark.parametrize('line', ['! What should I do?', '!whoami', ' \t! rm everything'])
def test_expert_bang_does_not_contact_model(tmp_path, capsys, model, line):
    shell, _, _ = run_shell(tmp_path, line)
    assert 'AI requests are available in AI mode. Enter: ai' in capsys.readouterr().out
    assert not model and shell.mode is Mode.EXPERT and shell.last_status == 2


@pytest.mark.parametrize('line', ['serach example.exe', 'What should I investigate?'])
def test_ai_mode_never_guesses_intent(tmp_path, capsys, model, line):
    shell, _, _ = run_shell(tmp_path, 'ai', line)
    assert 'Unknown command' in capsys.readouterr().out
    assert not model and shell.mode is Mode.AI and shell.last_status == 2


@pytest.mark.parametrize('line', ['ai extra', 'expert extra'])
def test_mode_commands_reject_arguments(tmp_path, capsys, model, line):
    shell, _, _ = run_shell(tmp_path, line)
    assert 'takes no arguments' in capsys.readouterr().out
    assert shell.mode is Mode.EXPERT and not model


def test_model_commands_are_inert_and_activity_is_derived(tmp_path, monkeypatch, capsys):
    payload = 'case new\ningest-evtx C:\\private\nsearch --path example.exe\nreport generate\n!whoami'
    class Client:
        def __init__(self, **kwargs):
            self.timeout = kwargs['timeout']
        def complete(self, *_args, **_kwargs):
            return json.dumps({'goal': None, 'assessment': [], 'steps': [{'text': 'Commands are suggestions only.', 'commands': payload.splitlines()}], 'cautions': []})
    monkeypatch.setattr(advisory, 'LocalClient', Client)
    monkeypatch.setattr('forensic_assistant.cli.dispatch', lambda *_a, **_k: pytest.fail('Model text dispatched'))
    monkeypatch.setattr(Shell, 'new', lambda _: pytest.fail('Model created a case'))
    _, _, database = run_shell(tmp_path, 'ai', '! A private question')
    output = capsys.readouterr().out
    assert 'AI assistant — advisory, not evidence' in output
    assert '  case new' in output and '{"advice"' not in output
    entries = [activity.decode(line + b'\n') for line in activity.sidecar(database).read_bytes().splitlines()]
    advice = [e for e in entries if e['action'] == 'AI_ADVICE']
    assert len(advice) == 1 and advice[0]['outcome'] == 'success'
    log = activity.sidecar(database).read_text(encoding='utf-8')
    assert 'A private question' not in log and 'ingest-evtx' not in log
    assert 'Session UI state only' in log


@pytest.mark.parametrize('failure,expected', [(OSError('private error'), 'unavailable'),
    (TimeoutError('private error'), 'timed out'), (KeyboardInterrupt(), 'Interrupted.')])
def test_failure_preserves_mode_and_shell(tmp_path, monkeypatch, capsys, failure, expected):
    class Client:
        def __init__(self, **kwargs):
            self.timeout = kwargs['timeout']
        def complete(self, *_a, **_k):
            raise failure
    monkeypatch.setattr(advisory, 'LocalClient', Client)
    shell, reader, _ = run_shell(tmp_path, 'ai', '! question', 'version')
    output = capsys.readouterr().out
    assert expected in output and 'private error' not in output
    assert 'Locard version ' + __version__ in output
    assert shell.mode is Mode.AI and reader.prompts[-1].endswith('# ')


@pytest.mark.parametrize('raw', ['not JSON', '[]', '{"advice":"x","tools":[]}',
    '{"advice":false}', '{"advice":""}', '{"advice":"x","advice":"y"}',
    json.dumps({'advice': 'x' * 6001}), 'x' * 16385])
def test_malformed_response_fails_safely(monkeypatch, raw):
    class Client:
        timeout = 45
        def __init__(self, **_kwargs):
            pass
        def complete(self, *_a, **_k):
            return raw
    monkeypatch.setattr(advisory, 'LocalClient', Client)
    with pytest.raises(advisory.AdvisoryError, match='invalid response'):
        advisory.advise({'case_name': 'synthetic'}, 'question')


@pytest.mark.parametrize('question', ['', '  ', 'x' * 4097, 'é' * 2049, 'line\nbreak', 'a\x00b'])
def test_empty_and_oversized_requests_do_not_contact_model(model, question):
    with pytest.raises(advisory.AdvisoryError):
        advisory.advise({'case_name': 'synthetic'}, question)
    assert not model


def test_prompt_boundaries_and_shared_loopback_transport():
    from forensic_assistant.llm.client import LocalClient
    assert advisory.LocalClient is LocalClient
    client = LocalClient()
    assert client.host == '127.0.0.1' and client.port == 8080
    with pytest.raises(ValueError, match='loopback'):
        LocalClient('https://example.com')
    for phrase in ('MFT presence does not prove execution', 'Detections do not prove compromise',
                   'Correlation is not causation', 'Semantic similarity is not evidence',
                   'Never claim you executed', 'Do not fabricate evidence IDs', 'no tools'):
        assert phrase in advisory.SYSTEM


def test_model_terminal_controls_are_escaped(monkeypatch):
    class Client:
        def __init__(self, **kwargs):
            self.timeout = kwargs['timeout']
        def complete(self, *_a, **_k):
            return json.dumps({'goal': None, 'assessment': ['\u001b[2Jhidden\u202e'], 'steps': [{'text': 'Advice only.', 'commands': ['status']}], 'cautions': []})
    monkeypatch.setattr(advisory, 'LocalClient', Client)
    result = advisory.advise({'case_name': 'synthetic'}, 'question')
    text = json.dumps(result, ensure_ascii=False)
    assert '\u001b' not in text and '\u202e' not in text
    assert result['steps'][0]['commands'] == ['status']


def test_wrapped_transport_timeout_preserves_clear_error(monkeypatch):
    from forensic_assistant.llm.client import LLMError
    class Client:
        def __init__(self, **kwargs):
            self.timeout = kwargs['timeout']
        def complete(self, *_a, **_k):
            try:
                raise TimeoutError('private diagnostic')
            except TimeoutError as exc:
                raise LLMError('wrapped transport error') from exc
    monkeypatch.setattr(advisory, 'LocalClient', Client)
    with pytest.raises(advisory.AdvisoryError, match='timed out'):
        advisory.advise({'case_name': 'synthetic'}, 'question')


def test_help_completion_and_bang_no_completion():
    from forensic_assistant.interactive.help import command_help, catalog
    from forensic_assistant.interactive.completion import complete
    from forensic_assistant.cli import build_parser
    for name in ('ai', 'expert'):
        assert name in catalog(build_parser(interactive=True))
        assert 'advisory only' in command_help(name)
        assert complete(name, len(name)).text == name + ' '
    assert '!<text>' in catalog(build_parser(interactive=True))
    assert complete('! question', 10).text == '! question'


def test_case_switch_uses_fresh_context_without_conversation(tmp_path, model):
    a, b = case(tmp_path, 'a.db'), case(tmp_path, 'b.db')
    before = (a.read_bytes(), b.read_bytes())
    reader = Input(str(a), 'ai', '! first private question', 'case ' + str(b), '! second question', 'exit')
    shell = Shell(State(None), reader)
    assert shell.run() == 0 and shell.mode is Mode.AI
    assert len(model) == 2
    assert json.loads(model[1][0][1]['content'])['case_context']['case_name'] == 'b.db'
    assert 'first private question' not in json.dumps(model[1])
    assert before == (a.read_bytes(), b.read_bytes())
    assert Shell(State(None)).mode is Mode.EXPERT

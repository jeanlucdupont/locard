"""Synthetic cases only; advisory text is never a command or evidence."""
import json

import pytest

from forensic_assistant import __version__, activity
from forensic_assistant.interactive import advisory
from forensic_assistant.interactive.shell import Shell
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
def test_compatibility_notices_preserve_prompt_style(tmp_path, monkeypatch, model, no_color):
    monkeypatch.delenv('NO_COLOR', raising=False)
    monkeypatch.setattr('forensic_assistant.terminal.capable', lambda _: True)
    fresh = Shell(State(None))
    assert not hasattr(fresh, 'mode')
    shell, reader, _ = run_shell(tmp_path, 'ai', 'expert', no_color=no_color)
    assert not hasattr(shell, 'mode') and not model
    prompts = reader.prompts[1:]
    assert prompts == [Palette(not no_color)('prompt', '[case é.db]> '),
                       Palette(not no_color)('prompt', '[case é.db]> '),
                       Palette(not no_color)('prompt', '[case é.db]> ')]


def test_no_color_environment_preserves_single_prompt(tmp_path, monkeypatch, model):
    monkeypatch.setenv('NO_COLOR', '1')
    monkeypatch.setattr('forensic_assistant.terminal.capable', lambda _: True)
    _, reader, _ = run_shell(tmp_path, 'ai', no_color=False)
    assert reader.prompts[1:] == ['[case é.db]> ', '[case é.db]> ']
    assert not model


@pytest.mark.parametrize('line,expected', [
    ('! test', 'test'), ('!test', 'test'), (' \t! test', 'test'),
    ('! Explain !important', 'Explain !important'), ('!!test', '!test'),
    ('!  two spaces  ', ' two spaces  '), ('!\ttab', '\ttab'),
    ('! Why "unclosed | & < > ; \\path?', 'Why "unclosed | & < > ; \\path?'),
])
def test_exact_natural_language_routing(tmp_path, model, line, expected):
    shell, _, _ = run_shell(tmp_path, 'ai', line)
    assert len(model) == 1 and not hasattr(shell, 'mode')
    supplied = json.loads(model[0][0][1]['content'])['case_context']
    assert json.loads(model[0][0][1]['content'])['request'] == expected
    assert supplied['case_name'] == 'case é.db'
    assert supplied['locard_version'] == __version__ and 'mode' not in supplied
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
    expected = [('ai', {'existing_only': True})] if mode == 'ai' else []
    assert dispatched == expected + [(command.split()[0], {'existing_only': True})]
    assert not hasattr(shell, 'mode')
    assert not model


@pytest.mark.parametrize('line', ['! What should I do?', '!whoami', ' \t! rm everything'])
def test_bang_works_directly_without_transition(tmp_path, capsys, model, line):
    shell, _, _ = run_shell(tmp_path, line)
    assert 'AI assistant — advisory, not evidence' in capsys.readouterr().out
    assert len(model) == 1 and not hasattr(shell, 'mode') and shell.last_status == 0


@pytest.mark.parametrize('line', ['serach example.exe', 'What should I investigate?'])
def test_shell_never_guesses_intent(tmp_path, capsys, model, line):
    shell, _, _ = run_shell(tmp_path, 'ai', line)
    assert 'Unknown command' in capsys.readouterr().out
    assert not model and not hasattr(shell, 'mode') and shell.last_status == 2


@pytest.mark.parametrize('line', ['ai extra', 'expert extra'])
def test_compatibility_notices_reject_arguments(tmp_path, capsys, model, line):
    shell, _, _ = run_shell(tmp_path, line)
    assert ('Invalid arguments' if line == 'ai extra' else 'takes no arguments') in capsys.readouterr().out
    assert not hasattr(shell, 'mode') and not model


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
    _, _, database = run_shell(tmp_path, '! A private question')
    output = capsys.readouterr().out
    assert 'AI assistant — advisory, not evidence' in output
    assert '  case new' in output and '{"advice"' not in output
    entries = [activity.decode(line + b'\n') for line in activity.sidecar(database).read_bytes().splitlines()]
    advice = [e for e in entries if e['action'] == 'AI_ADVICE']
    assert len(advice) == 1 and advice[0]['outcome'] == 'success'
    log = activity.sidecar(database).read_text(encoding='utf-8')
    assert 'A private question' not in log and 'ingest-evtx' not in log
    assert not any(e['action'] == 'SHELL_MODE' for e in entries)


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
    assert not hasattr(shell, 'mode') and reader.prompts[-1].endswith('> ')


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
    from forensic_assistant.ai.backend import backend
    assert advisory.LocalClient is backend
    from forensic_assistant.llm.client import LocalClient
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
    for name in ('expert',):
        assert not any(row.strip().startswith(name + ' ') for row in catalog(build_parser(interactive=True)).splitlines())
        assert 'approval before each proposed tool' in command_help(name)
        assert complete(name, len(name)).text == name
    assert 'Configure AI provider and local runtime' in catalog(build_parser(interactive=True))
    import argparse
    parser = build_parser(interactive=True)
    commands = next(a.choices for a in parser._actions if isinstance(a, argparse._SubParsersAction))
    assert 'provider' in commands['ai'].format_help()
    assert 'natural-language request with !' in catalog(build_parser(interactive=True))
    assert complete('! question', 10).text == '! question'


def test_case_switch_uses_fresh_context_without_conversation(tmp_path, model):
    a, b = case(tmp_path, 'a.db'), case(tmp_path, 'b.db')
    before = (a.read_bytes(), b.read_bytes())
    reader = Input(str(a), 'ai', '! first private question', 'case ' + str(b), '! second question', 'exit')
    shell = Shell(State(None), reader)
    assert shell.run() == 0 and not hasattr(shell, 'mode')
    assert len(model) == 2
    assert json.loads(model[1][0][1]['content'])['case_context']['case_name'] == 'b.db'
    assert 'first private question' not in json.dumps(model[1])
    assert before == (a.read_bytes(), b.read_bytes())
    assert not hasattr(Shell(State(None)), 'mode')


def test_direct_advice_interleaves_commands_and_deprecated_ask(tmp_path, model, capsys):
    shell, reader, _ = run_shell(tmp_path, '! What evidence is available?', 'search --path example.exe --ids',
                                'ask How should I investigate this?', '! What next?')
    requests = [json.loads(call[0][1]['content'])['request'] for call in model]
    assert requests == ['What evidence is available?', 'How should I investigate this?', 'What next?']
    output = capsys.readouterr().out
    assert '`ask` is deprecated' in output and 'No matching evidence.' in output
    assert all(prompt == '[case é.db]> ' for prompt in reader.prompts[1:])
    assert shell.last_status == 0 and not hasattr(shell, 'mode')


@pytest.mark.parametrize('line', ['ask', 'ask   '])
def test_empty_compatibility_request_does_not_invoke_model(tmp_path, model, capsys, line):
    run_shell(tmp_path, line)
    assert 'Enter a question after !.' in capsys.readouterr().out
    assert not model


@pytest.mark.parametrize('line', ['"ask" question', '--no-color ask question'])
def test_parser_resolved_ask_still_uses_advisory_only(tmp_path, monkeypatch, model, line):
    monkeypatch.setattr('forensic_assistant.cli.dispatch', lambda *a, **kw: pytest.fail('Legacy retrieval dispatched'))
    run_shell(tmp_path, line)
    assert len(model) == 1
    assert json.loads(model[0][0][1]['content'])['request'] == 'question'

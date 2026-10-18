"""6.68 command names reuse the accepted read-only history implementation."""
import argparse
import json
import pytest
from forensic_assistant.cli import build_parser, main
from forensic_assistant.interactive.help import catalog
from forensic_assistant.investigation_ai import cli
from test_interactive_shell import case


def choices(parser):
    return next(a.choices for a in parser._actions if isinstance(a, argparse._SubParsersAction))


@pytest.mark.parametrize('interactive', [False, True])
def test_history_single_parser_and_internal_identity(interactive):
    parser = build_parser(interactive=interactive)
    commands = choices(parser)
    assert commands['ai-history'] is commands['investigation']
    assert 'investigation' not in commands['ai-history'].prog
    for operation in ('show', 'replay'):
        canonical = parser.parse_args(['ai-history', operation, 'synthetic-id', '--json'])
        alias = parser.parse_args(['investigation', operation, 'synthetic-id', '--json'])
        assert vars(canonical) == vars(alias)
        assert canonical.command == 'investigation'
        assert canonical.investigation_command == operation


def test_discovery():
    parser = build_parser(interactive=True)
    text = catalog(parser)
    names = [line.split()[0] for line in text.splitlines() if line.startswith('  ')]
    assert 'ai-history' in names
    assert 'investigate' in names and 'analyze-timeline' in names
    assert 'investigation' not in names and 'investigate-ai' not in names
    assert 'Prefix a natural-language request with !' in text
    assert 'approval required' in text
    normal = build_parser().format_help()
    assert 'ai-history' in normal and 'investigate-ai' not in normal


@pytest.mark.parametrize('name', ['ai-history', 'investigation'])
@pytest.mark.parametrize('interactive', [False, True])
def test_history_help(name, interactive, capsys):
    with pytest.raises(SystemExit) as stopped:
        build_parser(interactive=interactive).parse_args([name, '--help'])
    assert stopped.value.code == 0
    text = ' '.join(capsys.readouterr().out.split())
    for expected in ('derived AI investigation records', 'not source evidence', 'show', 'replay',
                     'deprecated compatibility alias for ai-history'):
        assert expected in text


@pytest.mark.parametrize('name', ['ai-history', 'investigation'])
@pytest.mark.parametrize('operation', ['show', 'replay'])
@pytest.mark.parametrize('json_flag', [False, True])
def test_real_history_handler_json_equivalence(tmp_path, monkeypatch, capsys, name, operation, json_flag):
    path = case(tmp_path)
    manifest = {'evidence_fingerprint': 'synthetic-fingerprint'}
    calls = []
    def load(root, identifier):
        calls.append(('load', identifier))
        return manifest, [{'kind': 'terminal', 'data': {'termination': 'ANSWER_SUPPORTED'}}]
    monkeypatch.setattr(cli, 'load', load)
    from forensic_assistant.investigation_ai import runner, replay
    class Worker:
        def __init__(self, config):
            assert config == {'case_path': str(path), 'semantic_enabled': False}
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def call(self, operation, **kwargs):
            assert operation == 'check'
            return {'fingerprint': 'synthetic-fingerprint'}
    monkeypatch.setattr(runner, 'ForensicWorker', Worker)
    def replay_record(config, root, identifier):
        calls.append(('replay', identifier))
        assert config['case_path'] == str(path)
        return {'replayed': identifier, 'evidence_ids': ['EVTX:synthetic:1']}
    monkeypatch.setattr(replay, 'replay', replay_record)
    def invoke(command):
        assert main(['--db', str(path), command, operation, 'synthetic-id', *(['--json'] if json_flag else [])]) == 0
        output = capsys.readouterr()
        assert 'deprecated' not in output.err
        return json.loads(output.out)
    result = invoke(name)
    assert result == invoke('ai-history')
    assert calls == [('load' if operation == 'show' else 'replay', 'synthetic-id')] * 2
    if operation == 'show':
        assert result['recorded_not_revalidated'] is True
        assert result['current_case_status']['matches_recorded_fingerprint'] is True
    else:
        assert result['evidence_ids'] == ['EVTX:synthetic:1']


def test_deterministic_help_and_defaults(capsys):
    parser = build_parser(interactive=True)
    with pytest.raises(SystemExit):
        parser.parse_args(['investigate', '--help'])
    text = ' '.join(capsys.readouterr().out.split())
    for expected in ('Deterministic correlation', 'canonical evidence_id', 'no AI required',
                     '--seconds', '--candidate-limit', '--timestamp-slot', 'anchor timestamp slot'):
        assert expected in text
    args = parser.parse_args(['investigate', 'EVTX:synthetic:1'])
    assert (args.evidence_id, args.seconds, args.candidate_limit, args.timestamp_slot) == ('EVTX:synthetic:1', 120, 500, None)


def test_specialized_and_advanced_help(capsys):
    for command, phrases in [
        ('analyze-timeline', ('Specialized workflow', 'deterministic retrieval', '--dry-run', 'without calling the model')),
        ('investigate-ai', ('Advanced / Diagnostic', 'Use ! <question>')),
    ]:
        with pytest.raises(SystemExit):
            build_parser(interactive=True).parse_args([command, '--help'])
        text = ' '.join(capsys.readouterr().out.split())
        assert all(phrase in text for phrase in phrases)


def test_shell_help_routes_canonical_and_alias(tmp_path, capsys):
    from forensic_assistant.interactive.shell import Shell
    from forensic_assistant.interactive.state import State
    from test_interactive_shell import Input
    db = case(tmp_path)
    shell = Shell(State(None), Input(str(db), 'color off', 'help ai-history',
        'help investigation', 'help investigate', 'help investigate-ai', 'exit'))
    assert shell.run() == 0 and shell.last_status == 0
    text = ' '.join(capsys.readouterr().out.split())
    assert text.count('deprecated compatibility alias for ai-history') == 2
    assert 'Deterministic correlation' in text
    assert 'Advanced / Diagnostic' in text
    assert 'Unknown command' not in text


@pytest.mark.parametrize('name', ['ai-history', 'investigation'])
def test_redirected_history_json(tmp_path, monkeypatch, name):
    db = case(tmp_path)
    output = tmp_path / 'history.txt'
    expected = {'manifest': {'synthetic': True}, 'recorded_not_revalidated': True}
    def handler(args):
        assert args.command == 'investigation' and args.investigation_command == 'show'
        return expected
    monkeypatch.setattr(cli, 'dispatch', handler)
    assert main(['--db', str(db), name, 'show', 'synthetic-id', '--json', '--output', str(output)]) == 0
    assert json.loads(output.read_text(encoding='utf-8')) == expected

import copy
import json
import pytest
from forensic_assistant.investigation_ai import controller, cli, contracts
from forensic_assistant.investigation_ai.presentation import render, proposal_text
from forensic_assistant.interactive.ai_routing import needs_investigation
from test_investigation_assessment import RecordingWorker, EID
from test_v4_controller import Scripted, tool, final
from test_ai_shell import run_shell

@pytest.mark.parametrize('question,expected', [
    ('What evidence is available in this case?', False),
    ('How should I investigate malware?', False),
    ('Explain example.exe', False), ('What is my current mode?', False),
    ('Did coreupdater.exe execute after loot.zip was downloaded?', True),
    ('When was example.exe created?', True),
    ('Inspect evidence for ' + EID, True),
    ('!! Did example.exe run?', False),
])
def test_conservative_routing(question, expected):
    assert needs_investigation(question) is expected


def test_human_projection_is_nonmutating_and_sanitized():
    result = dict(termination='EVIDENCE_STATE_CHANGED', state=dict(accepted_calls=2,
        investigation_path=[{'operation':'initial'}, {'operation':'show_evidence'}],
        final_grounding_rejections=2, final_grounding_reasons=['unexposed_field']),
        findings={'observed':[dict(field='/process_name', reported_value='evil\x1b[2J.exe', evidence_ids=[EID],
                                  source_context={'hostname':'asserted'}, truncated_fields=['timestamps'])]},
        metrics={'integrity':{'strategy':'private_sqlite_snapshot', 'live_case_matches':False}},
        limitations=['Source metadata includes analyst assertions.', 'Source metadata contains analyst assertions.'],
        model_metadata=['HIDDEN'], evidence_fingerprint='HIDDEN')
    original = copy.deepcopy(result)
    text = render(result)
    assert result == original
    assert EID in text and 'Completed: 1' in text
    assert 'live case changed' in text and 'not accepted against the changed case state' in text
    assert 'Locard rejected 2' in text
    assert 'Source metadata includes analyst assertions.' not in text
    assert '\x1b' not in text and 'HIDDEN' not in text
    assert 'truncated' in text and 'No supported conclusion' in text


@pytest.mark.parametrize('answers,executed', [(['n'], []), (['y','n'], ['show_evidence']), (['y','y'], ['show_evidence','process_tree'])])
def test_bang_reuses_engine_and_every_approval(tmp_path, monkeypatch, capsys, answers, executed):
    worker = RecordingWorker({})
    phases = []
    class Indicator:
        def __init__(self, *a, **k): pass
        def __enter__(self): return self
        def __exit__(self, *a): phases.append('cleared')
        def phase(self, phase): phases.append(phase)
    monkeypatch.setattr('forensic_assistant.terminal_activity.ActivityIndicator', Indicator)
    client = Scripted([tool('show_evidence', {'evidence_id':EID}), tool('process_tree', {'evidence_id':EID}), final])
    answers = iter(answers)
    proposals = []
    def read(prompt, seconds):
        assert phases[-1] == 'approval'
        proposals.append(prompt)
        # The operation awaiting this approval has not executed yet.
        assert len([n for n in worker.calls if n not in ('initial','check')]) == len(proposals)-1
        assert '[y/N]' in prompt and seconds > 0
        return next(answers)
    monkeypatch.setattr('sys.stdin.isatty', lambda: True)
    monkeypatch.setattr('forensic_assistant.interactive.console.timed_line', read)
    def engine(config, question, root, **kwargs):
        assert kwargs['approval'].func is cli.approve
        assert kwargs['approval'].keywords['args'].approve_tools
        assert (kwargs['budget'].steps, kwargs['budget'].calls, kwargs['budget'].seconds) == (8,6,300)
        kwargs['client'] = client
        return controller.run({**config, '_status': kwargs.pop('status')}, question, root, worker_factory=lambda _:worker, **kwargs)
    monkeypatch.setattr(cli, 'run', engine)
    shell, _, _ = run_shell(tmp_path, '! Did synthetic.exe execute?')
    assert not hasattr(shell, 'mode')
    assert [n for n in worker.calls if n not in ('initial','check')] == executed
    output = capsys.readouterr()
    assert 'More evidence needs to be inspected.' in output.out
    assert 'Proposed forensic lookup' in output.err
    assert output.out.count('More evidence needs to be inspected.') == 1
    assert 'Locard may propose additional forensic lookups.' in output.out
    assert 'More evidence is needed' not in output.err
    assert 'bounded read-only investigation' not in output.out
    assert EID in output.err and '"action"' not in output.err
    assert 'Investigation' in output.out
    assert phases[-1] == 'cleared'
    assert phases.count('operation') == len(executed)


def test_inventory_bang_never_enters_engine(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(cli, 'run', lambda *a, **k: pytest.fail('investigation launched'))
    run_shell(tmp_path, '! What evidence is available in this case?')
    assert 'More evidence needs to be inspected.' not in capsys.readouterr().out


def test_invalid_window_feedback_does_not_rewrite_or_execute(tmp_path):
    invalid = tool('search_evidence', {'start':'2020-01-01T00:00:00Z', 'end':'2020-01-03T00:00:00Z'})
    client = Scripted([invalid] * 3)
    worker = RecordingWorker({})
    result = controller.run({}, 'Inspect', tmp_path, client=client, worker_factory=lambda _:worker)
    assert result['termination'] == 'TOO_MANY_REJECTIONS'
    assert result['state']['accepted_calls'] == 0 and worker.calls == ['initial','check']
    packet = json.loads(client.calls[1][1]['content'])['controller']
    feedback = packet['last_result']
    assert feedback['category'] == 'INVALID_ARGUMENT'
    assert '<= 24 hours' in feedback['reason'] and 'valid bounded window' in feedback['correction']
    assert 'start <= end' in packet['time_window_contract']
    assert '24 hours' in contracts.catalog()['search_evidence']['description']
    with pytest.raises(ValueError, match='Time window'):
        contracts.arguments('search_evidence', invalid['arguments'])


def test_json_approval_uses_stderr(monkeypatch, capsys):
    monkeypatch.setattr('sys.stdin.isatty', lambda:True)
    def read(prompt, seconds):
        print(prompt)
        return 'y'
    monkeypatch.setattr('forensic_assistant.interactive.console.timed_line', read)
    assert cli.approve(tool('show_evidence', {'evidence_id':EID}), 3)
    output = capsys.readouterr()
    assert output.out == '' and EID in output.err and '[y/N]' in output.err


def test_malformed_tool_feedback_is_bounded(tmp_path):
    client = Scripted([{'action':'tool', 'tool':[], 'arguments':{}, 'reason':'x'}] * 3)
    result = controller.run({}, 'Inspect', tmp_path, client=client, worker_factory=RecordingWorker)
    assert result['state']['accepted_calls'] == 0
    assert result['termination'] == 'TOO_MANY_REJECTIONS'
    correction = json.loads(client.calls[1][1]['content'])['controller']['last_result']
    assert correction['tool'] is None and len(json.dumps(correction)) < 600

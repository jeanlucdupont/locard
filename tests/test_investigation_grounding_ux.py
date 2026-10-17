import json

import pytest

from forensic_assistant.investigation_ai import controller, cli
from forensic_assistant.investigation_ai.state import State, Budget, SYSTEM
from test_investigation_assessment import RecordingWorker, EID
from test_v4_controller import Scripted, tool, final


def unsupported():
    return dict(action='final', answer=dict(observed=[dict(evidence_id=EID, field='/not_disclosed')],
        relationships=[], detections=[], hypotheses=[], unknowns=[]))


def test_guidance_disclosure_and_existing_grammar_stay_bounded():
    for phrase in ('ONLY exact leaf fields/values explicitly disclosed',
                   'An exposed ID does not expose every field',
                   'truncated_fields omissions', 'NOT disclosed values',
                   'propose an allowed grounded read-only tool',
                   'Never invent OBSERVED entries or guess yes/no',
                   'an unresolved final result is valid'):
        assert phrase in SYSTEM
    assert 'coreupdater' not in SYSTEM and 'loot.zip' not in SYSTEM
    state = State(Budget())
    state.records[EID] = dict(id=EID, process_name='synthetic.exe', truncated_fields=['timestamps'])
    messages, exposed, size = state.prompt('Inspect', ['show_evidence'], [])
    assert size <= 5600 and exposed['records'] == [state.records[EID]]
    assert json.loads(messages[1]['content'])['UNTRUSTED FORENSIC EVIDENCE'] == exposed
    state.disclose(exposed)
    with pytest.raises(ValueError, match='unexposed'):
        state.render(unsupported()['answer'])


def test_observed_sequence_notice_uses_actual_controller_counts(tmp_path):
    worker = RecordingWorker({})
    result = controller.run({}, 'Inspect', tmp_path, budget=Budget(steps=3),
        client=Scripted([unsupported(), tool('show_evidence', {'evidence_id': EID}), unsupported()]),
        approval=lambda *_: True, worker_factory=lambda _: worker)
    state = result['state']
    assert [state[k] for k in ('steps', 'requested_calls', 'accepted_calls', 'rejected_requests')] == [3, 1, 1, 2]
    assert state['final_grounding_rejections'] == 2
    assert state['final_grounding_reasons'] == ['unexposed_field']
    notice = cli.rejection_notice(result)
    assert 'rejected 2 unsupported AI conclusions' in notice
    assert 'evidence fields that had not been exposed' in notice
    assert 'Successfully completed read-only operations: 1' in notice
    assert 'not accepted as findings' in notice
    assert '/not_disclosed' not in notice and EID not in notice


def test_minor_correction_and_supported_final_do_not_warn(tmp_path):
    result = controller.run({}, 'Inspect', tmp_path, client=Scripted([tool('shell', {}), final]),
        worker_factory=RecordingWorker)
    assert result['state']['rejected_requests'] == 1
    assert result['state']['final_grounding_rejections'] == 0
    assert cli.rejection_notice(result) == ''
    result = controller.run({}, 'Inspect', tmp_path, client=Scripted([unsupported(), final]),
        worker_factory=RecordingWorker)
    assert result['termination'] == 'ANSWER_SUPPORTED'
    assert result['state']['final_grounding_rejections'] == 1
    assert cli.rejection_notice(result) == ''


def test_failed_approved_call_is_not_reported_as_completed(tmp_path):
    from forensic_assistant.investigation_ai.runner import WorkerError
    class Failed(RecordingWorker):
        def call(self, name, *a, **kw):
            if name == 'show_evidence':
                raise WorkerError('synthetic failure')
            return super().call(name, *a, **kw)
    result = controller.run({}, 'Inspect', tmp_path,
        client=Scripted([unsupported(), tool('show_evidence', {'evidence_id': EID})]), worker_factory=Failed)
    assert result['state']['accepted_calls'] == 1
    assert 'Successfully completed read-only operations: 0' in cli.rejection_notice(result)


@pytest.mark.parametrize('json_mode', [False, True])
def test_json_preserved_and_notice_not_model_prose(tmp_path, monkeypatch, capsys, json_mode):
    from forensic_assistant.cli import main, dispatch, build_parser
    from test_interactive_shell import case
    path = case(tmp_path)
    result = dict(termination='BUDGET_EXHAUSTED', findings={}, state=dict(
        final_grounding_rejections=2, final_grounding_reasons=['unexposed_field'],
        investigation_path=[dict(operation='initial'), dict(operation='show_evidence')]),
        model_proposed_explanation='MODEL CLAIM: nothing was rejected')
    monkeypatch.setattr(cli, 'dispatch', lambda _: result)
    args = ['--db', str(path), 'investigate-ai', 'Inspect'] + (['--json'] if json_mode else [])
    assert dispatch(build_parser(interactive=True).parse_args(args), existing_only=True) == 0
    output = capsys.readouterr().out
    if json_mode:
        assert json.loads(output) == result
        assert 'Locard rejected' not in output
    else:
        assert 'Locard rejected 2' in output and 'MODEL CLAIM' not in output
        assert 'Investigation incomplete' in output
        assert 'model_proposed_explanation' not in output

    assert main(args) == 0
    output = capsys.readouterr().out
    if json_mode:
        assert json.loads(output) == result
    else:
        assert 'Investigation incomplete' in output and 'MODEL CLAIM' not in output

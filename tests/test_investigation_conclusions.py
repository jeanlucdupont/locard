"""Synthetic 6.72 final selection; no provider or real case access."""
import json
import pytest
from forensic_assistant.investigation_ai import contracts, tools, controller
from forensic_assistant.investigation_ai.state import State, Budget, SYSTEM
from forensic_assistant.investigation_ai.conclusions import assess
from forensic_assistant.investigation_ai.presentation import render
from test_investigation_assessment import RecordingWorker
from test_v4_controller import Scripted, final


def fixture():
    raw = dict(id='EVTX:' + 'a'*64 + ':Offset:1', source_type='evtx',
        provider='Microsoft-Windows-Windows Defender',
        channel='Microsoft-Windows-Windows Defender/Operational', event_id=1121,
        hostname='synthetic-host', timestamp_utc='2026-09-30T14:05:47Z',
        event_data_json=json.dumps([{'name': n, 'value': v} for n,v in [
            ('Path', 'sample.exe'), ('Process Name', 'parent.exe'),
            ('Target Commandline', 'sample.exe sample.ps1'), ('Parent Commandline', 'parent.exe'),
            ('Duplicate', 'first'), ('Duplicate', 'second')]]))
    record = tools.compact(raw)
    state = State(Budget()); state.records[record['id']] = record; state.recent = [record['id']]
    _, exposed, size = state.prompt('Inspect recorded activity involving sample.ps1',
        ['search_evidence', 'timeline', 'show_evidence'], [])
    state.disclose(exposed)
    assert size <= 5600 and exposed['records']
    return state, record


def answer(record, fields=('/event_id', '/provider', '/hostname')):
    return dict(observed=[dict(evidence_id=record['id'], field=f) for f in fields],
                relationships=[], detections=[], hypotheses=[], unknowns=[],
                interpretations=[], answer_status='answered')


def test_more_than_three_original_observations_and_ordinals():
    state, record = fixture()
    paths = ['/event_id', '/timestamp_utc'] + [f'/original_event_data/{i}/value' for i in range(6)]
    result = state.render(answer(record, paths))
    assert len(result['observed']) == 8
    assert [r['recorded_field']['ordinal'] for r in result['observed'][2:]] == list(range(6))
    assert [r['reported_value'] for r in result['observed'][-2:]] == ['first', 'second']
    assert 'objective-relevant' in SYSTEM and 'activity details over generic metadata' in SYSTEM
    invalid = answer(record, [f'/field{i}' for i in range(13)])
    with pytest.raises(ValueError, match='item count'): state.render(invalid)
    with pytest.raises(ValueError, match='unexposed'): state.render(answer(record, ['/hidden']))


def test_interpretation_requires_recognized_exposure_and_not_arbitrary_text():
    state, record = fixture(); a = answer(record)
    a['interpretations'] = record['interpretation_ids']
    findings = state.render(a)
    derived = findings['interpretations'][0]
    assert derived['derivation_id'] == 'defender-asr-block-v1'
    assert derived['evidence_ids'] == [record['id']]
    assert 'does not establish successful' in render(dict(termination='ANSWER_SUPPORTED', findings=findings))
    a['interpretations'] = ['INT:invented']
    with pytest.raises(ValueError, match='Interpretation'): state.render(a)
    a['interpretations'] = record['interpretation_ids']
    state.exposed[record['id']]['defender_asr']['action'] = 'execution succeeded'
    with pytest.raises(ValueError, match='Interpretation'): state.render(a)
    with pytest.raises(ValueError, match='unexposed'): state.render(answer(record, ['/defender_asr/action']))


def test_completeness_cannot_be_self_certified():
    state, record = fixture(); a = answer(record); f = state.render(a)
    assert assess('Did sample.exe execute?', a, f)['status'] == 'PARTIAL'
    a = answer(record, ['/hostname']); f = state.render(a)
    # This narrow objective is independently decidable; broad investigations are not.
    assert assess('What is the hostname?', a, f, candidate_count=1)['status'] == 'COMPLETE'
    assert assess('What is the hostname?', a, f, candidate_count=2)['status'] == 'PARTIAL'
    a['unknowns'] = ['Host attribution remains uncertain.']
    assert assess('What is the hostname?', a, f, candidate_count=1)['status'] == 'PARTIAL'
    a['unknowns'] = []
    assert assess('What is the hostname?', a, f, omitted=True, candidate_count=1)['status'] == 'PARTIAL'
    assert assess('Inspect', a, dict(observed=[]))['status'] == 'UNRESOLVED'


def test_unknowns_are_bounded_unverified_and_escaped():
    state, record = fixture(); a = answer(record)
    a['unknowns'] = ['Execution is not established.\x1b[31m']
    text = render(dict(termination='ANSWER_SUPPORTED', findings=state.render(a)))
    assert 'Model-proposed uncertainty (unverified)' in text and '\x1b' not in text
    assert 'Model-proposed uncertainty' not in render(dict(findings=state.render(answer(record))))
    a['unknowns'] = ['x'*201]
    with pytest.raises(ValueError): state.render(a)
    a['unknowns'] = ['one','two','three','four']
    with pytest.raises(ValueError): state.render(a)


def test_coverage_is_distinct_and_raw_json_marker_removed():
    state, record = fixture()
    assert 'event_data_json' not in record.get('truncated_fields', [])
    raw = dict(record, event_data_json=json.dumps([{'name':'Text','value':'x'*400}]*20),
               content_matches=[dict(name='Text',ordinal=0,excerpt='x',truncated=True)])
    projected = tools.compact(raw)
    from forensic_assistant.investigation_ai.conclusions import coverage_text
    notes = ' '.join(coverage_text(n) for n in projected['coverage_notes'])
    assert 'names or values were shortened' in notes
    assert 'not all original fields' in notes
    assert 'Search excerpts' in notes
    with_warnings = tools.compact(dict(raw, warnings=['warning']*5))
    assert 'context_shortened' in with_warnings['coverage_notes']
    state.content_search = {'complete':False}
    state.records['large'] = dict(id='large', value='x'*6000)
    state.prompt('Inspect', ['show_evidence'], [])
    assert state.prompt_omitted
    assert any('search coverage is partial' in n for n in state.limits)
    assert any('records were omitted' in n for n in state.limits)


def test_controller_keeps_grounding_separate_without_retry(tmp_path):
    client = Scripted([final])
    result = controller.run({}, 'Did a process execute?', tmp_path, client=client, worker_factory=RecordingWorker)
    assert result['termination'] == 'ANSWER_SUPPORTED'
    assert result['answer_assessment']['grounding'] == 'SUPPORTED'
    assert result['answer_assessment']['status'] == 'PARTIAL'
    assert len(client.calls) == 1 and result['state']['accepted_calls'] == 0
    assert 'Answer status: PARTIAL' in render(result)


def test_provider_grammar_advertises_new_bounded_contract():
    grammar = contracts.schema(['show_evidence'])
    final_schema = grammar['oneOf'][-1]['properties']['answer']
    assert final_schema['properties']['observed']['maxItems'] == 12
    assert final_schema['properties']['interpretations']['maxItems'] == 4
    assert {'interpretations','answer_status'} <= set(final_schema['required'])


@pytest.mark.parametrize('provider', ['openai', 'anthropic', 'gemini', 'deepseek', 'xai', 'local'])
def test_expanded_answer_survives_provider_contracts(provider):
    from forensic_assistant.ai import openai_schema, anthropic_strategy
    from forensic_assistant.ai.response_contract import validate
    state, record = fixture()
    a = answer(record, ['/event_id','/timestamp_utc'] + [f'/original_event_data/{i}/value' for i in range(6)])
    a['interpretations'] = record['interpretation_ids']
    proposal = dict(action='final', answer=a)
    grammar = contracts.schema(['search_evidence', 'show_evidence'])
    if provider == 'anthropic':
        _, branches = anthropic_strategy.stages(grammar)
        validate(json.dumps({'answer':a}), anthropic_strategy.payload_schema(branches['final']))
    wire = {'proposal':proposal} if provider == 'openai' else proposal
    decoded = json.loads(openai_schema.response(provider, json.dumps(wire), grammar))
    assert decoded == proposal
    assert len(state.render(decoded['answer'])['observed']) == 8


def test_interpretation_id_not_in_exposure_is_rejected():
    state, record = fixture(); a = answer(record); a['interpretations'] = record['interpretation_ids']
    del state.exposed[record['id']]['interpretation_ids']
    with pytest.raises(ValueError, match='Interpretation'): state.render(a)


def test_fake_provider_search_show_complete_original_details(tmp_path):
    from contextlib import closing
    from forensic_assistant.database.db import connect
    from test_evtx_content import add, SCOPE
    from test_investigation_scope import MemoryWorker, QUESTION
    from test_v4_controller import tool
    with closing(connect(':memory:')) as db:
        eid = add(db)
        worker = MemoryWorker(db, {})
        approved = []
        def select(messages):
            r = json.loads(messages[1]['content'])['UNTRUSTED FORENSIC EVIDENCE']['records'][0]
            a = answer(r, ['/event_id', '/provider', '/hostname', '/timestamp_utc'] +
                       [f'/original_event_data/{i}/value' for i,e in enumerate(r['original_event_data'])
                        if e['name'] in ('Path','Process Name','Target Commandline','Parent Commandline')])
            a['interpretations'] = r['interpretation_ids']
            a['unknowns'] = ['Successful execution is not established.']
            return dict(action='final', answer=a)
        args = dict(SCOPE, evtx_text='baje.ps1', start='2026-09-30T14:05:40Z', end='2026-09-30T14:06:10Z')
        result = controller.run({}, QUESTION, tmp_path, worker_factory=lambda _: worker,
            client=Scripted([tool('search_evidence', args), tool('show_evidence', {'evidence_id':eid}), select]),
            approval=lambda *args: approved.append(args) or True)
        assert len(approved) == 2 and result['state']['accepted_calls'] == 2
        assert len(result['findings']['observed']) == 8
        assert result['answer_assessment']['status'] == 'PARTIAL'
        assert result['termination'] == 'ANSWER_SUPPORTED'
        text = render(result)
        assert 'baje.ps1' in text and 'recorded an ASR blocking action' in text
        assert 'Successful execution is not established.' in text
        assert max(result['metrics']['prompt_bytes']) <= 5600

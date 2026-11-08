"""Synthetic reproduction of the 6.97 citation shape; no real case content."""
from copy import deepcopy
import pytest
from forensic_assistant.investigation_ai.state import State, Budget, GroundingReferenceError, fields
from forensic_assistant.investigation_ai.contracts import FINAL
from forensic_assistant.investigation_ai.conclusions import interpretations
from forensic_assistant.retrieval.event_data import interpretation

E = 'EVTX:' + 'a'*64 + ':Offset:1'
B = 'BROWSER:' + 'b'*64 + ':download:1'


def fixture_state():
    event = dict(id=E, event_id=1121, timestamp_utc='2026-01-01T00:00:20Z',
        provider='Microsoft-Windows-Windows Defender',
        channel='Microsoft-Windows-Windows Defender/Operational',
        source_context={'hostname': 'synthetic-host'},
        original_event_data=[{}, {}, {}, {}, {},
            dict(name='Target Commandline', ordinal=11, value='powershell.exe synthetic.ps1', truncated=False),
            dict(name='Target Commandline', ordinal=12, value='synthetic-parent.exe', truncated=False)])
    event['defender_asr'] = interpretation(event)
    event['interpretation_ids'] = list(interpretations(event))
    browser = dict(id=B, target_path='C:\\synthetic\\archive.zip', timestamps=[{'utc':'2026-01-01T00:00:00Z'}, {'utc':'2026-01-01T00:00:01Z'}])
    state = State(Budget())
    state.disclose(dict(records=[event,browser],relationships=[],detections=[]))
    state.last_disclosed = {E:deepcopy(event),B:deepcopy(browser)}
    refs = [(B,'/target_path'),(B,'/timestamps/1/utc'),(B,'/timestamps/0/utc'),
        (E,'/timestamp_utc'),(E,'/source_context/hostname'),(E,'/event_id'),
        (E,'/original_event_data/5/value'),(E,'/original_event_data/6/value'),
        (E,'/defender_asr/action'),(E,'/defender_asr/limitation')]
    answer = dict(observed=[dict(evidence_id=e,field=f) for e,f in refs],
        interpretations=event['interpretation_ids'], relationships=[],detections=[],hypotheses=[],
        unknowns=['Execution and causation remain unresolved.'],answer_status='partial')
    return state,answer


def test_transcript_shaped_rejection_and_corrected_partial():
    state,answer=fixture_state()
    for index in (4,8,9):
        current=deepcopy(answer)
        current['observed']=[answer['observed'][index]]
        with pytest.raises(GroundingReferenceError) as error: state.render(current)
        d=error.value.reference_detail
        assert d['code']=='non_observation_field'
        assert d['visible_in_latest_prompt'] and d['visible_in_exposure_ledger']
        assert not d['observation_eligible'] and not d['field_disclosed']
    with pytest.raises(GroundingReferenceError) as error: state.render(answer)
    assert error.value.reference_detail['validation_path']=='answer.observed[4]'
    answer['observed']=[x for i,x in enumerate(answer['observed']) if i not in (4,8,9)]
    result=state.render(answer)
    assert len(result['observed'])==7 and len(result['interpretations'])==1
    assert [r['recorded_field']['ordinal'] for r in result['observed'] if 'recorded_field' in r]==[11,12]
    assert result['observed'][-1]['reported_value']=='synthetic-parent.exe'


@pytest.mark.parametrize('eid,pointer', [(E,'/original_event_data/11/value'),(E,'/original_event_data/0/value'),
    (E,'/original_event_data/Target Commandline/value'),(E,'/Original_Event_Data/5/value'),
    (B,'/url'),('E1','/event_id'),('EVTX:'+'c'*64+':Offset:9','/event_id')])
def test_no_aliases_hidden_fields_or_historical_ids(eid,pointer):
    state,answer=fixture_state()
    answer['observed']=[dict(evidence_id=eid,field=pointer)]
    with pytest.raises(GroundingReferenceError) as error: state.render(answer)
    assert not error.value.reference_detail['visible_in_exposure_ledger']
    assert not error.value.reference_detail['visible_in_latest_prompt']


def test_prior_disclosure_remains_eligible_but_metadata_is_not():
    state,answer=fixture_state()
    state.last_disclosed={}
    answer['observed']=[dict(evidence_id=E,field='/original_event_data/5/value')]
    assert state.render(answer)['observed'][0]['recorded_field']['ordinal']==11
    answer['observed'][0]['field']='/source_context/hostname'
    with pytest.raises(GroundingReferenceError) as error: state.render(answer)
    d=error.value.reference_detail
    assert d['visible_in_exposure_ledger'] and not d['visible_in_latest_prompt']
    state.exposed={}
    answer['interpretations']=[]
    with pytest.raises(GroundingReferenceError) as error: state.render(answer)
    assert error.value.reference_detail['code']=='unknown_evidence_id'


def test_schema_explains_observation_contract_without_expanding_eligibility():
    description=FINAL['properties']['observed']['items']['properties']['field']['description']
    for text in ('source_context','defender_asr','array position','ordinal','duplicate','E1/E2'):
        assert text in description
    state,_=fixture_state()
    assert '/source_context/hostname' not in dict(fields(state.exposed[E]))

import copy
import pytest
from forensic_assistant.investigation_ai.presentation import render, proposal_text, LABELS
from test_investigation_presentation import result

@pytest.mark.parametrize('count,phrase', [(1,'1 AI conclusion that was'),(2,'2 AI conclusions that were')])
def test_rejection_grammar_and_single_outcome(count,phrase):
    value=result();value['dry_run_proposal']=None;value['termination']='TOO_MANY_REJECTIONS'
    value['state']['final_grounding_rejections']=count
    value['limitations'] += ['No supported conclusion was produced.'] * 2
    original=copy.deepcopy(value);text=render(value)
    assert value==original
    assert phrase+' not supported by the evidence available to the model.' in text
    assert 'Unsupported AI conclusions are rejected' not in text and 'hallucination' not in text
    assert text.count('No supported conclusion was produced.')==1
    assert 'Rejection limit reached' in text

@pytest.mark.parametrize('code', list(LABELS))
def test_known_outcome_has_specific_label(code):
    value=result();value['dry_run_proposal']=None;value['termination']=code
    text=render(value)
    assert 'Investigation stopped' not in text and 'see diagnostic details' not in text


def test_integrity_uncertainty_is_one_warning_not_raw_error():
    value=result();value['dry_run_proposal']=None
    value['metrics']['integrity']['live_case_matches']=None
    value['limitations'] += ['Final state check failed: TOOL_TIMEOUT',
        'Live-case equality was not confirmed at completion; findings cover only the original private snapshot.']
    text=render(value)
    assert text.count('could not confirm')==1
    assert 'TOOL_TIMEOUT' not in text and 'Final state check failed' not in text
    assert text.count('No supported conclusion was produced.')==1


def test_context_only_not_material_and_dirty_hive_dedup():
    value=result();row=value['findings']['observed'][0]
    row.update(field='/hostname',reported_value='host',source_context={'hostname':'host','basis':'artifact-reported'})
    value['limitations'] += ['Registry hive was dirty; transaction logs were not replayed.',
       'Some evidence fields were truncated; omitted values are unavailable.']
    text=render(value)
    assert 'Source context relies' not in text
    assert text.count('Registry hive was dirty')==text.count('Some evidence fields were truncated.')==1
    assert 'More evidence is needed' not in proposal_text(value['dry_run_proposal'])

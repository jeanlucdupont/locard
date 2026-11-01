"""Controller recovery with synthetic reproduction; no live provider calls."""
import json
import pytest
from forensic_assistant import briefing_interview as m
from forensic_assistant.ai.provider_diagnostics import ProviderFailure
from test_briefing_interview import current,run,ask,finish,Fake
from test_briefing_information import session

FIRST='Callie Wade tried to print a PDF game worksheet, but it was blocked, so she logged out.'
DATE='It in the morning. September 30, 2026.'
HOST='It was Dell laptop. Hostname: BWP-8292456'
ALERT="We don't know. She just logged out when she saw the message. Defender said it blocked:\nC:\\ProgramData\\baje.ps1"


def test_partial_answer_retains_anchors_and_unknown_details():
    s=session(('incident','Tell me what happened?',FIRST),('time','When?',DATE),('systems','Which device?',HOST),('alerts','What did the message say?',ALERT))
    a=m.information(current(),s)
    assert a['topics']['alerts']['state']=='partially_supplied'
    assert 'alerts' in a['explicit_unknown_details']
    assert all(a['topics'][t]['state']=='supplied_hint' for t in ('time','systems','indicators'))
    assert a['initial_discovery_possible'] and a['briefing_can_be_saved']
    assert 'exact time or timezone' in a['timestamp_caution']
    assert a['semantic_assessment']=='not_performed_by_deterministic_readiness'
    assert m.fallback(current(),s)[0]=='discovery'
    assert 'alerts' in m.covered_topics(current(),s)


def test_reproduction_rejection_fallback_then_continuation(capsys):
    results=[ask('time','When did this happen?'),ask('systems','Which device was involved?'),
             ask('alerts','What did the message say?'),ask('time','When did this happen?'),
             ask('uncertainty','What remains unclear?'),finish()]
    result,fake,metrics=run([FIRST,DATE,HOST,ALERT,'Determine whether anything executed.','The execution outcome remains unclear.','done','save'],results)
    assert len(fake.calls)==6 and metrics['fallbacks']==1
    turns=result['interviews'][0]['turns']
    assert turns[3]['answer']==ALERT
    assert turns[4]['question_origin']=='locard' and turns[4]['topic']=='discovery'
    assert turns[5]['question_origin']=='ai'
    assert 'How was the suspicious material or activity first encountered?' in capsys.readouterr().out
    assert metrics['diagnostics'][0]['category']=='repeated_question'
    requests=[json.dumps(c[0],sort_keys=True) for c in fake.calls]
    assert len(requests)==len(set(requests))


@pytest.mark.parametrize('failure,code,recoverable',[
 ({'malformed':True},'structured_response_invalid',True),
 (ask('incident','Tell me what happened?'),'repeated_question',True),
 (ProviderFailure('timeout','timeout'),'provider_failure',False),
 (ProviderFailure('output_truncated','response_envelope'),'output_truncated',True)])
def test_failure_classification_and_bounded_recovery(failure,code,recoverable,capsys):
    result,fake,metrics=run(['Suspicious activity','done','save'],[failure])
    assert metrics['diagnostics'][0]['category']==code
    assert bool(metrics.get('fallbacks')) is recoverable
    assert len(fake.calls)==1 and result['interviews'][0]['turns'][0]['answer']=='Suspicious activity'


def test_safe_details_no_raw_error_or_narrative_in_diagnostic(capsys):
    f=Fake([RuntimeError('SECRET RESPONSE')]);answers=iter(['Private description','done','save']);metrics={}
    m.interview(current(),lambda p:next(answers),client_factory=lambda:f,metrics=metrics,details=True)
    output=capsys.readouterr().out
    assert 'Interview diagnostic: provider_failure' in output
    assert 'SECRET RESPONSE' not in output
    assert 'Private description' not in json.dumps(metrics['diagnostics'])


def test_fallback_excludes_skipped_and_unknown():
    s=session(('incident','What happened?','Suspicious activity'),('time','When?',''),('systems','Which device?',"I don't know."))
    assert m.fallback(current(),s)[0]=='indicators'


def test_no_requests_after_transport_failure():
    result,fake,metrics=run(['Reported activity','Additional information','done','save'],[ProviderFailure('network_error','provider_request')])
    assert len(fake.calls)==1 and len(result['interviews'][0]['turns'])==2

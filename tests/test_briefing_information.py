"""6.78 controller assertions, not claims about live model question quality."""
import json
import pytest
from forensic_assistant import briefing_interview as module
from test_briefing_interview import current,run,ask,finish,Fake


def session(*turns):
    return {'id':'a'*32,'created':'2026-10-31T00:00:00+00:00','purpose':'supplement','turns':[
        {'topic':topic,'answer':answer,'answer_status':'skipped' if answer=='' else 'answered',
         'question':question,'question_origin':'locard' if i==0 else 'ai','supersedes':None}
        for i,(topic,question,answer) in enumerate(turns)]}


def test_sparse_observed_off_topic_answer_and_finish_guard(capsys):
    first='Callie Wade tried to print a PDF game worksheet, but it was blocked, so she logged out.'
    second='She received a Microsoft Defender ASR message.'
    s=session(('incident','Tell me what happened?',first),('objective','What do you want to establish?',second))
    status=module.information(current(),s)
    assert status['topics']['objective']['state']=='asked_unresolved'
    assert status['topics']['alerts']['state']=='supplied_hint'
    assert {'time','systems','indicators'}<=set(status['search_anchor_gaps'])
    result,fake,metrics=run([first,second,'done','save'],[
        ask('objective','What do you want to establish?'),
        {'action':'finish','topic':'time','question':'Do you know when this happened?'}])
    assert 'Locard: Do you know when this happened?' in capsys.readouterr().out
    assert metrics['completion_guard']=='missing_search_anchors'
    assert len(fake.calls)==2
    assert result['interviews'][0]['turns'][1]['answer']==second


@pytest.mark.parametrize('text,topic',[
 ('2026-10-20','time'),('HOST-123','systems'),('invoice.pdf','indicators')])
def test_supplied_anchors(text,topic):
    info=module.information(current(),session(('incident','Tell me what happened?',text)))
    assert info['topics'][topic]['state']=='supplied_hint' and topic not in info['search_anchor_gaps']


@pytest.mark.parametrize('topic,text', [('time',"I don't know when."),('systems',"I don't know which computer it was."),('indicators',"I don't know the filename.")])
def test_explicit_unknown_not_negative(topic,text):
    s=session(('objective','What should be established?',text))
    info=module.information(current(),s)
    assert info['topics'][topic]['state']=='explicitly_unknown'
    assert info['topics']['objective']['state']=='asked_unresolved' if topic!='objective' else True
    assert topic in module.covered_topics(current(),s)


def test_skip_and_unrelated_answer():
    info=module.information(current(),session(('time','When?',''),('objective','What should be established?','The analyst is out of office.')))
    assert info['topics']['time']['state']=='deferred'
    assert info['topics']['objective']['state']=='asked_unresolved'


def test_multiple_details_can_finish_without_further_question(capsys):
    result,fake,metrics=run(['On 2026-10-20 HOST-123 opened invoice.pdf; determine its origin.','done','save'],[finish()])
    assert len(fake.calls)==1 and metrics['termination_reason']=='model_finish_after_gap_check'
    assert 'briefing can be saved' in capsys.readouterr().out


def test_alert_product_does_not_establish_blocked_activity():
    s=session(('incident','What happened?','Defender showed a message during printing.'))
    info=module.information(current(),s)
    assert info['topics']['alerts']['state']=='supplied_hint'
    assert 'alerts' not in module.covered_topics(current(),s)
    assert 'blocked printing' not in json.dumps(info)


def test_correction_removes_old_hint_from_assessment():
    s=session(('incident','What happened?','2026-10-20'),('time','Correction','I do not know the date.'))
    s['turns'][1]['supersedes']=1
    info=module.information(current(),s)
    assert info['topics']['time']['state']=='explicitly_unknown'


def test_repeated_equivalent_question_rejected():
    s=session(('incident','Tell me what happened?','Something happened.'),('objective','What should be established?','Something unrelated.'))
    fake=Fake([ask('objective','What should be established?')]);metrics={'calls':0,'model_seconds':0,'request_bytes':[]}
    with pytest.raises(ValueError,match='repeated'):module.decision(fake,current(),s,metrics)


def test_invalid_finish_never_claims_ready(capsys):
    result,_,metrics=run(['Something happened.','done','save'],[finish()])
    output=capsys.readouterr().out
    assert 'Useful search details remain unresolved' in output
    assert metrics['termination_reason']=='response_or_budget_rejected'
    assert 'enough reported context for an initial assessment' not in output

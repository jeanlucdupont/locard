import json
import sqlite3
import pytest
from forensic_assistant.reporting.bundle import generate,inspect,validate
from test_v4_worker import make_case

class Model:
    timeout=45
    def __init__(self,action): self.action=action;self.calls=0
    def complete(self,messages,schema):
        self.calls+=1
        return self.action(messages)

def test_optional_ordering_never_rewrites_facts(tmp_path):
    case=tmp_path/'case.db';event=make_case(case)
    def order(messages):
        packet=json.loads(messages[1]['content'])
        return json.dumps({'claim_order':[c['claim_id'] for c in reversed(packet['claims'])]})
    client=Model(order)
    generate(case,tmp_path/'report',evidence_ids=[event['id']],narrative_client=client)
    report,_=inspect(tmp_path/'report')
    assert client.calls==1 and report['narrative']['status']=='ACCEPTED'
    assert report['narrative']['prompt_bytes']<=5600
    assert validate(tmp_path/'report',case=case)['evidence_grounding']=='PASS'

@pytest.mark.parametrize('response',[
    '{"claim_order":["invented"]}',
    '{"claim_order":[],"conclusion":"Definitely compromised"}',
    '{"claim_order":[],"claim_order":[]}',
    'not JSON'])
def test_invalid_narrative_falls_back(tmp_path,response):
    case=tmp_path/'case.db';event=make_case(case)
    generate(case,tmp_path/'report',evidence_ids=[event['id']],narrative_client=Model(lambda _:response))
    report,_=inspect(tmp_path/'report')
    assert report['narrative']['status']=='FALLBACK'
    assert report['data']['status']=='COMPLETE_WITH_LIMITATIONS'
    assert 'Definitely compromised' not in (tmp_path/'report'/'report.html').read_text()
    assert validate(tmp_path/'report',case=case)['evidence_grounding']=='PASS'

def test_case_change_during_model_wait_prevents_publication(tmp_path):
    case=tmp_path/'case.db';event=make_case(case)
    def change(_):
        db=sqlite3.connect(case);db.execute("UPDATE events SET command_line='concurrent change'");db.commit();db.close()
        return '{"claim_order":[]}'
    with pytest.raises(ValueError,match='STATE_CHANGED'):
        generate(case,tmp_path/'report',evidence_ids=[event['id']],narrative_client=Model(change))
    assert not (tmp_path/'report').exists()

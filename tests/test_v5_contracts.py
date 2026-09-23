import json
import pytest
from forensic_assistant.reporting.model import CATEGORIES, claim, graph, loads, Limits
from forensic_assistant.reporting.transcripts import load
from forensic_assistant.investigation_ai.controller import run
from test_v4_worker import make_case, config
from test_v4_controller import Scripted, final

def test_categories_graph_and_strict_json():
    assert len(CATEGORIES)==8
    for category in CATEGORIES:
        c=claim(category,{'field':'/process_name','value':'synthetic.exe'},['synthetic'])
        assert graph([c],['synthetic'])['evidence_to_claims']['synthetic']==[c['claim_id']]
        with pytest.raises(ValueError): graph([c],[])
    for raw in ('{"x":1,"x":2}','{"x":NaN}','{"x":1e999}', '['*40+'0'+']'*40):
        with pytest.raises(ValueError): loads(raw)
    with pytest.raises(ValueError): Limits(claims=True)

def test_adapter_checks_final_not_just_hash_chain(tmp_path):
    case=tmp_path/'case.db';make_case(case)
    result=run(config(case),'PowerShell',tmp_path/'runs',client=Scripted([final]))
    adapter=load(tmp_path/'runs',result['investigation_id'])
    assert adapter['findings']['observed'][0]['reported_value']=='powershell.exe'
    directory=tmp_path/'runs'/result['investigation_id']
    events=[json.loads(line) for line in (directory/'events.jsonl').read_text().splitlines()]
    events[-1]['data']['findings']['observed'][0]['reported_value']='fabricated.exe'
    from forensic_assistant.investigation_ai.transcript import digest
    chain='0'*64
    for event in events:
        event['previous']=chain;event.pop('hash');event['hash']=digest(event);chain=event['hash']
    (directory/'events.jsonl').write_text('\n'.join(json.dumps(e) for e in events)+'\n')
    manifest=json.loads((directory/'manifest.json').read_text());manifest['chain']=chain
    (directory/'manifest.json').write_text(json.dumps(manifest))
    with pytest.raises(ValueError,match='Terminal findings'):load(tmp_path/'runs',result['investigation_id'])

import json
import pytest
from forensic_assistant.database.db import connect
from forensic_assistant.artifacts.ingest import ingest_artifact
from forensic_assistant.correlation.investigation import investigate
from forensic_assistant.llm.context import context_bundle,annotate_relationship_support
from forensic_assistant.llm.prompts import SYSTEM_PROMPT,PROMPT_BYTES,messages,validate_answer
from forensic_assistant.llm.ask import ask
from forensic_assistant.retrieval.queries import Queries
from v2_fixtures import prefetch_file,registry_file,mft_file,evtx_process


def test_heterogeneous_bundle_budget_and_omission_reporting(tmp_path):
    db=connect(':memory:');event=evtx_process(db)
    for kind,maker in [('prefetch',prefetch_file),('registry',registry_file),('mft',mft_file)]:
        ingest_artifact(db,maker(tmp_path/kind),kind,hostname='host',volume_root='C:')
    context=investigate(db,event['id']);bundle=context_bundle(context,'Explain these observations')
    assert bundle['EVIDENCE'][0]['id']==event['id']
    assert len(SYSTEM_PROMPT.encode())+len(messages(bundle)[1]['content'].encode())<=PROMPT_BYTES
    for kind,counts in bundle['metadata']['artifact_distribution'].items():
        assert counts['candidate']==counts['selected']+counts['omitted']
        if counts['candidate'] and not counts['selected']:assert kind in bundle['metadata']['omitted_artifact_classes']
    supplied={e['id'] for e in bundle['EVIDENCE']}
    for r in bundle['CORRELATED_EVIDENCE']+bundle['DETECTIONS']:assert set(r['evidence_ids'])<=supplied


def test_registry_anchor_keeps_key_proof_and_semantics(tmp_path):
    db=connect(':memory:');ingest_artifact(db,registry_file(tmp_path/'hive'),'registry')
    eid=db.execute("SELECT evidence_id FROM registry_values WHERE value_name='Example'").fetchone()[0]
    bundle=context_bundle(investigate(db,eid),'Inspect this value')
    record=next(r for r in bundle['EVIDENCE'] if r['id']==eid)
    assert record['key_evidence_id'] in {r['id'] for r in bundle['EVIDENCE']}
    assert record['timestamps'][0]['type']=='Registry Key LastWrite'
    assert 'not individual value creation' in record['timestamps'][0]['meaning']
    output=ask(Queries(db),'Investigate '+eid,dry_run=True)
    assert output['status']=='retrieved_only'


def test_all_namespace_citations_and_uncertainty():
    eid='PREFETCH:'+'a'*64+':File'
    answer={'findings':[dict(finding='PREFETCH:invented',evidence_ids=[eid],interpretation='Possibly relevant',confidence='low',alternative_explanations=[],next_evidence=[])],'missing_evidence':[]}
    with pytest.raises(ValueError,match='unknown evidence'):validate_answer(json.dumps(answer),{eid})
    claim={'statement':'same file','classification':'CORRELATED','evidence_ids':['a','b']}
    annotate_relationship_support(claim,{'CORRELATED_EVIDENCE':[dict(relationship_id='r',status='POSSIBLE',evidence_ids=['a','b'])]})
    assert claim['correlation_status']=='POSSIBLE' and claim['statement'].startswith('POSSIBLE')


def test_mft_bundle_keeps_si_fn_semantics(tmp_path):
    db=connect(':memory:');ingest_artifact(db,mft_file(tmp_path/'mft'),'mft')
    eid=db.execute('SELECT evidence_id FROM mft_records WHERE record_number=6').fetchone()[0]
    output=ask(Queries(db),'Inspect '+eid,dry_run=True)
    record=output['evidence_bundle']['EVIDENCE'][0]
    assert {t['type'] for t in record['timestamps']}=={'MFT SI Created','MFT FN Created'}
    assert record['truncated_fields']

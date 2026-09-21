from v1_fixtures import database,process
from forensic_assistant.correlation.investigation import investigate
from forensic_assistant.llm.context import context_bundle


def test_semantic_reasons_preserve_anchor_and_relationship_payloads():
    db=database()
    parent=process(db,1,'10',name='WINWORD.EXE')
    child=process(db,2,'20','10',time='14:30:10')
    context=investigate(db,child['id'])
    assert context['correlated_evidence']
    context['semantic_retrieval']=True
    context['selection_reasons']={e['id']:['semantic_similarity'] for e in context['evidence_records']}
    bundle=context_bundle(context,'Inspect the reported parent relationship',budget=20000)
    assert bundle['DIRECT_EVIDENCE']==[child['id']]
    assert bundle['CORRELATED_EVIDENCE']
    for relation in bundle['CORRELATED_EVIDENCE']:
        assert {'relationship','status','evidence_ids','relationship_id'}<=relation.keys()
        assert any(relation['relationship']==original['relationship'] and
                   relation['status']==original['status'] and
                   relation['evidence_ids']==original['evidence_ids'] for original in context['correlated_evidence'])
    assert all('selection_reasons' in e for e in bundle['EVIDENCE'])
    assert {parent['id'],child['id']}<={e['id'] for e in bundle['EVIDENCE']}

"""Explicit optional-dependency integration; only generated synthetic data."""
import argparse
import json
from pathlib import Path
import time
from forensic_assistant.database.db import connect
from forensic_assistant.semantic.model import LocalModel
from forensic_assistant.semantic.index import build
from forensic_assistant.semantic.hybrid import retrieve
from forensic_assistant.retrieval.queries import Queries
from forensic_assistant.investigation_ai.controller import run
from forensic_assistant.investigation_ai.runner import ForensicWorker
from forensic_assistant.investigation_ai.replay import replay
from test_v4_evaluation import scenario, observed
from test_v4_controller import Scripted, tool
from forensic_assistant.detections.engine import available_rules

def validate(root, model_path):
    root=Path(root);model_path=str(Path(model_path).resolve());model=LocalModel(model_path)
    results=[]
    for number in range(1,6):
        directory=root/str(number)
        path,question,actions,relevant,_,_=scenario(directory,number)
        db=connect(path);index=directory/'synthetic.semantic-index'
        build(db,index,model)
        _,context=retrieve(Queries(db),question,index_root=index,model=model,limit=20)
        baseline={e['id'] for e in context['evidence_records']};db.close()
        config={'case_path':str(path),'semantic_enabled':True,'index_root':str(index),'model_path':model_path}
        # The control-policy exercise requests one semantic operation, then stops.
        # Five scripted path evaluations are measured separately without embeddings.
        result=run(config,question,directory/'runs',client=Scripted([tool('semantic_search',{'query':'PowerShell persistence behavior','limit':3}),observed]))
        assert result['state']['semantic_searches']==2, result
        assert result['termination']=='ANSWER_SUPPORTED', result
        assert max(result['metrics']['prompt_bytes'])<=5600
        repeated=replay(config,directory/'runs',result['investigation_id'])
        assert repeated['termination']=='REPLAY_MATCH', repeated
        found=set(result['state']['retrieved_ids'])
        results.append({'case':number,'v3_hybrid_relevant':len(baseline & relevant),
            'v3_hybrid_unnecessary':len(baseline-relevant),'v4_relevant':len(found & relevant),
            'v4_unnecessary':len(found-relevant),'termination':result['termination'],
            'metrics':result['metrics'],'transcript_bytes':result['transcript_bytes'],
            'replay':repeated['termination']})
    return {'method':'Real local BGE/FAISS; scripted model; not forensic accuracy','cases':results}

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('output');parser.add_argument('--model-path',required=True)
    args=parser.parse_args();print(json.dumps(validate(args.output,args.model_path),indent=2))

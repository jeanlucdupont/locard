"""Matched mock investigations and a bounded large reference stream; no live I/O."""
import ctypes
import json
import os
import time

import pytest

from forensic_assistant.investigation_ai import explanation_live as x
from forensic_assistant.investigation_ai.transcript import load,digest
from test_explanation_live import synthetic
from test_synthesis_consumer import setup,reply


def peak_process_bytes():
    if os.name!='nt':return None
    from ctypes import wintypes
    class Counters(ctypes.Structure):
        _fields_=[('cb',wintypes.DWORD),('PageFaultCount',wintypes.DWORD)]+[
            (name,ctypes.c_size_t) for name in ('PeakWorkingSetSize','WorkingSetSize','QuotaPeakPagedPoolUsage',
            'QuotaPagedPoolUsage','QuotaPeakNonPagedPoolUsage','QuotaNonPagedPoolUsage','PagefileUsage','PeakPagefileUsage')]
    counters=Counters();counters.cb=ctypes.sizeof(counters)
    current=ctypes.windll.kernel32.GetCurrentProcess;current.restype=wintypes.HANDLE
    query=ctypes.windll.psapi.GetProcessMemoryInfo
    query.argtypes=[wintypes.HANDLE,ctypes.POINTER(Counters),wintypes.DWORD]
    if not query(current(),ctypes.byref(counters),counters.cb):raise ctypes.WinError()
    return counters.PeakWorkingSetSize


def measured(path,enabled,large):
    path.mkdir()
    config,worker,client,seen,closed=setup(path)
    original_worker=worker
    class MultiSourceWorker(original_worker):
        def call(self,*args,**kw):
            response=super().call(*args,**kw)
            for record in response['result']['records']:
                record['source_context']={'source_ids':['admin-browser' if record['source_type']=='browser' else 'admin-host'],
                                         'basis':'synthetic analyst assertion'}
            return response
    worker=MultiSourceWorker
    config['_stage_a']['source_ids']=['admin-browser','admin-host']
    config['_live_explanation']=enabled
    if large:
        actions=list(client.actions);base=actions[1];number=0
        def crowded(messages):
            nonlocal number
            number+=1;value=base(messages)
            eid=value['answer']['observed'][0]['evidence_id']
            value['answer']['hypotheses']=[dict(statement=f'Possibility {number}-{n}: administrative maintenance may explain this record.',
                evidence_ids=[eid],alternatives=['An unapproved installation is also possible.']) for n in range(3)]
            value['answer']['unknowns']=[f'Was maintenance item {number}-{n} approved?' for n in range(3)]
            return value
        client.actions=iter([actions[0]]+[crowded]*6+[reply,reply])
    started=time.perf_counter()
    from forensic_assistant.investigation_ai import autonomous
    result=autonomous.run(config,config['_stage_a']['objective'],path/'runs',client=client,worker_factory=worker)
    elapsed=time.perf_counter()-started
    _,events=load(path/'runs',result['investigation_id'])
    assert result['validated_batches']==6 and len(client.calls)==9 and closed
    assert len([s for s in seen if s[0]=='show_evidence'])==6 and result['state']['steps']==10
    local=result.get('explanation',{})
    out=dict(enabled=enabled,large=large,wall_seconds=elapsed,
        accepted_frontiers=sum(e['kind']=='validated_delta' or e['kind']=='synthesis_decision' and e['data']['status']=='accepted' for e in events),
        c1_checkpoints=sum(e['kind']=='organization_checkpoint' for e in events),
        c1_seconds=result['organization']['elapsed_seconds'],
        d1b_checkpoints=sum(e['kind']=='explanation_checkpoint' for e in events),
        d1b=local,peak_process_bytes=peak_process_bytes())
    if enabled:
        rebuilt=x.reconstruct(path/'runs',result['investigation_id'])
        out['operations']=rebuilt['state']['operations'];out['pending']=len(rebuilt['state']['pending'])
        out['omitted']=len(rebuilt['state']['omitted'])
        assert local['elapsed_seconds']<=1 and local['metrics']['peak_owned_heap']<=4194304
        assert local['journal_bytes']<=65536 and local['charged_visits']<=2048
    return out


@pytest.mark.parametrize('large',[False,True])
def test_matched_mock_measurements(tmp_path,large):
    reports=[measured(tmp_path/str(enabled),enabled,large) for enabled in (False,True)]
    print('D1B_MEASUREMENT '+json.dumps(reports,sort_keys=True))


def test_large_reference_measurement():
    session,org,facts,receipt=synthetic()
    for n in range(230):
        key=digest(['question',n]);org.entities[key]=dict(id=key,kind='question',role='analysis_proposal',
            text='Unverified question '+str(n),introduced_by={'contract':'synthetic'},dependencies=[])
    src=x.Sources(session.manifest,org,facts);reducer=x.Reducer(session.binding['run_id'],session.binding['read_view'])
    started=time.perf_counter();prepared,reason=reducer.prepare(receipt(),src);elapsed=time.perf_counter()-started
    state,cp=prepared
    assert len(state['pending'])<=192 and len(cp['operations'])<=32 and state['omitted']
    assert reducer.peak_owned<=4194304 and x.d1._size(state)<=131072
    print('D1B_REFERENCE_MEASUREMENT '+json.dumps(dict(entities=len(org.entities),elapsed_seconds=elapsed,
        timings=reducer.timings,heap=reducer.peak_owned,operations=cp['applied'],pending=len(state['pending']),
        omitted=len(state['omitted']),stop=reason),sort_keys=True))

import http.server
import json
import threading
import time
import pytest
from forensic_assistant.llm.client import LocalClient, LLMError
from forensic_assistant.investigation_ai.state import State, Budget
from forensic_assistant.investigation_ai.contracts import request, TOOLS
from forensic_assistant.investigation_ai.controller import run
from test_v4_controller import Scripted, tool
from test_v4_worker import make_case, config

def test_slow_http_body_has_wall_clock_deadline():
    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self,*args):pass
        def do_POST(self):
            self.rfile.read(int(self.headers['Content-Length']))
            self.send_response(200);self.send_header('Content-Length','10000');self.end_headers()
            try:
                for _ in range(50):self.wfile.write(b' ');self.wfile.flush();time.sleep(.04)
            except (OSError,ValueError):pass
    server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler)
    thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    try:
        client=LocalClient('http://127.0.0.1:'+str(server.server_port),timeout=.2)
        started=time.monotonic()
        with pytest.raises(LLMError):client.complete([{'role':'user','content':'synthetic'}])
        assert time.monotonic()-started<1.2
    finally:server.shutdown();server.server_close();thread.join(timeout=2)

def test_model_cannot_fabricate_or_upgrade_engine_objects():
    state=State(Budget());eid='EVTX:'+'a'*64+':Offset:1'
    state.records[eid]={'id':eid,'kind':'process','process_name':'synthetic.exe'}
    state.relationships['REL:one']={'relationship_id':'REL:one','relationship':'parent_process',
        'status':'LIKELY','evidence_ids':[eid],'reason':'Reported fields','limitations':['PID reuse may be hidden']}
    _,data,_=state.prompt('Inspect',[],[]);state.disclose(data)
    answer=dict(observed=[],relationships=['REL:one'],detections=[],hypotheses=[],unknowns=[])
    rendered=state.render(answer)['deterministically_correlated'][0]
    assert rendered['status']=='LIKELY' and rendered['limitations']==['PID reuse may be hidden']
    answer['relationships']=['REL:invented']
    with pytest.raises(ValueError,match='not exposed'):state.render(answer)
    answer['relationships']=[];answer['detections']=['DET:invented']
    with pytest.raises(ValueError,match='not exposed'):state.render(answer)
    answer['detections']=[];answer['observed']=[dict(evidence_id=eid,field='/process_name',status='CONFIRMED')]
    with pytest.raises(ValueError,match='unknown'):state.render(answer)

def test_semantic_retrieval_marker_is_not_an_observed_machine_field():
    state=State(Budget());eid='EVTX:'+'a'*64+':Offset:1'
    state.records[eid]={'id':eid,'process_name':'synthetic.exe','retrieval_basis':'SEMANTICALLY_RETRIEVED'}
    _,data,_=state.prompt('Inspect',[],[]);state.disclose(data)
    assert data['records'][0]['retrieval_basis']=='SEMANTICALLY_RETRIEVED'
    with pytest.raises(ValueError,match='unexposed'):
        state.render(dict(observed=[dict(evidence_id=eid,field='/retrieval_basis')],relationships=[],detections=[],hypotheses=[],unknowns=[]))

def test_model_sees_action_format_inputs_and_completed_tools_inside_budget():
    state=State(Budget());eid='EVTX:'+'a'*64+':Offset:1'
    state.records[eid]={'id':eid,'process_name':'synthetic.exe','kind':'process'}
    state.path=[{'operation':'initial','new_records':1},{'operation':'process_tree','new_records':0}]
    messages,_,size=state.prompt('Inspect process relationships',['process_tree','show_evidence'],[])
    controller=json.loads(messages[1]['content'])['controller']
    assert '"action":"tool"' in messages[0]['content'] and '"action":"final"' in messages[0]['content']
    assert 'evidence_id*' in controller['tool_inputs']['process_tree']
    assert controller['completed_tools']==['process_tree'] and size<=5600

def test_dry_run_rejects_first_invalid_proposal_without_retry(tmp_path):
    path=tmp_path/'case.db';make_case(path)
    client=Scripted([tool('shell',{'command':'forbidden'})])
    result=run(config(path),'PowerShell',tmp_path/'runs',client=client,dry_run=True)
    assert len(client.calls)==1 and result['state']['rejected_requests']==1
    assert result['state']['accepted_calls']==0

@pytest.mark.parametrize('text',[
    '{"action":"tool",', 'plain prose',
    json.dumps({'action':'final','answer':{'observed':[], 'relationships':['REL:one','REL:one'],
        'detections':[],'hypotheses':[],'unknowns':[]}}),
])
def test_malformed_and_duplicate_final_references_rejected(text):
    with pytest.raises(ValueError):request(text,TOOLS)

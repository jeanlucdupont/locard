"""D2 terminal IPC regression; synthetic providers, no network or case access."""
import copy
import hashlib
import json
import multiprocessing
import os
import threading
import time
from pathlib import Path
from unittest.mock import patch

import pytest
from forensic_assistant.investigation_ai import d2, d2_execution as ex, d2_result as ipc
from forensic_assistant.ai import settings
from test_d2_execution import prepared, response, config, _successful_child


def terminal(p):
    return ipc.envelope(ipc.binding(p),response=json.dumps(response(p.packet)),attempted=True,received=True)


@pytest.mark.parametrize('key',['request_id','packet_digest','request_sha256','source','issue','provider','model'])
def test_forged_binding(key):
    p=prepared();v=terminal(p);v['binding'][key]='forged'
    with pytest.raises(ValueError):ipc.parse(ipc.encode(v),ipc.binding(p))


@pytest.mark.parametrize('change',['extra','s3','bad_json','duplicate','unknown_alias','execution','causal','schema','oversized'])
def test_invalid_result_or_response(change):
    p=prepared();v=terminal(p)
    if change=='extra':v['extra']='forged'
    elif change=='s3':v['original_s3_assessment']={'status':'SUPPORTED'}
    elif change=='bad_json':v['response']='not JSON'
    elif change=='duplicate':v['response']='{"s":"x","s":"y"}'
    elif change=='oversized':v['response']='x'*16385
    else:
        r=json.loads(v['response'])
        if change=='unknown_alias':r['e']=['O999']
        elif change=='execution':r['verified_execution']=True
        elif change=='causal':r['relationship']={'predicate':'caused_execution'}
        else:r['s']=[]
        v['response']=json.dumps(r)
    with pytest.raises(ValueError):
        parsed=ipc.parse(ipc.encode(v),ipc.binding(p))
        d2.validate_response(p.packet,ex.wire.expand_response(parsed['response'],p.packet),p._response_context)


class Pipe:
    def __init__(self,broken=False):self.values=[];self.broken=broken;self.calls=0
    def send_bytes(self,b):
        self.calls+=1
        if self.broken:raise BrokenPipeError('SENSITIVE')
        self.values.append(b)


@pytest.mark.parametrize('bad',['oversize','serialization','unicode'])
def test_small_failure_envelope(bad):
    p=prepared();v=terminal(p)
    v['response']='x'*40000 if bad=='oversize' else object() if bad=='serialization' else '\ud800'
    pipe=Pipe();assert ipc.send(pipe,v)
    assert pipe.calls==1 and len(pipe.values[0])+8<=ipc.LIMIT
    failure=ipc.parse(pipe.values[0],ipc.binding(p))
    assert failure['status']=='rejected' and failure['response'] is None
    assert failure['category']==('result_byte_limit' if bad=='oversize' else 'result_serialization_failure')


def test_broken_pipe_single_send():
    p=prepared();pipe=Pipe(True)
    assert not ipc.send(pipe,terminal(p)) and pipe.calls==1


def test_utf8_usage_and_no_io_parent_validation(monkeypatch):
    p=prepared();v=terminal(p);r=json.loads(v['response']);r['s']='界'*100;v['response']=json.dumps(r,ensure_ascii=False)
    raw=ipc.encode(v);assert len(raw)>len(raw.decode())
    parsed=ipc.parse(raw,ipc.binding(p));assert parsed['usage']=={}
    monkeypatch.setattr(p.history,'preview',lambda **kw:pytest.fail('replay'))
    monkeypatch.setattr('sqlite3.connect',lambda *a,**k:pytest.fail('case'))
    result=d2.validate_response(p.packet,ex.wire.expand_response(parsed['response'],p.packet),p._response_context)
    assert result['original_s3_assessment']==p.history._original
    assert all(x['classification']=='mechanically_accepted_unverified' for x in result['proposals'])


def test_deadline_during_parent_validation():
    p=prepared()
    def expired():raise TimeoutError()
    with pytest.raises(TimeoutError):d2.validate_response(p.packet,ex.wire.expand_response(json.dumps(response(p.packet)),p.packet),p._response_context,expired)


def _crash(c,g,r):os._exit(7)
def _empty(c,g,r):g.wait();c.close()
def _oversize(c,g,r):
    g.wait()
    try:c.send_bytes(b'x'*(ipc.RECEIVE_LIMIT+1))
    except OSError:pass
    c.close()
def _bad(c,g,r):g.wait();c.send_bytes(b'not JSON');c.close()
def _hang(c,g,r):g.wait();time.sleep(120)


@pytest.mark.parametrize('target,reasons',[(_crash,{'worker_terminated_unexpectedly','ipc_channel_closed'}),(_empty,{'ipc_channel_closed'}),(_oversize,{'ipc_receive_failure'}),(_bad,{'ipc_invalid_message'})])
def test_spawn_channel_failures(monkeypatch,target,reasons):
    p=prepared();permit=ex.authorize(p,lambda _:True);p.history._root=Path('unused')
    monkeypatch.setattr(ex,'_child',target)
    result=ex.execute(permit)
    assert result['reason'] in reasons and result['cleanup']=='confirmed' and result['status']!='accepted'
    assert not multiprocessing.active_children()


def test_cancel_after_spawn(monkeypatch):
    p=prepared();permit=ex.authorize(p,lambda _:True);p.history._root=Path('unused')
    monkeypatch.setattr(ex,'_child',_hang)
    cancelled=threading.Event();timer=threading.Timer(.6,cancelled.set);timer.start()
    try:result=ex.execute(permit,cancelled=cancelled)
    finally:timer.join()
    assert result['reason']=='cancelled' and result['cleanup']=='confirmed'
    assert not multiprocessing.active_children()


def _historical_success(connection,gate,request):
    original=ex._child
    def complete(client,messages,sha):
        view=json.loads(messages[1]['content'])
        value=dict(s='Recorded observations may be related.',e=[s[0] for s in view['supports']],i=[],c=[],
                   a=['The observations may be unrelated.'],u=[],g=['Coverage is limited.'],
                   l=['Causality is unresolved.'],n='Seek separately authorized corroboration.')
        return dict(text=json.dumps(value),usage={})
    with patch.object(settings,'load',config),patch('forensic_assistant.ai.backend.ModelBackend.complete_d2',complete),patch('socket.socket.connect',side_effect=AssertionError('network')),patch('sqlite3.connect',side_effect=AssertionError('case')):
        original(connection,gate,request)


def test_exact_historical_overflow_fixed(monkeypatch):
    root=Path(r'C:\tmp\locard-diagnostics\6.118-live');rid='6ad0c85499564406aa4d949f3b0e72e5'
    if not (root/rid/'manifest.json').exists():pytest.skip('readable historical diagnostic fixture not installed')
    issue='d81869143ab5f3a355285bd79802d93912491834bc4f602c0a5fda6fd28739e7'
    files=[root/rid/n for n in ('manifest.json','events.jsonl')]
    hashes=lambda:[hashlib.sha256(f.read_bytes()).hexdigest() for f in files]
    before=hashes()
    monkeypatch.setattr('sqlite3.connect',lambda *a,**k:pytest.fail('case'))
    monkeypatch.setattr('socket.socket.connect',lambda *a,**k:pytest.fail('network'))
    p=ex.prepare(root,rid,issue,config(),exploratory=True,profile='d2c1')
    v=dict(s='Recorded observations may be related.',e=[s['alias'] for s in p.packet['content']['supports']],i=[],c=[],a=['The observations may be unrelated.'],u=[],g=['Coverage is limited.'],l=['Causality is unresolved.'],n='Seek separately authorized corroboration.')
    validated=p.history.validate(p.packet,ex.wire.expand_response(json.dumps(v),p.packet),**p.options)
    legacy=json.dumps(dict(status='accepted',validated=validated,usage={},attempted=True)).encode()
    assert len(legacy)==191464 and len(legacy)>ipc.RECEIVE_LIMIT
    assert len(json.dumps(validated['original_s3_assessment']).encode())==172460
    permit=ex.authorize(p,lambda _:True)
    monkeypatch.setattr(ex,'_child',_historical_success)
    result=ex.execute(permit)
    assert result['status']=='accepted' and result['attempts']==1 and result['lookups']==0 and result['cleanup']=='confirmed'
    assert result['validated']==validated
    assert result['validated']['original_s3_assessment']['status']=='NOT_ASSESSABLE'
    assert result['ipc_result_bytes']+8<=ipc.LIMIT
    from forensic_assistant.investigation_ai.d2_reasoning import render
    text=render(result,p)
    assert 'Established by the evidence' in text and 'AI explanation — unverified' in text
    assert before==hashes()
    print('RESULT_BYTES',result['ipc_result_bytes'],'LEGACY_BYTES',len(legacy))

def _direct_success(connection,gate,request):
    original=ex._child
    p=prepared()
    def complete(*args):return dict(text=json.dumps(response(p.packet)),usage={})
    with patch.object(settings,'load',config),patch.object(ex,'prepare',lambda *a,**k:p),patch('forensic_assistant.ai.backend.ModelBackend.complete_d2',complete):
        original(connection,gate,request)


@pytest.mark.parametrize('closed',[False,True])
def test_spawn_normal_exit_or_single_send_failure(closed):
    p=prepared();ctx=multiprocessing.get_context('spawn');parent,child=ctx.Pipe(duplex=False);gate=ctx.Event()
    request=dict(root='unused',run_id='b'*32,issue='c'*64,config=config(),exploratory=True,seal=p.identity(),deadline=time.monotonic()+10,binding=ipc.binding(p))
    process=ctx.Process(target=_direct_success,args=(child,gate,request));process.start();child.close()
    try:
        if closed:parent.close()
        gate.set()
        if not closed:
            assert parent.poll(8)
            assert parent.recv_bytes(ipc.RECEIVE_LIMIT)==b'{"phase":"attempt"}'
            assert parent.poll(8)
            assert ipc.parse(parent.recv_bytes(ipc.RECEIVE_LIMIT),ipc.binding(p))['status']=='accepted'
        process.join(3)
        assert not process.is_alive() and process.exitcode==(74 if closed else 0)
    finally:
        if process.is_alive():process.kill();process.join(2)
        parent.close()


def test_receive_envelope_limit_and_escaped_utf8():
    p=prepared();v=terminal(p)
    # Escaping expansion is measured on the complete JSON message, not character count.
    v['response']='\x00'*6000
    pipe=Pipe();assert ipc.send(pipe,v)
    assert ipc.parse(pipe.values[0],ipc.binding(p))['category']=='result_byte_limit'
    with pytest.raises(ValueError):ipc.parse(b' '*ipc.LIMIT,ipc.binding(p))


def test_usage_cannot_carry_payload():
    p=prepared();v=terminal(p);v['usage']={'secret':'forged'}
    with pytest.raises(ValueError):ipc.parse(ipc.encode(v),ipc.binding(p))

"""Synthetic provider-free memory acceptance, or read-only journal reconstruction."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import time
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))


def reply(text='',name=None,args=None):
    return dict(text=text,tool_calls=[dict(id='call-'+name,name=name,arguments=args)] if name else [],finish_reason='tool_calls' if name else 'stop',usage={'total_tokens':30},cost=None)


def last(messages):return json.loads(next(m['content'] for m in reversed(messages) if m['role']=='tool'))


def synthetic_case(directory):
    from forensic_assistant.database.db import connect,register_source,insert_events
    from forensic_assistant.database import sources
    from forensic_assistant.ingest.normalize import normalize,SECURITY
    root=Path(directory);root.mkdir(parents=True,exist_ok=True)
    os.environ['LOCALAPPDATA']=str(root)
    path=root/'case.db';db=connect(path);sid=sources.create(db,hostname='synthetic-workstation')
    register_source(db,'a'*64,100,'synthetic.evtx');sources.assign(db,sid,['a'*64],reason='Synthetic diagnostic')
    for i in range(8):
        xml=f'<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="{SECURITY}"/><EventID>4688</EventID><Channel>Security</Channel><TimeCreated SystemTime="2020-01-01T12:00:00Z"/></System><EventData><Data Name="NewProcessName">reviewer.exe</Data><Data Name="CommandLine">reviewer.exe document{i}.txt</Data></EventData></Event>'
        insert_events(db,[normalize(xml,'a'*64,'synthetic.evtx',i)])
    db.commit();db.close();before=hashlib.sha256(path.read_bytes()).hexdigest()
    return path,sid,before


def diagnostic(directory,capacity=32000,checkpoint_seconds=.01,provider_factory=None):
    from forensic_assistant.conversational_ai.contracts import authorize,FAMILIES
    from forensic_assistant.conversational_ai.provider import ScriptedProvider
    from forensic_assistant.conversational_ai.service import Session,notebook,encoded
    from forensic_assistant.conversational_ai.workspace import reconstruct
    root=Path(directory);path,sid,before=synthetic_case(root)
    seen={};checks={}
    def inspect(messages):
        row=last(messages)['records'][0];seen['eid']=row['evidence_id']
        return reply(name='show_evidence',args=dict(evidence_id=seen['eid'],limit=40))
    def verify(messages):
        f=next(f for f in last(messages)['fields'] if f['field']=='/command_line')
        seen['value']=f['value'];return reply(name='verify_observation',args=dict(evidence_id=seen['eid'],field=f['field'],value_json=json.dumps(f['value'])))
    def hypothesis(messages):
        assert last(messages)['verified'];return reply(name='note',args=dict(kind='hypothesis',text='Recorded activity may be ordinary document review; causality is unestablished.',status='active',evidence_ids=[seen['eid']],alternatives=['Unrelated maintenance remains possible.']))
    steps=[reply(name='search_evidence',args=dict(artifact='evtx',limit=1)),inspect,verify,hypothesis]
    steps.append(lambda _:reply(name='note',args=dict(kind='observation',text='The inspected field was compared with its original scalar; this does not establish causality.',status='active',evidence_ids=[seen['eid']])))
    for n in range(16):
        if n==8:steps.append(reply(name='search_evidence',args=dict(artifact='evtx',offset=4,limit=1)))
        steps.append(reply(name='note',args=dict(kind='open_question',text=f'Question {n}: '+('Investigate coverage and legitimate explanations. '*30),status='unresolved')))
    def recover(messages):
        checks['original_value_omitted_before_recovery']=seen['value'] not in encoded(messages)
        return reply(name='memory',args=dict(kind='verified'))
    def recover_original(messages):
        entries=last(messages)['items'];checks['verification_recovered']=any(x['eid']==seen['eid'] and x['pointer']=='/command_line' for x in entries)
        return reply(name='show_evidence',args=dict(evidence_id=entries[0]['eid'],limit=40))
    def coverage(messages):
        checks['original_value_recovered']=any(f['field']=='/command_line' and f['value']==seen['value'] for f in last(messages)['fields'])
        return reply(name='memory',args=dict(kind='actions',query='search_evidence'))
    def finish(messages):
        actions=last(messages)['items'];checks['incomplete_search_recovered']=any(x['status']=='partial' and json.loads(x['coverage']).get('next_offset') is not None for x in actions)
        return reply('The original command and its field-equality verification were recovered. The earlier search had additional pages. Activity remains provisional; ordinary use is an alternative, and causality is unresolved.')
    steps.extend([recover,recover_original,coverage,finish]);provider=provider_factory(steps) if provider_factory else ScriptedProvider(steps)
    local=provider.conversation_binding() if provider.provider_name=='local' else None
    scope=authorize(path,[sid],'2020-01-01T00:00:00Z','2020-01-02T00:00:00Z',list(FAMILIES),provider.provider_name,provider.model_name,
        {'request_bytes':capacity,**({'output_tokens':2048} if local else {})},local=local)
    import tracemalloc
    tracemalloc.start()
    start=time.monotonic();session=Session(scope,provider,lambda _:True,checkpoint_seconds=checkpoint_seconds)
    try:session.submit('Investigate recorded activity without assuming compromise.')
    finally:session.close()
    python_current,python_peak=tracemalloc.get_traced_memory();tracemalloc.stop()
    workspace_bytes=(session.journal.path/'workspace.db').stat().st_size
    saved=notebook(str(path)+'.conversations',session.journal.id)
    one=reconstruct(session.journal.path,root/'reconstructed-one');two=reconstruct(session.journal.path,root/'reconstructed-two')
    checks.update(reconstruction_equal=one==two,case_unchanged=hashlib.sha256(path.read_bytes()).hexdigest()==before,
        history_omitted=session.compacted>0,automatic_checkpoints=session.used['automatic_checkpoints']>0,worker_closed=session.worker.process.poll() is not None)
    sizes=[len(encoded(dict(messages=m,tools=session.catalog())).encode()) for m in provider.calls]
    checks['request_budget_preserved']=max(sizes)<=capacity
    if not all(checks.values()):raise AssertionError(checks)
    return dict(checks=checks,workspace_bytes=workspace_bytes,python_current_bytes=python_current,python_peak_bytes=python_peak,elapsed_seconds=time.monotonic()-start,request_sizes=sizes,usage=session.used,workspace=one,
        journal=str(session.journal.path),events=len(saved['events']),provider='deterministic scripted provider; no network requests',
        limitation='Synthetic byte accounting, not billed token savings or real-model reasoning acceptance.')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--context-bytes',type=int,default=32000)
    parser.add_argument('--checkpoint-seconds',type=float,default=.01)
    parser.add_argument('--reconstruct',type=Path,help='Existing journal session directory; read-only')
    parser.add_argument('--output',type=Path,help='New private output directory for reconstruction only')
    args=parser.parse_args()
    if args.reconstruct:
        if not args.output:parser.error('--output is required with --reconstruct')
        from forensic_assistant.conversational_ai.workspace import reconstruct
        result=reconstruct(args.reconstruct,args.output)
    else:
        with tempfile.TemporaryDirectory(prefix='locard-memory-synthetic-') as tmp:
            result=diagnostic(tmp,args.context_bytes,args.checkpoint_seconds)
            result['journal']='Temporary synthetic journal removed after validation'
    print(json.dumps(result,indent=2));return 0


if __name__=='__main__':raise SystemExit(main())

"""Unrelated synthetic records for generic D2 wire regression; no live data."""
import copy
import time
from forensic_assistant.investigation_ai import d2, packets as b1
from forensic_assistant.investigation_ai.transcript import digest
from forensic_assistant.investigation_ai import synthesis as s1,relationships as s2,disclosure,autonomous,question_assessment as s3
from forensic_assistant.investigation_ai.state import State,Budget
VIEW={'contract':'sqlite-read-view-v1','view_id':'a'*32,'file_identity':{'device':1,'inode':2}}
def row(family,n,**fields):
 return dict(id=family.upper()+':'+format(n,'064x')+':Record:'+str(n),source_type=family,kind='synthetic',source_context={'source_ids':['synthetic-source'],'basis':'analyst supplied','hostname':'lab-node'},**fields)
browser=row('browser',1,target_path=r'C:\Users\Analyst\Documents\budget.csv',url='https://finance.invalid/budget.csv')
registry=row('registry',2,objects=[r'HKCU\Software\Microsoft\Windows\CurrentVersion\Run','LedgerSync',r'C:\Apps\ledger-sync.exe'])
process=row('evtx',3,event_id=4688,process_name='render-job.exe',command_line='render-job.exe --batch invoices')
service=row('evtx',4,event_id=7045,original_event_data=[dict(name='ServiceName',ordinal=0,value='ArchiveAgent',truncated=False),dict(name='ImagePath',ordinal=1,value=r'C:\Services\archive-agent.exe',truncated=False)])
filesystem=row('mft',5,objects=[r'D:\Projects\design.dwg'],timestamps=[dict(utc='2026-10-12T08:00:00Z',slot='si:c',type='SI Created',meaning='filesystem metadata')])
prefetch=row('prefetch',6,executable='RENDER-JOB.EXE',objects=[r'C:\Templates\invoice.dat'])
incomplete=row('evtx',7,original_event_data=[dict(name='RecordedState',ordinal=0,value='running',truncated=True)],truncated_fields=['original_event_data'],coverage_notes=['Records from the preceding interval are unavailable.'])
incomplete['source_context']['conflicts']=[{'field':'hostname','values':['lab-node','lab-other'],'status':'unresolved'}]
large=row('registry',8,objects=[r'HKCU\Software\Example\Config'],command_line='z'*2100)
extensive=copy.deepcopy(filesystem);extensive['warnings']=['Acquisition limitation '+str(i)+': '+'Unknown context remains. '*12 for i in range(10)]
scenarios={'browser_only':[browser],'registry_persistence':[registry],'process_service':[process,service],
 'filesystem_no_evtx':[filesystem],'prefetch_only':[prefetch],'mixed':[browser,registry,filesystem,prefetch],
 'mixed_small':[browser,filesystem],
 'shared_path_relationship':[row('browser',10,target_path=r'D:\Archive\receipt.csv'),row('mft',11,current_path=r'D:\Archive\receipt.csv')],
 'no_relationships':[row('registry',9,objects=['IndependentSetting'])],
 'contradictory_incomplete':[incomplete,service],'large_value':[large],'extensive_qualifications':[extensive]}
too_large=copy.deepcopy(large);too_large['command_line']='z'*2500
scenarios['oversized_original_value']=[too_large]
def context(rows):
 reducer=s1._Reducer();retained=State(Budget());accepted=set();previous=None;counts=[]
 question='Explain the selected recorded activity, limitations and alternative explanations.'
 for number,record in enumerate(rows,1):
  st=State(Budget());st.compact_final=True;st.finalization_requested=True
  st.ingest(dict(tool='show_evidence',behavior='deterministic',records=[record],relationships=[],detections=[],limitations=[],returned_count=1,truncated=False,semantic_candidates=[],label='UNTRUSTED FORENSIC EVIDENCE'),operation='show_evidence')
  _,packet,_=st.prompt(question,[],[]);st.disclose(packet);plain=disclosure.decode(packet)
  observed=[dict(evidence_id=r['id'],field=o['field']['pointer']) for r in plain['records'] for o in r['observations']]
  proposal=dict(action='final',answer=dict(observed=observed,interpretations=[],relationships=[],detections=[],hypotheses=[],unknowns=['Coverage is incomplete.'],answer_status='partial'))
  delta=dict(contract=autonomous.DELTA,id=digest(proposal),evidence_state=VIEW,disclosure_sha256=digest(packet),proposal=proposal,findings=st.render(proposal['answer']),batch=number,based_on=previous)
  reducer.consume(st,delta,packet);retained.records.update(st.records);retained.exposed.update(st.exposed);accepted.add((delta['id'],delta['disclosure_sha256'],number));previous=delta['id'];counts.append(len(observed))
 factual=reducer.finish();related=s2._build(factual)
 manifest=dict(question=question,evidence_state=VIEW,investigation_id='b'*32,authorization=dict(contract='investigation-authorization-v1',id='synthetic-grant',source_ids=['synthetic-source'],evidence_ids=[r['id'] for r in rows],families=sorted({r['source_type'] for r in rows})))
 return b1.Context(retained,factual,related,manifest,None,accepted),counts

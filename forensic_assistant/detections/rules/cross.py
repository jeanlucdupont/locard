"""Four bounded V2 review rules; none asserts an attack or value creation."""
import re
from forensic_assistant.detections.models import Rule
from forensic_assistant.correlation.cross_artifact import correlate
from forensic_assistant.retrieval.evidence import get_evidence
from forensic_assistant.correlation.models import time_ns


class CrossRule(Rule):
    def evaluate(self,db,event,parameters):
        anchor=get_evidence(db,event['id'])
        target={'LOCARD-X-001':'prefetch','LOCARD-X-002':'mft','LOCARD-X-003':'registry'}[self.rule_id]
        if self.rule_id=='LOCARD-X-003':
            from forensic_assistant.detections.rules.office import RULES as OFFICE
            from forensic_assistant.detections.rules.powershell import RULES as PS
            if not any(rule.evaluate(db,event,parameters) for rule in (*OFFICE,*PS)):return None
        result=correlate(db,anchor['id'])
        if parameters.get('_cross_coverage') is not None:
            parameters['_cross_coverage'].append({'candidate_count':result['candidate_count'],'truncated':result['truncated']})
        supporting=[]
        for r in result['relationships']:
            if r['status']!='CORROBORATED' or not r['target_id'].startswith(target.upper()+':'):continue
            candidate=get_evidence(db,r['target_id'])
            if self.rule_id=='LOCARD-X-003':
                if not any(o['role']=='persistence_target' for o in candidate['objects']):continue
                comparison=r['timestamp_comparison']
                if time_ns(comparison['candidate']['timestamp_utc'])<=time_ns(comparison['anchor']['timestamp_utc']):continue
            supporting.append(r)
        if not supporting:return None
        ids=sorted({eid for r in supporting for eid in r['evidence_ids']})
        item=self.observation(event,self.description,evidence_ids=ids,parameters={'object_window_seconds':2 if target=='prefetch' else 300 if target=='registry' else 120},
                              limitations=['Independent observations do not prove causation, download, identical file content, or persistence installation'])
        item.update(correlation_status='CORROBORATED',relationships=supporting)
        return item


class PersistenceRule(Rule):
    sources=('registry',)
    def evaluate(self,db,event,parameters):
        e=get_evidence(db,event['id'])
        matches=[o for o in e['objects'] if o['role']=='persistence_target' and re.search(r'(\\users\\[^\\]+\\(appdata|downloads|desktop)\\|\\windows\\temp\\|^[a-z]:\\temp\\|^%temp%\\)',o['original'],re.I)]
        if not matches:return None
        item=self.observation(e,'Persistence snapshot references a common user/temporary-path pattern; actual permissions are not established',
                              evidence_ids=[e['id'],*e.get('supporting_evidence_ids',[])],
                              limitations=['Key last-write does not date value creation','A configured value does not establish that its target executed','Path pattern does not prove filesystem writability'])
        item['correlation_status']='POSSIBLE';return item


RULES=(
    CrossRule('LOCARD-X-001','Execution corroboration','Process creation and Prefetch agree on image path, host scope, and execution time','low','1',('process',)),
    CrossRule('LOCARD-X-002','Filesystem metadata near execution','Process image path agrees with nearby MFT SI creation metadata','low','1',('process',)),
    CrossRule('LOCARD-X-003','Process and persistence reference','A reviewed process precedes a persistence key last-write whose snapshot value references its image path','medium','1',('process',)),
    PersistenceRule('LOCARD-X-004','Persistence path review','Persistence reference matches a common user/temporary-path pattern','medium','1',('registry_value',)),
)

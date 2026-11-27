"""Scoped adapters over Locard retrieval; no model-generated SQL or dispatch."""
import json,time
from forensic_assistant.retrieval.performance import measured
from datetime import datetime,timedelta
from .contracts import arguments,check
from forensic_assistant.retrieval.evidence import EvidenceQueries,get_evidence,same_host_window
from forensic_assistant.retrieval.queries import required_time


def exclusive_end(value):
    value=required_time(value);n=int(value[20:29])
    if n:return value[:20]+str(n-1).zfill(9)+'Z'
    return (datetime.strptime(value[:19],'%Y-%m-%dT%H:%M:%S')-timedelta(seconds=1)).strftime('%Y-%m-%dT%H:%M:%S')+'.999999999Z'


def leaves(value,prefix=''):
    if isinstance(value,dict):
        for k,v in value.items():yield from leaves(v,prefix+'/'+str(k).replace('~','~0').replace('/','~1'))
    elif isinstance(value,list):
        for i,v in enumerate(value):yield from leaves(v,prefix+'/'+str(i))
    elif value is None or type(value) in (str,int,float,bool):yield prefix,value


def meaning(record,pointer):
    if pointer.startswith('/timestamps/'):
        try:stamp=record['timestamps'][int(pointer.split('/')[2])]
        except (KeyError,IndexError,ValueError):return None
        if (pointer.endswith(('/timestamp_utc','/original')) or record['source_type']=='defender' and pointer.endswith('/original_value')):return str(stamp.get('meaning') or stamp.get('source') or 'Unknown timestamp meaning')
    if pointer=='/timestamp_utc':return 'EVTX SystemTime' if record['source_type']=='evtx' else 'Record summary timestamp; inspect individual timestamp observations'
    return None


class Tools:
    def __init__(self,db,scope,*,profile=None,read_view=None):
        self.db,self.scope=db,scope;self.profile=profile
        self.known=set();self.disclosed={}
        from forensic_assistant.detections.execution_cache import PopulationCache
        self.population_cache=PopulationCache(read_view,scope) if read_view is not None else None
        self.computation=None
        self.cancel_check=lambda:None
        self.progress=lambda value:None

    @measured('scope_resolution')
    def source(self,args):
        sid=args.get('source_id')
        if sid is None and len(self.scope['source_ids'])==1:sid=self.scope['source_ids'][0]
        if sid not in self.scope['source_ids']:raise ValueError('Choose an approved source_id')
        return sid

    @measured('identity_source_time_eligibility')
    def eligible(self,eid,source=None,start=None,end=None):
        # Identity-only hydration: source and inherited/derived time predicates run
        # in the existing retrieval service before original content is fetched.
        row=self.db.execute('SELECT source_type FROM evidence_records WHERE evidence_id=?',(eid,)).fetchone()
        if not row or row[0] not in self.scope['families']:return False
        for sid in ([source] if source else self.scope['source_ids']):
            result=EvidenceQueries(self.db,hydrate=lambda value:{'id':value},profile=self.profile).search(
                evidence_id=eid,artifact=row[0],exact_count=False,source_scope=sid,start=start or self.scope['start'],end=end or exclusive_end(self.scope['end']),limit=1)
            if result.records:return True
        return False

    @measured('original_construction')
    def original(self,eid,*,known=True,_scoped=False):
        if known and eid not in self.known:raise ValueError('Evidence identity not previously retrieved')
        if not _scoped and not self.eligible(eid):raise ValueError('Evidence outside approved source/time scope')
        started=time.monotonic()
        record=get_evidence(self.db,eid)
        if self.profile is not None:self.profile.append(dict(phase='retained_record_hydration',seconds=time.monotonic()-started))
        if record['source_type'] not in self.scope['families']:raise ValueError('Artifact outside scope')
        sources=record.get('context',{}).get('source_ids',[])
        if len(sources)!=1 or sources[0] not in self.scope['source_ids']:raise ValueError('Ambiguous source attribution')
        if record['source_type']=='evtx':
            from forensic_assistant.retrieval.event_data import payload
            record['original_event_data'],record['event_data_limitations']=payload(record)
        for support in record.get('supporting_evidence_ids',[]):
            if not self.eligible(support):raise ValueError('Supporting context outside approved scope')
        return record

    @measured('field_extraction')
    def page(self,record,offset=0,limit=20):
        from forensic_assistant.ai.backend import redact
        values=[];more=False;examined=0;field_cap=False
        for i,(pointer,value) in enumerate(leaves(record)):
            if i<offset:continue
            if i>=10000:field_cap=True;more=False;break
            if len(values)>=limit:more=True;break
            original=value;truncated=False;redacted=False
            if isinstance(value,str):
                value=redact(value);redacted=value!=original
                if len(value.encode())>1024:
                    value=value.encode()[:1024].decode('utf-8','ignore');truncated=True
            field=dict(field=pointer,value=value,truncated=truncated,redacted=redacted)
            label=meaning(record,pointer)
            if label:field['timestamp_meaning']=label
            values.append(field);examined+=1
            if not truncated and not redacted:self.disclosed.setdefault(record['id'],{})[pointer]=original
        self.known.add(record['id'])
        return dict(evidence_id=record['id'],artifact=record['source_type'],source_ids=record['context']['source_ids'],
            fields=values,next_offset=offset+examined if more else None,field_limit_reached=field_cap,
            limitations=['Bounded original-field page; additional timestamps are contextual, not necessarily in the search window.',
                        'Source metadata may be analyst supplied; it is not independently verified.',
                        'Field equality and temporal proximity do not establish causality or execution.'])

    @measured('operation_total')
    def execute(self,name,args):
        self.computation=None
        try:return self._execute(name,args)
        except BaseException:
            if self.population_cache is not None:self.population_cache.clear()
            raise

    def _execute(self,name,args):
        arguments(name,args);check(self.scope,self.scope['case'])
        if name=='discover_execution_behaviors':
            from forensic_assistant.detections.execution import discover
            query=dict(args);sid=self.source(query);query.pop('source_id',None)
            start=required_time(query.pop('start',self.scope['start']));end=required_time(query.pop('end',self.scope['end']))
            if not self.scope['start']<=start<end<=self.scope['end']:raise ValueError('Discovery cannot expand approval')
            family=query.pop('artifact',None)
            if family is not None and family not in self.scope['families']:raise ValueError('Artifact outside approval')
            query.setdefault('presentation','compact');query.setdefault('limit',10 if query['presentation']=='compact' else 5)
            result=discover(self.db,sid,start,end,cache=self.population_cache,authorization=self.scope,diagnostics_sink=lambda d:setattr(self,'computation',d),families=[family] if family else self.scope['families'],
                hydrate=lambda eid:self.original(eid,known=False,_scoped=True),byte_limit=min(12000,self.scope['limits']['result_bytes']),
                check=self.cancel_check,progress=self.progress,**query)
            for item in [*result['records'],*result.get('omitted_candidates',[])]:
                eid=item['evidence_id'];self.known.add(eid)
                for f in item.get('original_fields',[]):
                    if not f['truncated'] and not f['redacted']:self.disclosed.setdefault(eid,{})[f['field']]=f['value']
            return result
        if name in ('discover_security_signals','activity_overview'):
            from forensic_assistant.detections.discovery import Discovery,OVERVIEWS
            query=dict(args);sid=self.source(query);query.pop('source_id',None)
            start=required_time(query.pop('start',self.scope['start']));end=required_time(query.pop('end',self.scope['end']))
            if not self.scope['start']<=start<end<=self.scope['end']:raise ValueError('Discovery cannot expand approved time interval')
            family=query.pop('artifact','evtx') if name=='discover_security_signals' else OVERVIEWS[query['kind']]
            if family=='defender' and name=='discover_security_signals':
                if query.get('category','all')!='all' or 'candidate_limit' in query:raise ValueError('Defender groups use whole scoped populations; use activity_overview or category-filtered search')
                query.pop('category',None);query['kind']='defender_groups'
            if family not in self.scope['families']:raise ValueError('Artifact outside scope')
            service=Discovery(self.db,sid,start,end,hydrate=lambda eid:self.original(eid,known=False,_scoped=True))
            result=(service.signals if name=='discover_security_signals' and family=='evtx' else service.overview)(**query,byte_limit=min(12000,self.scope['limits']['result_bytes']))
            for item in result['records']:
                eid=item['evidence_id'];self.known.add(eid)
                for f in item.get('original_fields',[]):
                    if not f['truncated'] and not f['redacted']:self.disclosed.setdefault(eid,{})[f['field']]=f['value']
            return result
        if name=='show_evidence':return self.page(self.original(args['evidence_id']),args.get('offset',0),args.get('limit',40))
        if name=='verify_observation':
            eid=args['evidence_id'];pointer=args['field'];record=self.original(eid)
            if record['source_type']=='defender':
                import re
                if pointer!='/detail/text' and not re.fullmatch(r'/detail/fields/\d+/value|/timestamps/\d+/(?:original_value|timestamp_utc)',pointer):
                    raise ValueError('Defender verification requires an original text/field or qualified timestamp; grouping and parser metadata are not observations')
            from forensic_assistant.investigation_ai.contracts import loads
            observed=loads(args['value_json'],max_bytes=4096)
            if pointer.startswith(('/context/','/source/','/source_locations/')) or pointer in ('/id','/evidence_id','/hostname','/username','/host_key','/source_type','/source_file','/file_sha256'):
                raise ValueError('Provenance or analyst metadata is not an original factual observation')
            if isinstance(observed,(dict,list)):raise ValueError('Only original scalar observations can be verified')
            current=dict(leaves(record));prior=self.disclosed.get(eid,{})
            if pointer not in prior or pointer not in current or json.dumps(current[pointer],sort_keys=True)!=json.dumps(observed,sort_keys=True) or current[pointer]!=prior[pointer]:raise ValueError('Observation not supported by disclosed original field')
            label=meaning(record,pointer)
            if args.get('timestamp_meaning')!=label:raise ValueError('Timestamp interpretation mismatch')
            return dict(verified=True,evidence_id=eid,field=pointer,value=observed,timestamp_meaning=label,
                        basis='deterministic derived field' if pointer.startswith('/detail/userassist/') else 'retained record field',
                        limitation='Verified original field equality only; accompanying model prose is not independently verified.')
        query=dict(args);timeline=name in ('timeline','around')
        if name=='around':
            record=self.original(query.pop('evidence_id'));slot=query.pop('timestamp_slot')
            stamps=[t for t in record['timestamps'] if t['slot']==slot and t.get('timestamp_utc')]
            if len(stamps)!=1:raise ValueError('Select an unambiguous original timestamp slot')
            stamp=required_time(stamps[0]['timestamp_utc'])
            if not self.scope['start']<=stamp<self.scope['end']:raise ValueError('Anchor outside approved time scope')
            window=same_host_window(record,stamp,query.pop('seconds',300))
            query.update(window,source_id=record['context']['source_ids'][0])
        sid=self.source(query);query.pop('source_id',None)
        start=required_time(query.pop('start',self.scope['start']));end=required_time(query.pop('end',self.scope['end']))
        if name=='around':start=max(start,self.scope['start']);end=min(end,self.scope['end'])
        if not self.scope['start']<=start<end<=self.scope['end']:raise ValueError('Search cannot expand approved time interval')
        if query.get('artifact') not in self.scope['families']:raise ValueError('Artifact outside scope')
        end=exclusive_end(end)
        if 'object_basename' in query:
            if set(query)-{'artifact','object_basename','object_after','limit'}:raise ValueError('Object basename does not combine with other filters or offset')
            query['limit']=min(query.get('limit',10),10)
        else:query.setdefault('limit',10)
        def hydrate(eid):
            if 'object_basename' in query and not self.eligible(eid,sid,start,end):return None
            # Only the trusted scoped SQL selector supplies IDs to this callback.
            # Exact standalone inspection still performs eligibility verification.
            return self.original(eid,known=False,_scoped=True)
        result=EvidenceQueries(self.db,hydrate=hydrate,profile=self.profile).search(start=start,end=end,source_scope=sid,timeline=timeline,exact_count=False,**query).as_dict()
        projection_started=time.monotonic()
        pages=[]
        for record in result.pop('records'):
            page=self.page(record,0,12)
            # Search summaries carry original timestamps with their full semantics.
            page['timestamps']=record.get('timestamps',[])[:8]
            page['timestamps_truncated']=len(record.get('timestamps',[]))>8
            pages.append(page)
        if self.profile is not None:self.profile.append(dict(phase='projection',seconds=time.monotonic()-projection_started))
        result['records']=pages
        result['scope']=dict(source_id=sid,start=start,end_inclusive=end,artifact=query['artifact'])
        result['next_offset']=query.get('offset',0)+len(pages) if result.get('has_more',result.get('truncated')) and not ('content_search' in result or 'object_search' in result) else None
        result['limitations']=['Bounded search; omitted or out-of-scope evidence was not assessed.','Timestamp meanings differ across artifacts; no absence or causal conclusion follows from this result.']
        return result

"""Session-local rendered-prompt measurement. No inference, evidence authority or disk cache."""
import hashlib
import time
from .local import auxiliary,body_for,encoded
from forensic_assistant.ai.provider_diagnostics import ProviderFailure

MARGIN=32  # Special-token/framing reserve after exact observed parity; not a byte multiplier.
HTTP_LIMIT=512*1024


def identity(value):return hashlib.sha256(encoded(value)).hexdigest()


def failure_kind(exc):
    if isinstance(exc,ProviderFailure):
        if exc.metadata.get('http_status') in (404,405,501):return 'unsupported_endpoints'
        if exc.category in ('network_error','timeout'):return exc.category
    return 'malformed_or_incompatible'


class ContextMeter:
    def __init__(self,config,authorization):
        self.config=dict(config);self.authorization=authorization
        self.server=None;self.capability='unknown';self.parity=set();self.disabled=False
        self.last=None;self.server_context=None

    def measure(self,messages,tools,output,byte_limit,timeout,before,choice='auto'):
        body=body_for(self.config,messages,tools,output,choice);size=len(encoded(body))
        result=dict(method='byte_fallback',capability=self.capability,request_digest=identity(body),
            configured_tokens=self.config['context_tokens'],output_tokens=output,input_tokens=None,
            request_bytes=size,request_byte_limit=min(byte_limit,HTTP_LIMIT),template_margin=2048,
            rendered_bytes=None,remaining_tokens=None,measurement_seconds=0.0,
            template_seconds=0.0,tokenize_seconds=0.0,metadata_seconds=0.0,
            template_supported=False,tokenizer_supported=False,
            parity='unverified',authorization=self.authorization)
        if self.server_context is not None:result['server_context_tokens']=self.server_context
        def finish():
            measured=result['input_tokens'] if result['method']=='template_tokenizer' else size
            effective=min(self.config['context_tokens'],result.get('server_context_tokens',self.config['context_tokens']))
            result['remaining_tokens']=effective-output-result['template_margin']-measured
            result['measured_remaining_tokens']=effective-output-MARGIN-result['input_tokens'] if result['input_tokens'] is not None else None
            result['fits']=size<=result['request_byte_limit'] and result['remaining_tokens']>=0
            result['reason']='fits' if result['fits'] else 'request_bytes' if size>result['request_byte_limit'] else 'model_tokens' if result['method']=='template_tokenizer' else 'unverified_token_capacity'
            self.last=dict(result);return result
        if size>result['request_byte_limit']:return finish()
        started=time.monotonic();deadline=started+min(timeout,30);admission_failed=False
        def call(path,data=None):
            nonlocal admission_failed
            remaining=deadline-time.monotonic()
            if remaining<=0:raise ProviderFailure('timeout','timeout')
            # Before every possible exposure: caller persists intent and charges bytes.
            try:before(path,data)
            except BaseException:
                admission_failed=True;raise
            remaining=min(remaining,deadline-time.monotonic())
            if remaining<=0:raise ProviderFailure('timeout','timeout')
            begin=time.monotonic()
            try:return auxiliary(self.config,path,data,remaining)
            finally:result[{'/props':'metadata_seconds','/apply-template':'template_seconds','/tokenize':'tokenize_seconds'}[path]]+=time.monotonic()-begin
        try:
            if self.disabled:return finish()
            props=call('/props')
            if type(props) is not dict or not isinstance(props.get('chat_template'),str):raise ValueError('template identity unavailable')
            allocation=props.get('default_generation_settings',{})
            allocation=allocation.get('n_ctx') if type(allocation) is dict else None
            if type(allocation) is int and 0<allocation<=1048576:
                result['server_context_tokens']=allocation;self.server_context=allocation
            server=identity(props)
            if server!=self.server:
                self.server=server;self.parity.clear();self.capability='unknown'
            if self.capability=='unknown':
                # Harmless feature probe: never substitute a completion for token counting.
                probe=[{'role':'system','content':'LOCARD_SYSTEM_SENTINEL'}, {'role':'user','content':'LOCARD_USER_SENTINEL'},
                    {'role':'assistant','content':None,'tool_calls':[{'id':'synthetic-1','type':'function','function':{'name':'memory','arguments':'{"kind":"state"}'}}]},
                    {'role':'tool','tool_call_id':'synthetic-1','content':'LOCARD_RESULT_SENTINEL'}]
                probe_body=body_for(self.config,probe,tools,output,choice)
                rendered=call('/apply-template',probe_body)
                prompt=rendered.get('prompt') if type(rendered) is dict else None
                if type(prompt) is not str or not all(x in prompt for x in ('LOCARD_SYSTEM_SENTINEL','LOCARD_USER_SENTINEL','LOCARD_RESULT_SENTINEL')):raise ValueError('template omitted messages')
                if not all(t['function']['name'] in prompt for t in tools):raise ValueError('template omitted tools')
                self.capability='template_supported_parity_pending'
            rendered=call('/apply-template',body)
            prompt=rendered.get('prompt') if type(rendered) is dict else None
            if type(prompt) is not str or not prompt or len(encoded({'content':prompt}))>HTTP_LIMIT:raise ValueError('invalid rendered prompt')
            result['template_supported']=True
            result['rendered_bytes']=len(prompt.encode('utf-8'))
            tokenized=call('/tokenize',dict(content=prompt,add_special=True,parse_special=True,with_pieces=False))
            tokens=tokenized.get('tokens') if type(tokenized) is dict else None
            if type(tokens) is not list or not tokens or len(tokens)>131072 or any(type(t) is not int or not 0<=t<=2147483647 for t in tokens):raise ValueError('invalid tokens')
            result['input_tokens']=len(tokens);result['server_identity']=server;result['tokenizer_supported']=True
            # Tool-bearing histories must independently demonstrate usage parity.
            family='tools' if any(m.get('role')=='tool' for m in messages) else 'initial'
            result['family']=family
            if family in self.parity:
                result.update(method='template_tokenizer',template_margin=MARGIN,parity='verified_in_session')
            result['capability']='usage_parity_observed' if family in self.parity else 'template_supported_parity_pending'
        except (ProviderFailure,ValueError,TypeError,UnicodeError) as exc:
            if admission_failed:raise
            self.capability=failure_kind(exc);result['capability']=self.capability
            self.parity.clear();self.disabled=True
        finally:result['measurement_seconds']=time.monotonic()-started
        return finish()

    def observe(self,result,usage):
        actual=usage.get('prompt_tokens');measured=result.get('input_tokens')
        difference=actual-measured if type(actual) is int and type(measured) is int else None
        if difference==0 and result.get('server_identity')==self.server and not self.disabled:
            self.parity.add(result['family']);self.capability='usage_parity_observed'
        elif difference is not None:
            self.parity.clear();self.disabled=True;self.capability='parity_mismatch'
        return dict(measured_tokens=measured,reported_tokens=actual,difference=difference,capability=self.capability,
            family=result.get('family'),verified_for_family=result.get('family') in self.parity)

    def receipt(self,config,messages,tools,output,choice):
        value=self.last
        if config!=self.config or not value or value['request_digest']!=identity(body_for(config,messages,tools,output,choice)) or not value['fits']:return None
        if value['method']=='template_tokenizer' and (value.get('server_identity')!=self.server or self.disabled):return None
        return dict(value)

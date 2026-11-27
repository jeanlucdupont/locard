"""Closed, content-free local transport diagnostics. Never retain arbitrary server text."""
MESSAGES={
    'grammar_rejected':'Server reported failure to parse grammar.',
    'grammar_complexity':'Server reported repeated grammar rules exceed sane defaults.',
    'context_exhausted':'Server reported context capacity exceeded.',
    'unavailable':'Server detail withheld: no recognized safe diagnostic fragment.',
}


def server_detail(error):
    message=error.get('message','') if isinstance(error,dict) else ''
    text=message.lower() if type(message) is str else ''
    code='grammar_complexity' if 'repetition exceeds sane defaults' in text else 'grammar_rejected' if 'failed to parse grammar' in text else 'context_exhausted' if isinstance(error,dict) and error.get('type')=='exceed_context_size_error' else 'unavailable'
    return dict(server_code=code,server_message=MESSAGES[code],inference_began='unknown')


def safe(value):
    if type(value) is not dict:return {}
    result={}
    code=value.get('server_code')
    if type(code) is str and code in MESSAGES:result.update(server_code=code,server_message=MESSAGES[code])
    for key,allowed in [('inference_began',('unknown',)),('client_cleanup',('confirmed','unconfirmed')),('server_cleanup',('unconfirmed',)),('usage',('unknown','available'))]:
        if value.get(key) in allowed:result[key]=value[key]
    if type(value.get('request_bytes')) is int and 0<=value['request_bytes']<=600*1024:result['request_bytes']=value['request_bytes']
    if type(value.get('timed_out')) is bool:result['timed_out']=value['timed_out']
    return result

"""Diagnostic metadata only; never used to authorize or repair an operation."""
import hashlib
import json

# Static application messages only: never serialize arbitrary exception text.
REASONS = frozenset(['Invalid pagination bounds','Invalid EVTX continuation for this search scope','Invalid object continuation for this scope','EVTX match/continuation requires --evtx-text','Malformed structured response','Duplicate JSON key','Nonfinite JSON value','AUTHORIZATION_EXPIRED',
 'Ambiguous source attribution',
 'Analyst message must be 1..8192 bytes',
 'Anchor outside approved time scope',
 'Artifact outside approval',
 'Artifact outside scope',
 'CASE_IDENTITY_CHANGED',
 'Choose an approved source_id',
 'Conversational provider unsupported; no cloud fallback',
 'Defender groups use whole scoped populations; use activity_overview or category-filtered search',
 'Defender verification requires an original text/field or qualified timestamp; grouping and '
 'parser metadata are not observations',
 'Discovery cannot expand approval',
 'Discovery cannot expand approved time interval',
 'Evidence identity not previously retrieved',
 'Evidence outside approved source/time scope',
 'INVALID_FAMILIES',
 'INVALID_LEGACY_AUTHORIZATION',
 'INVALID_LIMITS',
 'INVALID_MODEL',
 'INVALID_SCOPE',
 'INVALID_TIME_SCOPE',
 'Invalid checkpoint interval',
 'Investigation not approved',
 'LOCAL_AUTHORIZATION_INVALID',
 'LOCAL_PROVIDER_CHANGED',
 'Local model binding mismatch',
 'MEMORY_FILTER_MISMATCH',
 'MEMORY_ITEM_CAPACITY',
 'Not a conversational notebook',
 'Object basename does not combine with other filters or offset',
 'Observation not supported by disclosed original field',
 'Only original scalar observations can be verified',
 'PROVIDER_CHANGED',
 'PROVIDER_CONTINUATION_REDACTED',
 'Provenance or analyst metadata is not an original factual observation',
 'Provider/model mismatch',
 'Record budget exhausted',
 'Record ceiling reached; narrow the search',
 'SESSION_CLOSED',
 'Search cannot expand approved time interval',
 'Select an unambiguous original timestamp slot',
 'Session closed; start a newly authorized session',
 'Supporting context outside approved scope',
 'TOOL_NOT_AUTHORIZED',
 'Timestamp interpretation mismatch',
 'UNEXPOSED_WORKSPACE_REFERENCE',
 'UNKNOWN_MEMORY_KIND',
 'UNKNOWN_NOTE_REVISION',
 'UNKNOWN_OPERATION_REFERENCE',
 'UNKNOWN_WORKSPACE_EVIDENCE',
 'Unexpected local binding',
 'Unknown evidence reference',
 'Unknown workspace evidence reference',
 'WORKSPACE_AHEAD_OF_JOURNAL',
 'WORKSPACE_ALREADY_EXISTS_RECONSTRUCT_REQUIRED',
 'WORKSPACE_AUTHORITY_CHANGED',
 'WORKSPACE_BINDING_CONFLICT',
 'WORKSPACE_EVENT_CONFLICT',
 'WORKSPACE_EVENT_GAP',
 'WORKSPACE_EVENT_HASH',
 'WORKSPACE_FILE_REDIRECTION',
 'WORKSPACE_IDENTITY_CHANGED',
 'WORKSPACE_JOURNAL_BINDING',
 'WORKSPACE_JOURNAL_CHAIN',
 'WORKSPACE_JOURNAL_FRONTIER',
 'WORKSPACE_JOURNAL_HASH',
 'WORKSPACE_JOURNAL_LIMIT',
 'WORKSPACE_MANIFEST_AUTHORIZATION',
 'WORKSPACE_MANIFEST_LIMIT',
 'WORKSPACE_SESSION_MISMATCH'])

def failure_detail(exc):
    detail = getattr(exc, 'validation_detail', None)
    result = dict(detail) if isinstance(detail, dict) else {}
    if str(exc) in REASONS:
        result['rule'] = str(exc)
    return result


def operation_trace(path):
    from .workspace import events
    rows=[];seen=set();request=0;pending=[];metrics=[];turn=0
    for event in events(path):
        kind=event['kind'];data=event['data']
        if kind=='analyst_message':turn+=1
        elif kind=='provider_attempt':
            request+=1
            # Match exact feedback, not only call IDs (some providers reuse IDs).
            for row in rows:
                if row['feedback_sent_request'] is None and row['feedback'] is not None:
                    for message in data['messages']:
                        if message.get('role')=='tool' and message.get('tool_call_id')==row['tool_call_id']:
                            try:matches=json.loads(message['content'])==row['feedback']
                            except (ValueError,KeyError):matches=False
                            if matches:row['feedback_sent_request']=request;pending.append(row);break
        elif kind=='provider_response':
            for row in pending:row['subsequent_response_identity']=event['hash']
            pending=[]
        elif kind=='operation_diagnostic':
            row=dict(data,turn=turn)
            signature=hashlib.sha256(json.dumps({'name':row['tool'],'arguments':row['arguments']},sort_keys=True,separators=(',',':')).encode()).hexdigest()
            row.update(argument_signature=signature,exact_repeat=signature in seen,feedback_sent_request=None,subsequent_response_identity=None)
            seen.add(signature);rows.append(row)
        elif kind in ('local_inference_metrics','context_candidate','context_capacity','provider_timing','paused'):
            metrics.append(dict(kind=kind,data=data))
    # Correlate normal subsequent operations, not retries or inferred comprehension.
    violations=set()
    for row in rows:
        error=row.get('error') or {};detail=error.get('validation_detail') or {}
        key=(row['tool'],error.get('code'),error.get('stage'),detail.get('rule'),detail.get('validation_path'),detail.get('constraint'))
        row['same_validation_error_recurred']=bool(detail.get('rule') or detail.get('constraint')) and key in violations
        row['validation_rule']=detail.get('rule') or detail.get('constraint')
        if error:violations.add(key)
        following=[dict(provider_request_sequence=r['provider_request_sequence'],tool_call_id=r['tool_call_id'],tool=r['tool'],arguments=r['arguments'],execution_outcome=r['execution_outcome']) for r in rows if r['provider_request_sequence']==row['feedback_sent_request']]
        row['subsequent_operations']=following
    consecutive=[]
    for row in rows:
        if row['turn']!=turn:continue
        if row['execution_outcome']=='failed':consecutive.append(row)
        else:consecutive=[]
    return dict(operations=rows,provider_diagnostics=metrics,repeated_failure=dict(
        threshold=3,policy='Consecutive failures within a submit; success resets; identity does not affect threshold',
        contributing_operations=consecutive[-3:],identical=bool(consecutive) and len({r['argument_signature'] for r in consecutive[-3:]})==1,
        prior_successes=[r for r in rows if r['execution_outcome']=='succeeded']))

"""Safe model-facing explanations. Never repairs arguments or grants authority."""
from .contracts import SCHEMAS
from .operation_diagnostics import REASONS

CONSTRAINTS=frozenset(('wrong type','missing parameter','unknown parameter','invalid item count',
    'duplicate items','invalid string length/content','value outside bounds','unsupported value'))
STAGES=frozenset(('argument_validation','scope_validation','workspace','worker_execution',
    'operation','authorization','read_view','integrity','query','projection'))
SCALAR='value_json must encode one exact original scalar, not its field descriptor. Examples: "\\\"example.txt\\\"", "42", "true". Inspect the original field first; truncated/redacted values are ineligible. Use timestamp_meaning only when the original timestamp semantics require it; copy that meaning exactly.'
RULE_GUIDANCE={
 'Use a full ISO timestamp with Z or an explicit UTC offset':'Use YYYY-MM-DDTHH:MM:SS[.fraction]Z or an explicit +/-HH:MM offset; a space may replace T. Fractional seconds use a dot and 1..9 digits, not a colon. Example: 2020-01-01T12:00:00.000000000Z. Preserve the approved time window; no automatic repair is performed.',
 'Invalid pagination bounds':'Use the tool schema bounds and returned next_offset; do not invent pagination values.',
 'Invalid EVTX continuation for this search scope':'Use the exact evtx_after cursor returned for the same authorized search and filters. Do not forge or reuse a cursor from another scope.',
 'Invalid object continuation for this scope':'Use the exact object_after cursor returned for the same authorized search. Do not forge or reuse cross-scope cursors.',
 'EVTX match/continuation requires --evtx-text':'evtx_match and evtx_after require evtx_text with the original search filters and approved scope.',
 'Only original scalar observations can be verified':SCALAR,
 'Malformed structured response':SCALAR,
 'Duplicate JSON key':SCALAR,
 'Nonfinite JSON value':SCALAR,
 'MEMORY_FILTER_MISMATCH':'Use evidence_id only with evidence/fields/verified; query only with notes/actions; status only with notes/actions. Omit unused filters. Paginate using returned next_offset.',
 'UNKNOWN_NOTE_REVISION':'Use an existing returned note_id for supersedes; omit supersedes for a new note.',
 'UNKNOWN_OPERATION_REFERENCE':'Use only an existing operation ID returned in this session; memory actions can list prior operations.',
 'UNEXPOSED_WORKSPACE_REFERENCE':'Reference only evidence already disclosed in this session. A note cannot establish evidence authority.',
 'Unknown evidence reference':'Use an exact evidence ID previously returned within the approved scope; do not invent IDs.',
 'Unknown workspace evidence reference':'Use only evidence registered in this workspace; memory does not grant new authority.',
 'Evidence identity not previously retrieved':'Retrieve within the existing authorized scope before inspecting a returned evidence ID.',
 'UNKNOWN_WORKSPACE_EVIDENCE':'Use only an evidence ID registered in this workspace.',
 'Observation not supported by disclosed original field':'Inspect the exact original field with show_evidence. Verify only an unchanged, completely disclosed, non-redacted scalar; feedback grants no authority.',
 'Timestamp interpretation mismatch':'For timestamp fields copy the exact disclosed timestamp_meaning. For non-timestamp fields omit timestamp_meaning.',
 'Select an unambiguous original timestamp slot':'Inspect the original timestamp slots and supply one exact returned slot.',
 'Object basename does not combine with other filters or offset':'Use only artifact, object_basename, object_after and limit for this operation. Continue with the returned cursor; do not invent it.',
 'MEMORY_ITEM_CAPACITY':'Request a smaller bounded memory page; preserve returned continuation and coverage limitations.',
 'Provenance or analyst metadata is not an original factual observation':'Choose an eligible original evidence field; metadata or analyst assertions cannot establish forensic verification.',
}
SCOPE_RULES=frozenset(('Choose an approved source_id','Evidence outside approved source/time scope',
 'Artifact outside scope','Artifact outside approval','Ambiguous source attribution','Supporting context outside approved scope',
 'Discovery cannot expand approval','Discovery cannot expand approved time interval','Search cannot expand approved time interval','Anchor outside approved time scope'))


def _parameter(schema,path):
    """Resolve only schema-owned names; never echo unknown model-controlled keys."""
    import re
    if type(path) is not str or not re.fullmatch(r'request(?:\.[a-z_]+(?:\[\d{1,5}\])?)*',path):return None
    node=schema
    for part in path.split('.')[1:]:
        name=part.split('[')[0]
        node=node.get('properties',{}).get(name)
        if node is None:return None
        if '[' in part:
            node=node.get('items')
            if node is None:return None
    return node


def tool_feedback(tool,args,diagnostic,worker_reached,read_view_available):
    value=dict(error=diagnostic['code'],limitation='No result accepted; this is not evidence absence. Narrow the query or choose another authorized approach.',read_view_available=read_view_available)
    schema=SCHEMAS.get(tool)
    if schema is None:return value
    detail=diagnostic.get('validation_detail') or {}
    rule=detail.get('rule');rule=rule if type(rule) is str and rule in REASONS else None
    constraint=detail.get('constraint');constraint=constraint if type(constraint) is str and constraint in CONSTRAINTS else None
    path=detail.get('validation_path');node=_parameter(schema,path)
    guidance=None;safe={}
    if not read_view_available or diagnostic['code'] in ('AUTHORIZATION_FAILURE','EVIDENCE_INTEGRITY','RESOURCE_PROTECTION'):
        guidance='Stop this operation. The authorization, integrity or containment boundary must be resolved by the analyst; do not bypass it.'
    elif node is not None and constraint:
        safe.update(parameter=path,expected_type=node['type'],constraint=constraint)
        safe.update({k:node[k] for k in ('enum','minimum','maximum','minLength','maxLength','minItems','maxItems') if k in node})
        guidance={'wrong type':'Supply the documented JSON type; do not send a descriptor object in place of a scalar.',
            'missing parameter':'Supply all required parameters.', 'unknown parameter':'Remove parameters absent from this tool schema.',
            'invalid item count':'Keep the array within the documented item limits.', 'duplicate items':'Supply unique array items.',
            'invalid string length/content':'Supply nonempty text within the UTF-8 byte limit, without NUL characters.',
            'value outside bounds':'Use the documented numeric bounds; for pagination use the returned continuation.',
            'unsupported value':'Choose one of the documented enumeration values.'}[constraint]
        if constraint=='missing parameter':safe['required_parameters']=list(node.get('required',()))
        if constraint=='unknown parameter':safe['allowed_parameters']=list(node.get('properties',{}))
        field=path.removeprefix('request.')
        if constraint=='invalid string length/content' and type(args) is dict and args.get(field)=='' and field in schema['properties'] and field not in schema['required']:
            guidance='Omit this optional parameter when unused; if supplied it must satisfy its schema and operation-specific restrictions.'
            if field in ('source_id','start','end','timestamp_meaning','evtx_after','object_after'):
                guidance='Supply a valid nonempty value when required by the operation, timestamp semantics, continuation or approved scope. Do not omit required source choices or paired bounds.'
            if tool=='note' and field=='supersedes':guidance='Omit supersedes when creating a new note. To supersede a note, supply an existing valid note_id. An empty string is invalid.'
    elif rule in SCOPE_RULES:guidance='Stay within the existing approved sources, artifact families and time window. Do not broaden authorization; unavailable evidence is not evidence absence.'
    elif rule in RULE_GUIDANCE:guidance=RULE_GUIDANCE[rule]
    if rule=='Use a full ISO timestamp with Z or an explicit UTC offset' and node is not None:
        safe.update(parameter=path,expected_type='string',constraint='invalid timestamp format')
    if guidance is None:return value
    value.update(tool=tool,stage=diagnostic['stage'] if diagnostic.get('stage') in STAGES else 'operation',
        worker_reached=worker_reached,result_accepted=False,correction=guidance,**safe)
    if rule:value['validation_rule']=rule
    if rule in ('Only original scalar observations can be verified','Malformed structured response','Duplicate JSON key','Nonfinite JSON value') and tool=='verify_observation':
        value.update(parameter='request.value_json',expected_representation='JSON encoding of one exact eligible original scalar')
    if rule=='Timestamp interpretation mismatch':value['parameter']='request.timestamp_meaning'
    value['limitation']='No result accepted; no evidence absence or verification authority established.'
    return value

"""Generation-only llama.cpp adaptation; canonical execution validation is unchanged."""
from copy import deepcopy

REMOVED=('minLength','maxLength','minItems','maxItems','uniqueItems','minimum','maximum')


def generation_catalog(tools):
    """Never mutate the caller's catalog. Idempotent, including limit descriptions."""
    result=deepcopy(tools)
    def visit(schema):
        limits={key:schema.pop(key) for key in REMOVED if key in schema}
        if limits:
            parts=[]
            if 'maxLength' in limits:parts.append(f"Nonblank; <= {limits['maxLength']} UTF-8 bytes.")
            if 'maxItems' in limits:parts.append(f"{limits.get('minItems',0)}..{limits['maxItems']} items.")
            if limits.get('uniqueItems'):parts.append('Unique.')
            if 'minimum' in limits or 'maximum' in limits:parts.append(f"Range {limits.get('minimum','unbounded')}..{limits.get('maximum','unbounded')}.")
            suffix=' '.join(parts)
            schema['description']=(schema.get('description','')+' '+suffix).strip()
        for child in schema.get('properties',{}).values():visit(child)
        if isinstance(schema.get('items'),dict):visit(schema['items'])
    for tool in result:visit(tool['function']['parameters'])
    return result

"""CLI-only name convenience; query comparisons never rewrite evidence."""
import ntpath
from forensic_assistant.artifacts.paths import normalize_path


def predicate(value, *, contains=False):
    # Preserve existing MFT filename/path and Registry target roles. Neither
    # establishes execution. Prefetch identity comes only from its executable.
    role = """((e.source_type='prefetch' AND o.role='executable_name') OR
        (e.source_type<>'prefetch' AND o.role IN
        ('process_image','executable_name','executable_path_candidate','file_path','filename','persistence_target')))"""
    if contains:
        match='instr(o.basename,?)>0';params=[value.lower()]
    else:
        p=normalize_path(value);names=[p['basename']]
        if names[0] and names[0] not in ('.','..') and not ntpath.splitext(names[0])[1] and not p['warnings']:
            names.append(names[0]+'.exe')
        match='o.basename IN ('+','.join('?' for _ in names)+')';params=names
    return ('EXISTS (SELECT 1 FROM evidence_objects o WHERE o.evidence_id=e.evidence_id AND '+role+' AND '+match+')',params)

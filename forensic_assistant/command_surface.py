"""Canonical CLI paths over stable internal operation identifiers.

Internal identifiers are not accepted aliases. They preserve existing service,
audit and presentation routing while the parser exposes only the paths below.
"""
from .command_catalog import COMMANDS

FAMILIES = {
    'case': 'Open, create and inspect a case',
    'evidence': 'Ingest, find, inspect and export evidence',
    'analyze': 'Model-free forensic correlation and detections',
    'investigation': 'Guided investigation, recorded review and findings',
    'report': 'Case-based and recorded-investigation reports',
    'ai': 'Provider configuration and explicit diagnostics',
    'audit': 'Analyst activity and integrity verification',
    'settings': 'Terminal preferences and application version',
}
PATHS = {
    'status': ('case', 'status'),
    **{name: ('evidence', name) for name in ('search', 'show', 'timeline', 'around', 'semantic', 'source')},
    'dump': ('evidence', 'export'),
    **{'ingest-'+kind: ('evidence', 'ingest', kind) for kind in ('all', 'browser', 'evtx', 'mft', 'prefetch', 'registry')},
    **{name: ('analyze', name) for name in ('logons', 'session', 'process-tree', 'detections')},
    'investigate': ('analyze', 'correlate'),
    'briefing': ('investigation', 'briefing'),
    'investigate-ai': ('investigation', 'advanced', 'current-case'),
    'analyze-timeline': ('investigation', 'advanced', 'timeline'),
    'ask': ('investigation', 'advanced', 'local-query'),
    'ai-history': ('investigation', 'history'),
    'report': ('report',), 'ai': ('ai',), 'activity': ('audit', 'activity'),
}


class Operations:
    """Build each existing operation directly at its canonical parser location."""
    def __init__(self, parser):
        self.root = parser.add_subparsers(dest='family', required=True)
        self.groups = {(): self.root}
        self.choices = {}

    def group(self, path):
        path = tuple(path)
        if path not in self.groups:
            parent = self.group(path[:-1])
            label = FAMILIES.get(path[-1], path[-1].replace('-', ' ').capitalize())
            p = parent.add_parser(path[-1], help=label, description=label)
            self.groups[path] = p.add_subparsers(dest='_'.join(path)+'_operation', required=True)
        return self.groups[path]

    def add_parser(self, name, **kwargs):
        path = PATHS[name]
        if name.startswith('ingest-'):
            note='Mutates the selected case through the existing ingestion service; source evidence is read-only. Review partial outcomes.'
        elif name in ('investigate-ai','ask','analyze-timeline'):
            note='Advanced model-consuming operation; existing provider disclosure and operation-specific approval controls apply.'
        elif name=='briefing':
            note='Analyst-supplied derived information, not evidence. Interview/AI interpretation may contact the configured provider; writes require confirmation.'
        elif name=='report':
            note='Derived output publication. Case and recorded-history reports retain separate grounding contracts.'
        elif name=='source':
            note='Read-only list/show; create/update/assign mutate analyst source metadata and retain existing confirmations.'
        elif name=='ai':
            note='Status and Quick are provider-free; connectivity/full checks and runtime start are explicit operations.'
        else:
            note='Read-only examination by default; derived output files and activity records may be written. Coverage limitations remain significant.'
        kwargs['epilog']=(kwargs.get('epilog','')+' '+note).strip()
        p = self.group(path[:-1]).add_parser(path[-1], **kwargs)
        p.set_defaults(command=name)
        self.choices[name] = p
        return p


def syntax(operation):
    return ' '.join(PATHS.get(operation, (operation,)))

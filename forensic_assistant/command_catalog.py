"""Stable internal operation descriptions; no parser or forensic dependencies."""

from types import MappingProxyType


COMMANDS = MappingProxyType({
    'briefing': 'Review analyst incident leads and approve bounded evidence discovery',
    'ai': 'Configure AI provider and local runtime',
    'activity': 'Review and verify analyst activity',
    'analyze-timeline': 'Analyze a bounded timeline bundle using the local AI model',
    'around': 'Show evidence near a specific event or timestamp',
    'ask': 'Ask the local AI questions about case evidence',
    'detections': 'Show evidence matching Locard detection rules',
    'dump': 'Export retained evidence to case-local CSV files',
    'ingest-all': 'Import all supported forensic artifacts',
    'ingest-browser': 'Ingest Chrome or Edge browsing history and downloads',
    'ingest-evtx': 'Import Windows Event Logs (EVTX)',
    'ingest-mft': 'Import NTFS Master File Table (MFT) evidence',
    'ingest-prefetch': 'Import Windows Prefetch evidence',
    'ingest-registry': 'Import Windows Registry evidence',
    'investigate': 'Gather and correlate evidence around a specific evidence record',
    'investigate-ai': 'Analyze case evidence using the local AI model',
    'ai-history': 'Review or replay saved AI investigations',
    'logons': 'Review Windows logon-related activity from normalized Windows Event Log evidence',
    'process-tree': 'Reconstruct process parent-child relationships',
    'report': 'Generate a forensic investigation report',
    'search': 'Search case evidence',
    'semantic': 'Search case evidence by meaning',
    'session': 'Reconstruct activity within a Windows logon session',
    'show': 'Show details about an evidence record',
    'source': 'Manage evidence sources',
    'status': 'Show case ingestion and evidence status',
    'timeline': 'Browse evidence chronologically',
})


# Compact advisory signatures, not executable templates or a second dispatcher.
# Names/purposes stay authoritative above; parser regression tests verify usage.
INVESTIGATION_INPUTS = MappingProxyType({
    'status': ('status', 'No input; use for the normal status display or details absent from context'),
    'search': ('search --path <filename-or-path> --ids', 'Filename/path lookup via --path; other text needs the appropriate named filter, not positional text; locates candidates; inspect returned IDs with show before correlation'),
    'show': ('show <evidence-id>', 'A known evidence record ID, NOT a filename or search term; inspect record meaning and timestamps before correlation'),
    'timeline': ('timeline --around <timestamp>', 'ISO 8601 timestamp with timezone established from inspected records; chronological analysis near that time'),
    'around': ('around <evidence-id>', 'A known inspected evidence ID; for a timestamp use timeline --around'),
    'process-tree': ('process-tree --evidence <evidence-id>', 'Known process-creation evidence ID; requires supported process evidence already identified; analyzes relationships, not an artifact category'),
    'logons': ('logons', 'No required input; normalized Windows authentication events'),
    'session': ('session --logon-id <logon-id>', 'Windows authentication Logon ID, not a Locard evidence ID; may need host/anchor disambiguation'),
    'detections': ('detections', 'No required input; deterministic rule matches, not proof of compromise'),
    'investigate': ('investigate <evidence-id>', 'Known evidence ID as the anchor for related evidence'),
    'semantic': ('semantic search "<text>"', 'Text/question for similarity retrieval; requires local semantic setup/index; similarity is not evidence'),
})


def investigation_capabilities():
    """Small catalog projection for advisory use only; no command execution."""
    from .command_surface import syntax
    return {syntax(name): {'purpose': COMMANDS[name], 'usage': syntax(name) + usage[len(name):], 'input': expected}
            for name, (usage, expected) in INVESTIGATION_INPUTS.items()}

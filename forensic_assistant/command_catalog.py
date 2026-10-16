"""Canonical top-level help metadata; no parser or forensic dependencies."""

from types import MappingProxyType


COMMANDS = MappingProxyType({
    'add-evidence': 'Compatibility alias for ingest wizard',
    'ingest-wizard': 'Guided evidence discovery and ingestion',
    'ai': 'Compatibility notice: prefix advisory requests with !',
    'expert': 'Compatibility notice: the shell has no mode switch',
    '?': 'Show help for a command',
    'activity': 'Review and verify analyst activity',
    'analyze-timeline': 'Analyze timeline evidence using the local AI model',
    'around': 'Show evidence near a specific event or timestamp',
    'ask': 'Ask the local AI questions about case evidence',
    'case': 'Open or create a case',
    'new-case': 'Create a case with guided evidence discovery and ingestion',
    'color': 'Turn terminal colors on or off',
    'detections': 'Show evidence matching Locard detection rules',
    'exit': 'Exit Locard',
    'help': 'Show help for a command',
    'ingest': 'Ingest evidence directly or launch guided ingestion',
    'ingest-all': 'Import all supported forensic artifacts',
    'ingest-browser': 'Ingest Chrome or Edge browsing history and downloads',
    'ingest-evtx': 'Import Windows Event Logs (EVTX)',
    'ingest-mft': 'Import NTFS Master File Table (MFT) evidence',
    'ingest-prefetch': 'Import Windows Prefetch evidence',
    'ingest-registry': 'Import Windows Registry evidence',
    'investigate': 'Gather related evidence around an event',
    'investigate-ai': 'Analyze case evidence using the local AI model',
    'investigation': 'Review or replay saved AI investigations',
    'logons': 'Review Windows logon-related activity from normalized Windows Event Log evidence',
    'process-tree': 'Reconstruct process parent-child relationships',
    'quit': 'Exit Locard',
    'report': 'Generate a forensic investigation report',
    'search': 'Search case evidence',
    'semantic': 'Search case evidence by meaning',
    'session': 'Reconstruct activity within a Windows logon session',
    'show': 'Show details about an evidence record',
    'source': 'Manage evidence sources',
    'status': 'Show case ingestion and evidence status',
    'timeline': 'Browse evidence chronologically',
    'version': 'Show the Locard version',
})


# Shell-only commands participate in the same catalog without adding CLI parsers.
SHELL_COMMANDS = MappingProxyType({
    name: COMMANDS[name]
    for name in ('?', 'add-evidence', 'ingest-wizard', 'ai', 'expert', 'case', 'new-case', 'color', 'exit', 'help', 'quit', 'version')
})


COMMAND_ALIASES = MappingProxyType({
    'add-evidence': 'ingest wizard',
    'ai': '!', 'expert': '!', 'ask': '!',
    **{'ingest-' + kind: 'ingest ' + kind for kind in
       ('all', 'browser', 'evtx', 'mft', 'prefetch', 'registry', 'wizard')},
})


# Compact advisory signatures, not executable templates or a second dispatcher.
# Names/purposes stay authoritative above; parser regression tests verify usage.
INVESTIGATION_INPUTS = MappingProxyType({
    'status': ('status', 'No input; use for the normal status display or details absent from context'),
    'search': ('search --path <filename-or-path> --ids', 'Filename/path lookup via --path; other text needs the appropriate named filter, not positional text; returned IDs can be used with show'),
    'show': ('show <evidence-id>', 'A known evidence record ID, NOT a filename or search term'),
    'timeline': ('timeline --around <timestamp>', 'ISO 8601 timestamp with timezone; chronological view near that time'),
    'around': ('around <evidence-id>', 'A known evidence ID; for a timestamp use timeline --around'),
    'process-tree': ('process-tree --evidence <evidence-id>', 'Known process-creation evidence ID; requires supported process evidence'),
    'logons': ('logons', 'No required input; normalized Windows authentication events'),
    'session': ('session --logon-id <logon-id>', 'Windows authentication Logon ID, not a Locard evidence ID; may need host/anchor disambiguation'),
    'detections': ('detections', 'No required input; deterministic rule matches, not proof of compromise'),
    'investigate': ('investigate <evidence-id>', 'Known evidence ID as the anchor for related evidence'),
    'semantic': ('semantic search "<text>"', 'Text/question for similarity retrieval; requires local semantic setup/index; similarity is not evidence'),
})


def investigation_capabilities():
    """Small catalog projection for advisory use only; no command execution."""
    return {name: {'purpose': COMMANDS[name], 'usage': usage, 'input': expected}
            for name, (usage, expected) in INVESTIGATION_INPUTS.items()}

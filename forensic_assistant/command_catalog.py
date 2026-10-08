"""Canonical top-level help metadata; no parser or forensic dependencies."""

from types import MappingProxyType


COMMANDS = MappingProxyType({
    '?': 'Show help for a command',
    'analyze-timeline': 'Analyze timeline evidence using the local AI model',
    'around': 'Show evidence near a specific event or timestamp',
    'ask': 'Ask the local AI questions about case evidence',
    'case': 'Open or create a case',
    'color': 'Turn terminal colors on or off',
    'detections': 'Show  evidence matching Locard detection rules',
    'exit': 'Exit Locard',
    'help': 'Show help for a command',
    'ingest': 'Import EVTX files from a directory',
    'ingest-all': 'Import all supported forensic artifacts',
    'ingest-browser': 'Ingest Chrome or Edge browsing history and downloads',
    'ingest-evtx': 'Import Windows Event Logs (EVTX)',
    'ingest-mft': 'Import NTFS Master File Table (MFT) evidence',
    'ingest-prefetch': 'Import Windows Prefetch evidence',
    'ingest-registry': 'Import Windows Registry evidence',
    'investigate': 'Gather related evidence around an event',
    'investigate-ai': 'Analyze case evidence using the local AI model',
    'investigation': 'Review or replay saved AI investigations',
    'logons': 'Review Windows logon activity',
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
    for name in ('?', 'case', 'color', 'exit', 'help', 'quit', 'version')
})
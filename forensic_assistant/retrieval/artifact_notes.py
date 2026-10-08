"""Shared human forensic notes; stored parser warnings remain unchanged."""

PREFETCH = (
    'Missing Prefetch does not prove a program never ran.',
    'The run count and retained run times are not a complete execution history.',
    'Referenced files were accessed or used by the program; they were not necessarily executed.',
    'Prefetch run times record execution-related timestamps, but they do not identify unique process instances.'
)
PREFETCH_PARSER = 'Directory information is not available with the current Prefetch parser.'
USERASSIST = (
    'UserAssist can indicate that an application was launched or interacted with, but it does not prove user intent or a unique process execution.',
    'Registry key LastWrite is separate from the UserAssist internal timestamp.',
    'Control and special UserAssist entries are not application executions.'
)
USERASSIST_PARSER = 'Known-folder GUIDs are preserved as recorded rather than mapped to guessed paths.'

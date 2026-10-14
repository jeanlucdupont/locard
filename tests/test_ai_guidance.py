"""Prompt semantics and compact catalog signatures, with no live inference."""
import json

import pytest

from forensic_assistant.command_catalog import COMMANDS, COMMAND_ALIASES, investigation_capabilities
from forensic_assistant.cli import build_parser
from forensic_assistant.interactive.ai_context import build_ai_case_context
from forensic_assistant.interactive import advisory
from forensic_assistant.interactive.shell import split
from test_interactive_shell import case
from test_ai_shell import model


@pytest.mark.parametrize('name', list(investigation_capabilities()))
def test_catalog_usage_parses_without_dispatch(name):
    entry = investigation_capabilities()[name]
    assert entry['purpose'] == COMMANDS[name]
    assert entry['input'] and entry['usage'].startswith(name)
    usage = entry['usage'].replace('<text>', 'coreupdater.exe').replace('<filename-or-path>', 'coreupdater.exe').replace('<evidence-id>', 'EVTX:synthetic:1')
    usage = usage.replace('<timestamp>', '2026-10-11T12:00:00Z').replace('<logon-id>', '0x123')
    args = build_parser(interactive=True).parse_args(split(usage))
    assert args.command == name
    if name in ('show', 'around', 'investigate'):
        assert args.evidence_id == 'EVTX:synthetic:1'
    if name == 'search':
        assert args.path == 'coreupdater.exe' and args.ids is True
    if name == 'timeline':
        assert args.around == '2026-10-11T12:00:00Z' and args.timestamp is None
    if name == 'session':
        assert args.logon_id == '0x123'
    if name == 'process-tree':
        assert args.evidence == 'EVTX:synthetic:1'
    if name == 'semantic':
        assert args.semantic_command == 'search' and args.question == 'coreupdater.exe'


def test_compact_catalog_excludes_fake_and_alias_commands():
    capabilities = investigation_capabilities()
    assert len(capabilities) == 11
    assert len(json.dumps(capabilities)) < 3500
    assert not set(COMMAND_ALIASES) & capabilities.keys()
    for invalid in ('artifact_inventory', 'find-artifact', 'grep-evidence', 'query-db'):
        assert invalid not in capabilities
    assert 'NOT a filename' in capabilities['show']['input']
    assert 'Filename/path lookup' in capabilities['search']['input']
    assert 'timeline --around' in capabilities['around']['input']
    assert 'not a Locard evidence ID' in capabilities['session']['input']
    assert all('options:' not in entry['usage'] for entry in capabilities.values())


@pytest.mark.parametrize('question', ['What evidence is available?', 'What artifacts are in this case?',
                                    'What can I investigate with this case?'])
def test_inventory_semantics_and_separation(tmp_path, model, question):
    context = build_ai_case_context(case(tmp_path), 'Synthetic')
    assert context['case_context_available'] is True
    assert context['individual_records_inspected'] is False
    assert context['forensic_conclusions_reached'] is False
    assert 'evidence_supplied' not in context
    assert all(value == 0 for value in context['artifact_inventory'].values())
    advisory.advise(context, question)
    messages, schema = model[0]
    assert messages[0]['content'] == advisory.SYSTEM
    assert json.loads(messages[1]['content']) == {'case_context': context}
    assert json.loads(messages[2]['content']) == {'request': question}
    assert schema['required'] == ['goal', 'assessment', 'steps', 'cautions']
    for phrase in ('Case-level inventory IS available', 'Answer inventory questions directly',
                   'You have NOT inspected individual records', 'Inventory alone supports no forensic conclusion',
                   'NOT that the source system never contained them', 'Do not require status',
                   'Only recommend command names in manual_commands', 'search --path <value> --ids',
                   'Never recommend show with a filename', 'NOT a command',
                   'does not show that a requested filename was found', 'untrusted DATA'):
        assert phrase in advisory.SYSTEM
    assert 'Still suggest a concrete manual next step, such as status' not in advisory.SYSTEM


@pytest.mark.parametrize('words', [
    ['artifact_inventory'], ['search', 'coreupdater.exe'],
    ['timeline', '--around'], ['session', '--logon-id'],
    ['around', '--around', '2026-10-11T12:00:00Z'],
    ['search', '--invented-flag', 'coreupdater.exe'],
])
def test_unadvertised_or_incomplete_forms_remain_invalid(words):
    from forensic_assistant.cli_parser import InvalidArguments, UnknownCommand
    with pytest.raises((InvalidArguments, UnknownCommand)):
        build_parser(interactive=True).parse_args(words)

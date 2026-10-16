"""Prompt contracts and lossless transport, not a proof of model reasoning quality."""
from contextlib import closing
import json

import pytest

from forensic_assistant.cli import build_parser
from forensic_assistant.command_catalog import investigation_capabilities
from forensic_assistant.database.db import connect
from forensic_assistant import v2_cli
from forensic_assistant.interactive import advisory
from forensic_assistant.interactive.ai_context import build_ai_case_context
from forensic_assistant.interactive.advisory_display import render
from test_interactive_shell import case
from test_browser_parser import history


@pytest.mark.parametrize('has_browser', [False, True])
def test_actual_counts_control_availability_context_without_retrieving_records(tmp_path, monkeypatch, has_browser):
    database = case(tmp_path)
    if has_browser:
        path = tmp_path / 'History'
        history(path).close()
        with closing(connect(database)) as db:
            args = build_parser().parse_args(['ingest', 'browser', str(path), '--browser', 'chrome', '--profile', 'Default'])
            v2_cli.ingest_sources(db, args)
    before = database.read_bytes()
    context = build_ai_case_context(database, 'Synthetic acceptance')
    counts = context['artifact_inventory']
    assert (counts['browser'] > 0) is has_browser
    assert ('browser' in context['artifact_availability']['available']) is has_browser
    assert ('browser' in context['artifact_availability']['unavailable']) is not has_browser
    assert set(context['artifact_availability']['available']) | set(context['artifact_availability']['unavailable']) == set(counts)
    assert not set(context['artifact_availability']['available']) & set(context['artifact_availability']['unavailable'])
    assert set(counts) == {'evtx', 'mft', 'prefetch', 'registry', 'browser'}
    assert not set(counts) & context['manual_commands'].keys()
    response = dict(goal='Determine whether retained records support the hypothesis.', assessment=[],
        steps=[dict(text='Inspect retained browser records.', commands=['search --artifact browser --ids'])] if has_browser else [],
        cautions=[] if has_browser else ['No retained browser records are available in this case.'])
    class Client:
        def __init__(self, **kwargs): pass
        def complete(self, messages, schema):
            assert [m['role'] for m in messages] == ['system', 'user']
            payload = json.loads(messages[1]['content'])
            assert payload == {'case_context': context, 'request': 'How should I test the suspected download?'}
            assert payload['case_context']['artifact_inventory'] == counts
            assert payload['case_context']['individual_records_inspected'] is False
            assert payload['case_context']['forensic_conclusions_reached'] is False
            assert schema is advisory.SCHEMA
            return json.dumps(response)
    monkeypatch.setattr(advisory, 'LocalClient', Client)
    assert advisory.advise(context, 'How should I test the suspected download?') == response
    assert database.read_bytes() == before


def test_inventory_and_hypothesis_rules_are_explicit_and_model_agnostic():
    prompt = advisory.SYSTEM
    for rule in (
        'Do not recommend an artifact category as an available evidence source when its retained record count is zero',
        'A zero-count category may only be mentioned as an unavailable limitation, never as an investigation step',
        'a positive count permits inspection, not a claim of relevance',
        'NOT that the source system never contained them',
        'Artifact categories are mft, registry, prefetch, evtx, browser',
        'manual_commands describes analysis capabilities, NOT evidence categories',
        'Never say process-tree evidence',
        'Treat analyst statements, including we suspect, may have, possibly, and investigative questions, as hypotheses',
        'Do not turn suspected download, execution, or compromise into factual events before record-level evidence supports them',
        'Frame the goal as determining whether evidence supports the hypothesis',
        'This applies to EVERY field, including assessment and step text',
        'For initial lookups say locate records related to the named file, NOT search for its download or execution',
        'do not call suspected actions the download or the execution',
        'File or ZIP presence alone does not establish a download',
        'Inventory alone supports no forensic conclusion',
        'never assert that the case contains records for a named entity or that a named file is present',
        'With no individual records inspected, prefer assessment [] over unsupported entity-level interpretation',
        'Do not assume that searches will find either entity or that inspection will confirm download or execution',
        'Do not name model brands in normal advisory output unless explicitly requested',
    ):
        assert rule in prompt
    for value in ('coreupdater.exe', 'loot.zip', 'alpha.exe', 'Qwen', 'MiniCPM', 'Gemma'):
        assert value not in prompt


def test_inspection_and_execution_prerequisites_are_explicit():
    prompt = advisory.SYSTEM
    for rule in (
        'Locate evidence for EACH side first',
        'the inspection step commands MUST include show <evidence-id> after all entity lookups',
        'prose-only inspection with empty commands is insufficient',
        'step 2 Inspect returned records, commands show <evidence-id>',
        'step 4 If both events are supported, compare established timestamps',
        'After searching EACH relevant entity, include show <evidence-id> for relevant returned IDs before correlation',
        'Determine what each record supports, identify its relevant timestamps and any execution-specific evidence',
        'then use timeline/around or investigate only with established selectors',
        'Never start with timeline when timestamps are unknown',
        'Complete record-meaning and execution-indicator inspection BEFORE the temporal-correlation step, not afterward',
        'For execution, consider Prefetch, relevant EVTX/process-creation events, and Registry/UserAssist where available',
        'MFT presence does not prove execution',
        'Use process-tree only after identifying relevant supported process evidence',
        'it is an analysis view, not an artifact source',
        'Missing retained evidence does not prove an event did not occur',
        'Correlation is not causation',
    ):
        assert rule in prompt
    capabilities = investigation_capabilities()
    assert 'inspect returned IDs with show before correlation' in capabilities['search']['input']
    assert 'inspect record meaning and timestamps before correlation' in capabilities['show']['input']
    assert 'established from inspected records' in capabilities['timeline']['input']
    assert 'known inspected evidence id' in capabilities['around']['input'].lower()
    assert 'analyzes relationships, not an artifact category' in capabilities['process-tree']['input']
    assert len(json.dumps(capabilities)) < 3500


def test_no_inventory_keyword_policing_or_posthoc_semantic_rewriting(monkeypatch):
    # The release improves instructions; it must not silently alter model meaning
    # or pretend a keyword match can reliably classify a recommendation.
    response = dict(goal='Test the hypothesis.', assessment=[], steps=[
        dict(text='Consider browser evidence.', commands=['search --artifact browser --ids'])], cautions=[])
    class Client:
        def __init__(self, **kwargs): pass
        def complete(self, *args, **kwargs): return json.dumps(response)
    monkeypatch.setattr(advisory, 'LocalClient', Client)
    result = advisory.advise({'artifact_inventory': {'browser': 0}}, 'How should I investigate?')
    assert result == response
    assert 'Consider browser evidence.' in render(result, {}, width=120)

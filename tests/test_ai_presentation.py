"""Presentation-only sections: synthetic context and fake model responses."""
import json

import pytest

from forensic_assistant.interactive import advisory
from forensic_assistant.interactive.advisory_display import render, sections, INTERNAL_TERMS
from forensic_assistant.terminal import Palette, SGR
from test_ai_shell import run_shell

INVENTORY = '[Case inventory]\n[Sources]\n[Current assessment]\n- Individual records have not been inspected.\n- No forensic conclusions have been reached.'
PLAN = ('[Goal]\nTest the proposed sequence for coreupdater.exe and loot.zip.\n'
        '[Suggested approach]\n1. Locate both files.\n'
        '   search --path coreupdater.exe --ids\n   search --path loot.zip --ids\n'
        '2. Inspect returned records, then compare timestamps.\n   show <evidence-id>\n'
        '[Important cautions]\n- MFT presence alone does not prove execution.\n'
        '- Correlation is not causation.\n- Individual records have not been inspected.')


def context():
    return {'artifact_inventory': dict(evtx=40917, mft=82, prefetch=196, registry=825888, browser=0),
            'sources': {'total': 2, 'shown': 2, 'truncated': False, 'items': [
                dict(display_name='G drive', hostname='desktop-test', username='J Smith', volume_root=None),
                dict(display_name='MFT from DFIR', hostname=None, username=None, volume_root='C:')]},
            'truncated_fields': []}


def test_inventory_rows_sources_and_assessment_are_separate():
    text = render(INVENTORY, context(), width=120)
    assert text.startswith('\nCase inventory\n')
    for row in ('evtx      40,917 records', 'mft       82 records', 'registry  825,888 records', 'browser   0 records'):
        assert '  ' + row in text.splitlines()
    assert '\n\nSources\n' in text and '\n\nCurrent assessment\n' in text
    assert '  1. G drive — host: desktop-test, user: J Smith' in text
    assert '  2. MFT from DFIR — volume: C:' in text
    assert '  - No forensic conclusions have been reached.' in text
    assert 'source system' not in text


def test_multi_entity_plan_layout_does_not_reorder_or_rewrite_claims():
    text = render(PLAN, context(), width=120)
    assert '\nGoal\n' in text and '\n\nSuggested approach\n' in text
    assert '  1. Locate both files.' in text
    assert '     search --path coreupdater.exe --ids' in text.splitlines()
    assert '     search --path loot.zip --ids' in text.splitlines()
    assert text.index('loot.zip --ids') < text.index('show <evidence-id>')
    assert '  - MFT presence alone does not prove execution.' in text.splitlines()
    assert 'status' not in text
    assert not any(term in text for term in INTERNAL_TERMS)
    assert 'Address every relevant named entity' in advisory.SYSTEM
    assert 'lookups for BOTH' in advisory.SYSTEM
    assert 'Do not require status to repeat inventory' in advisory.SYSTEM


def test_semantic_styles_never_mark_advice_as_success():
    calls = []
    def palette(role, text):
        calls.append((role, text))
        return text
    text = render(PLAN + '\n[Recommended commands]\nsearch --path loot.zip --ids', context(), palette, width=120)
    assert ('heading', 'Goal') in calls
    assert any(role == 'warning' and 'Correlation' in text for role, text in calls)
    assert ('key', '  search --path loot.zip --ids') in calls
    assert not any(role in ('success', 'string_value') for role, _ in calls)
    assert not any('Test the proposed' in text for _, text in calls)
    assert '\x1b' not in text


def test_wrapping_and_control_escaping():
    data = context()
    data['sources']['items'][0]['display_name'] = 'évidence\x1b[2J\nsource'
    text = render(INVENTORY, data, Palette(True), width=35)
    assert '\x1b[2J' not in text
    assert all(len(SGR.sub('', line)) <= 35 for line in text.splitlines())
    assert '\x1b' not in render(PLAN, context(), Palette(False), width=80)


@pytest.mark.parametrize('term', INTERNAL_TERMS)
def test_internal_vocabulary_is_rejected_not_rewritten(term):
    with pytest.raises(ValueError, match='vocabulary'):
        sections('[Notes]\nUse the ' + term + '\n[Important cautions]\n- Advice only.')


@pytest.mark.parametrize('bad', [
    'One dense paragraph with no sections.', '[Goal]\nOnly one section',
    '[Goal]\n[Notes]\nEmpty goal', '[Goal]\nA\n[Goal]\nB',
    '[Case inventory]\nevtx 999999 records\n[Notes]\nUnverified counts',
    '[Sources]\n1. Invented source\n[Notes]\nUnverified source',
])
def test_invalid_layout_never_invents_sections_or_inventory(bad):
    with pytest.raises(ValueError):
        sections(bad)


def test_source_truncation_and_missing_registry_are_visible():
    data = context()
    data['sources'].update(total=12, truncated=True)
    data['truncated_fields'] = ['sources[0].display_name']
    text = render(INVENTORY, data, width=120)
    assert '12 sources; showing 2' in text
    assert 'Additional sources are not shown.' in text and 'were shortened.' in text
    data['sources'].update(total=None, items=[], shown=0)
    assert 'registry unavailable' in render(INVENTORY, data)


@pytest.mark.parametrize('response', [INVENTORY, PLAN])
def test_shell_response_header_and_readonly_advisory_boundary(tmp_path, monkeypatch, capsys, response):
    class Client:
        timeout = 45
        def __init__(self, **kwargs):
            pass
        def complete(self, messages, schema):
            assert schema['required'] == ['advice']
            return json.dumps({'advice': response})
    monkeypatch.setattr(advisory, 'LocalClient', Client)
    monkeypatch.setattr('forensic_assistant.cli.dispatch', lambda *a, **k: pytest.fail('Model dispatched'))
    run_shell(tmp_path, 'ai', '! Compare coreupdater.exe and loot.zip')
    text = capsys.readouterr().out
    assert text.count('AI assistant — advisory, not evidence') == 1
    assert '\n\n' in text
    assert not any(term in text for term in INTERNAL_TERMS)


def test_internal_term_response_is_not_printed_or_recorded(tmp_path, monkeypatch, capsys):
    class Client:
        timeout = 45
        def __init__(self, **kwargs):
            pass
        def complete(self, *args, **kwargs):
            return json.dumps({'advice': '[Notes]\nSECRET manual_commands\n[Goal]\nTest'})
    monkeypatch.setattr(advisory, 'LocalClient', Client)
    _, _, path = run_shell(tmp_path, 'ai', '! question')
    from forensic_assistant import activity
    text = capsys.readouterr().out
    assert 'invalid response' in text and 'SECRET' not in text and 'manual_commands' not in text
    log = activity.sidecar(path).read_text(encoding='utf-8')
    assert 'SECRET' not in log and 'manual_commands' not in log

"""Structured advice and deterministic inventory; synthetic data only."""
import json
import pytest
from forensic_assistant.interactive import advisory
from forensic_assistant.interactive.advisory_display import render, INTERNAL_TERMS
from forensic_assistant.terminal import Palette, SGR
from test_ai_shell import run_shell


def plan():
    return {'goal': 'Compare coreupdater.exe and loot.zip.', 'assessment': [],
            'steps': [{'text': 'Locate both files.', 'commands': [
                'search --path coreupdater.exe --ids', 'search --path loot.zip --ids']},
                {'text': 'Inspect returned records.', 'commands': ['show <evidence-id>']}],
            'cautions': ['MFT presence alone does not prove execution.']}


def model(monkeypatch, raw):
    class Client:
        timeout = 45
        def __init__(self, **kwargs): pass
        def complete(self, messages, schema):
            assert schema is advisory.SCHEMA
            return raw
    monkeypatch.setattr(advisory, 'LocalClient', Client)


def context():
    return {'artifact_inventory': dict(evtx=40917, mft=82, prefetch=196, registry=825888, browser=0),
            'sources': {'total': 2, 'shown': 2, 'truncated': False, 'items': [
                dict(display_name='G drive', hostname='desktop-test', username='J Smith', volume_root=None),
                dict(display_name='MFT from DFIR', hostname=None, username=None, volume_root='C:')]},
            'truncated_fields': []}



def test_structured_contract_and_deterministic_rendering(monkeypatch):
    model(monkeypatch, json.dumps(plan()))
    result = advisory.advise(context(), 'Investigate both files')
    assert result == plan()
    text = render(result, context(), width=120)
    assert '\nGoal\n' in text and '\nSuggested approach\n' in text
    assert '  1. Locate both files.' in text and '  2. Inspect returned records.' in text
    for command in plan()['steps'][0]['commands']:
        assert '     ' + command in text.splitlines()
    assert text.index('loot.zip --ids') < text.index('2. Inspect') < text.index('show <evidence-id>')
    assert '  - MFT presence alone does not prove execution.' in text
    assert 'Current assessment' not in text
    assert 'coreupdater.exe' not in advisory.SYSTEM and 'loot.zip' not in advisory.SYSTEM
    assert 'do not leave a filename placeholder when its value is known' in advisory.SYSTEM
    assert '[Goal]' not in advisory.SYSTEM and '2 to 5' not in advisory.SYSTEM
    assert 'Apply operating and safety rules silently' in advisory.SYSTEM


@pytest.mark.parametrize('goal', [None, ''])
def test_optional_sections_omitted(goal):
    result = advisory.validate_response(dict(goal=goal, assessment=['Unknown.'], steps=[], cautions=[]), 'question')
    assert render(result, {}) == '\nCurrent assessment\n  - Unknown.'


@pytest.mark.parametrize('field,value', [
    ('goal', 1), ('goal', 'x' * 501), ('assessment', 'text'),
    ('assessment', ['x'] * 7), ('assessment', ['x' * 501]),
    ('steps', [{}] * 9), ('steps', [{'text': 'x', 'commands': ['x'] * 7}]),
    ('steps', [{'text': 'x' * 801, 'commands': []}]),
    ('steps', [{'text': 'x', 'commands': ['x' * 501]}]),
    ('steps', [{'text': 'x', 'commands': [False]}]),
    ('steps', [{'text': 'x', 'commands': ['a\nb']}]),
    ('steps', [{'text': 'x', 'commands': [], 'actions': []}]),
    ('cautions', ['x'] * 9), ('cautions', ['x' * 501]), ('cautions', [None]),
])
def test_invalid_fields_fail_closed(monkeypatch, field, value):
    response = plan(); response[field] = value
    model(monkeypatch, json.dumps(response))
    with pytest.raises(advisory.AdvisoryError, match='schema'):
        advisory.advise({}, 'question')


@pytest.mark.parametrize('raw', [
    'not JSON', '[]', '{"advice":"legacy prose"}',
    '{"goal":null,"goal":null,"assessment":[],"steps":[],"cautions":["x"]}',
    '{"goal":null,"assessment":[],"steps":[{"text":"x","text":"y","commands":[]}],"cautions":[]}',
    json.dumps(dict(plan(), inventory={'registry': 1})),
    json.dumps(dict(plan(), sources=['invented'])),
    json.dumps(dict(assessment=[], steps=[], cautions=['x'])),
    json.dumps(dict(goal=None, assessment=[], steps=[], cautions=[])),
    'x' * 16385, None,
])
def test_invalid_contract_and_bounds(monkeypatch, raw):
    model(monkeypatch, raw)
    with pytest.raises(advisory.AdvisoryError, match='invalid response') as error:
        advisory.advise({}, 'question')
    assert len(str(error.value)) < 6800


def put_text(response, field, text):
    if field in ('goal',): response[field] = text
    elif field in ('assessment', 'cautions'): response[field] = [text]
    elif field == 'text': response['steps'][0]['text'] = text
    else: response['steps'][0]['commands'] = [text]


@pytest.mark.parametrize('field', ['goal', 'assessment', 'text', 'commands', 'cautions'])
@pytest.mark.parametrize('term', INTERNAL_TERMS)
def test_every_structured_text_field_rejects_internal_terms(monkeypatch, field, term):
    response = plan(); put_text(response, field, term)
    model(monkeypatch, json.dumps(response))
    with pytest.raises(advisory.AdvisoryError, match='internal_vocabulary'):
        advisory.advise({}, 'question')


@pytest.mark.parametrize('field', ['goal', 'assessment', 'text', 'commands', 'cautions'])
def test_metadata_guard_applies_to_all_fields(monkeypatch, field):
    response = plan(); put_text(response, field, 'locard_version historical')
    model(monkeypatch, json.dumps(response))
    with pytest.raises(advisory.AdvisoryError, match='metadata_echo'):
        advisory.advise({}, 'Investigate')
    assert advisory.advise({}, 'What is the Locard version?') == response


def test_styles_and_wrapping():
    response = plan()
    response['cautions'] = ['Individual records remain uninspected; metadata is analyst-supplied, not verified evidence.']
    plain = render(response, {}, Palette(False), width=35)
    colored = render(response, {}, Palette(True), width=35)
    assert SGR.sub('', colored) == plain
    assert all(len(row) <= 35 for row in plain.splitlines())
    assert 'analyst-supplied, not verified evidence.' in ' '.join(plain.split())
    roles = []
    render(response, {}, lambda role, text: roles.append(role) or text)
    assert 'heading' in roles and 'key' in roles and 'warning' in roles
    assert 'success' not in roles and 'string_value' not in roles


def test_commands_wrap_without_interpretation():
    response = plan(); response['steps'] = [{'text': 'Inspect.', 'commands': ['search --path example.exe --ids']}]
    rows = render(response, {}, width=25).splitlines()
    commands = [row for row in rows if row.startswith('     ')]
    assert ' '.join(' '.join(commands).split()) == 'search --path example.exe --ids'


@pytest.mark.parametrize('question', sorted(advisory.INVENTORY_QUESTIONS))
def test_inventory_remains_authoritative_without_model(monkeypatch, question):
    monkeypatch.setattr(advisory, 'LocalClient', lambda **kw: pytest.fail('Inventory called model'))
    result = advisory.advise(context(), question.upper() + '?')
    text = render(result, context(), width=120)
    assert 'registry  825,888 records' in text and 'evtx      40,917 records' in text
    assert 'browser   0 records' in text
    assert 'G drive — host: desktop-test, user: J Smith' in text
    assert 'Individual records have not been inspected.' in text
    assert 'No forensic conclusions have been reached.' in text
    assert 'locard_version' not in text and 'mode AI' not in text
    assert text.index('evtx') < text.index('mft') < text.index('prefetch') < text.index('registry') < text.index('browser')


def test_inventory_source_limits():
    data=context(); data['sources'].update(total=12, truncated=True)
    data['truncated_fields']=['sources[0].display_name']
    text=render(advisory.INVENTORY_ADVICE, data)
    assert 'Additional sources are not shown.' in text and 'were shortened.' in text
    data['sources'].update(total=None, items=[], shown=0)
    assert 'registry unavailable' in render(advisory.INVENTORY_ADVICE, data)


@pytest.mark.parametrize('question', ['What sources are loaded and what should I investigate?', 'What does this case contain about example.exe?'])
def test_qualified_inventory_questions_use_model(monkeypatch, question):
    model(monkeypatch, json.dumps(plan()))
    assert advisory.advise(context(), question) == plan()


def test_deterministic_inventory_shell_preserves_header_audit(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(advisory, 'LocalClient', lambda **kw: pytest.fail('Model'))
    monkeypatch.setattr('forensic_assistant.cli.dispatch', lambda *a, **k: pytest.fail('Dispatch'))
    _, _, path=run_shell(tmp_path, 'ai', '! What evidence is available in this case?')
    from forensic_assistant import activity
    assert 'AI assistant — advisory, not evidence' in capsys.readouterr().out
    assert 'AI_ADVICE' in activity.sidecar(path).read_text(encoding='utf-8')


def test_rejected_diagnostic_not_accepted_or_logged(tmp_path, monkeypatch, capsys):
    response=plan(); response['goal']='SECRET manual_commands'
    model(monkeypatch, json.dumps(response))
    _, _, path=run_shell(tmp_path, 'ai', '! question')
    from forensic_assistant import activity
    text=capsys.readouterr().out
    assert 'diagnostic only, not evidence' in text and 'SECRET' in text
    assert 'AI assistant — advisory, not evidence' not in text
    assert 'SECRET' not in activity.sidecar(path).read_text(encoding='utf-8')


def test_response_character_count_is_text_not_field_count():
    response=plan()
    assert advisory.response_characters(response) == sum(map(len, [response['goal'], *[v for s in response['steps'] for v in [s['text'], *s['commands']]], *response['cautions']]))

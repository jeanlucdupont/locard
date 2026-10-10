"""Shared lifecycle and human ASK integration, using synthetic evidence only."""
import copy
import json
from pathlib import Path

import pytest

from forensic_assistant.cli import build_parser, dispatch
from forensic_assistant.database.db import connect
from forensic_assistant.llm.ask import ask
from forensic_assistant.llm.presentation import render
from forensic_assistant.retrieval.queries import Queries
from forensic_assistant.semantic import cli, index, model, runtime
from forensic_assistant.semantic.documents import fingerprint
from forensic_assistant.semantic.presentation import render as semantic_render
from forensic_assistant.terminal import Palette, STYLES
from forensic_assistant.activity import Cancelled
from test_semantic_workflow import environment, ready_model, manifest
from v1_fixtures import database, process
from v2_fixtures import mft_file


@pytest.fixture
def case(environment):
    path = environment / 'synthetic.db'
    source = database()
    eid = process(source, 1, '100')['id']
    db = connect(path)
    source.backup(db)
    source.close()
    yield path, db, eid
    db.close()


def request(path, *extra, interactive=True, question='suspicious credential use'):
    return build_parser(interactive=interactive).parse_args(['--db', str(path), 'ask', question, *extra])


@pytest.mark.parametrize('persist', [False, True])
def test_ask_reuses_current_shared_state(case, monkeypatch, persist):
    path, db, eid = case
    fake = ready_model(monkeypatch)
    if persist:
        old = runtime.model_path()
        chosen = path.parent / 'chosen model é'
        old.rename(chosen)
        runtime.remember(chosen)
    seen = []
    monkeypatch.setattr(model, 'LocalModel', lambda p: seen.append(p) or fake)
    root = index.default_root(path)
    index.build(db, root, fake)
    before = fingerprint(db)
    args = request(path)
    args._confirm = lambda p: pytest.fail('ready state must not prompt')
    result = ask(Queries(db), args.question, dry_run=True, semantic_options=args)
    assert seen == [runtime.model_path()]
    assert result['plan']['semantic_coverage'] == 'searched'
    assert result['plan']['semantic_results']['results'][0]['evidence_id'] == eid
    assert result['evidence_bundle']['EVIDENCE'][0]['id'] == eid
    assert result['status'] == 'retrieved_only'
    assert 'Local model unavailable' not in json.dumps(result)
    assert cli.status(db, build_parser().parse_args(['--db', str(path), 'semantic', 'status']))['state'] == 'ready'
    assert fingerprint(db) == before


def test_ask_build_rebuild_resume_and_single_line_confirmation(case, monkeypatch, capsys):
    path, db, eid = case
    ready_model(monkeypatch)
    args = request(path)
    prompts = []
    def confirm(prompt):
        assert not db.in_transaction, 'Approval must not hold an evidence snapshot'
        assert '\n' not in prompt and '\\n' not in prompt
        prompts.append(prompt)
        return 'y'
    args._confirm = confirm
    first = ask(Queries(db), args.question, dry_run=True, semantic_options=args)
    assert first['evidence_bundle']['EVIDENCE'][0]['id'] == eid
    db.execute("UPDATE events SET command_line='synthetic change'")
    db.commit()
    ask(Queries(db), args.question, dry_run=True, semantic_options=args)
    assert prompts == ['Build now? [Y/n]: ', 'Rebuild now? [Y/n]: ']
    output = capsys.readouterr().out
    assert output.count('Semantic index is stale for this case.') == 1
    assert '\\n' not in output
    assert index.status(db, index.default_root(path))['state'] == 'current'


@pytest.mark.parametrize('mode', ['--json', '--text'])
def test_direct_ask_missing_runtime_never_prompts(case, monkeypatch, mode):
    path, db, _ = case
    monkeypatch.setattr(runtime, 'dependencies', lambda: dict(state='missing', python='test-python', install_command='manual install'))
    args = request(path, mode, interactive=False)
    # Direct CLI has no shell reader, including explicit --text.
    with pytest.raises(ValueError, match='manual install'):
        ask(Queries(db), args.question, dry_run=True, semantic_options=args)
    assert not index.default_root(path).exists()


def test_json_never_calls_supplied_approval(case, monkeypatch):
    path, db, _ = case
    ready_model(monkeypatch)
    args = request(path, '--json')
    args._confirm = lambda p: pytest.fail('JSON approval')
    with pytest.raises(ValueError, match='semantic build'):
        ask(Queries(db), args.question, dry_run=True, semantic_options=args)
    assert not index.default_root(path).exists()


def test_ask_declined_setup_cancels_even_with_deterministic_evidence(case, monkeypatch):
    path, db, _ = case
    ready_model(monkeypatch)
    args = request(path, question='PowerShell')
    args._confirm = lambda p: 'n'
    with pytest.raises(Cancelled):
        ask(Queries(db), args.question, dry_run=True, semantic_options=args)
    assert not index.default_root(path).exists()


def test_ask_missing_semantics_preserves_deterministic_fallback(case, monkeypatch):
    path, db, eid = case
    monkeypatch.setattr(runtime, 'dependencies', lambda: dict(state='missing', python='test-python', install_command='manual install'))
    result = ask(Queries(db), 'PowerShell', dry_run=True)
    assert result['plan']['semantic_coverage'] == 'unavailable'
    assert result['evidence_bundle']['EVIDENCE'][0]['id'] == eid
    empty = ask(Queries(db), 'unobserved.exe', dry_run=True)
    assert empty['status'] == 'insufficient_evidence'
    assert empty['plan']['semantic_coverage'] == 'unavailable'
    assert empty['evidence_bundle']['EVIDENCE'] == []
    monkeypatch.setattr(runtime, 'dependencies', lambda: pytest.fail('precise query needs no embeddings'))
    assert ask(Queries(db), 'event ID 4688', dry_run=True)['evidence_bundle']['EVIDENCE'][0]['id'] == eid


def test_ask_first_use_approved_setup_and_overrides(case, monkeypatch, capsys):
    from test_v3_index import FakeModel
    path, db, eid = case
    configured = path.parent / 'saved model'
    configured.mkdir()
    runtime.remember(configured)
    override = path.parent / 'override model'
    root = path.parent / 'override index'
    prompts, downloads = [], []
    def download(destination, choice):
        downloads.append(destination)
        assert prompts == ['Continue? [Y/n]: ']
        destination.mkdir()
    monkeypatch.setattr(model, 'setup', download)
    monkeypatch.setattr(model, 'inspect_model', lambda p: manifest())
    class Model(FakeModel):
        identity = manifest()
        def __init__(self, p):
            assert p == override
    monkeypatch.setattr(model, 'LocalModel', Model)
    args = request(path, '--embedding-model', str(override), '--semantic-index', str(root))
    args._confirm = lambda p: prompts.append(p) or 'yes'
    result = ask(Queries(db), args.question, dry_run=True, semantic_options=args,
                 embedding_model=args.embedding_model, semantic_index=args.semantic_index)
    assert result['evidence_bundle']['EVIDENCE'][0]['id'] == eid
    assert prompts == ['Continue? [Y/n]: ', 'Build now? [Y/n]: ']
    assert downloads == [override] and runtime.model_path() == configured
    assert (root / 'CURRENT').exists() and not index.default_root(path).exists()
    assert capsys.readouterr().out.count('Download the pinned') == 1


def test_ask_malformed_model_preserved_and_index_failure_cleanup(case, monkeypatch):
    path, db, _ = case
    selected = runtime.model_path()
    selected.mkdir(parents=True)
    marker = selected / 'partial'
    marker.write_bytes(b'synthetic partial model')
    args = request(path)
    args._confirm = lambda p: pytest.fail('malformed model must not be overwritten')
    with pytest.raises(ValueError, match='model_malformed'):
        ask(Queries(db), args.question, dry_run=True, semantic_options=args)
    assert marker.read_bytes() == b'synthetic partial model'
    from test_v3_index import FakeModel
    monkeypatch.setattr(model, 'inspect_model', lambda p: manifest())
    class Broken(FakeModel):
        identity = manifest()
        def __init__(self, p):
            pass
        def encode(self, *a, **k):
            raise KeyboardInterrupt()
    monkeypatch.setattr(model, 'LocalModel', Broken)
    args._confirm = lambda p: 'y'
    with pytest.raises(KeyboardInterrupt):
        ask(Queries(db), args.question, dry_run=True, semantic_options=args)
    assert list(index.default_root(path).iterdir()) == []


def test_ask_human_escapes_evidence_control_characters():
    db = database()
    eid = process(db, 1, '100', name='café.exe')['id']
    result = ask(Queries(db), 'event ID 4688', dry_run=True)
    result['evidence_bundle']['EVIDENCE'][0]['process_name'] = 'C:\\café\\bad\x1b[31m.exe'
    text = render(result, Palette())
    assert 'C:\\café\\bad\\u001b[31m.exe' in text
    assert '\x1b' not in text and eid in text
    db.close()


@pytest.mark.parametrize('interactive,flags,json_output', [
    (True, [], False), (False, [], True), (True, ['--json'], True), (False, ['--text'], False),
])
def test_ask_output_contract_and_dry_run(case, monkeypatch, capsys, interactive, flags, json_output):
    path, db, eid = case
    from forensic_assistant.llm.client import LocalClient
    monkeypatch.setattr(LocalClient, 'complete', lambda *a, **k: pytest.fail('dry run contacted LLM'))
    args = request(path, '--dry-run', *flags, interactive=interactive, question='event ID 4688')
    assert args.json is json_output
    assert dispatch(args) == 0
    text = capsys.readouterr().out
    assert eid in text
    if json_output:
        result = json.loads(text)
        assert result['status'] == 'retrieved_only'
        assert 'fields_truncated' in result['evidence_bundle']['metadata']
        assert '\x1b' not in text
    else:
        assert ('Question\n' in text) is (not interactive)
        assert 'Evidence selected:' in text
        assert 'No analysis model was contacted.' in text


def test_mft_human_context_and_model_boundaries(tmp_path):
    from forensic_assistant.artifacts.ingest import ingest_artifact
    from forensic_assistant.llm.prompts import SYSTEM_PROMPT
    db = connect(':memory:')
    ingest_artifact(db, mft_file(tmp_path / 'synthetic-mft', names=('coreupdater.exe',)), 'mft')
    eid = db.execute('SELECT evidence_id FROM mft_records WHERE record_number=6').fetchone()[0]
    before = fingerprint(db)
    class Transport:
        def complete(self, messages, schema=None):
            bundle = json.loads(messages[1]['content'])
            assert bundle['EVIDENCE'][0]['id'] == eid
            assert bundle['metadata']['fields_truncated']
            assert 'XML' not in bundle['metadata']['field_selection']
            return json.dumps(dict(findings=[dict(finding='The file is represented in filesystem metadata.',
                evidence_ids=[eid], interpretation='Execution is not established by this record.', confidence='high',
                alternative_explanations=['It may have existed without being executed.'],
                next_evidence=['Related Prefetch or execution-related EVTX'])], missing_evidence=[]))
    result = ask(Queries(db), 'Inspect ' + eid, client=Transport())
    original = copy.deepcopy(result)
    text = render(result, Palette())
    assert eid in text and 'Model analysis — not evidence' in text
    assert 'MFT presence and access timestamps do not prove execution.' in text
    assert 'timestamps: 6 omitted from model context' in text
    assert 'full normalized record' in text and 'XML' not in text
    assert 'confidence' not in text.lower() and result['analysis']['findings'][0]['confidence'] == 'high'
    assert 'Confidence is model assessment metadata' in result['notice']
    assert result == original and fingerprint(db) == before
    assert 'presence/access times do not prove execution' in SYSTEM_PROMPT
    assert 'event XML only for EVTX' in SYSTEM_PROMPT
    db.close()


@pytest.mark.parametrize('interactive,flags,expected', [(True, [], 10), (True, ['--json'], 20),
    (False, [], 20), (False, ['--text'], 20), (True, ['--limit', '7'], 7)])
def test_semantic_default_limits(interactive, flags, expected):
    args = build_parser(interactive=interactive).parse_args(['semantic', 'search', 'query', *flags])
    assert args.limit == expected


def test_semantic_weak_display_paths_and_immutable_json():
    args = build_parser(interactive=True).parse_args(['semantic', 'search', 'abracadabra'])
    eid = 'MFT:' + 'a' * 64 + ':Offset:80896'
    result = dict(model=manifest(), representation_version='2', candidate_vectors=1,
                  results=[dict(evidence_id=eid, source_type='mft', artifact_type='mft_record',
                                semantic_similarity=.461, excerpt='original: \\Windows\\Temp\\café.exe')])
    original = copy.deepcopy(result)
    text = semantic_render(result, args, Palette())
    assert 'No semantic candidates meet the display cutoff.' in text
    assert 'Best similarity: 0.461' in text and 'not proof of irrelevance' in text
    assert eid not in text
    args.show_weak = True
    text = semantic_render(result, args, Palette())
    assert eid in text and '\\Windows\\Temp\\café.exe' in text
    assert '\\\\Windows' not in text
    assert result == original and '\\\\Windows' in json.dumps(result)
    args.show_weak = False
    result['model']['model_id'] = 'unreviewed-score-distribution'
    assert eid in semantic_render(result, args, Palette())


def test_forensic_style_capability_and_warning_colors(monkeypatch):
    for key in ('WT_SESSION', 'TERM', 'COLORTERM'):
        monkeypatch.delenv(key, raising=False)
    assert Palette(True)('forensic_note', 'note') == '\x1b[33mnote\x1b[0m'
    monkeypatch.setenv('TERM', 'xterm-256color')
    assert Palette(True)('forensic_note', 'note') == '\x1b[38;5;136mnote\x1b[0m'
    assert Palette()('forensic_note', 'note') == 'note'
    assert {k: STYLES[k] for k in ('warning', 'error', 'success')} == dict(warning='33', error='31', success='32')
    from forensic_assistant.retrieval.browser_display import note_role, SHARED_NOTES
    assert note_role(SHARED_NOTES[0]) == 'forensic_note'
    assert note_role(SHARED_NOTES[1]) == 'warning'
    assert note_role('unknown parser warning') == 'warning'


def test_setup_message_once_and_plain_path(environment, monkeypatch, capsys):
    from test_semantic_workflow import args
    request = args('setup')
    request._confirm = lambda p: 'n'
    with pytest.raises(Cancelled):
        cli.setup(request)
    text = capsys.readouterr().out
    assert text.count('Download the pinned') == 1
    assert str(runtime.model_path()) in text
    assert '\\n' not in text

"""6.37 workflow tests use synthetic evidence and no network/model downloads."""
import io
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from forensic_assistant.cli import build_parser, main
from forensic_assistant.semantic import cli, runtime, index, model, documents
from forensic_assistant.semantic.presentation import render, Progress
from forensic_assistant.terminal import Palette
from forensic_assistant.activity import Cancelled
from test_v3_index import FakeModel
from v1_fixtures import database, process


@pytest.fixture
def environment(tmp_path, monkeypatch):
    monkeypatch.setenv('LOCALAPPDATA', str(tmp_path / 'appdata'))
    monkeypatch.setattr(runtime, 'dependencies', lambda: {'state': 'ready', 'python': 'synthetic-python',
                        'packages': {}, 'failures': [], 'install_command': 'synthetic-install'})
    return tmp_path


def args(command, *extra, interactive=True):
    return build_parser(interactive=interactive).parse_args(['semantic', command, *extra])


def manifest():
    return {'model_id': model.MODELS['bge'][0], 'revision': model.MODELS['bge'][1], 'files': {}}


def ready_model(monkeypatch):
    path = runtime.model_path()
    path.mkdir(parents=True)
    monkeypatch.setattr(model, 'inspect_model', lambda path: manifest())
    class Model(FakeModel):
        identity = {**manifest(), 'dimension': 384, 'backend': 'sentence-transformers-cpu', 'packages': {}}
        def __init__(self, path):
            pass
    monkeypatch.setattr(model, 'LocalModel', Model)
    return Model(path)


def test_status_states_and_integrity(environment, monkeypatch):
    db = database()
    process(db, 1, '100')
    request = args('status', '--index', str(environment / 'index'))
    assert cli.status(db, request)['state'] == 'model_missing'
    runtime.model_path().mkdir(parents=True)
    assert cli.status(db, request)['state'] == 'model_malformed'
    monkeypatch.setattr(model, 'inspect_model', lambda p: manifest())
    assert cli.status(db, request)['state'] == 'index_missing'
    synthetic = FakeModel()
    synthetic.identity = manifest()
    index.build(db, request.index, synthetic)
    current = cli.status(db, request)
    assert current['state'] == 'ready'
    assert current['hashes'] == current['index']['hashes']
    assert current['vectors'] == current['index']['vectors']
    assert current['model'] == current['index']['model']
    db.execute("UPDATE events SET command_line='changed'")
    db.commit()
    assert cli.status(db, request)['state'] == 'index_stale'
    index.build(db, request.index, synthetic, rebuild=True)
    generation = index._generation(request.index)
    (generation / 'vectors.f32').write_bytes(b'corrupt')
    result = cli.status(db, request)
    assert result['state'] == 'index_malformed' and result['next_step'] == 'semantic rebuild'


def test_dependencies_missing_uses_exact_runtime_guidance(environment, monkeypatch):
    monkeypatch.setattr(runtime, 'dependencies', lambda: {'state': 'missing', 'python': 'test runtime/python.exe',
                        'packages': {}, 'failures': ['torch: ImportError'], 'install_command': 'exact pinned command'})
    db = database()
    result = cli.status(db, args('status'))
    assert result['state'] == 'dependencies_missing' and result['model_state'] == 'not_checked'
    assert 'test runtime/python.exe' in render(result, args('status'), Palette())
    with pytest.raises(ValueError, match='exact pinned command'):
        cli.dispatch(db, args('search', 'query'))
    assert not (environment / 'appdata').exists()


def test_metadata_is_dependency_pin_authority(monkeypatch):
    monkeypatch.setattr(runtime.importlib.metadata, 'requires', lambda name: ['torch==123.4; extra == "semantic"', 'other==1'])
    monkeypatch.setattr(runtime.importlib.metadata, 'version', lambda name: '123.4')
    imported = []
    monkeypatch.setattr(runtime.importlib, 'import_module', lambda name: imported.append(name))
    result = runtime.dependencies()
    assert result['state'] == 'ready' and imported == ['torch']
    assert 'torch==123.4' in result['install_command'] and runtime.sys.executable in result['install_command']
    def broken(name):
        raise OSError('native library unavailable')
    monkeypatch.setattr(runtime.importlib, 'import_module', broken)
    assert runtime.dependencies()['state'] == 'missing'


def test_setup_persistence_override_and_restart(environment, monkeypatch):
    chosen = environment / 'custom é model'
    def download(path, selection):
        Path(path).mkdir(parents=True)
        return manifest()
    monkeypatch.setattr(model, 'setup', download)
    monkeypatch.setattr(model, 'inspect_model', lambda path: manifest())
    request = args('setup', '--model-path', str(chosen))
    prompts = []
    request._confirm = lambda text: prompts.append(text) or 'yes'
    result = cli.setup(request)
    assert 'Internet' in prompts[0] and 'No case evidence is uploaded' in prompts[0]
    assert result['verification'] == 'passed'
    assert runtime.model_path() == chosen
    assert json.loads(runtime.settings_path().read_text())['model_path'] == str(chosen)
    assert runtime.model_path(environment / 'override') == environment / 'override'
    assert runtime.model_path() == chosen
    # A new request reuses the persisted directory without downloading again.
    monkeypatch.setattr(model, 'setup', lambda *a: pytest.fail('repeat download'))
    assert cli.setup(args('setup'))['location'] == str(chosen)


@pytest.mark.parametrize('answer', ['n', 'no'])
def test_decline_has_no_filesystem_effect(environment, answer):
    request = args('setup')
    request._confirm = lambda text: answer
    with pytest.raises(Cancelled):
        cli.setup(request)
    assert not (environment / 'appdata').exists()


def test_noninteractive_setup_requires_download_flag(environment, monkeypatch):
    monkeypatch.setattr(model, 'setup', lambda *a: pytest.fail('unapproved download'))
    with pytest.raises(ValueError, match='--download'):
        cli.setup(args('setup', interactive=False))
    assert not (environment / 'appdata').exists()


def test_download_failure_is_not_installed(environment, monkeypatch):
    def failure(path, choice):
        Path(path).mkdir(parents=True)
        (Path(path) / 'partial').write_bytes(b'partial')
        raise OSError('synthetic interrupted download')
    monkeypatch.setattr(model, 'setup', failure)
    with pytest.raises(OSError):
        cli.setup(args('setup', '--download'))
    assert not runtime.settings_path().exists()
    assert cli.status(database(), args('status'))['state'] == 'model_malformed'


def test_search_build_resume_stale_rebuild_and_case_isolation(environment, monkeypatch):
    ready_model(monkeypatch)
    db = database()
    eid = process(db, 1, '100')['id']
    request = args('search', 'original query', '--index', str(environment / 'a.index'))
    prompts = []
    request._confirm = lambda text: prompts.append(text) or 'y'
    seen = []
    monkeypatch.setattr(index, 'search', lambda db, root, model, question, **kw: seen.append(question) or {'results': [eid]})
    assert cli.dispatch(db, request)['results'] == [eid]
    assert seen == ['original query'] and len(prompts) == 1
    assert cli.dispatch(db, request)['results'] == [eid]
    assert len(prompts) == 1
    db.execute("UPDATE events SET command_line='changed'")
    db.commit()
    cli.dispatch(db, request)
    assert len(prompts) == 2 and 'rebuild' in prompts[-1]
    request.index = str(environment / 'b.index')
    cli.dispatch(db, request)
    assert len(prompts) == 3 and Path(environment / 'a.index' / 'CURRENT').exists()


def test_missing_index_script_and_json_never_prompt(environment, monkeypatch):
    ready_model(monkeypatch)
    db = database()
    for request in (args('search', 'q', interactive=False), args('search', 'q', '--json')):
        request.index = str(environment / 'absent')
        request._confirm = lambda text: pytest.fail('script/json prompt')
        with pytest.raises(ValueError, match='semantic build'):
            cli.dispatch(db, request)
    assert not (environment / 'absent').exists()


@pytest.mark.parametrize('exception', [KeyboardInterrupt, RuntimeError])
def test_failed_build_cleanup_and_previous_publication(environment, exception):
    db = database()
    process(db, 1, '100')
    root = environment / 'index'
    class Failed(FakeModel):
        def encode(self, texts, query=False):
            raise exception('synthetic')
    with pytest.raises(exception):
        index.build(db, root, Failed())
    assert list(root.iterdir()) == []
    index.build(db, root, FakeModel())
    before = sorted(p.name for p in root.iterdir())
    with pytest.raises(exception):
        index.build(db, root, Failed(), rebuild=True)
    assert sorted(p.name for p in root.iterdir()) == before
    assert index.status(db, root)['state'] == 'current'


def test_old_representation_requires_rebuild(environment):
    db = database()
    process(db, 1, '100')
    index.build(db, environment / 'index', FakeModel())
    path = index._generation(environment / 'index') / 'manifest.json'
    value = json.loads(path.read_text())
    value['representation_version'] = '1'
    path.write_text(json.dumps(value))
    assert index.status(db, environment / 'index')['state'] == 'stale'
    with pytest.raises(ValueError, match='Incompatible'):
        index._manifest(environment / 'index')


def test_token_accounting_progress_and_no_evidence_mutation(environment):
    db = database()
    eid = process(db, 1, '100', data={'CommandLine': 'payload.exe ' * 1800})['id']
    before = documents.fingerprint(db)
    accounting = {}
    chunks, cut = documents.chunks(db, eid, FakeModel(), accounting=accounting)
    assert accounting['over_limit_records'] == 1 and accounting['chunked_records'] == 1
    assert accounting['chunks_created'] == len(chunks) and accounting['truncated_records'] == int(cut)
    assert chunks == documents.chunks(db, eid, FakeModel())[0]
    assert all(c['evidence_id'] == eid and FakeModel().count(c['text']) <= 512 for c in chunks)
    updates = []
    result = index.build(db, environment / 'index', FakeModel(), progress=updates.append)
    assert result['over_limit_records'] == 1 and result['chunked_records'] == 1
    assert result['chunks_created'] == result['vectors']
    assert updates[0]['records'] == 0 and updates[-1]['records'] == 1
    assert updates[-1]['vectors'] == result['vectors']
    assert documents.fingerprint(db) == before
    text = render(result, args('build'), Palette())
    for expected in ('Device: CPU', 'Evidence indexed: 1 / 1', 'Skipped: 0', 'Chunked records: 1', 'Build time:', 'Index state: Ready'):
        assert expected in text
    assert 'hashes' not in text and 'packages' not in text


def test_human_search_and_json_fields(environment):
    eid = 'MFT:' + 'a' * 64 + ':Offset:80896'
    result = {'results': [{'evidence_id': eid, 'source_type': 'mft', 'artifact_type': 'mft_record',
                           'semantic_similarity': .658123, 'chunk_id': '2:0:40',
                           'excerpt': 'reconstructed_path: \\Windows\\Temp\\coreupdater.exe\nallocated: 1\nfile_size: 77'}],
              'candidate_vectors': 173, 'model': {'files': {'secret': 'hash'}}}
    text = render(result, args('search', 'core updater executable'), Palette())
    for expected in ('0.658', 'coreupdater.exe', eid, 'Artifact: MFT', 'Showing 1 semantic results', 'not confidence of maliciousness'):
        assert expected in text
    assert 'secret' not in text and 'hash' not in text and 'chunk_id' not in text
    assert result['model']['files'] == {'secret': 'hash'}


def test_progress_throttled_and_machine_silent():
    class Terminal(io.StringIO):
        def isatty(self):
            return True
    stream = Terminal()
    ticks = iter([0, .1, .9, 1.1])
    reporter = Progress(args('build'), stream=stream, clock=lambda: next(ticks))
    state = dict(records=1, total=2, vectors=3, elapsed=1.2, model='synthetic', device='CPU')
    for _ in range(4):
        reporter(state)
    assert len(stream.getvalue().splitlines()) == 2
    silent = Terminal()
    Progress(args('build', '--json'), stream=silent)(state)
    assert silent.getvalue() == ''


def test_cap_help_and_lower_bound(environment):
    db = database()
    process(db, 1, '100')
    process(db, 2, '200')
    with pytest.raises(ValueError, match='at least 2 vectors; configured limit 1. No index was published'):
        index.build(db, environment / 'index', FakeModel(), max_vectors=1)
    assert not (environment / 'index' / 'CURRENT').exists()


def tokenizer_model():
    # Real tokenizer counting, including two special tokens; no downloaded files.
    from tokenizers import Tokenizer
    from tokenizers.models import WordLevel
    from tokenizers.pre_tokenizers import Whitespace
    from tokenizers.processors import TemplateProcessing
    from transformers import PreTrainedTokenizerFast
    tokenizer = Tokenizer(WordLevel({'[UNK]': 0, '[CLS]': 1, '[SEP]': 2, 'word': 3}, unk_token='[UNK]'))
    tokenizer.pre_tokenizer = Whitespace()
    tokenizer.post_processor = TemplateProcessing(single='[CLS] $A [SEP]', special_tokens=[('[CLS]', 1), ('[SEP]', 2)])
    fast = PreTrainedTokenizerFast(tokenizer_object=tokenizer, unk_token='[UNK]', model_max_length=512)
    local = model.LocalModel.__new__(model.LocalModel)
    local.document_limit = 512
    local.prefix = 'word '
    encoded = []
    def encode(texts, **kw):
        encoded.extend(texts)
        return [[1.0] + [0.0] * 383 for _ in texts]
    local.model = SimpleNamespace(tokenizer=fast, encode=encode)
    return local, encoded


@pytest.mark.parametrize('tokens', [511, 512, 513, 698, 852])
def test_real_token_boundaries_and_no_warning(tokens, caplog):
    local, encoded = tokenizer_model()
    text = ' '.join(['word'] * (tokens - 2))
    assert local.count(text) == tokens
    if tokens <= 512:
        local.encode([text])
        assert encoded == [text]
    else:
        with pytest.raises(ValueError, match='token limit'):
            local.encode([text])
        assert encoded == []
    assert 'sequence length' not in caplog.text


def test_query_prefix_counts_toward_limit():
    local, encoded = tokenizer_model()
    with pytest.raises(ValueError, match='token limit'):
        local.encode([' '.join(['word'] * 510)], query=True)
    assert encoded == []


def test_real_tokenizer_chunks_search_and_provenance(environment, caplog):
    local, _ = tokenizer_model()
    local.identity = FakeModel.identity
    db = database()
    eid = process(db, 1, '100', data={'CommandLine': 'word ' * 600})['id']
    before = documents.fingerprint(db)
    built = index.build(db, environment / 'real-tokenizer', local)
    assert built['over_limit_records'] == 1 and built['chunked_records'] == 1
    assert built['truncated_records'] == 0
    result = index.search(db, environment / 'real-tokenizer', local, 'word')
    assert result['results'][0]['evidence_id'] == eid
    assert documents.fingerprint(db) == before
    assert 'sequence length' not in caplog.text


def test_progress_cancellation_never_publishes(environment):
    db = database()
    process(db, 1, '100')
    def cancel(state):
        raise KeyboardInterrupt()
    with pytest.raises(KeyboardInterrupt):
        index.build(db, environment / 'index', FakeModel(), progress=cancel)
    assert list((environment / 'index').iterdir()) == []


def test_cli_status_json_plain(environment, monkeypatch, capsys):
    from forensic_assistant.database.db import connect
    from forensic_assistant import terminal
    path = environment / 'case.db'
    connect(path).close()
    monkeypatch.setattr(terminal, 'capable', lambda stream: True)
    assert main(['--db', str(path), 'semantic', 'status', '--json']) == 0
    text = capsys.readouterr().out
    assert '\x1b' not in text
    assert json.loads(text)['state'] == 'model_missing'


def test_first_search_download_build_resume_and_restart(environment, monkeypatch):
    db = database()
    eid = process(db, 1, '100')['id']
    prompts = []
    def download(path, choice):
        Path(path).mkdir(parents=True)
        return manifest()
    monkeypatch.setattr(model, 'setup', download)
    monkeypatch.setattr(model, 'inspect_model', lambda path: manifest())
    class Model(FakeModel):
        identity = manifest()
        def __init__(self, path):
            assert Path(path) == runtime.model_path()
    monkeypatch.setattr(model, 'LocalModel', Model)
    request = args('search', 'payload', '--index', str(environment / 'case.index'))
    request._confirm = lambda text: prompts.append(text) or 'y'
    result = cli.dispatch(db, request)
    assert result['results'][0]['evidence_id'] == eid
    assert len(prompts) == 2 and 'Internet' in prompts[0] and 'build' in prompts[1]
    assert runtime.settings_path().exists()
    # Fresh parser/request represents a new shell session; no setup overrides.
    restarted = args('search', 'payload', '--index', str(environment / 'case.index'))
    restarted._confirm = lambda text: pytest.fail('unnecessary repeat setup')
    assert cli.dispatch(db, restarted)['results'][0]['evidence_id'] == eid


def test_failed_model_validation_never_remembers_path(environment, monkeypatch):
    def download(path, choice):
        Path(path).mkdir(parents=True)
        return manifest()
    monkeypatch.setattr(model, 'setup', download)
    with pytest.raises(ValueError, match='malformed'):
        cli.setup(args('setup', '--download'))
    assert not runtime.settings_path().exists()


def test_bounded_settings_fail_closed(environment):
    path = runtime.settings_path()
    path.parent.mkdir(parents=True)
    path.write_text('{"format":1,"model_path":"relative"}')
    before = path.read_bytes()
    with pytest.raises(ValueError, match='Malformed'):
        runtime.model_path()
    with pytest.raises(ValueError, match='Malformed'):
        runtime.remember(environment / 'model')
    assert path.read_bytes() == before


def test_search_model_override_setup_does_not_change_preference(environment, monkeypatch):
    configured = environment / 'configured'
    configured.mkdir()
    runtime.remember(configured)
    def download(path, choice):
        Path(path).mkdir()
        return manifest()
    monkeypatch.setattr(model, 'setup', download)
    monkeypatch.setattr(model, 'inspect_model', lambda path: manifest())
    class Model(FakeModel):
        identity = manifest()
        def __init__(self, path):
            assert path == environment / 'override'
    monkeypatch.setattr(model, 'LocalModel', Model)
    request = args('search', 'payload', '--model-path', str(environment / 'override'), '--index', str(environment / 'index'))
    request._confirm = lambda text: 'y'
    db = database()
    process(db, 1, '100')
    assert cli.dispatch(db, request)['results']
    assert runtime.model_path() == configured


def test_compact_text_retains_observation_boundaries():
    text = documents.compact_text({'objects': [{'role': 'a', 'original': 'same'}, {'role': 'b', 'original': 'same'}]})
    assert text.count('objects:') == 2 and text.count('original: same') == 2
    assert text.index('role: a') < text.rindex('original: same') < text.index('role: b')


def test_malformed_package_identity_is_not_ready(environment):
    db = database()
    process(db, 1, '100')
    index.build(db, environment / 'index', FakeModel())
    path = index._generation(environment / 'index') / 'manifest.json'
    value = json.loads(path.read_text())
    value['model']['packages'] = ['invalid']
    path.write_text(json.dumps(value))
    assert index.status(db, environment / 'index')['state'] == 'unavailable'

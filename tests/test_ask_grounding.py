"""ASK safeguards exercise actual selection, hydration and index lookup offline."""
import copy
import json
import math
import sys
from types import SimpleNamespace

import pytest

from forensic_assistant.artifacts.ingest import ingest_artifact
from forensic_assistant.cli import build_parser, dispatch
from forensic_assistant.database.db import connect
from forensic_assistant.llm.ask import ask
from forensic_assistant.llm.grounding import ARTIFACT_GUIDANCE
from forensic_assistant.llm.presentation import render
from forensic_assistant.llm.prompts import SYSTEM_PROMPT, PROMPT_BYTES
from forensic_assistant.retrieval.queries import Queries
from forensic_assistant.semantic import model, index
from forensic_assistant.semantic.documents import fingerprint
from forensic_assistant.terminal import Palette
from test_semantic_workflow import environment, ready_model, manifest
from v1_fixtures import database, add
from v2_fixtures import mft_file


@pytest.fixture
def mft_case(environment, monkeypatch):
    path = environment / 'synthetic.db'
    db = connect(path)
    ingest_artifact(db, mft_file(environment / 'synthetic-mft', names=('coreupdater.exe', 'update.ps1')), 'mft')
    fake = ready_model(monkeypatch)
    index.build(db, index.default_root(path), fake)
    yield path, db, fake
    db.close()


class ForbiddenTransport:
    def complete(self, *a, **k):
        pytest.fail('Unsupported MFT activity question must not solicit speculative findings')


@pytest.mark.parametrize('score', [0.0, 1.0])
def test_mft_credential_guard_is_independent_of_similarity(mft_case, monkeypatch, score):
    path, db, fake = mft_case
    def encode(texts, query=False):
        vector = [score, math.sqrt(1 - score * score)] if query else [1.0, 0.0]
        return [vector + [0.0] * 382 for _ in texts]
    fake.encode = encode
    monkeypatch.setattr(model, 'LocalModel', lambda p: fake)
    before = fingerprint(db)
    result = ask(Queries(db), 'What evidence is there of suspicious credential use?', client=ForbiddenTransport())
    assert result['plan']['operation'] == 'conceptual'
    assert all(h['semantic_similarity'] == score for h in result['plan']['semantic_results']['results'])
    bundle = result['evidence_bundle']
    ids = [r['id'] for r in bundle['EVIDENCE']]
    assert ids and not bundle['DIRECT_EVIDENCE']
    assert result['grounding']['candidate_lead_ids'] == ids
    assert result['status'] == 'insufficient_evidence' and 'analysis' not in result
    assert result['grounding']['withhold_model_analysis']
    assert all('semantic_similarity' in r['selection_reasons'] for r in bundle['EVIDENCE'])
    original = copy.deepcopy(result)
    text = render(result, Palette(), include_question=False)
    assert text.startswith('Plan\n  Retrieval: semantic')
    for unwanted in ('Question\n', 'Retrieval: conceptual', 'Semantic retrieval: used',
                     'Selection: direct evidence', 'Finding (model assessment)', 'potentially related to credential handling'):
        assert unwanted not in text
    assert 'Candidate leads from semantic retrieval:' in text
    assert 'Selection: semantic similarity' in text
    assert 'No direct evidence of credential use was identified in the selected MFT metadata.' in text
    assert 'MFT metadata, which does not by itself establish credential use.' in text
    assert 'No analysis model was contacted.' in text
    assert all(eid in text for eid in ids)
    assert result == original and fingerprint(db) == before
    structured = json.loads(json.dumps(result))
    assert structured['evidence_bundle']['QUESTION'] == bundle['QUESTION']
    assert structured['evidence_bundle']['EVIDENCE'] == bundle['EVIDENCE']


def test_direct_mft_metadata_still_does_not_support_credential_use(mft_case):
    _, db, _ = mft_case
    result = ask(Queries(db), 'credential use by coreupdater.exe', client=ForbiddenTransport())
    assert result['plan']['operation'] == 'search'
    assert result['evidence_bundle']['DIRECT_EVIDENCE']
    assert result['grounding']['withhold_model_analysis']
    assert 'Retrieval: deterministic search' in render(result, Palette())


@pytest.mark.parametrize('question', ['What evidence is there about coreupdater.exe?', 'Was coreupdater.exe executed?'])
def test_direct_mft_selection_and_execution_safety_preserved(mft_case, question):
    _, db, _ = mft_case
    eid = db.execute('SELECT evidence_id FROM mft_records WHERE record_number=6').fetchone()[0]
    calls = []
    class Transport:
        def complete(self, prompt, schema=None):
            calls.append(prompt)
            bundle = json.loads(prompt[1]['content'])
            assert bundle['DIRECT_EVIDENCE'] == [eid]
            assert 'MFT presence/access times do not prove execution' in prompt[0]['content']
            return answer(eid, 'The selected MFT record contains the filename.',
                          'MFT presence and access timestamps do not establish execution.')
    before = fingerprint(db)
    result = ask(Queries(db), question, client=Transport())
    assert len(calls) == 1 and result['status'] == 'model_analysis'
    assert result['evidence_bundle']['DIRECT_EVIDENCE'] == [eid]
    assert not result['grounding']['withhold_model_analysis']
    text = render(result, Palette(), include_question=False)
    assert text.startswith('Plan\n  Retrieval: deterministic search')
    assert 'Process: coreupdater.exe' in text and 'Evidence selected: 1' in text
    assert 'Candidate leads' not in text and 'Semantic retrieval: used' not in text
    assert 'MFT presence and access timestamps do not prove execution.' in text
    assert eid in text and fingerprint(db) == before


def answer(eid, finding, interpretation):
    return json.dumps(dict(findings=[dict(finding=finding, interpretation=interpretation,
        evidence_ids=[eid], confidence='low', alternative_explanations=[], next_evidence=[])], missing_evidence=[]))


def test_semantic_authentication_event_is_available_for_field_based_review(environment, monkeypatch):
    source = database()
    eid = add(source, 1, event_id=4624, data={'TargetUserName': 'synthetic-user', 'LogonType': '3'})['id']
    path = environment / 'events.db'
    db = connect(path)
    source.backup(db)
    source.close()
    fake = ready_model(monkeypatch)
    index.build(db, index.default_root(path), fake)
    class Transport:
        def complete(self, prompt, schema=None):
            bundle = json.loads(prompt[1]['content'])
            assert bundle['EVIDENCE'][0]['event_id'] == 4624
            assert 'semantic_similarity' in bundle['EVIDENCE'][0]['selection_reasons']
            assert len(prompt[0]['content'].encode()) + len(prompt[1]['content'].encode()) <= PROMPT_BYTES
            return answer(eid, 'An event 4624 logon was recorded.', 'The event does not by itself establish malicious intent.')
    result = ask(Queries(db), 'What evidence is there of suspicious credential use?', client=Transport())
    assert not result['grounding']['withhold_model_analysis']
    assert result['grounding']['candidate_lead_ids'] == [eid]
    text = render(result, Palette())
    assert 'Candidate assessment (model; relevance unverified)' in text
    assert 'Finding (model assessment)' not in text
    assert 'EVTX meaning depends on event type' in text
    assert 'An event 4624 logon was recorded.' in text
    db.close()


@pytest.mark.parametrize('destination', [None, '--output', '--append'])
def test_interactive_question_hidden_but_persistent_text_self_contained(mft_case, tmp_path, capsys, destination):
    path, _, _ = mft_case
    question = 'What evidence is there about coreupdater.exe?'
    target = tmp_path / 'derived.txt'
    words = ['--db', str(path), 'ask', question, '--dry-run']
    if destination:
        words += [destination, str(target)]
    args = build_parser(interactive=True).parse_args(words)
    assert dispatch(args) == 0
    terminal = capsys.readouterr().out
    text = target.read_text(encoding='utf-8') if destination else terminal
    assert ('Question\n' in text) is bool(destination)
    assert (question in text) is bool(destination)
    assert 'Retrieval: deterministic search' in text
    assert 'No analysis model was contacted.' in text


def test_dry_run_retains_credential_candidates_and_suitability(mft_case):
    _, db, _ = mft_case
    result = ask(Queries(db), 'credential use', dry_run=True, client=ForbiddenTransport())
    assert result['status'] == 'retrieved_only'
    assert result['grounding']['withhold_model_analysis']
    assert result['grounding']['candidate_lead_ids']


def test_prompt_and_guidance_do_not_promote_similarity_or_access_times():
    assert 'Outside DIRECT_EVIDENCE' in SYSTEM_PROMPT
    assert 'semantic_similarity' in SYSTEM_PROMPT and 'candidate leads' in SYSTEM_PROMPT
    assert 'Only fields with appropriate artifact semantics can support an activity claim' in SYSTEM_PROMPT
    assert 'never similarity, filenames or directory names alone' in SYSTEM_PROMPT
    assert 'do not invent a speculative connection' in SYSTEM_PROMPT
    assert 'not validated claims' in SYSTEM_PROMPT
    assert 'MFT presence/access times do not prove execution or meaningful usage' in SYSTEM_PROMPT
    assert 'MFT access timestamps for usage' not in SYSTEM_PROMPT + str(ARTIFACT_GUIDANCE)
    assert 'filesystem activity context' in ARTIFACT_GUIDANCE['mft']
    assert 'MFT has no execution/usage timestamps: never request them' in SYSTEM_PROMPT
    assert 'MFT does not record execution timestamps.' in ARTIFACT_GUIDANCE['mft']
    assert set(ARTIFACT_GUIDANCE) == {'mft', 'evtx', 'prefetch', 'registry', 'browser'}


@pytest.mark.parametrize('failure', [False, True])
def test_loading_progress_suppressed_but_errors_and_locard_progress_survive(monkeypatch, tmp_path, capsys, failure):
    from transformers.utils import logging
    from transformers.core_model_loading import tqdm
    import sentence_transformers
    from forensic_assistant.semantic.presentation import Progress
    import io
    from test_semantic_workflow import args
    was_enabled = logging.is_progress_bar_enabled()
    logging.enable_progress_bar()
    monkeypatch.setattr(model, 'inspect_model', lambda p: manifest())
    def constructor(*a, **kw):
        for _ in tqdm(range(2), desc='Loading weights', file=sys.stderr):
            pass
        print('real loader diagnostic', file=sys.stderr)
        if failure:
            raise RuntimeError('real loader error')
        return SimpleNamespace(max_seq_length=512)
    monkeypatch.setattr(sentence_transformers, 'SentenceTransformer', constructor)
    try:
        if failure:
            with pytest.raises(RuntimeError, match='real loader error'):
                model.LocalModel(tmp_path)
        else:
            model.LocalModel(tmp_path)
        output = capsys.readouterr()
        assert 'Loading weights' not in output.out + output.err
        assert 'real loader diagnostic' in output.err
        class Terminal(io.StringIO):
            def isatty(self):
                return True
        stream = Terminal()
        Progress(args('build'), stream=stream)(dict(records=1, total=2, vectors=3, elapsed=1, model='synthetic', device='CPU'))
        assert 'Embedding: 1 / 2' in stream.getvalue()
    finally:
        (logging.enable_progress_bar if was_enabled else logging.disable_progress_bar)()

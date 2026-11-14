"""Disposable local stores, synthetic providers, read-only historical compatibility."""
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys

import pytest

from forensic_assistant.investigation_ai import findings as f, d2, d2_cross as cross
from forensic_assistant.investigation_ai import d2_execution as ex, d2_quality as q, d2_wire as wire
from test_explanation_live import execute
from test_explanation_replay_status import empty_run


@pytest.fixture(scope='module')
def source(tmp_path_factory):
    root = tmp_path_factory.mktemp('findings-source')
    result, _, _, _ = execute(root)
    history = d2.open_history(root/'runs', result['investigation_id'])
    return root/'runs', result['investigation_id'], history


@pytest.fixture(autouse=True)
def no_provider(monkeypatch):
    def forbidden(*a, **kw):
        pytest.fail('unexpected provider request')
    monkeypatch.setattr('forensic_assistant.ai.backend.ModelBackend.complete', forbidden)


@pytest.fixture
def workspace(tmp_path, source):
    return f.create(tmp_path/'review.findings', source[0], source[1], actor='Synthetic analyst')


def refs(source):
    return [c['id'] for c in source[2]._ctx.factual['clauses'] if c['type']=='observation']


def register(w, source, revision=0):
    return w.register(actor='Analyst', expected_revision=revision, kind='analyst_hypothesis',
        statement='The recorded activities might be related.', supporting_ids=refs(source)[:1],
        contrary_ids=refs(source)[1:2], limitations=['Clock agreement not established.'])


def test_create_reopen_export_new_process(workspace, source):
    original = workspace.export()
    assert original['source_binding_status']=='valid_recorded_binding'
    assert original['metadata']['binding']==f._binding(source[2])
    assert original['findings']==[]
    fid = register(workspace, source)
    assert workspace.export()==f.Workspace(workspace.directory).export()
    out = subprocess.run([sys.executable, '-B', '-m', 'forensic_assistant.investigation_ai.findings',
        str(workspace.directory), 'export'], capture_output=True, text=True, check=True)
    assert json.loads(out.stdout)==workspace.export()
    assert workspace.get(fid)['findings'][0]['state']=='proposed'


def test_review_supersession_contrary_and_qualifications(workspace, source):
    fid = register(workspace, source)
    candidate = workspace.get(fid)['findings'][0]['candidate']
    workspace.review(fid, 'accept', actor='Locally asserted person', expected_revision=1, rationale='Reviewed.')
    accepted = workspace.get(fid)['findings'][0]
    assert accepted['candidate']==candidate and accepted['candidate']['contrary']
    assert accepted['reviewed_classification']=='analyst_reviewed_conclusion'
    assert accepted['candidate']['origin']=='analyst_hypothesis'
    replacement = workspace.supersede(fid, actor='Analyst', expected_revision=2, rationale='Corrected scope.',
        statement='The association remains unresolved.', supporting_ids=refs(source)[:1], contrary_ids=refs(source)[1:2])
    assert workspace.get(fid)['findings'][0]['state']=='superseded'
    assert workspace.get(replacement)['findings'][0]['state']=='proposed'
    workspace.review(replacement, 'accept', actor='Analyst', expected_revision=3)
    assert len(workspace.decisions()['history'])==4
    assert all(e['actor_authority']=='locally asserted' for e in workspace.decisions()['history'])
    assert workspace.get(fid)['findings'][0]['candidate']==candidate


def test_reject_and_invalid_duplicate_stale_decisions(workspace, source):
    fid = register(workspace, source)
    workspace.review(fid, 'reject', actor='Analyst', expected_revision=1)
    before = workspace.export()
    for decision, revision in [('accept', 2), ('reject', 2), ('accept', 1), ('magic', 2)]:
        with pytest.raises(ValueError):
            workspace.review(fid, decision, actor='Analyst', expected_revision=revision)
    with pytest.raises(ValueError):
        workspace.supersede(fid, actor='Analyst', expected_revision=2, rationale='No.', statement='No.', supporting_ids=refs(source)[:1])
    assert before==workspace.export()


def test_concurrent_conflict(workspace, source):
    fid = register(workspace, source)
    def attempt(decision):
        try:
            f.Workspace(workspace.directory).review(fid, decision, actor='Analyst', expected_revision=1)
            return 'ok'
        except ValueError as exc:
            return str(exc)
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(attempt, ['accept', 'reject']))
    assert sorted(results)==['FINDINGS_STALE_REVISION', 'ok']
    assert workspace.export()['revision']==2


@pytest.mark.parametrize('kind,support', [('ai_proposal', 'real'), ('analyst_reviewed_conclusion', 'real'),
    ('analyst_hypothesis','O1'), ('analyst_hypothesis','0'*64), ('analyst_hypothesis','empty'),
    ('deterministic_interpretation','real')])
def test_invalid_candidates(workspace, source, kind, support):
    values = refs(source)[:1] if support=='real' else [] if support=='empty' else [support]
    with pytest.raises(ValueError):
        workspace.register(actor='Analyst', expected_revision=0, kind=kind, statement='Text', supporting_ids=values)
    assert workspace.export()['revision']==0


def test_original_observation_registration(workspace, source):
    fid = workspace.register(actor='Analyst', expected_revision=0, kind='original_observation',
        statement='Recorded field reference (analyst wording).', supporting_ids=refs(source)[:1])
    leaf = workspace.get(fid)['findings'][0]['candidate']['support'][0]['leaves'][0]
    assert leaf['evidence_id'] and leaf['field']['pointer'] and leaf['source'] and leaf['lineage']


def prepared(source):
    h = cross.History(d2.open_history(source[0], source[1]), 'Compare the recorded fields and their limitations.', 'synthetic-model', q.CURRENT)
    packet = h.preview()['packets'][0]
    return ex.Prepared(h, packet, dict(provider='openai', model='synthetic-model'), dict(exploratory=True), profile=cross.VERSION)


def answer(p):
    aliases = [s['alias'] for s in p.packet['content']['supports']]
    return dict(v=q.CURRENT, o='new_inference', r='Provisional only.', a=[dict(
        s='The recorded activities may be associated.', e=aliases[:1], c=aliases[1:2], i=[],
        a='They may be independent.', u='Clock agreement unknown.', d='Compare original artifact timestamps.',
        n='Examine process records for corresponding activity; availability is unknown.')])


def test_d2_import_original_refs_no_execution(workspace, source):
    p = prepared(source); raw = wire.J(answer(p))
    fid = workspace.import_d2(p, raw, 0, actor='Analyst', expected_revision=0)
    saved = workspace.get(fid)['findings'][0]
    assert saved['state']=='proposed' and saved['candidate']['origin']=='ai_proposal'
    assert saved['candidate']['contrary'] and saved['candidate']['ai']['validated']['dependencies']
    assert saved['candidate']['support'][0]['leaves'][0]['evidence_id']
    assert all(r['execution']=='unexecuted' for r in saved['candidate']['recommendations'])
    assert saved['candidate']['ai']['validated']['item']['assumptions']==['Clock agreement unknown.']
    workspace.review(fid,'accept',actor='Analyst',expected_revision=1)
    assert workspace.get(fid)['findings'][0]['candidate']==saved['candidate']
    assert f.Workspace(workspace.directory).export()==workspace.export()


def test_available_validated_result_import(workspace,source):
    p=prepared(source)
    validated,_=ex.validate_model_response(p,wire.J(answer(p)))
    fid=workspace.import_result(p,validated,0,actor='Analyst',expected_revision=0)
    assert workspace.get(fid)['findings'][0]['candidate']['ai']['validated']==validated['proposals'][0]
    forged=deepcopy(validated)
    forged['proposals'][0]['dependencies'][0]['evidence_id']='FOREIGN'
    with pytest.raises(ValueError,match='RESULT_CHANGED'):
        workspace.import_result(p,forged,0,actor='Analyst',expected_revision=1)
    with pytest.raises(ValueError):
        workspace.import_result(p,{'status':'accepted','contract':'d2-quality-validation-v1'},0,actor='Analyst',expected_revision=1)


def test_registered_interpretation_and_relationship(workspace,source):
    clauses=source[2]._ctx.factual['clauses']
    interpretation=next(c for c in clauses if c['type']=='deterministic_interpretation')
    fid=workspace.register(actor='Analyst',expected_revision=0,kind='deterministic_interpretation',
        statement='Reference to the registered interpretation, not proof of execution.',supporting_ids=[interpretation['id']])
    bundle=workspace.get(fid)['findings'][0]['candidate']['support'][0]
    assert bundle['interpretations'] and bundle['qualifications']
    assert set(bundle['interpretations'][0]['premise_pointers']) <= {v['field']['pointer'] for v in bundle['leaves']}
    relationship=source[2]._ctx.related['relationships'][0]
    fid=workspace.register(actor='Analyst',expected_revision=1,kind='deterministic_relationship',
        statement='Qualified registered relationship reference.',supporting_ids=[relationship['id']])
    bundle=workspace.get(fid)['findings'][0]['candidate']['support'][0]
    assert set(relationship['endpoints']) <= set(bundle['clauses'])
    assert bundle['relationships'] and bundle['qualifications']


@pytest.mark.parametrize('mutation',['raw_object','alias','bad_type','packet','source','no_item'])
def test_invalid_ai_import(workspace, source, mutation):
    p = prepared(source); value = answer(p); index=0
    if mutation=='alias': value['a'][0]['e']=['O99']
    if mutation=='bad_type': value['a'][0]['e']=['I1']
    if mutation=='packet': p.packet['packet_digest']='0'*64
    if mutation=='source': p.packet['content']['source']['run_id']='f'*32
    if mutation=='no_item': index=3
    if mutation=='raw_object': p={'status':'accepted'}
    with pytest.raises(ValueError): workspace.import_d2(p,wire.J(value),index,actor='Analyst',expected_revision=0)
    assert workspace.export()['revision']==0


def test_rollback_after_insert(workspace, source, monkeypatch):
    # A transaction interrupted after SQLite has received its write must roll back.
    fid = register(workspace, source); before=workspace.export()
    with pytest.raises(KeyboardInterrupt):
        with workspace._connection(True) as conn:
            conn.execute('DELETE FROM events')
            raise KeyboardInterrupt()
    assert before==workspace.export()


@pytest.mark.parametrize('mutation',['hash','shape','transition','version','metadata','trigger','duplicate_key','boolean_sequence'])
def test_corruption(workspace, source, mutation):
    register(workspace, source)
    with sqlite3.connect(workspace.path) as db:
        if mutation=='version': db.execute('PRAGMA user_version=99')
        elif mutation=='hash': db.execute("UPDATE events SET hash='bad'")
        elif mutation=='trigger': db.execute('CREATE TRIGGER forbidden AFTER INSERT ON events BEGIN DELETE FROM metadata; END')
        elif mutation=='metadata':
            value=json.loads(db.execute('SELECT value FROM metadata').fetchone()[0]);value['id']='b'*32
            db.execute('UPDATE metadata SET value=?',(json.dumps(value),))
        else:
            value=json.loads(db.execute('SELECT body FROM events').fetchone()[0])
            if mutation=='shape': value['payload']['candidate']['unexpected']=True
            elif mutation=='boolean_sequence': value['sequence']=True
            elif mutation=='transition': value['action']='accept'
            raw=json.dumps(value)
            if mutation=='duplicate_key':raw=raw.replace('"sequence": 1','"sequence": 1, "sequence": 1')
            db.execute('UPDATE events SET body=?, hash=?',(raw,f.digest(value)))
    with pytest.raises(ValueError): workspace.export()


def test_unavailable_and_mismatched_source(workspace, source, monkeypatch):
    fid=register(workspace,source)
    def unavailable(*args): raise FileNotFoundError()
    monkeypatch.setattr(d2,'open_history',unavailable)
    assert workspace.get(fid)['source_binding_status']=='unresolved_source_unavailable'
    with pytest.raises(ValueError,match='UNRESOLVED'): workspace.review(fid,'accept',actor='Analyst',expected_revision=1)
    monkeypatch.setattr(d2,'open_history',lambda *args: source[2])
    binding=f._binding
    monkeypatch.setattr(f,'_binding',lambda h: {**binding(h), 'view':{}})
    assert workspace.export()['source_binding_status']=='invalid_source_binding'
    with pytest.raises(ValueError,match='INVALID_SOURCE'): workspace.review(fid,'accept',actor='Analyst',expected_revision=1)


def test_safe_paths(workspace, source, tmp_path):
    with pytest.raises(FileExistsError): f.create(workspace.directory,source[0],source[1],actor='Analyst')
    with pytest.raises(ValueError): f.create(tmp_path/'case.db',source[0],source[1],actor='Analyst')
    with pytest.raises(ValueError): f.create(source[0]/'new.findings',source[0],source[1],actor='Analyst')
    protected=tmp_path/'case';protected.mkdir();(protected/'case.db').write_bytes(b'synthetic protected file')
    with pytest.raises(ValueError): f.create(protected/'new.findings',source[0],source[1],actor='Analyst')
    assert (protected/'case.db').read_bytes()==b'synthetic protected file'


def test_hardlinked_database_rejected(workspace,tmp_path):
    import os
    alias=tmp_path/'alias.sqlite3'
    try:
        os.link(workspace.path,alias)
    except PermissionError:
        pytest.skip('native hard-link creation denied by environment; guard separately tested')
    try:
        with pytest.raises(ValueError,match='UNSAFE_FILE'):workspace.export()
    finally:
        alias.unlink()


def test_hardlink_count_guard(workspace,monkeypatch):
    from types import SimpleNamespace
    original=Path.stat
    def stat(path,*args,**kwargs):
        info=original(path,*args,**kwargs)
        if path==workspace.path:
            fields={name:getattr(info,name) for name in dir(info) if name.startswith('st_')}
            fields['st_nlink']=2
            return SimpleNamespace(**fields)
        return info
    monkeypatch.setattr(Path,'stat',stat)
    with pytest.raises(ValueError,match='UNSAFE_FILE'):workspace.export()


def test_readonly_retrieval_and_no_transcript_writes(workspace, source, monkeypatch):
    register(workspace,source)
    paths=[workspace.path,source[0]/source[1]/'manifest.json',source[0]/source[1]/'events.jsonl']
    before=[hashlib.sha256(p.read_bytes()).hexdigest() for p in paths]
    connect=sqlite3.connect
    def guard(path,*args,**kwargs):
        assert str(path).endswith('findings.sqlite3?mode=ro') and kwargs['uri'] is True
        return connect(path,*args,**kwargs)
    monkeypatch.setattr(sqlite3,'connect',guard)
    workspace.export();workspace.list();workspace.decisions()
    assert before==[hashlib.sha256(p.read_bytes()).hexdigest() for p in paths]


def test_empty_history(tmp_path):
    source_dir=tmp_path/'source';source_dir.mkdir()
    result=empty_run(source_dir,'structure');root=source_dir/'runs'
    w=f.create(tmp_path/'empty.findings',root,result['investigation_id'],actor='Analyst')
    assert not w.export()['findings']
    with pytest.raises(ValueError): w.register(actor='Analyst',expected_revision=0,kind='analyst_hypothesis',statement='No evidence',supporting_ids=['0'*64])


def test_cross_workspace_source_substitution(tmp_path, source):
    source_dir=tmp_path/'source';source_dir.mkdir()
    result=empty_run(source_dir,'structure')
    w=f.create(tmp_path/'other.findings',source_dir/'runs',result['investigation_id'],actor='Analyst')
    p=prepared(source)
    with pytest.raises(ValueError,match='SOURCE_BINDING'):
        w.import_d2(p,wire.J(answer(p)),0,actor='Analyst',expected_revision=0)
    assert not w.export()['findings']


@pytest.mark.parametrize('change',['missing','malformed','wrong_view','wrong_run'])
def test_invalid_source_authority_before_creation(tmp_path,source,change):
    from test_organization import rehash
    from forensic_assistant.investigation_ai.transcript import load
    root=tmp_path/'copied';folder=root/source[1]
    shutil.copytree(source[0]/source[1],folder)
    m,events=load(root,source[1])
    if change=='missing': del m['evidence_state']
    elif change=='malformed': m['evidence_state']={'contract':'unknown'}
    elif change=='wrong_view': m['evidence_state']['view_id']='f'*32
    else: m['investigation_id']='f'*32
    rehash(folder,m,events)
    target=tmp_path/'invalid.findings'
    with pytest.raises((ValueError,KeyError,TypeError)):
        f.create(target,root,source[1],actor='Analyst')
    assert not target.exists()


def test_changed_support_rehashed_store_rejected(workspace,source):
    register(workspace,source)
    with sqlite3.connect(workspace.path) as db:
        event=json.loads(db.execute('SELECT body FROM events').fetchone()[0])
        event['payload']['candidate']['support'][0]['leaves'][0]['field']['value']='forged'
        db.execute('UPDATE events SET body=?,hash=?',(json.dumps(event),f.digest(event)))
    with pytest.raises(ValueError,match='SUPPORT_CHANGED'):workspace.export()


def test_bounded_text_and_payload(workspace,source,monkeypatch):
    with pytest.raises(ValueError):workspace.register(actor='Analyst',expected_revision=0,kind='analyst_hypothesis',statement='é'*1025,supporting_ids=refs(source)[:1])
    monkeypatch.setattr(f,'MAX_EVENT',200)
    with pytest.raises(ValueError,match='BOUNDS'):register(workspace,source)
    assert workspace.export()['revision']==0


@pytest.mark.parametrize('folder,rid', [('6.118-live','08cfd054f85a4a36b8520832427201c3'),
    ('6.118-live','6ad0c85499564406aa4d949f3b0e72e5'),('6.111-b2','ec81a1af5b1f471ca4f3a4c0bb917fa2')])
def test_historical_readonly(tmp_path,folder,rid):
    root=Path(r'C:\tmp\locard-diagnostics')/folder
    if not (root/rid/'manifest.json').exists():pytest.skip('historical copy absent')
    paths=[root/rid/n for n in ('manifest.json','events.jsonl')]
    before=[hashlib.sha256(p.read_bytes()).hexdigest() for p in paths]
    w=f.create(tmp_path/'history.findings',root,rid,actor='Analyst')
    assert w.export()==f.Workspace(w.directory).export()
    assert not w.export()['findings']
    assert before==[hashlib.sha256(p.read_bytes()).hexdigest() for p in paths]

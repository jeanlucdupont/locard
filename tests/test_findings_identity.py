"""Workspace substitution uses only disposable directories and synthetic histories."""
from contextlib import contextmanager
from copy import deepcopy
from types import SimpleNamespace
import sqlite3
import json
import pytest

from test_findings import source, workspace, no_provider, register, refs, prepared, answer
from test_finding_capture import result, no_network
from forensic_assistant.investigation_ai import findings as f, d2_wire as wire


def move_owned(workspace, tmp_path):
    origin = workspace.directory.resolve()
    destination = tmp_path.resolve() / 'retained-a.findings'
    assert origin.parent == tmp_path.resolve()
    assert destination.parent == tmp_path.resolve() and not destination.exists()
    origin.rename(destination)
    return destination


def unchanged(workspace):
    db = sqlite3.connect(workspace.path.as_uri()+'?mode=ro', uri=True)
    try:
        return db.execute('SELECT * FROM metadata').fetchall(), db.execute('SELECT * FROM events ORDER BY sequence').fetchall()
    finally:
        db.close()


def test_exact_revision_three_substitution(tmp_path, source):
    a = f.create(tmp_path/'selected.findings', source[0], source[1], actor='Synthetic')
    for revision in range(3): register(a, source, revision)
    stale = f.Workspace(a.directory)
    original = unchanged(a)
    history = [(source[0]/source[1]/name).read_bytes() for name in ('manifest.json','events.jsonl')]
    moved = move_owned(a, tmp_path)
    b = f.create(a.directory, source[0], source[1], actor='Synthetic')
    for revision in range(3): register(b, source, revision)
    before = b.export()
    assert before['revision'] == 3
    assert before['metadata']['id'] != stale._selection[0]
    assert before['metadata']['binding'] == stale._selection[1]
    with pytest.raises(ValueError, match='^FINDINGS_WORKSPACE_CHANGED$'):
        register(stale, source, 3)
    assert b.export() == before
    assert unchanged(f.Workspace(moved)) == original
    assert history == [(source[0]/source[1]/name).read_bytes() for name in ('manifest.json','events.jsonl')]


@pytest.mark.parametrize('operation', ['review', 'supersede', 'import_d2', 'import_result', 'import_results'])
def test_all_mutations_reject_substitution(tmp_path, source, monkeypatch, operation):
    a = f.create(tmp_path/'selected.findings', source[0], source[1], actor='Synthetic')
    fid = register(a, source)
    stale = f.Workspace(a.directory)
    original = unchanged(a)
    moved = move_owned(a, tmp_path)
    b = f.create(a.directory, source[0], source[1], actor='Synthetic')
    # A finding ID collision must not make the replacement an eligible workspace.
    with monkeypatch.context() as patch:
        patch.setattr(f.uuid, 'uuid4', lambda: SimpleNamespace(hex=fid))
        assert register(b, source) == fid
    before = unchanged(b)
    p = prepared(source) if operation.startswith('import') else None
    with pytest.raises(ValueError, match='^FINDINGS_WORKSPACE_CHANGED$'):
        if operation == 'review': stale.review(fid, 'accept', actor='Synthetic', expected_revision=1)
        elif operation == 'supersede': stale.supersede(fid, actor='Synthetic', expected_revision=1, rationale='Synthetic', statement='Alternative.', supporting_ids=refs(source)[:1])
        elif operation == 'import_d2': stale.import_d2(p, wire.J(answer(p)), 0, actor='Synthetic', expected_revision=1)
        elif operation == 'import_result': stale.import_result(p, result(p)['validated'], 0, actor='Synthetic', expected_revision=1)
        else: stale.import_results(p, result(p)['validated'], actor='Synthetic', expected_revision=1)
    assert unchanged(b) == before
    assert unchanged(f.Workspace(moved)) == original
    with pytest.raises(ValueError, match='WORKSPACE_CHANGED'): stale.export()


@pytest.mark.parametrize('expectation', [None, ('bad', {}, ''), ('', {}, '')])
def test_missing_or_invalid_handle_identity(workspace, source, expectation):
    before = unchanged(workspace)
    workspace._selection = expectation
    with pytest.raises(ValueError, match='^FINDINGS_EXPECTED_WORKSPACE_ID$'):
        register(workspace, source)
    assert unchanged(workspace) == before


def test_explicit_identity_and_revision_independent(workspace):
    before = unchanged(workspace)
    def forbidden(*args): pytest.fail('build must not run')
    with pytest.raises(ValueError, match='^FINDINGS_WORKSPACE_CHANGED$'):
        workspace._write('propose', 'Synthetic', 0, forbidden, expected_workspace_id='f'*32)
    with pytest.raises(ValueError, match='^FINDINGS_EXPECTED_WORKSPACE_ID$'):
        workspace._write('propose', 'Synthetic', 0, forbidden, expected_workspace_id='')
    with pytest.raises(ValueError, match='^FINDINGS_STALE_REVISION$'):
        workspace._write('propose', 'Synthetic', 1, forbidden, expected_workspace_id=workspace._selection[0])
    assert unchanged(workspace) == before


def test_source_binding_stays_pinned(workspace, source):
    # Empty valid genesis with a changed source path: structural loading alone permits it.
    with sqlite3.connect(workspace.path) as db:
        metadata=json.loads(db.execute('SELECT value FROM metadata').fetchone()[0])
        metadata['source_root'] += '-different'
        db.execute('UPDATE metadata SET value=?', (json.dumps(metadata),))
    before = unchanged(workspace)
    with pytest.raises(ValueError, match='^FINDINGS_WORKSPACE_BINDING_CHANGED$'):
        register(workspace, source)
    assert unchanged(workspace) == before


def test_replacement_between_preflight_and_transaction(tmp_path, source, monkeypatch):
    a = f.create(tmp_path/'selected.findings', source[0], source[1], actor='Synthetic')
    a.export()  # Thin CLI/service preflight completed before mutation.
    real_connection = a._connection
    replacement=[]
    @contextmanager
    def substituted(write=False):
        if write:
            move_owned(a,tmp_path)
            b=f.create(a.directory,source[0],source[1],actor='Synthetic')
            replacement.append((b,unchanged(b)))
        with real_connection(write) as conn: yield conn
    monkeypatch.setattr(a,'_connection',substituted)
    with pytest.raises(ValueError, match='^FINDINGS_WORKSPACE_CHANGED$'): register(a,source)
    b,before=replacement[0]
    assert unchanged(b)==before


def test_identity_check_is_inside_write_transaction(workspace, source, monkeypatch):
    original=workspace._selected
    connection=workspace._connection
    active=[]
    @contextmanager
    def observed(write=False):
        with connection(write) as conn:
            active.append((conn,write))
            try: yield conn
            finally: active.pop()
    def check(metadata, expected_workspace_id=None):
        assert active and active[-1][1] and active[-1][0].in_transaction
        return original(metadata,expected_workspace_id)
    monkeypatch.setattr(workspace,'_connection',observed)
    monkeypatch.setattr(workspace,'_selected',check)
    register(workspace,source)


@pytest.mark.parametrize('same_uuid', [False, True])
def test_different_source_equal_revision(tmp_path, source, same_uuid):
    from test_explanation_replay_status import empty_run
    other = tmp_path/'other'
    other.mkdir()
    run=empty_run(other,'structure')
    a=f.create(tmp_path/'selected.findings',source[0],source[1],actor='Synthetic')
    move_owned(a,tmp_path)
    b=f.create(a.directory,other/'runs',run['investigation_id'],actor='Synthetic')
    if same_uuid:
        db = sqlite3.connect(b.path)
        try:
            metadata = json.loads(db.execute('SELECT value FROM metadata').fetchone()[0])
            metadata['id'] = a._selection[0]
            db.execute('UPDATE metadata SET value=?', (json.dumps(metadata),))
            db.commit()
        finally:
            db.close()
        b = f.Workspace(b.directory)
    before=b.export()
    assert before['revision']==0 and before['metadata']['binding']!=a._selection[1]
    assert before['source_binding_status']=='valid_recorded_binding'
    error = 'FINDINGS_WORKSPACE_BINDING_CHANGED' if same_uuid else 'FINDINGS_WORKSPACE_CHANGED'
    with pytest.raises(ValueError,match='^'+error+'$'):register(a,source)
    assert b.export()==before

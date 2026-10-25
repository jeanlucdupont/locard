"""Completion needs retained counts, not the full forensic status projection."""
from contextlib import closing
from types import SimpleNamespace

import pytest

from forensic_assistant import v2_cli
from forensic_assistant.artifacts import userassist
from forensic_assistant.database import artifacts, sources
from forensic_assistant.database.db import connect, register_source
from forensic_assistant.interactive import creation
from forensic_assistant.retrieval import status_display
from forensic_assistant.retrieval.queries import Queries
from forensic_assistant.terminal import Palette


def make_case(path, state):
    kinds = [] if state == 'empty' else ['mft'] if state == 'complete' else [
        'mft', 'mft', 'registry', 'prefetch', 'browser', 'evtx']
    with closing(connect(path)) as db, db:
        if kinds:
            register_source(db, 'synthetic', 1, 'synthetic-source')
            for index, kind in enumerate(kinds):
                eid = f'synthetic:{index}'
                artifacts.register(db, dict(evidence_id=eid, source_type=kind,
                    artifact_type=kind, file_sha256='synthetic',
                    source_file='synthetic-source', locator_json='{}'))
                db.execute('INSERT INTO evidence_timestamps VALUES (?,?,?,?,?,?,?,?,?)',
                    (eid, 'synthetic', '2020-01-01T00:00:00Z', '0', 'synthetic',
                     'synthetic', 'synthetic', 1, 'valid'))
            run = db.execute(
                'INSERT INTO ingestion_runs(source_file,started_utc,status,inserted_count,duplicate_count,error_count) '
                'VALUES (?,?,?,?,?,?)',
                ('synthetic-source', '2020-01-01', state, len(kinds),
                 2 if state == 'partial' else 0, 1 if state == 'partial' else 0)).lastrowid
            if state == 'partial':
                db.execute('INSERT INTO ingestion_errors(run_id,stage,message) VALUES (?,?,?)',
                           (run, 'parse', 'Synthetic retained parser error'))
    return kinds


@pytest.mark.parametrize('state', ['empty', 'complete', 'partial'])
@pytest.mark.parametrize('wizard', [False, True])
@pytest.mark.parametrize('color', [False, True])
def test_summary_matches_full_status_without_unused_work(tmp_path, monkeypatch, capsys, state, wizard, color):
    path = tmp_path / 'case.db'
    kinds = make_case(path, state)
    before = path.read_bytes()
    # Reproduce the previous summary's full-status count lookup, preserving all
    # surrounding rendering and diagnostic behavior for a byte-exact comparison.
    with monkeypatch.context() as old:
        old.setattr(creation, 'artifact_counts', lambda db:
                    v2_cli.dispatch(db, SimpleNamespace(command='status'))[0]['artifact_counts'])
        expected = creation.summarize(path, Palette(color), wizard=wizard)
        expected_text = capsys.readouterr().out

    def forbidden(*args, **kwargs):
        pytest.fail('Completion calculated unused full-status information')

    monkeypatch.setattr(v2_cli, 'dispatch', forbidden)
    monkeypatch.setattr(Queries, 'coverage', forbidden)
    monkeypatch.setattr(sources, 'coverage', forbidden)
    monkeypatch.setattr(userassist, 'timeline_cte', forbidden)
    monkeypatch.setattr(status_display, 'error_details', forbidden)
    actual = creation.summarize(path, Palette(color), wizard=wizard)
    assert actual == expected
    assert capsys.readouterr().out == expected_text
    assert actual == (len(kinds), {} if not kinds else {state: 1}, int(state == 'partial'))
    assert path.read_bytes() == before


@pytest.mark.parametrize('state', ['empty', 'complete', 'partial'])
def test_explicit_status_retains_full_calculations(tmp_path, monkeypatch, state):
    path = tmp_path / 'case.db'
    kinds = make_case(path, state)
    before = path.read_bytes()
    called = []
    for owner, name in [(v2_cli, 'artifact_counts'), (Queries, 'coverage'),
                        (sources, 'coverage'), (userassist, 'timeline_cte'),
                        (status_display, 'error_details')]:
        original = getattr(owner, name)
        def spy(*args, _original=original, _name=name, **kwargs):
            called.append(_name)
            return _original(*args, **kwargs)
        monkeypatch.setattr(owner, name, spy)
    with closing(creation.open_existing(path)) as db:
        result, code = v2_cli.dispatch(db, SimpleNamespace(command='status'))
    assert code == 0
    assert result['artifact_counts'] == {kind: kinds.count(kind) for kind in kinds}
    assert result['timeline_observations'] == len(kinds)
    assert {'schema_version', 'source_coverage', 'browser_counts', 'ingestion_errors',
            'total_events', 'events_without_utc', 'ingestion_runs', 'caution'} <= result.keys()
    assert called.count('coverage') == 2
    assert {'artifact_counts', 'timeline_cte', 'error_details'} <= set(called)
    assert path.read_bytes() == before

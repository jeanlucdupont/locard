from pathlib import Path
from types import SimpleNamespace
from forensic_assistant.interactive import setup_display as display
from forensic_assistant.terminal import Palette
from forensic_assistant.artifacts.ingest import discover, ingest_artifact
from forensic_assistant.database.db import connect


def test_explicit_registry_companion_routes_without_signature_or_parser(tmp_path):
    path = tmp_path / 'SECURITY.LOG2'
    path.write_bytes(b'not a hive or validated transaction log')
    assert list(discover(path, 'registry')) == [(path, 'registry')]
    db = connect(tmp_path / 'case.db')
    try:
        def forbidden(*a):
            raise AssertionError('Companion must not run a hive parser')
        result = ingest_artifact(db, path, 'registry', runner=forbidden)
        assert result['status'] == 'unsupported'
        assert result['inserted'] == 0 and result['errors'] == 0
        assert result['replay_performed'] is False
        assert 'not validated' in result['classification_basis']
        assert db.execute('SELECT count(*) FROM evidence_records').fetchone()[0] == 0
    finally:
        db.close()


def test_normal_failure_wording_keeps_source_data(capsys):
    reason = 'Source signature does not match requested artifact type'
    rows = [dict(path='bad.pf', status=reason)]
    display.print_file_exceptions('prefetch', rows, Palette())
    text = capsys.readouterr().out
    assert 'Failed: bad.pf' in text and 'invalid Prefetch file' in text
    assert reason not in text
    assert rows[0]['status'] == reason


def test_companions_grouped_and_errors_singular(capsys):
    rows = [dict(path='A.LOG1', status='unsupported'), dict(path='A.LOG2', status='unsupported')]
    assert display.print_file_exceptions('registry', rows, Palette()) == 2
    text = capsys.readouterr().out
    assert text.count('not replayed') == 1
    assert 'A.LOG' not in text
    assert 'unsupported companions' in display.file_outcomes({'unsupported': 2}, Palette(), 'registry')
    progress = SimpleNamespace(outcome='partial', records=1, duplicates=0, errors=1)
    assert '1 error' in display.category_line('registry', progress, Palette())
    assert '1 errors' not in display.category_line('registry', progress, Palette())


def test_raw_parser_diagnostics_stay_out_of_normal_summary(monkeypatch, capsys):
    group = dict(stage='parse', message='PRIVATE parser traceback', count=17, files={'bad.evtx'}, limitation=False, no_records=True)
    monkeypatch.setattr(display, 'diagnostic_groups', lambda *a: [group])
    display.print_diagnostics(None, Palette())
    text = capsys.readouterr().out
    assert 'PRIVATE' not in text and '17 recorded errors' in text
    assert group['message'] == 'PRIVATE parser traceback'

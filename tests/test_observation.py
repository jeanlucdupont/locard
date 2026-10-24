import io
from forensic_assistant.ingest.observation import Observation, emit, CURRENT


def test_liveness_is_not_progress():
    now = [0]
    observer = Observation('Parser', stream=io.StringIO(), clock=lambda: now[0])
    observer.update(records_emitted=1)
    now[0] = 30
    observer.update(worker_pid=42, worker_alive=True, worker_exit_code=None)
    assert observer.last_progress == 0
    observer.update(records_emitted=2)
    assert observer.last_progress == 30


def test_scope_cleanup_and_path():
    output = io.StringIO()
    with Observation('Discovery', stream=output) as observer:
        emit(current_path=r'E:\Users\Example\NTUSER.DAT', entries_examined=3)
    assert CURRENT.get() is None
    assert observer.thread is None
    assert output.getvalue() == ''
    assert r'E:\Users\Example\NTUSER.DAT' in observer.render()
    assert '%' not in output.getvalue()


def test_render_sanitizes_control_characters():
    observer = Observation('Discovery', stream=io.StringIO())
    observer.update(current_path='bad\x1b[2J')
    assert '\x1b' not in observer.render()


def test_discovery_candidates_unchanged(tmp_path):
    from forensic_assistant.interactive.discovery import Inventory
    path = tmp_path / 'NTUSER.DAT'
    path.write_bytes(b'synthetic')
    with Observation('Discovery', stream=io.StringIO()) as observer:
        inventory = Inventory()
        inventory.children(tmp_path)
        inventory.add(path, 'registry')
        inventory.add(path, 'registry')
    assert len(inventory.candidates) == 1
    assert observer.fields['registry_candidates'] == 1
    assert observer.fields['entries_examined'] == 1


def test_slow_display_threshold_and_snapshot_throttle(monkeypatch):
    now = [0]
    output = io.StringIO()
    observer = Observation('Discovery', stream=output, clock=lambda: now[0], slow_after=5, diagnostics=True)
    observer.update(current_path='example', entries_examined=12)
    now[0] = 4
    observer.refresh()
    assert output.getvalue() == ''
    now[0] = 5
    observer.refresh()
    first = output.getvalue()
    assert 'example' in first and '12' in first
    now[0] = 8
    observer.refresh()
    assert output.getvalue() == first
    now[0] = 35
    observer.refresh()
    assert len(output.getvalue()) > len(first)


def test_normal_ingestion_never_escalates_and_preserves_telemetry():
    now = [0]
    output = io.StringIO()
    observer = Observation('Ingest', stream=output, clock=lambda: now[0])
    observer.update(worker_pid=123, stage_bytes=456)
    for elapsed in (0, 1, 10, 30, 60, 300, 3600, 86400):
        now[0] = elapsed
        observer.refresh()
        assert output.getvalue() == ''
    assert observer.fields['worker_pid'] == 123
    assert observer.fields['stage_bytes'] == 456
    assert '123' in observer.render() and '456' in observer.render()


def test_exception_grouping_preserves_input(capsys):
    import copy
    from forensic_assistant.interactive.setup_display import print_file_exceptions
    from forensic_assistant.terminal import Palette
    rows = [dict(path='NTUSER.DAT.LOG1', status='unsupported'),
            dict(path='bad.hive', status='failed', inserted=0),
            dict(path='partial.hive', status='partial', inserted=3)]
    before = copy.deepcopy(rows)
    print_file_exceptions('registry', rows, Palette())
    text = capsys.readouterr().out
    assert 'not replayed' in text and 'NTUSER.DAT.LOG1' not in text
    assert 'bad.hive' in text and 'partial.hive' in text
    assert 'no records retained' in text and '3 records' in text
    assert rows == before


def test_tty_refresh_and_cleanup(monkeypatch):
    import forensic_assistant.ingest.observation as module
    now = [0]
    output = io.StringIO()
    updates = []
    monkeypatch.setattr(module, 'capable', lambda stream: True)
    monkeypatch.setattr(module, 'replace_progress_line', lambda text, stream: updates.append(text))
    with Observation('Ingest', stream=output, clock=lambda: now[0], diagnostics=True) as observer:
        observer.update(current_path='slow.pf', worker_pid=123)
        now[0] = 10
        observer.refresh()
        first = output.getvalue()
        now[0] = 13
        observer.refresh()
        assert output.getvalue() == first
        assert 'slow.pf' in updates[-1] and '123' in updates[-1]
    assert updates[-1] == ''
    assert not observer.thread.is_alive()


def test_exception_files_across_families(capsys):
    from forensic_assistant.interactive.setup_display import print_file_exceptions
    from forensic_assistant.terminal import Palette
    for kind in ('evtx', 'prefetch', 'browser', 'mft'):
        print_file_exceptions(kind, [dict(path=kind + '.bad', status='failed'),
                                   dict(path=kind + '.partial', status='partial', inserted=5)], Palette())
        text = capsys.readouterr().out
        assert kind + '.bad' in text and kind + '.partial' in text
        assert 'no records retained' in text and '5 records' in text


def test_normal_discovery_and_ingestion_never_write_terminal(monkeypatch):
    import forensic_assistant.ingest.observation as module
    monkeypatch.setattr(module, 'replace_progress_line', lambda *a: (_ for _ in ()).throw(AssertionError('Unexpected terminal write')))
    for label in ('Discovering evidence', 'Ingesting artifact'):
        now = [0]
        output = io.StringIO()
        with Observation(label, stream=output, clock=lambda: now[0]) as observer:
            emit(current_path='private/path', records_emitted=5, parser_stage='parsing')
            now[0] = 3600
            observer.refresh()
            assert observer.thread is None
        assert output.getvalue() == ''
        assert observer.fields['records_emitted'] == 5
        assert CURRENT.get() is None

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
    assert not observer.thread.is_alive()
    assert r'E:\Users\Example\NTUSER.DAT' in output.getvalue()
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

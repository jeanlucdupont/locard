import io
import json
import os
from contextlib import contextmanager
from pathlib import Path
import pytest
from forensic_assistant.cli import main, build_parser
from forensic_assistant.database.db import connect, register_source
from forensic_assistant.database.artifacts import register, add_object, add_timestamp
from forensic_assistant.artifacts.context import bind_context
from forensic_assistant import output


@pytest.fixture
def case(tmp_path):
    path = tmp_path / 'case.db'
    with connect(path) as db:
        sha = 'a' * 64
        eid = 'PREFETCH:' + sha + ':File'
        source = tmp_path / 'synthetic.pf'
        source.write_bytes(b'synthetic source')
        register_source(db, sha, source.stat().st_size, str(source))
        register(
            db,
            dict(
                evidence_id=eid,
                source_type='prefetch',
                artifact_type='prefetch_file',
                file_sha256=sha,
                source_file=str(source),
                locator_json='{}'
            )
        )
        db.execute(
            'INSERT INTO prefetch_records VALUES (?,?,?,?,?,?,?)',
            (eid, 'APP.EXE', 42, 5, 30, b'synthetic raw', '[]')
        )
        bind_context(db, sha, str(source), 'lab')
        add_object(db, eid, 'a', 'executable_path_candidate', r'\WINDOWS\APP.EXE')
        for i in range(220):
            name = f'REFERENCE_ONLY_{i:03}.dll'
            add_object(db, eid, f'ref:{i:03}', 'referenced_file', name)
            db.execute('INSERT INTO prefetch_references VALUES (?,?,?)', (eid, i, name))
        for i in (1, 2):
            add_timestamp(
                db,
                eid,
                dict(
                    slot=f'run:{i}',
                    timestamp_utc=f'2020-01-0{i}T00:00:00.000000000Z',
                    source='Prefetch LastRun',
                    meaning='execution',
                    normalization_status='normalized'
                )
            )
    db.close()
    return path, eid, source


def test_search_show_raw_json(case, capsys):
    path, eid, _ = case
    args = ['--db', str(path)]
    before = path.read_bytes()
    assert main(args + ['search', '--artifact', 'prefetch', '--limit', '1']) == 0
    text = capsys.readouterr().out
    for value in ('APP.EXE', '2020-01-02', 'RUNS', 'lab', 'CANDIDATE PATH'):
        assert value in text
    assert 'REFERENCE_ONLY' not in text and len(text) < 1400
    assert main(args + ['show', eid, '--json']) == 0
    shown = json.loads(capsys.readouterr().out)
    assert shown['detail']['reference_count'] == 220 and shown['detail']['references_truncated']
    assert main(args + ['search', '--raw']) == 0
    raw = json.loads(capsys.readouterr().out)
    assert raw['records'][0]['detail']['raw_file']['encoding'] == 'base64'
    assert main(args + ['search', '--json']) == 0
    structured = json.loads(capsys.readouterr().out)
    assert structured['total'] == 1 and structured['records'][0]['detail']['reference_count'] == 220
    assert path.read_bytes() == before


def test_summary_other_artifacts_and_counts():
    from forensic_assistant.retrieval.search_display import render
    rows = [
        dict(
            id='EVTX:full',
            source_type='evtx',
            artifact_type='process',
            event_id=4688,
            command_line='secret long command',
            context={}
        ),
        dict(
            id='MFT:full',
            source_type='mft',
            artifact_type='mft_record',
            detail={'names': [{'filename': 'file.exe'}], 'allocated': 1, 'file_size': 12},
            context={}
        ),
        dict(
            id='REGISTRY:full',
            source_type='registry',
            artifact_type='registry_value',
            detail={
                'key_path': 'Software\\Example',
                'value_name': 'Example',
                'value_type': 1,
                'value_data': 'HUGE_NOT_SHOWN'
            },
            context={}
        )
    ]
    text = render(dict(records=rows, total=10, limit=3, offset=3))
    assert 'Showing 4\u20136 of 10' in text and 'additional results' not in text and 'offset=' not in text
    assert 'file.exe' in text and '4688' in text and 'HUGE_NOT_SHOWN' not in text
    rows[0]['process_name'] = 'bad\x1b[31m\ntext'
    assert '\x1b' not in render(dict(records=rows, total=3, limit=3, offset=0))


@pytest.mark.parametrize('mode', ['--output', '--append'])
@pytest.mark.parametrize('absolute', [False, True])
def test_files_create_replace_append(case, tmp_path, monkeypatch, capsys, mode, absolute):
    path, _, _ = case
    monkeypatch.chdir(tmp_path)
    target = Path('résultats with spaces.txt')
    destination = str(target.absolute() if absolute else target)
    args = ['--db', str(path), 'search', '--json', mode, destination]
    assert main(args) == 0
    first = target.read_text(encoding='utf-8')
    assert json.loads(first)['total'] == 1
    assert capsys.readouterr().out == ''
    if mode == '--output':
        target.write_text('old output', encoding='utf-8')
        assert main(args) == 2
        assert target.read_text(encoding='utf-8') == 'old output'
        args += ['--force']
    assert main(args) == 0
    second = target.read_text(encoding='utf-8')
    assert second == (first if mode == '--output' else first + '\n' + first)
    assert 'Output' in capsys.readouterr().err


@pytest.mark.parametrize(
    'flags',
    [
        ['--output', 'a', '--append', 'b'], ['--page', '--output', 'a'], ['--page', '--append', 'b'], ['--json', '--page']]
)
def test_contradictions_before_database(tmp_path, flags, capsys):
    path = tmp_path / 'absent.db'
    try:
        code = main(['--db', str(path), 'search', *flags])
    except SystemExit as exc:
        code = exc.code
    assert code == 2 and not path.exists()
    assert capsys.readouterr().err


@pytest.mark.parametrize('destination', ['missing/notes.txt', 'case.db', 'synthetic.pf', 'case.db-wal'])
def test_protected_or_invalid_destination(case, tmp_path, destination, capsys):
    path, _, source = case
    before = path.read_bytes()
    original = source.read_bytes()
    assert main(['--db', str(path), 'status', '--output', str(tmp_path / destination)]) == 2
    assert path.read_bytes() == before and source.read_bytes() == original
    assert capsys.readouterr().err


@pytest.mark.parametrize('mode', ['--output', '--append'])
def test_hardlink_source_rejected(case, tmp_path, mode):
    path, _, source = case
    alias = tmp_path / 'alias.txt'
    os.link(source, alias)
    assert main(['--db', str(path), 'status', mode, str(alias)]) == 2
    assert source.read_bytes() == b'synthetic source'


def test_unregistered_database_and_artifact_protection(case, tmp_path):
    path, _, _ = case
    for name, data in [('other.txt', b'SQLite format 3\x00'), ('artifact.txt', b'ElfFile\x00synthetic')]:
        target = tmp_path / name
        target.write_bytes(data)
        assert main(['--db', str(path), 'status', '--output', str(target), '--force']) == 2
        assert target.read_bytes() == data


def test_replace_failure_preserves_old_file(case, tmp_path, monkeypatch, capsys):
    path, _, _ = case
    target = tmp_path / 'old.txt'
    target.write_text('old')
    def fail(*a):
        raise PermissionError('synthetic denied')
    monkeypatch.setattr(output.os, 'replace', fail)
    assert main(['--db', str(path), 'status', '--output', str(target), '--force']) == 2
    assert target.read_text() == 'old' and not list(tmp_path.glob('.locard-output-*'))
    assert 'synthetic denied' in capsys.readouterr().err


def test_append_permission_failure(case, tmp_path, monkeypatch, capsys):
    path, _, _ = case
    target = tmp_path / 'notes.txt'
    original = Path.open
    def fail(self, *args, **kwargs):
        if self == target and args and args[0] == 'a':
            raise PermissionError('append denied')
        return original(self, *args, **kwargs)
    monkeypatch.setattr(Path, 'open', fail)
    assert main(['--db', str(path), 'status', '--append', str(target)]) == 2
    assert 'append denied' in capsys.readouterr().err


def test_failed_command_does_not_replace_destination(case, tmp_path):
    path, _, _ = case
    target = tmp_path / 'notes.txt'
    target.write_text('keep')
    assert main(['--db', str(path), 'show', 'missing', '--output', str(target)]) == 2
    assert target.read_text() == 'keep'


class Terminal(io.StringIO):
    def isatty(self):
        return True


@pytest.mark.parametrize(
    'keys,expected',
    [(('q',), 2), (('Q',), 2), (('\r', 'q'), 3), (('\n', 'q'), 3), ((' ', 'q'), 4), (('\x03',), 2), (('',), 2)]
)
def test_pager_keys(monkeypatch, keys, expected):
    terminal = Terminal()
    monkeypatch.setattr(output, 'redraw_viewport', lambda lines, footer: terminal.write('\n'.join([*lines, footer]) + '\n') or True)
    monkeypatch.setattr(output.sys, 'stdout', terminal)
    monkeypatch.setattr(output.sys, 'stdin', Terminal())
    monkeypatch.setattr(output.shutil, 'get_terminal_size', lambda **kw: os.terminal_size((80, 4)))
    restored = []
    @contextmanager
    def keyboard():
        iterator = iter(keys)
        try:
            yield lambda: next(iterator)
        finally:
            restored.append(True)
    monkeypatch.setattr(output, 'keyboard', keyboard)
    output.page(io.StringIO(''.join(f'row{i}\n' for i in range(10))))
    assert sum(f'row{i}\n' in terminal.getvalue() for i in range(10)) == expected
    assert restored == [True]


def test_pager_size_fallback_and_nonterminal(monkeypatch):
    terminal = Terminal()
    monkeypatch.setattr(output, 'redraw_viewport', lambda lines, footer: terminal.write('\n'.join([*lines, footer]) + '\n') or True)
    monkeypatch.setattr(output.sys, 'stdout', terminal)
    monkeypatch.setattr(output.sys, 'stdin', Terminal())
    def fail(**kw):
        raise OSError('size unavailable')
    monkeypatch.setattr(output.shutil, 'get_terminal_size', fail)
    @contextmanager
    def keyboard():
        yield lambda: 'q'
    monkeypatch.setattr(output, 'keyboard', keyboard)
    output.page(io.StringIO(''.join(f'row{i}\n' for i in range(30))))
    assert 'row21\n' in terminal.getvalue() and 'row22\n' not in terminal.getvalue()
    terminal = io.StringIO()
    monkeypatch.setattr(output.sys, 'stdout', terminal)
    def forbidden():
        raise AssertionError('Nonterminal must not read keys')
    monkeypatch.setattr(output, 'keyboard', forbidden)
    output.page(io.StringIO('all\noutput\n'))
    assert terminal.getvalue() == 'all\noutput\n'


def test_page_routes_internally_and_no_external_process(case, monkeypatch):
    import subprocess
    def forbidden(*a, **kw):
        raise AssertionError('External process forbidden')
    monkeypatch.setattr(subprocess, 'Popen', forbidden)
    monkeypatch.setattr(os, 'system', forbidden)
    path, _, _ = case
    captured = []
    monkeypatch.setattr(output, 'page', lambda stream, palette=None: captured.append(stream.read()))
    assert main(['--db', str(path), 'search', '--page']) == 0
    assert 'LAST RUN (UTC)' in captured[0]


def test_report_output_collision_preserved(tmp_path, monkeypatch, capsys):
    from forensic_assistant.reporting import cli
    seen = []
    monkeypatch.setattr(cli, 'dispatch', lambda args: seen.append(args.output) or {'status': 'COMPLETE'})
    bundle = tmp_path / 'bundle'
    target = tmp_path / 'summary.txt'
    assert main([
        '--db',
        str(tmp_path / 'unused.db'),
        'report',
        '--output',
        str(target),
        'generate',
        '--evidence',
        'x',
        '--output',
        str(bundle)
    ]) == 0
    assert seen == [str(bundle)] and json.loads(target.read_text())['status'] == 'COMPLETE'
    assert not (tmp_path / 'unused.db').exists()
    with pytest.raises(SystemExit):
        build_parser().parse_args(['report', 'generate', '--evidence', 'x'])


def test_interactive_quoted_output_and_recovery(case, tmp_path, capsys):
    from forensic_assistant.interactive.shell import Shell
    from forensic_assistant.interactive.state import State
    from test_interactive_shell import Input
    path, eid, _ = case
    target = tmp_path / 'résultat notes.txt'
    reader = Input(
        str(path),
        f'search --output "{target}"',
        f'show "{eid}" --output "{tmp_path / "missing" / "file"}"',
        'status',
        'exit'
    )
    shell = Shell(State(None), reader)
    assert shell.run() == 0 and shell.active == path and shell.last_status == 0
    assert 'LAST RUN (UTC)' in target.read_text(encoding='utf-8')


def test_help_exposes_destinations(capsys):
    for command in ('search', 'show', 'status', 'detections', 'ask', 'timeline'):
        with pytest.raises(SystemExit) as exc:
            main([command, '--help'])
        assert exc.value.code == 0
        text = capsys.readouterr().out
        assert all(flag in text for flag in ('--page', '--output FILE', '--append FILE'))


@pytest.mark.parametrize(
    'command',
    [
        ['status'], ['detections'], ['detections', '--text'], ['ask', 'Inspect PowerShell', '--dry-run'],
        ['timeline', '--start', '2020-01-01T00:00:00Z', '--end', '2020-01-03T00:00:00Z', '--text']]
)
def test_file_matches_normal_command_rendering(case, tmp_path, capsys, command):
    path, _, _ = case
    args = ['--db', str(path), *command]
    target = tmp_path / 'output.txt'
    assert main(args) == 0
    expected = capsys.readouterr().out
    assert main(args + ['--output', str(target)]) == 0
    assert target.read_text(encoding='utf-8') == expected
    assert capsys.readouterr().out == ''


def test_cross_level_conflict_and_empty_path(tmp_path, capsys):
    path = tmp_path / 'absent.db'
    assert main(['--db', str(path), 'report', '--page', 'show', 'missing', '--output', 'summary.txt']) == 2
    assert main(['--db', str(path), 'search', '--output', '']) == 2
    assert not path.exists()


def test_pager_input_failure_returns_cleanly(monkeypatch, capsys):
    terminal = Terminal()
    monkeypatch.setattr(output.sys, 'stdout', terminal)
    monkeypatch.setattr(output.sys, 'stdin', Terminal())
    @contextmanager
    def broken():
        raise RuntimeError('synthetic console failure')
        yield
    monkeypatch.setattr(output, 'keyboard', broken)
    output.page(io.StringIO('text\n'))
    assert 'paging stopped' in capsys.readouterr().err


def test_source_symlink_rejected(case, tmp_path):
    path, _, source = case
    alias = tmp_path / 'linked.txt'
    try:
        alias.symlink_to(source)
    except OSError:
        pytest.skip('Symlink privilege unavailable')
    assert main(['--db', str(path), 'status', '--output', str(alias)]) == 2
    assert source.read_bytes() == b'synthetic source'

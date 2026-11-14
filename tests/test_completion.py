"""Metadata and synthetic editor checks; no real case is needed."""
import argparse
import io
import os
from contextlib import nullcontext
from types import SimpleNamespace

import pytest

from forensic_assistant.cli import build_parser
from forensic_assistant.command_surface import FAMILIES
COMMANDS = {**FAMILIES, "help":"", "?":"", "quit":""}
from forensic_assistant.interactive import completion, console
from forensic_assistant.terminal import Palette, SGR


@pytest.fixture(autouse=True)
def fresh_metadata():
    cached = completion._parser
    cached.cache_clear()
    yield
    cached.cache_clear()


@pytest.mark.parametrize('text,expected', [
    ('sett', 'settings '), ('qui', 'quit '), ('exi', 'exi'), ('?', '? '),
    ('inv', 'investigation '), ('evi', 'evidence '),
    ('analyze session --lo', 'analyze session --logon-id '),
    ('analyze correlate --time', 'analyze correlate --timestamp-slot '),
    ('evidence source a', 'evidence source assign '), ('report sh', 'report show '),
    ('analyze session --js', 'analyze session --json '),
    ('analyze session --hostname "Lab host" --lo', 'analyze session --hostname "Lab host" --logon-id '),
    ('analyze session --hostname=lab --lo', 'analyze session --hostname=lab --logon-id '),
])
def test_unique_and_common_prefix(text, expected):
    result = completion.complete(text, len(text))
    assert result.text == expected and result.cursor == len(expected)
    assert not result.candidates


@pytest.mark.parametrize('text,expected', [
    ('', tuple(sorted(set(COMMANDS)))),
    ('evidence ingest ', ('all', 'browser', 'evtx', 'mft', 'prefetch', 'registry', 'wizard')),
    ('analyze session --l', ('--limit', '--logon-id')),
])
def test_ambiguous_sorted_candidates_preserve_buffer(text, expected):
    result = completion.complete(text, len(text))
    assert result.text == text and result.cursor == len(text)
    assert result.candidates == expected
    assert completion.complete(result.text, result.cursor) == result


@pytest.mark.parametrize('text', [
    'nonsense', 'nonsense --', 'analyze session --logon-id ', 'analyze session --logon-id --lo',
    'analyze session --lo ', 'analyze session --logon-id=0x', 'analyze session --hostname ',
    'analyze session --output ', 'evidence source show ', 'evidence source assign --file-hash ',
    'evidence source assign --source ', 'evidence show EVTX:', 'case open ', 'case "C:\\Cases\\',
    'ask "quoted --lo', 'ask \'quoted --lo', 'ask "say ""hello"" --lo',
    'analyze session -- ', 'analyze session --unknown value --lo', 'status;ver',
    'analyze session --help', 'analyze session -h', 'evidence search --path ', 'report from-case --investigation ',
])
def test_unknown_prefixes_and_values_do_nothing(text):
    assert completion.complete(text, len(text)) == completion.Completion(text, len(text))


def test_options_come_from_active_nested_parser_and_hide_suppressed():
    text = 'evidence source assign --'
    result = completion.complete(text, len(text))
    assert '--confirmation-fingerprint' in result.candidates
    assert '--file-hash' in result.candidates and '--reason' in result.candidates
    for absent in ('--hostname', '--candidate-limit', '--help', '-h', '--no-color'):
        assert absent not in result.candidates
    assert result.candidates == tuple(sorted(result.candidates))


def test_catalog_and_parser_changes_feed_completion_without_another_registry(monkeypatch):
    monkeypatch.setattr(completion, 'FAMILIES', {**FAMILIES, 'future-command': 'Synthetic'})
    assert completion.complete('future-', 7).text == 'future-command '
    parser = build_parser(interactive=True)
    commands = next(a for a in parser._actions if isinstance(a, argparse._SubParsersAction))
    next(a.choices for a in commands.choices['analyze']._actions if isinstance(a,argparse._SubParsersAction))['session'].add_argument('--future-option')
    next(a.choices for a in commands.choices['analyze']._actions if isinstance(a,argparse._SubParsersAction))['session'].add_argument('--future-hidden', help=argparse.SUPPRESS)
    monkeypatch.setattr(completion, '_parser', lambda: parser)
    assert completion.complete('analyze session --future-', 25).text == 'analyze session --future-option '


@pytest.mark.parametrize('text,cursor,expected,expected_cursor', [
    ('analyze session --lo --hostname lab', 20, 'analyze session --logon-id --hostname lab', 27),
    ('analyze session --logon-id --hostname lab', 20, 'analyze session --logon-id --hostname lab', 27),
    ('analyze session --loXXX --hostname lab', 20, 'analyze session --loXXX --hostname lab', 20),
    ('sett  --example', 4, 'settings  --example', 9),
    ('analyze session --hostname "two words" --lo', 33, 'analyze session --hostname "two words" --lo', 33),
    ('  sett', 6, '  settings ', 11),
])
def test_cursor_and_suffix_preservation(text, cursor, expected, expected_cursor):
    result = completion.complete(text, cursor)
    assert (result.text, result.cursor) == (expected, expected_cursor)


def test_metadata_cache_and_narrow_failure_handling(monkeypatch):
    import forensic_assistant.cli as cli
    factory = cli.build_parser
    calls = []
    def build(**kwargs):
        calls.append(kwargs)
        return factory(**kwargs)
    monkeypatch.setattr(cli, 'build_parser', build)
    for _ in range(5):
        completion.complete('analyze session --lo', 20)
    assert len(calls) == 1
    def unavailable():
        raise completion.MetadataUnavailable('Synthetic missing metadata')
    monkeypatch.setattr(completion, '_parser', unavailable)
    text = 'analyze session --lo'
    assert completion.complete(text, len(text)) == completion.Completion(text, len(text))
    def programming_error():
        raise RuntimeError('Unexpected programming error')
    monkeypatch.setattr(completion, '_parser', programming_error)
    with pytest.raises(RuntimeError, match='Unexpected programming error'):
        completion.complete(text, len(text))


def test_parser_construction_failure_is_isolated(monkeypatch):
    def invalid_metadata(**kwargs):
        raise argparse.ArgumentError(None, 'Synthetic conflicting parser metadata')
    monkeypatch.setattr('forensic_assistant.cli.build_parser', invalid_metadata)
    text = 'analyze session --lo'
    assert completion.complete(text, len(text)) == completion.Completion(text, len(text))


def test_argument_arity_and_abbreviations_are_metadata_driven(monkeypatch):
    parser = build_parser(interactive=True)
    commands = next(a for a in parser._actions if isinstance(a, argparse._SubParsersAction))
    next(a.choices for a in commands.choices['analyze']._actions if isinstance(a,argparse._SubParsersAction))['session'].add_argument('--pair', nargs=2)
    next(a.choices for a in commands.choices['analyze']._actions if isinstance(a,argparse._SubParsersAction))['session'].add_argument('--optional', nargs='?')
    next(a.choices for a in commands.choices['analyze']._actions if isinstance(a,argparse._SubParsersAction))['session'].add_argument('--many', nargs='+')
    monkeypatch.setattr(completion, '_parser', lambda: parser)
    for text in ('analyze session --pair ', 'analyze session --pair one ', 'analyze session --optional ',
                 'analyze session --many one ', 'analyze session --logon ', 'evidence search --kind '):
        assert completion.complete(text, len(text)).text == text
        assert not completion.complete(text, len(text)).candidates
    for text in ('analyze session --pair one two --lo', 'analyze session --optional value --lo',
                 'analyze session --many a b --json --lo', 'analyze session --logon 123 --ho'):
        expected = text[:-4] + ('--hostname ' if text.endswith('--ho') else '--logon-id ')
        assert completion.complete(text, len(text)).text == expected


def test_middle_completion_accepts_a_value_without_damaging_suffix():
    text = 'analyze session --lo --hostname lab'
    keys = [*text, *(['LEFT'] * (len(text) - 20)), '\t', *'0x123 ', '\r']
    assert console.edit(keys, complete=completion.complete, output=io.StringIO()) == (
        'analyze session --logon-id 0x123 --hostname lab')


def test_empty_tab_lists_commands_and_preserves_empty_prompt():
    stream = io.StringIO()
    assert console.edit(['\t', '\r'], prompt='locard> ', complete=completion.complete, output=stream) == ''
    rows = screen(stream.getvalue())
    assert rows[1:-2] == sorted(set(COMMANDS))
    assert rows[-2] == 'locard>'


def test_completion_does_not_dispatch_or_access_case_network_or_paths(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail('Completion attempted execution or external data access')
    monkeypatch.setattr('forensic_assistant.cli.dispatch', forbidden)
    monkeypatch.setattr('sqlite3.connect', forbidden)
    monkeypatch.setattr('socket.create_connection', forbidden)
    monkeypatch.setattr('subprocess.Popen', forbidden)
    monkeypatch.setattr('os.scandir', forbidden)
    monkeypatch.setattr('pathlib.Path.glob', forbidden)
    monkeypatch.setattr('pathlib.Path.read_text', forbidden)
    assert completion.complete('evidence source a', 17).text == 'evidence source assign '
    for text in ('evidence show EVTX:', 'case C:\\', 'analyze session --logon-id ', 'evidence search --path '):
        assert completion.complete(text, len(text)).text == text


@pytest.mark.parametrize('text,expected', [
    ('inv', 'investigation '), ('ingest-', 'ingest-'), ('analyze session --lo', 'analyze session --logon-id '),
    ('analyze correlate --time', 'analyze correlate --timestamp-slot '), ('evidence source a', 'evidence source assign '),
    ('evidence source assign --', 'evidence source assign --'), ('sett', 'settings '), ('nonsense', 'nonsense'),
])
def test_requested_synthetic_editor_examples(text, expected):
    assert console.edit([*text, '\t', '\r'], complete=completion.complete, output=io.StringIO()) == expected


def screen(text):
    """Small CR/LF display oracle for the editor's existing single-row viewport."""
    rows = [[]]
    cursor = 0
    for char in SGR.sub('', text):
        if char == '\r':
            cursor = 0
        elif char == '\n':
            rows.append([])
            cursor = 0
        else:
            row = rows[-1]
            row.extend(' ' for _ in range(max(0, cursor + 1 - len(row))))
            row[cursor] = char
            cursor += 1
    return [''.join(row).rstrip() for row in rows]


@pytest.mark.parametrize('color', [False, True])
@pytest.mark.parametrize('width', [25, 100])
def test_candidate_redraw_middle_cursor_repeated_tab_and_ctrl_l(monkeypatch, color, width):
    monkeypatch.setattr('shutil.get_terminal_size', lambda: os.terminal_size((width, 24)))
    cleared = []
    monkeypatch.setattr(console, 'clear_screen', lambda: cleared.append(True))
    prompt = Palette(color)('prompt', '[db]> ')
    stream = io.StringIO()
    text = 'evidence ingest  tail'
    keys = [*text, *(['LEFT'] * 5), '\t', '\t', '\x0c', 'a', '\r']
    value = console.edit(keys, output=stream, prompt=prompt, complete=completion.complete)
    assert value == 'evidence ingest a tail' and cleared == [True]
    rows = screen(stream.getvalue())
    assert rows.count('all') == 2 and rows.count('registry') == 2
    assert 'Import all supported' not in stream.getvalue()
    frame = (SGR.sub('', prompt) + 'evidence ingest a')[-(width - 1):]
    expected = frame + ' tail'[:max(0, width - 1 - len(frame))]
    assert rows[-2] == expected.rstrip()
    assert ('\x1b' in stream.getvalue()) == color


def test_history_draft_cancel_and_limit_are_preserved():
    history = ['status']
    stream = io.StringIO()
    assert console.edit([*'evidence ingest ', '\t', 'UP', 'DOWN', '\r'], history=history,
                        complete=completion.complete, output=stream) == 'evidence ingest '
    assert history == ['status']
    with pytest.raises(KeyboardInterrupt):
        console.edit([*'evidence ingest ', '\t', '\x03'], complete=completion.complete, output=io.StringIO())
    assert console.edit([*'ver', '\t', '\r'], limit=3, complete=completion.complete,
                        output=io.StringIO()) == 'ver'
    # Tab remains inert in ordinary value/approval readers without a completer.
    assert console.edit([*'ver', '\t', '\r'], output=io.StringIO()) == 'ver'


def test_windows_virtual_tab_maps_to_unicode_tab_and_repeat():
    key = SimpleNamespace(virtual=9, char=SimpleNamespace(unicode='\t'), down=True, repeat=2)
    source = console.WindowsKeys.__new__(console.WindowsKeys)
    source.remaining = 0
    source.handle = 0
    source.w = SimpleNamespace(DWORD=lambda: SimpleNamespace(value=0))
    source.ctypes = SimpleNamespace(byref=lambda value: value)
    source.Record = lambda: SimpleNamespace(kind=1, event=SimpleNamespace(key=key))
    def count(handle, value):
        value.value = 1
        return True
    source.kernel = SimpleNamespace(GetNumberOfConsoleInputEvents=count,
                                    ReadConsoleInputW=lambda *args: True)
    assert source.poll() == source.poll() == '\t'


@pytest.mark.skipif(os.name != 'nt', reason='Windows command editor integration')
def test_reader_enables_completion_only_for_submitted_command_history(monkeypatch):
    keys = list('sett\t\r')
    class Keys:
        def poll(self):
            return keys.pop(0) if keys else None
        def flush(self):
            keys.clear()
    monkeypatch.setattr('sys.stdin', SimpleNamespace(isatty=lambda: True))
    monkeypatch.setattr(console, 'windows_input', nullcontext)
    monkeypatch.setattr(console, 'WindowsKeys', Keys)
    reader = console.Reader()
    assert reader.read('locard> ', remember=True) == 'settings '
    assert reader.history == ['settings ']
    keys.extend('ver\t\r')
    assert reader.read('Value: ') == 'ver' and reader.history == ['settings ']
    keys.extend('evidence ingest \t\x03')
    with pytest.raises(KeyboardInterrupt):
        reader.read('locard> ', remember=True)
    assert reader.history == ['settings ']

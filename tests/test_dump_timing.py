"""Presentation and duration accounting must preserve dump contents."""
import argparse
import logging
import re

from forensic_assistant import dump_cli as dump
from forensic_assistant.cli import main
from forensic_assistant.dump_timing import Timings
from test_dump import mixed, mixed_template, Output, export
from test_interactive_shell import case


class Clock:
    def __init__(self): self.value = 0.0
    def __call__(self): return self.value
    def advance(self, seconds): self.value += seconds


def test_overwrite_two_safe_lines(mixed, capsys):
    export(mixed, 'mft')
    target = mixed.parent / 'dump' / 'mft.csv'
    before = target.read_bytes(), mixed.read_bytes()
    assert main(['--db', str(mixed), 'dump', 'mft']) == 2
    error = capsys.readouterr().err
    assert 'mft.csv\nUse --force to replace it.\n' in error
    assert 'mft.csv\\nUse' not in error
    assert before == (target.read_bytes(), mixed.read_bytes())
    assert main(['--db', str(mixed), 'dump', 'mft', '--force']) == 0
    assert before == (target.read_bytes(), mixed.read_bytes())


def test_untrusted_error_path_stays_escaped(mixed, monkeypatch, capsys):
    def refuse(*args, **kwargs):
        raise dump.DumpExistsError('bad\npath\x1b[31m.csv')
    monkeypatch.setattr(dump, 'run', refuse)
    assert main(['--db', str(mixed), 'dump', 'mft']) == 2
    error = capsys.readouterr().err
    assert 'bad\\npath' in error and '\x1b' not in error
    assert '\nUse --force to replace it.\n' in error


def test_timed_all_preserves_bytes_and_is_debug_only(mixed, caplog):
    export(mixed)
    before = {p.name: p.read_bytes() for p in (mixed.parent / 'dump').glob('*.csv')}
    database = mixed.read_bytes()
    clock = Clock()
    timing = Timings(clock)
    output = Output()
    with caplog.at_level(logging.DEBUG, logger='forensic_assistant.dump_cli'):
        dump.run(argparse.Namespace(db=str(mixed), dump_type='all', force=True), output, timings=timing)
    created = [line for line in output.lines if line.startswith('Dump created:')]
    assert len(created) == 5
    assert all(re.fullmatch(r'Dump created: \w+\.csv — [\d,]+ rows — 0.00 sec', line) for line in created)
    assert output.lines[-1] == 'Total elapsed time: 0.00 sec'
    assert 'database_read' not in '\n'.join(output.lines)
    assert 'database_read' in caplog.text and 'publication' in caplog.text
    assert str(mixed) not in caplog.text and 'SELECT' not in caplog.text
    assert before == {p.name: p.read_bytes() for p in (mixed.parent / 'dump').glob('*.csv')}
    assert mixed.read_bytes() == database
    assert all(timing.phases[k]['publication'] == 0 for k in dump.TYPES)


def test_single_and_skipped_categories(mixed, tmp_path):
    text = export(mixed, 'mft')
    assert re.search(r'Dump created: mft.csv — 3 rows\nElapsed time: \d+\.\d{2} sec$', text)
    root = tmp_path / 'empty'
    root.mkdir()
    empty = case(root)
    assert export(empty, 'browser') == 'No retained browser records to dump.'
    assert not (root / 'dump').exists()


def test_clock_and_phase_attribution():
    clock = Clock()
    timing = Timings(clock)
    class Cursor:
        def __init__(self): self.done = False
        def __iter__(self): return self
        def __next__(self):
            clock.advance(2)
            if self.done: raise StopIteration
            self.done = True
            return {'value': 42}
        def fetchone(self):
            clock.advance(3)
            return 'provenance'
    class Database:
        def execute(self, sql, params):
            clock.advance(1)
            return Cursor()
    def generate(db, kind):
        assert db.execute('SELECT * FROM source_contexts').fetchone() == 'provenance'
        for row in db.execute('SELECT * FROM evidence_records'):
            clock.advance(5)
            yield row
    assert list(timing.records(Database(), 'mft', generate)) == [{'value': 42}]
    assert timing.phases['mft']['database_read'] == 5
    assert timing.phases['mft']['provenance_read'] == 4
    assert timing.phases['mft']['normalization'] == 5
    with timing.measure('csv_write', 'mft'): clock.advance(7)
    timing.call('publication', 'mft', clock.advance, 11)
    timing.total = clock()
    assert timing.phases['mft']['csv_write'] == 7
    assert timing.phases['mft']['publication'] == 11
    assert timing.elapsed('mft') == timing.total == 32
    assert timing.summary()['other'] == 0


def test_default_clock_is_monotonic():
    import time
    assert Timings().clock is time.perf_counter
    assert time.get_clock_info('perf_counter').monotonic

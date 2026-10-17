"""Byte equivalence to the original conversion, plus page/cache isolation."""
from contextlib import closing
import copy
import csv
import hashlib
import io

import pytest

from forensic_assistant import dump_cli as dump
from forensic_assistant.investigation_ai.case import open_readonly
from registry_dump_benchmark import legacy_values, representative_rows
from test_dump import mixed, mixed_template, export


def csv_bytes(rows, converter):
    stream = io.StringIO(newline='')
    writer = csv.writer(stream, lineterminator='\r\n')
    writer.writerow(dump.COMMON + dump.FIELDS['registry'])
    for row in rows: writer.writerow(converter(row))
    return stream.getvalue().encode('utf-8')


@pytest.mark.parametrize('value', [None, '', "'quoted", '\t=SUM(1,2)', '\rtext', '\ntext',
    ' =1', '\u2003+1', '-1', '@x', '雪,"value"\nnext', -7, 0, True, False,
    ['=formula', None, '雪'], {'z': [1, None], 'a': 'x\n"y"'}, 'x' * 100000], ids=[str(i) for i in range(18)])
def test_exact_value_and_formula_equivalence(value):
    row = next(representative_rows())
    row['value_name'] = value
    row['value_data_json'] = value
    fields = dump.COMMON + dump.FIELDS['registry']
    before = copy.deepcopy(row)
    actual = dump.CsvValues(fields)(row)
    assert actual == legacy_values(row, fields)
    assert row == before


def test_safe_source_projection_cache_is_bounded_and_immutable(monkeypatch):
    rows = list(representative_rows())
    source = rows[0]['source_assertions_json']
    before = copy.deepcopy(source)
    context = rows[0]['legacy_contexts_json']
    cached = dump.source_csv_cells(['a'], {'a': source}, {'a': context})
    with pytest.raises(TypeError): cached['a']['hostname'] = 'wrong'
    assert source == before
    monkeypatch.setattr(dump, 'MAX_SOURCE_CELL_CACHE', 1)
    assert dump.source_csv_cells(['a'], {'a': source}, {'a': context}) == {}


def test_conversion_cache_does_not_cross_case_or_source():
    convert = dump.CsvValues(dump.COMMON + dump.FIELDS['registry'])
    for host in ('host-A', 'host-B'):
        row = next(representative_rows())
        row['source_assertions_json'][0]['hostname'] = host
        row['hostname'] = [host]
        row.csv_cells = dump.source_csv_cells(['same-hash'],
            {'same-hash': row['source_assertions_json']},
            {'same-hash': row['legacy_contexts_json']})['same-hash']
        assert convert(row) == legacy_values(row, dump.COMMON + dump.FIELDS['registry'])
    assert not hasattr(convert, 'cache')


def test_new_command_rebuilds_source_projection(mixed):
    from forensic_assistant.database.db import connect
    from forensic_assistant.database import sources
    export(mixed, 'registry')
    target = mixed.parent / 'dump' / 'registry.csv'
    previous = target.read_bytes()
    # A legitimate change between commands in this synthetic test case must not
    # reuse the old snapshot's derived projection, even with identical file IDs.
    with closing(connect(mixed)) as db, db:
        for row in db.execute('SELECT source_id FROM sources'):
            sources.update(db, row[0], hostname='replacement-host')
    before = mixed.read_bytes()
    export(mixed, 'registry', True)
    with target.open(encoding='utf-8', newline='') as stream:
        rows = list(csv.DictReader(stream))
    assert target.read_bytes() != previous
    assert all('replacement-host' in row['hostname'] for row in rows)
    assert mixed.read_bytes() == before


@pytest.mark.parametrize('page', [1, 3, 128, 256, 512, 1024, 2048])
def test_pages_preserve_csv_hash_and_database(mixed, monkeypatch, page):
    before = mixed.read_bytes()
    fields = dump.COMMON + dump.FIELDS['registry']
    with closing(open_readonly(mixed)) as db:
        expected = csv_bytes(dump.rows(db, 'registry'), lambda row: legacy_values(row, fields))
    monkeypatch.setattr(dump, 'PAGE', page)
    export(mixed, 'registry')
    actual = (mixed.parent / 'dump' / 'registry.csv').read_bytes()
    assert hashlib.sha256(actual).digest() == hashlib.sha256(expected).digest()
    assert actual == expected and mixed.read_bytes() == before


def test_cell_bounds_still_apply_to_cached_and_uncached_values(monkeypatch):
    monkeypatch.setattr(dump, 'MAX_CELL', 16)
    with pytest.raises(ValueError, match='safety bound'):
        dump.source_csv_cells(['a'], {'a': [{'source_id': 'a', 'display_name': 'x' * 17,
            'hostname': None, 'username': None, 'volume_root': None}]}, {})
    with pytest.raises(ValueError, match='safety bound'):
        dump.CsvValues(('value_name',))({'value_name': '雪' * 6})


def test_page_byte_bound_is_unchanged_at_larger_page_size(mixed, monkeypatch):
    monkeypatch.setattr(dump, 'PAGE', 2048)
    monkeypatch.setattr(dump, 'MAX_PAGE_BYTES', 1)
    with pytest.raises(ValueError, match='page exceeds safety bound'):
        export(mixed, 'registry')
    assert not (mixed.parent / 'dump' / 'registry.csv').exists()


def test_buffer_change_is_registry_only(mixed, monkeypatch):
    original = dump.tempfile.NamedTemporaryFile
    opened = []
    def observe(*args, **kwargs):
        opened.append((kwargs['buffering'], kwargs['encoding'], kwargs['newline']))
        return original(*args, **kwargs)
    monkeypatch.setattr(dump.tempfile, 'NamedTemporaryFile', observe)
    export(mixed, 'registry')
    export(mixed, 'mft')
    assert opened == [(1024 * 1024, 'utf-8', ''), (-1, 'utf-8', '')]

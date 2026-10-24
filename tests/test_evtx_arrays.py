import binascii
import struct
from unittest.mock import Mock

import pytest
from Evtx.BinaryParser import ParseException
from Evtx import Nodes
from forensic_assistant.ingest.evtx_arrays import (
    NumericArray, ScalarText, render_root_node_with_subs,
)
from forensic_assistant.ingest.evtx_recovery import read_records
from test_evtx_recovery import file_bytes, chunk, decode


@pytest.mark.parametrize('type_,fmt,values,expected', [
    (0x86, 'H', [0, 1, 256, 65535], ['0', '1', '256', '65535']),
    (0x84, 'B', [0, 2, 0, 255], ['0', '2', '0', '255']),
    (0x88, 'I', [4420, 0xffffffff], ['4420', '4294967295']),
    (0x8a, 'Q', [0, 75, 10920, 21694, 143, 2**64-1],
     ['0', '75', '10920', '21694', '143', '18446744073709551615']),
    (0x94, 'I', [0, 0xd0040f3, 2], ['0x0', '0xd0040f3', '0x2']),
    (0x95, 'Q', [0x3e3ffbcfe7f7859f, 0x1108f1f9777e3],
     ['0x3e3ffbcfe7f7859f', '0x1108f1f9777e3']),
])
def test_array_values(type_, fmt, values, expected):
    data = struct.pack('<' + fmt * len(values), *values)
    node = NumericArray(data, 0, len(data), type_, 0, len(data))
    assert list(node.values) == expected
    assert node.length() == len(data)
    with pytest.raises(ParseException):
        node.string()  # Never silently stringify arrays in unsupported positions.


@pytest.mark.parametrize('type_', [0x84, 0x86, 0x88, 0x8a, 0x94, 0x95])
def test_array_bounds(type_):
    for offset, length, lower, upper in [(0, -1, 0, 16), (0, None, 0, 16),
                                        (-1, 8, 0, 16), (0, 8, 1, 16),
                                        (12, 8, 0, 16), (0, 8, 0, 4),
                                        (0, 24, 0, 32)]:
        with pytest.raises(ParseException):
            NumericArray(bytes(16), offset, length, type_, lower, upper)
    if type_ != 0x84:
        with pytest.raises(ParseException):
            NumericArray(bytes(16), 0, 3, type_, 0, 16)
    assert NumericArray(b'', 0, 0, type_, 0, 0).values == ()


@pytest.mark.parametrize('type_,fmt', [(0x84, 'B'), (0x86, 'H')])
def test_repeat_containing_element_not_joined_text(type_, fmt):
    sub = Mock(spec=Nodes.NormalSubstitutionNode)
    sub.index = Mock(return_value=0)
    close = Mock(spec=Nodes.CloseElementNode)
    element = Mock(spec=Nodes.OpenStartElementNode)
    element.tag_name.return_value = 'Data'
    element.children.return_value = [sub, close]
    root = Mock()
    root.template.return_value.children.return_value = [element]
    data = struct.pack('<' + fmt * 3, 0, 2, 0)
    array = NumericArray(data, 0, len(data), type_, 0, len(data))
    assert render_root_node_with_subs(root, [array]) == '<Data>0</Data>\n<Data>2</Data>\n<Data>0</Data>\n'
    assert render_root_node_with_subs(root, [ScalarText('unchanged')]) == '<Data>unchanged</Data>\n'
    assert render_root_node_with_subs(root, [NumericArray(b'', 0, 0, type_, 0, 0)]) == '<Data></Data>\n'
    element.children.return_value = [sub, sub, close]
    with pytest.raises(ParseException, match='structure'):
        render_root_node_with_subs(root, [array])


@pytest.mark.parametrize('minor', [1, 2])
def test_supported_header_no_false_warning(tmp_path, decode, minor):
    p = tmp_path/'generated.evtx'
    p.write_bytes(file_bytes([chunk([1])], minor=minor))
    records = list(read_records(p))
    assert len(records) == 1 and records[0].xml and not records[0].error


@pytest.mark.parametrize('field,value', [(32, 127), (36, 3), (38, 4), (40, 2048)])
def test_malformed_or_unsupported_header_still_rejected(tmp_path, field, value):
    data = file_bytes([chunk([1])], minor=2)
    struct.pack_into('<H', data, field, value)
    struct.pack_into('<I', data, 124, binascii.crc32(data[:120]))
    p = tmp_path/'bad.evtx'; p.write_bytes(data)
    records = list(read_records(p))
    assert not any(r.xml for r in records)
    assert any('Unsupported EVTX header' in r.error for r in records)


def test_checksum_failure_not_hidden(tmp_path, decode):
    data = file_bytes([chunk([1])], minor=2)
    data[124] ^= 1
    p = tmp_path/'bad.evtx'; p.write_bytes(data)
    records = list(read_records(p))
    warning = next(r for r in records if r.error)
    assert warning.error == 'File header verification failed'
    assert warning.diagnostics['header_checksum_valid'] is False
    assert sum(bool(r.xml) for r in records) == 1  # Existing conservative recovery.


@pytest.mark.parametrize('type_', [0x86, 0x88])
def test_nested_array_cannot_escape_record_or_binxml_payload(type_):
    from types import SimpleNamespace
    from Evtx.Evtx import Record
    from forensic_assistant.ingest.evtx_arrays import array_bounds
    record = Mock(spec=Record)
    record.offset.return_value = 512
    record.length.return_value = 128
    record._parent = None
    nested = Mock(spec=Nodes.BXmlTypeNode)
    nested.offset.return_value = 560
    nested._length = 32
    nested._parent = record
    chunk = SimpleNamespace(offset=lambda: 0, next_record_offset=lambda: 1000)
    root = SimpleNamespace(_chunk=chunk, _parent=nested)
    assert array_bounds(root) == (560, 592)
    with pytest.raises(ParseException):
        NumericArray(bytes(1000), 588, 8, type_, *array_bounds(root))
    root._parent = record
    assert array_bounds(root) == (536, 636)


@pytest.mark.parametrize('bad_checksum,bad_record', [(True, False), (False, True)])
def test_version_two_keeps_chunk_and_record_validation(tmp_path, decode, bad_checksum, bad_record):
    p = tmp_path/'bad.evtx'
    p.write_bytes(file_bytes([chunk([1], bad_checksum=bad_checksum, bad_record=bad_record)], minor=2))
    records = list(read_records(p))
    assert not any(r.xml for r in records)
    assert any('verification failed' in r.error for r in records)
    assert not any(r.error == 'File header verification failed' for r in records)

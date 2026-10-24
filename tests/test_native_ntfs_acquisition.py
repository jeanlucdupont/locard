"""Synthetic bytes only. No real volume is opened by these tests."""
import io

import pytest

from forensic_assistant.artifacts.ntfs_acquisition import (AcquisitionError, Geometry, boot_geometry, compare,
                         copy_stream, fix_record, mft_data, runlist)


def put(buf, offset, size, value, signed=False):
    buf[offset:offset + size] = value.to_bytes(size, 'little', signed=signed)


def boot():
    b = bytearray(512)
    b[3:11] = b'NTFS    '
    b[510:512] = b'\x55\xaa'
    put(b, 11, 2, 512); b[13] = 8
    put(b, 40, 8, 8192); put(b, 48, 8, 4); put(b, 56, 8, 8)
    put(b, 64, 1, -10, signed=True); put(b, 72, 8, 123)
    return b


def geometry():
    return boot_geometry(boot(), 8192 * 512)


def attribute(mapping=b'\x11\x02\x04\x00', size=8192, flags=0, resident=None):
    if resident is not None:
        a = bytearray((24 + len(resident) + 7) // 8 * 8)
        put(a, 16, 4, len(resident)); put(a, 20, 2, 24)
        a[24:24 + len(resident)] = resident
    else:
        start = 72 if flags & 0x8000 else 64
        a = bytearray((start + len(mapping) + 7) // 8 * 8)
        a[8] = 1
        put(a, 24, 8, 1); put(a, 32, 2, start)
        put(a, 40, 8, 8192); put(a, 48, 8, size); put(a, 56, 8, size)
        a[start:start + len(mapping)] = mapping
    put(a, 0, 4, 0x80); put(a, 4, 4, len(a)); put(a, 12, 2, flags)
    return a


def record(attrs=None):
    attrs = attrs if attrs is not None else [attribute()]
    r = bytearray(1024)
    r[:4] = b'FILE'
    put(r, 4, 2, 48); put(r, 6, 2, 3); put(r, 20, 2, 56)
    put(r, 22, 2, 1); put(r, 28, 4, 1024)
    r[48:54] = b'\x13\x57ABCD'
    cursor = 56
    for a in attrs:
        r[cursor:cursor + len(a)] = a; cursor += len(a)
    put(r, cursor, 4, 0xFFFFFFFF); put(r, 24, 4, cursor + 8)
    r[510:512] = r[1022:1024] = b'\x13\x57'
    return r


def test_boot_geometry():
    g = geometry()
    assert (g.bytes_per_sector, g.cluster_size, g.record_size, g.mft_lcn, g.mirror_lcn) == (512, 4096, 1024, 4, 8)
    b = boot(); put(b, 64, 1, 1)
    assert boot_geometry(b, 8192 * 512).record_size == 4096


@pytest.mark.parametrize('offset,value', [(3, 0), (510, 0), (13, 3), (64, 0)])
def test_invalid_boot(offset, value):
    b = boot(); b[offset] = value
    with pytest.raises(AcquisitionError): boot_geometry(b, 8192 * 512)


def test_geometry_outside_device():
    with pytest.raises(AcquisitionError, match='volume length'): boot_geometry(boot(), 512)
    b = boot(); put(b, 48, 8, 999999)
    with pytest.raises(AcquisitionError, match='outside'): boot_geometry(b, 8192 * 512)


def test_fixups_do_not_mutate_raw():
    r = record(); saved = bytes(r)
    fixed = fix_record(r, 512)
    assert fixed[510:512] == b'AB' and fixed[1022:1024] == b'CD'
    assert r == saved


@pytest.mark.parametrize('offset,size,value', [(0, 4, 0), (6, 2, 2), (4, 2, 510), (510, 2, 0), (28, 4, 2048)])
def test_bad_record(offset, size, value):
    r = record(); put(r, offset, size, value)
    with pytest.raises(AcquisitionError): fix_record(r, 512)


def test_signed_fragmented_sparse_runs():
    assert runlist(bytes.fromhex('11 02 0a 11 03 fc 01 01 11 01 05 00'), 100, 7) == [
        (0, 2, 10), (2, 3, 6), (5, 1, None), (6, 1, 11)]


@pytest.mark.parametrize('mapping,total', [
    (b'\x10', 1), (b'\x19', 1), (b'\x91', 1), (b'\x11\x01', 1),
    (b'\x11\x00\x04\x00', 1), (b'\x11\x01\xff\x00', 1),
    (b'\x11\x01\x64\x00', 1), (b'\x11\x01\x01', 1), (b'\x00', 1),
    (b'\x11\x02\x63\x00', 2),
])
def test_malformed_runs(mapping, total):
    with pytest.raises(AcquisitionError): runlist(mapping, 100, total)


def test_data_forms_and_preallocation():
    data = mft_data(record(), geometry())
    assert data['runs'] == [(0, 2, 4)] and data['logical_size'] == 8192
    assert mft_data(record([attribute(resident=b'abc')]), geometry())['resident'] == b'abc'
    assert mft_data(record([attribute(size=1024)]), geometry())['allocated_size'] == 8192


def test_attribute_list_extents_and_encoding_rejected():
    listing = attribute(resident=b''); put(listing, 0, 4, 0x20)
    with pytest.raises(AcquisitionError, match='ATTRIBUTE_LIST'): mft_data(record([listing, attribute()]), geometry())
    with pytest.raises(AcquisitionError, match='multiple'): mft_data(record([attribute(), attribute()]), geometry())
    a = attribute(); put(a, 16, 8, 1)
    with pytest.raises(AcquisitionError, match='extent'): mft_data(record([a]), geometry())
    for flag in (1, 0x4000):
        with pytest.raises(AcquisitionError, match='compressed/encrypted'):
            mft_data(record([attribute(flags=flag)]), geometry())
    with pytest.raises(AcquisitionError, match='Missing unnamed'): mft_data(record([]), geometry())


def test_sparse_attribute():
    a = attribute(mapping=b'\x11\x01\x04\x01\x01\x00', flags=0x8000)
    put(a, 64, 8, 4096)
    assert mft_data(record([a]), geometry())['runs'] == [(0, 1, 4), (1, 1, None)]


def test_logical_size_sparse_and_uninitialized():
    class Reader:
        calls = []
        def read(self, offset, length):
            self.calls.append((offset, length))
            return b'x' * length
    data = dict(resident=None, logical_size=9000, initialized_size=8500,
                runs=[(0, 1, 4), (1, 1, None), (2, 1, 2)])
    reader, output = Reader(), io.BytesIO()
    count, digest = copy_stream(reader, output, data, geometry())
    assert count == 9000 and len(digest) == 64
    assert output.getvalue() == b'x' * 4096 + bytes(4096) + b'x' * 308 + bytes(500)
    assert reader.calls == [(16384, 4096), (8192, 308)]


def test_eof_and_resident():
    class Short:
        def read(self, offset, size): return b''
    with pytest.raises(AcquisitionError, match='EOF'):
        copy_stream(Short(), io.BytesIO(), mft_data(record(), geometry()), geometry())
    out = io.BytesIO()
    assert copy_stream(None, out, mft_data(record([attribute(resident=b'abc')]), geometry()), geometry())[0] == 3
    assert out.getvalue() == b'abc'


def test_comparison(tmp_path):
    a, b = tmp_path / 'a', tmp_path / 'b'
    a.write_bytes(b'abc'); b.write_bytes(b'abc')
    assert compare(a, b)['byte_equal']
    b.write_bytes(b'axc'); assert compare(a, b)['first_differing_offset'] == 1
    b.write_bytes(b'abcd'); assert compare(a, b)['first_differing_offset'] == 3


def fake_volume(monkeypatch, changing=False, failure=None):
    from forensic_assistant.artifacts import ntfs_acquisition as poc
    image = bytearray(8192 * 512)
    image[:512] = boot()
    image[16384:17408] = record()
    instances = []
    class Volume:
        path = r'\\.\E:'
        length = len(image)
        physical_read = 0
        closed = False
        def __init__(self, source):
            self.calls = 0
            instances.append(self)
        def read(self, offset, count):
            self.calls += 1
            if self.calls == 3 and failure:
                raise failure
            self.physical_read += count
            result = bytes(image[offset:offset + count])
            if changing and self.calls > 3 and offset == 0:
                result = b'X' + result[1:]
            return result
        def close(self): self.closed = True
    monkeypatch.setattr(poc, 'RawVolume', Volume)
    monkeypatch.setattr(poc, 'volume_id', lambda path: 'source' if str(path).startswith('E:') else 'destination')
    return poc, instances


def test_acquisition_raw_bytes_and_cleanup(tmp_path, monkeypatch):
    poc, instances = fake_volume(monkeypatch)
    destination = tmp_path / 'acquired'
    report = poc.acquire('E:', destination)
    assert destination.read_bytes()[:1024] == record()  # Raw USA bytes retained.
    assert report['bytes_written'] == 8192 and report['bootstrap_recheck_equal']
    assert report['independent_validation'] == 'pending'
    assert (tmp_path / 'acquired.json').exists()
    assert instances[0].closed and not list(tmp_path.glob('.mft-poc-*'))


@pytest.mark.parametrize('changing,failure', [(True, None), (False, OSError('read failed')), (False, KeyboardInterrupt())])
def test_failed_acquisition_never_publishes(tmp_path, monkeypatch, changing, failure):
    poc, instances = fake_volume(monkeypatch, changing, failure)
    with pytest.raises((AcquisitionError, OSError, KeyboardInterrupt)):
        poc.acquire('E:', tmp_path / 'acquired')
    assert list(tmp_path.iterdir()) == [] and instances[0].closed


def test_no_overwrite_and_same_volume(tmp_path, monkeypatch):
    poc, instances = fake_volume(monkeypatch)
    destination = tmp_path / 'acquired'
    destination.write_bytes(b'existing')
    with pytest.raises(AcquisitionError, match='overwrite'): poc.acquire('E:', destination)
    assert destination.read_bytes() == b'existing' and instances[0].closed
    monkeypatch.setattr(poc, 'volume_id', lambda path: 'source')
    with pytest.raises(AcquisitionError, match='source volume'): poc.acquire('E:', tmp_path / 'other')
    assert not (tmp_path / 'other').exists()


def test_invalid_name_and_missing_parent(tmp_path, monkeypatch):
    poc, _ = fake_volume(monkeypatch)
    with pytest.raises(AcquisitionError, match='stream'):
        poc.acquire('E:', tmp_path / 'file:stream')
    with pytest.raises(AcquisitionError, match='parent'):
        poc.acquire('E:', tmp_path / 'missing' / 'output')

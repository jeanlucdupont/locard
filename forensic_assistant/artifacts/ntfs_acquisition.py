"""Read-only NTFS acquisition, independent of MFT parsing and case storage.

No dependencies outside the Python standard library. Run tests without Windows;
actual acquisition requires Windows raw-volume read access (normally elevated).
"""
import argparse
import ctypes
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import tempfile
import time


class AcquisitionError(ValueError):
    pass


LIVE_LIMITATION = ('Source volume was live and not frozen during acquisition. '
                  'Metadata may have changed while the artifact was being read.')


def mounted_volume(value):
    """Only an explicit drive root selects native acquisition, never a file."""
    text = str(value)
    return text[:2].upper() if os.name == 'nt' and re.fullmatch(r'[A-Za-z]:[\\/]?', text) else None


def failure_reason(exc):
    if getattr(exc, 'winerror', None) == 5 or isinstance(exc, PermissionError):
        return 'administrator privileges required', 'Raw-volume access denied; restart with administrator privileges or supply an extracted $MFT.'
    message = str(exc)
    if 'Non-NTFS' in message:
        return 'non-NTFS source', message
    if 'changed' in message:
        return 'source changed/inconsistent', message
    if 'Unsupported' in message or 'unsupported' in message or 'ATTRIBUTE_LIST' in message:
        return 'unsupported NTFS structure', message
    if isinstance(exc, OSError):
        return 'raw-volume access/read failure', message
    return 'acquisition metadata validation failure', message


def probe(source):
    """Read boot/base metadata only. No acquisition or analyst-side writes."""
    reader = RawVolume(source)
    try:
        g = boot_geometry(reader.read(0, 4096), reader.length)
        reader.sector = g.bytes_per_sector
        data = mft_data(reader.read(g.mft_lcn * g.cluster_size, g.record_size), g)
        validate_bootstrap(data, g)
        return dict(geometry=asdict(g), run_count=len(data['runs']))
    finally:
        reader.close()


def validate_bootstrap(data, geometry):
    require(data['resident'] is None, 'Resident $MFT cannot contain its own base record; unsupported')
    require(data['logical_size'] % geometry.record_size == 0 and data['initialized_size'] >= geometry.record_size,
            'Invalid MFT stream length/initialized size')
    require(data['runs'][0][2] == geometry.mft_lcn and data['runs'][0][1] * geometry.cluster_size >= geometry.record_size,
            'Bootstrap record spans unsupported first extent or disagrees with runlist')


def require(condition, message):
    if not condition:
        raise AcquisitionError(message)


def number(data, offset, size, signed=False):
    require(0 <= offset <= len(data) - size, f'Truncated metadata at offset {offset}')
    return int.from_bytes(data[offset:offset + size], 'little', signed=signed)


@dataclass(frozen=True)
class Geometry:
    bytes_per_sector: int
    sectors_per_cluster: int
    cluster_size: int
    total_sectors: int
    mft_lcn: int
    mirror_lcn: int
    record_size: int
    serial: str

    @property
    def volume_bytes(self):
        return self.total_sectors * self.bytes_per_sector


def boot_geometry(boot, device_length):
    require(len(boot) >= 512, 'Truncated boot sector')
    require(boot[3:11] == b'NTFS    ', 'Non-NTFS volume')
    require(boot[510:512] == b'\x55\xaa', 'Invalid boot-sector signature')
    sector = number(boot, 11, 2)
    spc = boot[13]
    require(sector in (512, 1024, 2048, 4096), 'Unsupported bytes per sector')
    require(spc in (1, 2, 4, 8, 16, 32, 64, 128), 'Invalid/unsupported cluster geometry')
    cluster = sector * spc
    total, mft, mirror = (number(boot, p, 8) for p in (40, 48, 56))
    code = number(boot, 64, 1, signed=True)
    require(-16 <= code < 0 or 0 < code <= 128, 'Invalid file-record size encoding')
    record = 1 << -code if code < 0 else code * cluster
    require(512 <= record <= 65536 and record % sector == 0 and record & (record - 1) == 0,
            'Unsupported file-record size')
    require(0 < total * sector <= device_length, 'Boot geometry exceeds volume length')
    require(mft > 0 and mirror > 0 and mft != mirror, 'Invalid MFT/mirror LCN')
    require(all(lcn * cluster + record <= total * sector for lcn in (mft, mirror)),
            'MFT/mirror outside volume')
    return Geometry(sector, spc, cluster, total, mft, mirror, record,
                    f'{number(boot, 72, 8):016X}')


def fix_record(raw, sector):
    require(raw[:4] == b'FILE', 'Invalid MFT FILE signature')
    require(len(raw) >= 48 and len(raw) % sector == 0, 'Invalid record-size constraints')
    usa, count = number(raw, 4, 2), number(raw, 6, 2)
    first = number(raw, 20, 2)
    used, allocated = number(raw, 24, 4), number(raw, 28, 4)
    require(allocated == len(raw) and 48 <= first < used <= allocated and first % 8 == 0,
            'Invalid MFT attribute/record bounds')
    require(count == len(raw) // sector + 1 and usa >= 42 and usa % 2 == 0
            and usa + count * 2 <= min(first, sector - 2), 'Invalid USA bounds/count')
    fixed = bytearray(raw)
    marker = raw[usa:usa + 2]
    for index in range(1, count):
        end = index * sector
        require(raw[end - 2:end] == marker, f'USA mismatch at sector {index}, offset {end - 2}')
        fixed[end - 2:end] = raw[usa + index * 2:usa + index * 2 + 2]
    return bytes(fixed)


def runlist(data, cluster_count, expected_clusters):
    """Return (VCN, length, LCN-or-None), with signed relative LCN decoding."""
    runs = []
    cursor = vcn = lcn = 0
    while cursor < len(data):
        header = data[cursor]
        cursor += 1
        if header == 0:
            require(vcn == expected_clusters, 'Runlist VCN coverage mismatch')
            return runs
        lengths, offsets = header & 15, header >> 4
        require(1 <= lengths <= 8 and offsets <= 8, 'Malformed runlist field widths')
        require(cursor + lengths + offsets <= len(data), 'Truncated runlist')
        length = number(data, cursor, lengths)
        cursor += lengths
        require(0 < length <= expected_clusters - vcn, 'Invalid run length/coverage')
        physical = None
        if offsets:
            lcn += number(data, cursor, offsets, signed=True)
            require(0 <= lcn < cluster_count and length <= cluster_count - lcn,
                    'Run outside volume')
            physical = lcn
        runs.append((vcn, length, physical))
        vcn += length
        cursor += offsets
    raise AcquisitionError('Unterminated runlist')


def mft_data(raw, geometry):
    record = fix_record(raw, geometry.bytes_per_sector)
    require(number(record, 22, 2) & 1 and not number(record, 22, 2) & 2,
            'MFT base record is not an allocated file')
    require(number(record, 32, 8) == 0, 'Unexpected extension/base reference in record zero')
    cursor, used = number(record, 20, 2), number(record, 24, 4)
    found = []
    terminated = False
    while cursor + 4 <= used:
        kind = number(record, cursor, 4)
        if kind == 0xFFFFFFFF:
            terminated = True
            break
        length = number(record, cursor + 4, 4)
        require(length >= 24 and length % 8 == 0 and cursor + length <= used,
                f'Invalid attribute length at {cursor}')
        attr = record[cursor:cursor + length]
        form, name_length = attr[8:10]
        require(form in (0, 1), 'Invalid attribute form')
        minimum = 64 if form else 24
        require(length >= minimum, 'Truncated attribute header')
        if name_length:
            name_offset = number(attr, 10, 2)
            require(minimum <= name_offset and name_offset + name_length * 2 <= length,
                    'Invalid attribute name bounds')
        if kind == 0x20:
            raise AcquisitionError('Unsupported $ATTRIBUTE_LIST: extent resolution required; no acquisition published')
        if kind == 0x80 and name_length == 0:
            flags = number(attr, 12, 2)
            require(flags & ~0x8000 == 0, 'Unsupported compressed/encrypted/unknown $DATA flags')
            if not form:
                size, start = number(attr, 16, 4), number(attr, 20, 2)
                require(24 <= start <= length and size <= length - start, 'Invalid resident $DATA bounds')
                found.append(dict(resident=attr[start:start + size], logical_size=size,
                                  initialized_size=size, allocated_size=size, runs=[]))
            else:
                low, high = number(attr, 16, 8), number(attr, 24, 8)
                start = number(attr, 32, 2)
                allocated, size, initialized = (number(attr, p, 8) for p in (40, 48, 56))
                require(low == 0, 'Unsupported nonzero lowest VCN: additional extent required')
                require(number(attr, 34, 2) == 0, 'Unsupported compression unit')
                require((72 if flags & 0x8000 else 64) <= start < length, 'Invalid mapping-pairs offset')
                require(0 < size <= geometry.volume_bytes and initialized <= size,
                        'Invalid logical/initialized size')
                require(allocated % geometry.cluster_size == 0 and allocated <= geometry.volume_bytes,
                        'Invalid allocated size')
                runs = runlist(attr[start:], geometry.total_sectors // geometry.sectors_per_cluster, high + 1)
                coverage = (high + 1) * geometry.cluster_size
                require(size <= coverage <= geometry.volume_bytes,
                        'Run coverage does not match logical stream size')
                sparse = any(lcn is None for _, _, lcn in runs)
                require(not sparse or flags & 0x8000, 'Sparse runs without sparse attribute flag')
                require(allocated == coverage, 'Unexpected allocated/VCN size semantics')
                if flags & 0x8000:
                    physical_size = sum(n for _, n, lcn in runs if lcn is not None) * geometry.cluster_size
                    require(number(attr, 64, 8) == physical_size, 'Sparse physical allocation mismatch')
                found.append(dict(resident=None, logical_size=size, initialized_size=initialized,
                                  allocated_size=allocated, runs=runs))
        cursor += length
    require(terminated, 'Missing attribute terminator')
    require(len(found) == 1, 'Missing unnamed $DATA' if not found else 'Unsupported multiple unnamed $DATA extents')
    return found[0]


class RawVolume:
    """Read-only DASD handle. Never issues write, lock, dismount or repair calls."""
    def __init__(self, source):
        require(os.name == 'nt', 'Raw acquisition requires Windows')
        require(re.fullmatch('[A-Za-z]:', source) is not None, 'Source must be a drive letter such as E:')
        from ctypes import wintypes as w
        self.path = '\\\\.\\' + source.upper()
        self.k = k = ctypes.WinDLL('kernel32', use_last_error=True)
        k.CreateFileW.argtypes = [w.LPCWSTR, w.DWORD, w.DWORD, w.LPVOID, w.DWORD, w.DWORD, w.HANDLE]
        k.CreateFileW.restype = w.HANDLE
        k.CloseHandle.argtypes = [w.HANDLE]
        k.SetFilePointerEx.argtypes = [w.HANDLE, ctypes.c_longlong, ctypes.POINTER(ctypes.c_longlong), w.DWORD]
        k.ReadFile.argtypes = [w.HANDLE, w.LPVOID, w.DWORD, ctypes.POINTER(w.DWORD), w.LPVOID]
        k.DeviceIoControl.argtypes = [w.HANDLE, w.DWORD, w.LPVOID, w.DWORD, w.LPVOID, w.DWORD, ctypes.POINTER(w.DWORD), w.LPVOID]
        self.handle = k.CreateFileW(self.path, 0x80000000, 3, None, 3, 0, None)
        if self.handle == ctypes.c_void_p(-1).value:
            raise ctypes.WinError(ctypes.get_last_error())
        self.sector = 512
        self.physical_read = 0
        try:
            length = ctypes.c_longlong()
            returned = w.DWORD()
            if not k.DeviceIoControl(self.handle, 0x7405C, None, 0, ctypes.byref(length), 8, ctypes.byref(returned), None):
                raise ctypes.WinError(ctypes.get_last_error())
            require(returned.value == 8 and length.value >= 4096, 'Invalid raw-volume length')
            self.length = length.value
        except BaseException:
            self.close()
            raise

    def read(self, offset, length):
        require(0 <= offset <= self.length and 0 <= length <= self.length - offset, 'Read outside device')
        if not length:
            return b''
        require(length <= 8 * 1024 * 1024, 'Read exceeds bounded block size')
        start = offset // self.sector * self.sector
        count = ((offset - start + length + self.sector - 1) // self.sector) * self.sector
        require(start + count <= self.length, 'Aligned read outside device')
        # Volume reads may be noncached. Align buffer to 64 KiB, offsets/lengths
        # to the NTFS sector size. No FILE_FLAG_NO_BUFFERING write semantics.
        buffer = ctypes.create_string_buffer(count + 65536)
        address = (ctypes.addressof(buffer) + 65535) & ~65535
        returned = ctypes.c_ulong()
        if not self.k.SetFilePointerEx(self.handle, start, None, 0):
            raise ctypes.WinError(ctypes.get_last_error())
        if not self.k.ReadFile(self.handle, address, count, ctypes.byref(returned), None):
            raise ctypes.WinError(ctypes.get_last_error())
        self.physical_read += returned.value
        require(returned.value == count, f'Unexpected EOF at raw offset {start}')
        return ctypes.string_at(address + offset - start, length)

    def close(self):
        if self.handle is not None:
            self.k.CloseHandle(self.handle)
            self.handle = None


def volume_id(path):
    from ctypes import wintypes as w
    k = ctypes.WinDLL('kernel32', use_last_error=True)
    k.GetVolumePathNameW.argtypes = [w.LPCWSTR, w.LPWSTR, w.DWORD]
    k.GetVolumeNameForVolumeMountPointW.argtypes = [w.LPCWSTR, w.LPWSTR, w.DWORD]
    mount, guid = ctypes.create_unicode_buffer(32768), ctypes.create_unicode_buffer(32768)
    if not k.GetVolumePathNameW(str(path), mount, len(mount)):
        raise ctypes.WinError(ctypes.get_last_error())
    if not k.GetVolumeNameForVolumeMountPointW(mount.value, guid, len(guid)):
        raise ctypes.WinError(ctypes.get_last_error())
    return guid.value.casefold()


def destination_check(destination, source_id):
    destination = Path(os.path.abspath(destination))
    require(destination.name not in ('', '.', '..') and ':' not in destination.name,
            'Invalid output filename / alternate data stream')
    require(destination.parent.is_dir(), 'Output parent must already exist on a different volume')
    for parent in (destination.parent, *destination.parent.parents):
        info = parent.lstat()
        require(not parent.is_symlink() and not getattr(info, 'st_file_attributes', 0) & 0x400,
                'Output reparse/symlink redirection is unsupported')
    require(volume_id(destination.parent) != source_id, 'Destination is on source volume; refusing writes')
    require(not os.path.lexists(destination), 'Destination already exists; refusing overwrite')
    return destination


def copy_stream(reader, stream, data, geometry):
    digest = hashlib.sha256()
    written = 0
    if data['resident'] is not None:
        block = data['resident']
        stream.write(block); digest.update(block); written += len(block)
    else:
        for vcn, clusters, lcn in data['runs']:
            logical = vcn * geometry.cluster_size
            remaining = min(clusters * geometry.cluster_size, data['logical_size'] - logical)
            physical = lcn * geometry.cluster_size if lcn is not None else None
            consumed = 0
            while remaining > 0:
                count = min(1024 * 1024, remaining)
                valid = max(0, min(count, data['initialized_size'] - logical - consumed))
                block = reader.read(physical + consumed, valid) if physical is not None and valid else b''
                require(len(block) == valid if physical is not None else True, 'Unexpected EOF while acquiring data run')
                block += bytes(count - len(block))
                stream.write(block); digest.update(block)
                written += count; consumed += count; remaining -= count
    require(written == data['logical_size'], 'Output length mismatch')
    return written, digest.hexdigest()


def compare(left, right):
    hashes = [hashlib.sha256(), hashlib.sha256()]
    sizes = [0, 0]
    first = None
    offset = 0
    with open(left, 'rb') as a, open(right, 'rb') as b:
        while True:
            blocks = [a.read(1024 * 1024), b.read(1024 * 1024)]
            if not any(blocks):
                break
            for i, block in enumerate(blocks):
                hashes[i].update(block); sizes[i] += len(block)
            if first is None and blocks[0] != blocks[1]:
                limit = min(map(len, blocks))
                first = offset + next((i for i in range(limit) if blocks[0][i] != blocks[1][i]), limit)
            offset += max(map(len, blocks))
    return dict(sizes=sizes, sha256=[h.hexdigest() for h in hashes],
                byte_equal=first is None, first_differing_offset=first)


def acquire(source, destination, *, write_metadata=True):
    started = time.monotonic()
    started_utc = datetime.now(timezone.utc).isoformat()
    reader = RawVolume(source)
    temporary = None
    try:
        identity = volume_id(source.upper() + '\\')
        destination = destination_check(destination, identity)
        metadata = destination_check(str(destination) + '.json', identity) if write_metadata else None
        boot = reader.read(0, 4096)
        geometry = boot_geometry(boot, reader.length)
        reader.sector = geometry.bytes_per_sector
        boot = boot[:geometry.bytes_per_sector]
        offset = geometry.mft_lcn * geometry.cluster_size
        raw = reader.read(offset, geometry.record_size)
        data = mft_data(raw, geometry)
        validate_bootstrap(data, geometry)
        # Exclusive staging; nothing is published until size and metadata checks pass.
        with tempfile.NamedTemporaryFile(mode='w+b', prefix='.mft-poc-', dir=destination.parent, delete=False) as output:
            temporary = Path(output.name)
            written, digest = copy_stream(reader, output, data, geometry)
            output.flush(); os.fsync(output.fileno())
            output.seek(0)
            require(output.read(geometry.record_size) == raw, 'Acquired record zero differs from bootstrap')
        after_boot = reader.read(0, geometry.bytes_per_sector)
        after_raw = reader.read(offset, geometry.record_size)
        require(after_boot == boot and after_raw == raw and volume_id(source.upper() + '\\') == identity,
                'Source identity/bootstrap changed during acquisition; no output published')
        report = dict(source=reader.path, method='CreateFileW GENERIC_READ; raw NTFS runlist acquisition',
                      access='GENERIC_READ (0x80000000)', share='FILE_SHARE_READ | FILE_SHARE_WRITE (3)',
                      volume_identifier=identity, geometry=asdict(geometry),
                      logical_size=data['logical_size'], initialized_size=data['initialized_size'],
                      allocated_size=data['allocated_size'], runs=data['runs'],
                      run_count=len(data['runs']), sparse_runs=sum(lcn is None for _, _, lcn in data['runs']),
                      multiple_runs=len(data['runs']) > 1, attribute_list=False, additional_extents=False,
                      fragmented=any(a[2] is None or b[2] is None or a[2] + a[1] != b[2]
                                     for a, b in zip(data['runs'], data['runs'][1:])),
                      started_utc=started_utc, finished_utc=datetime.now(timezone.utc).isoformat(),
                      physical_bytes_read=reader.physical_read, bytes_written=written, sha256=digest,
                      boot_sha256=hashlib.sha256(boot).hexdigest(),
                      bootstrap_sha256=hashlib.sha256(raw).hexdigest(),
                      bootstrap_recheck_equal=True, elapsed_seconds=round(time.monotonic() - started, 3),
                      independent_validation='pending',
                      limitations=[LIVE_LIMITATION, 'Bootstrap checks do not prove whole-stream consistency.',
                                   'No full-disk integrity claim. Uninitialized logical bytes are zero-filled.',
                                   'Independent extraction comparison is required before validation.'])
        # Windows rename does not replace an existing destination. Recheck parent
        # immediately before publishing; controlled analyst output directory only.
        destination_check(destination, identity)
        if metadata is not None:
            destination_check(metadata, identity)
        os.rename(temporary, destination)
        temporary = None
        try:
            if metadata is not None:
                with metadata.open('x', encoding='utf-8') as stream:
                    json.dump(report, stream, indent=2)
        except OSError as exc:
            raise AcquisitionError(f'Output published at {destination}, but metadata could not be saved: {exc}') from exc
        return report
    finally:
        reader.close()
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    acquisition = commands.add_parser('acquire')
    acquisition.add_argument('volume')
    acquisition.add_argument('destination')
    comparison = commands.add_parser('compare')
    comparison.add_argument('acquired')
    comparison.add_argument('trusted')
    args = parser.parse_args()
    try:
        result = acquire(args.volume, args.destination) if args.command == 'acquire' else compare(args.acquired, args.trusted)
        print(json.dumps(result, indent=2))
        return 1 if result.get('byte_equal') is False else 0
    except (OSError, AcquisitionError) as exc:
        print(f'Acquisition/comparison failed: {exc}', file=sys.stderr)
        if getattr(exc, 'winerror', None) == 5:
            print('Raw volume access denied. An elevated Windows process is normally required; no permissions were changed.', file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print('Cancelled; unpublished staging is cleaned up. Check destination for output already published.', file=sys.stderr)
        return 130


if __name__ == '__main__':
    raise SystemExit(main())

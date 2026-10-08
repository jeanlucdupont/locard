"""Aligned EVTX recovery; never carve records from arbitrary bytes.

The deadline is cooperative between parser operations, not process isolation.
"""
import mmap
import time
from Evtx.Evtx import FileHeader, ChunkHeader, Record

FILE_HEADER = 4096
CHUNK = 65536


def read_records(path, *, timeout=300):
    from .evtx import ParsedRecord
    if not 1 <= timeout <= 3600:
        raise ValueError('Parser timeout must be 1..3600 seconds')
    deadline = time.monotonic() + timeout
    parsed = 0
    last_number = None
    errors = []
    pending = []

    def check_time():
        if time.monotonic() >= deadline:
            raise TimeoutError('EVTX parser deadline exceeded')

    def error(message, offset, chunk_number=None, record_id=None, *, recover=True, **details):
        diagnostic = dict(format='evtx', file_offset=offset, chunk_number=chunk_number,
                          chunk_offset=FILE_HEADER + chunk_number * CHUNK if chunk_number is not None else None,
                          record_number=record_id, last_record_number=last_number,
                          resume_offset=None, parsed_records_after_error=0, **details)
        errors.append((diagnostic, parsed))
        if recover:
            pending.append(diagnostic)
        return ParsedRecord(offset, record_id, error=message, diagnostics=diagnostic)

    try:
        with open(path, 'rb') as stream, mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as buf:
            if len(buf) < FILE_HEADER:
                yield error('Truncated EVTX file header', 0, recover=False)
                return
            header = FileHeader(buf, 0)
            shape = (header.check_magic() and header.major_version() == 3
                     and header.minor_version() in (1, 2) and header.header_size() == 128
                     and header.header_chunk_size() == FILE_HEADER)
            checksum = header.checksum() == header.calculate_checksum()
            if not header.verify():
                yield error('File header verification failed', 0, recover=False,
                            major_version=header.major_version(), minor_version=header.minor_version(),
                            header_checksum_valid=checksum, declared_chunks=header.chunk_count(),
                            dirty=header.is_dirty())
            if not shape:
                yield error('Unsupported EVTX header structure; recovery not attempted', 0, recover=False)
                return
            declared = header.chunk_count()
            physical = (len(buf) - FILE_HEADER) // CHUNK
            previous = None
            tail_started = False
            for index in range(physical):
                check_time()
                offset = FILE_HEADER + index * CHUNK
                tail = index >= declared
                # Zero-filled allocated capacity is not evidence or corruption.
                if tail and not any(buf[offset:offset + CHUNK]):
                    break
                chunk = ChunkHeader(buf, offset)
                position = offset
                try:
                    if not (chunk.check_magic() and chunk.header_size() == 128
                            and 512 <= chunk.next_record_offset() <= CHUNK
                            and (chunk.next_record_offset() == 512 or
                                 512 <= chunk.last_record_offset() < chunk.next_record_offset())
                            and chunk.verify()):
                        raise ValueError('Chunk checksum/header/bounds verification failed')
                    ranges = (chunk.file_first_record_number(), chunk.file_last_record_number(),
                              chunk.log_first_record_number(), chunk.log_last_record_number())
                    if tail:
                        # Do not import preallocated/stale chunks from a clean or
                        # wrapped log merely because an old chunk still validates.
                        if not (header.is_dirty() and checksum and previous is not None
                                and ranges[0] == previous[1] + 1 and ranges[2] == previous[3] + 1):
                            yield error('Undeclared chunk excluded: current-log continuity not established',
                                        offset, index, recover=False)
                            break
                    if tail and not tail_started:
                        tail_started = True
                        yield error('Validated EVTX chunks extend beyond the declared chunk count', offset, index,
                                    declared_chunks=declared, recovery='validated_contiguous_dirty_tail')
                    position = offset + 512
                    end = offset + chunk.next_record_offset()
                    final_start = None
                    chunk_last = None
                    while position < end:
                        check_time()
                        # Record boundaries are obtained only from validated sizes;
                        # after a bad boundary, abandon this chunk, never byte-scan.
                        record = Record(buf, position, chunk)
                        size = record.length()
                        number = record.record_num()
                        if not (record.magic() == 0x2a2a and 32 <= size <= CHUNK and size % 8 == 0
                                and position + size <= end and record.verify()):
                            raise ValueError('Record signature/size/bounds verification failed')
                        if chunk_last is not None and number <= chunk_last:
                            raise ValueError('Record numbers do not advance within chunk')
                        chunk_last = number
                        final_start = position
                        try:
                            xml = record.xml()
                            check_time()
                        except TimeoutError:
                            raise
                        except Exception as exc:
                            yield error(f'Record XML parsing failed: {type(exc).__name__}: {exc}', position, index, number)
                        else:
                            for diagnostic in pending:
                                diagnostic['resume_offset'] = position
                            pending.clear()
                            parsed += 1
                            last_number = number
                            yield ParsedRecord(position, number, xml)
                        position += size
                    if position != end or (final_start is not None and final_start != offset + chunk.last_record_offset()):
                        raise ValueError('Record chain does not match declared chunk end')
                    # Binary header numbers remain separate from XML EventRecordID.
                    previous = ranges
                except TimeoutError:
                    raise
                except Exception as exc:
                    yield error(f'EVTX chunk parsing failed: {type(exc).__name__}: {exc}',
                                position, index)
                    previous = None
                    if tail:
                        break
            if physical < declared:
                yield error('File truncated: fewer complete chunks than declared', len(buf), recover=False)
    except TimeoutError as exc:
        yield error(str(exc), None, recover=False)
    finally:
        for diagnostic, at_error in errors:
            diagnostic['parsed_records_after_error'] = parsed - at_error

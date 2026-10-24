# Native mounted-volume MFT acquisition POC

Compatibility entry point for `forensic_assistant.artifacts.ntfs_acquisition`.
The original experiment's acquisition implementation has moved to that module;
there is no second production decoder. The existing commands below remain usable.
The analyst independently validated fresh original POC/RawCopy acquisitions;
production equivalence is also tested using identical captured real-volume reads.
Independent comparison is still required to validate any particular acquisition.

Run from the repository in a Windows process allowed to read raw volumes
(normally an elevated administrator terminal). This script does not elevate
itself, change ACLs, enable privileges, lock/dismount, repair or write the source.
Create the analyst output directory on a **different** volume first:

```powershell
New-Item -ItemType Directory -Force C:\tmp\mft-poc
.\.venv\Scripts\python.exe .\poc\mft_acquire.py acquire E: 'C:\tmp\mft-poc\$MFT'
```

The single quotes are important: PowerShell otherwise expands `$MFT` as a
variable. Output and its `.json` metadata sidecar must not already exist.
Run `--help` for syntax. No real samples belong under version control.

After acquiring an independent FTK Imager extraction from the same source state:

```powershell
.\.venv\Scripts\python.exe .\poc\mft_acquire.py compare 'C:\tmp\mft-poc\$MFT' 'C:\trusted\$MFT'
```

Comparison streams both files, reports both sizes/SHA-256 hashes, compares all
bytes and reports the first differing offset. A mismatch exits nonzero and must
be investigated; it is not accepted as harmless. Comparison does not overwrite
the acquisition's metadata or automatically promote it to validated evidence.

## Read-only boundary

`CreateFileW("\\\\.\\E:", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
..., OPEN_EXISTING, 0, ...)` opens a synchronous DASD handle. Sharing write access
allows the filesystem's existing handles; it does **not** grant this handle
write access. The only subsequent device operations are the read-only
`IOCTL_DISK_GET_LENGTH_INFO`, `SetFilePointerEx`, `ReadFile`, and `CloseHandle`.
Buffers are 64-KiB aligned and reads are sector aligned. The destination volume
GUID is checked against the source; parent reparse points and existing output
files are rejected. Use a controlled analyst directory, not a directory another
process can maliciously replace during acquisition.

A read-only handle does not freeze a mounted filesystem or stop Windows/other
processes from modifying it. Before/after boot-sector and MFT base-record hashes
and volume GUID checks detect some changes, **not whole-stream consistency**.
No full-disk integrity or historical integrity claim is made. A write-blocked,
stable source is preferable. The tool never requests source write access.

## Metadata handling

Boot geometry bounds reads. USA validation/fixups occur only in a separate copy
of the base record used for attribute parsing. The acquired stream retains the
raw on-disk USA bytes. Run offsets are signed relative LCNs; lengths are positive
cluster counts. Multiple/fragmented/backward runs are supported. Sparse holes
and bytes beyond initialized size are zero-filled; allocation slack beyond
logical size is omitted. Physical byte counts include bootstrap/recheck reads.

An attribute list, multiple unnamed data extents, compressed/encrypted flags,
unusual unsupported geometry or inconsistent sizes cause an explicit failure.
Resident attributes can be parsed, but a resident MFT stream cannot contain its
own bootstrap record and is rejected for acquisition. No partial stream is
published on a parsing/read/recheck failure. A private temporary file is removed
on failure/cancellation; normal publication is Windows no-overwrite rename.
If sidecar publication fails after data publication, the error identifies the
already-published output. Process kill/power loss can leave an unaccepted temp
file; there is no automatic adoption of old staging files.

The code is ours; no third-party extractor performs acquisition. Microsoft API
and attribute-format documentation informed the implementation:

- [CreateFile volume access](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew)
- [NTFS attribute headers and mapping pairs](https://learn.microsoft.com/en-us/windows/win32/devnotes/attribute-record-header)
- [NTFS record layouts](https://kernel.googlesource.com/pub/scm/linux/kernel/git/torvalds/linux/+/865730eec5435ce40a5dc3c615077d04c8f95098/fs/ntfs/layout.h)

## Validation status

Synthetic tests cover boot geometry, USA bounds/trailers, fragmented signed
runs, sparse runs, malformed mappings, resident/nonresident attributes,
unsupported structures, logical/initialized size, EOF, raw-byte preservation,
source-change rejection, cancellation cleanup, no-overwrite/same-volume guards,
and comparison offsets. Run only this standalone set:

```powershell
.\.venv\Scripts\python.exe -m pytest tests/test_native_ntfs_acquisition.py tests/test_native_mft_ingest.py -q
```

The authorized mounted test volume was acquired successfully on 2026-10-24:
512-byte sectors, 4096-byte clusters, 1024-byte records; eight fragmented data
runs, no sparse runs or attribute list; 736,100,352 logical/initialized/allocated
bytes. Acquisition took 21.484 seconds. Source identity details, hashes and
run locations remain in the ignored local sidecar, not in repository fixtures.
The initial sandbox open returned access denied; the approved unsandboxed
process succeeded without any ACL or system changes.

The analyst subsequently supplied independent RawCopy validation for fresh
same-state acquisitions. Earlier differing hashes are not used as acceptance
baselines. Live-source comparisons can still differ between acquisitions.
A successful native read alone does not prove a frozen, consistent source state.

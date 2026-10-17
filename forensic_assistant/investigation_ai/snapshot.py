"""Private derived SQLite copies, owned and removed by the supervising process."""
import os
from pathlib import Path
import sqlite3
import tempfile
import time
import uuid

from .storage import DirectoryGuard, local_path
from .lifecycle import CleanupError


def _private_mkdir(path):
    if os.name != 'nt':
        path.mkdir(mode=0o700)
        return
    # Explicit protected DACL at creation: current user and SYSTEM only, inherited
    # by files. Never change permissions on an existing directory or case.
    import ctypes as c
    from ctypes import wintypes as w
    adv = c.WinDLL('advapi32', use_last_error=True)
    kernel = c.WinDLL('kernel32', use_last_error=True)
    kernel.GetCurrentProcess.restype = w.HANDLE
    kernel.CloseHandle.argtypes = [w.HANDLE]
    kernel.LocalFree.argtypes = [w.HLOCAL]
    adv.OpenProcessToken.argtypes = [w.HANDLE, w.DWORD, c.POINTER(w.HANDLE)]
    adv.GetTokenInformation.argtypes = [w.HANDLE, c.c_int, w.LPVOID, w.DWORD, c.POINTER(w.DWORD)]
    adv.ConvertSidToStringSidW.argtypes = [w.LPVOID, c.POINTER(w.LPWSTR)]
    adv.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [w.LPCWSTR, w.DWORD, c.POINTER(w.LPVOID), w.LPVOID]
    class Security(c.Structure):
        _fields_ = [('length', w.DWORD), ('descriptor', w.LPVOID), ('inherit', w.BOOL)]
    kernel.CreateDirectoryW.argtypes = [w.LPCWSTR, c.POINTER(Security)]
    token, sid, descriptor = w.HANDLE(), w.LPWSTR(), w.LPVOID()
    try:
        if not adv.OpenProcessToken(kernel.GetCurrentProcess(), 8, c.byref(token)):
            raise OSError(c.get_last_error(), 'Cannot establish private snapshot owner')
        size = w.DWORD()
        adv.GetTokenInformation(token, 1, None, 0, c.byref(size))
        buffer = c.create_string_buffer(size.value)
        if not adv.GetTokenInformation(token, 1, buffer, size, c.byref(size)):
            raise OSError(c.get_last_error(), 'Cannot read snapshot owner')
        sid_pointer = c.cast(buffer, c.POINTER(w.LPVOID))[0]
        if not adv.ConvertSidToStringSidW(sid_pointer, c.byref(sid)):
            raise OSError(c.get_last_error(), 'Cannot encode snapshot owner')
        sddl = 'D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;' + sid.value + ')'
        if not adv.ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, 1, c.byref(descriptor), None):
            raise OSError(c.get_last_error(), 'Cannot establish private snapshot permissions')
        security = Security(c.sizeof(Security), descriptor, False)
        if not kernel.CreateDirectoryW(str(path), c.byref(security)):
            raise OSError(c.get_last_error(), 'Cannot create private snapshot directory')
    finally:
        if descriptor:
            kernel.LocalFree(descriptor)
        if sid:
            kernel.LocalFree(c.cast(sid, w.HLOCAL))
        if token:
            kernel.CloseHandle(token)


class SnapshotDirectory:
    def __init__(self):
        self.path = local_path(Path(tempfile.gettempdir()) / ('locard-investigation-' + uuid.uuid4().hex))
        self.parent_guard = DirectoryGuard(self.path.parent)
        self.guard = None
        created = False
        try:
            _private_mkdir(self.path)
            created = True
            self.guard = DirectoryGuard(self.path)
        except BaseException:
            try:
                if created:
                    local_path(self.path).rmdir()
            except (OSError, ValueError) as exc:
                raise CleanupError('CLEANUP_LIMITATION: private snapshot setup cleanup failed') from exc
            finally:
                self.parent_guard.close()
            raise

    def close(self):
        try:
            local_path(self.path)
            # No recursive deletion, no paths derived from model/evidence input.
            for child in self.path.iterdir():
                if child.name not in ('snapshot.db', 'snapshot.db-journal', 'snapshot.db-wal', 'snapshot.db-shm'):
                    raise ValueError('Unexpected file in private snapshot directory')
                local_path(child)
                child.unlink()
            if self.guard:
                self.guard.close()
                self.guard = None
            self.path.rmdir()
            if self.path.exists():
                raise OSError('Snapshot directory still exists')
        except (OSError, ValueError) as exc:
            raise CleanupError('CLEANUP_LIMITATION: private investigation snapshot cleanup could not be confirmed') from exc
        finally:
            if self.guard:
                self.guard.close()
            self.parent_guard.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


class SnapshotFile:
    """Hold the derived file against Windows writes/replacement until worker exit."""
    def __init__(self, path):
        self.path = local_path(path)
        self.active = True
        self.handle = None
        if os.name != 'nt':
            self.path.chmod(0o400)
            return
        import ctypes as c
        from ctypes import wintypes as w
        kernel = c.WinDLL('kernel32', use_last_error=True)
        kernel.CreateFileW.argtypes = [w.LPCWSTR, w.DWORD, w.DWORD, w.LPVOID, w.DWORD, w.DWORD, w.HANDLE]
        kernel.CreateFileW.restype = w.HANDLE
        kernel.CloseHandle.argtypes = [w.HANDLE]
        kernel.GetFileInformationByHandleEx.argtypes = [w.HANDLE, c.c_int, w.LPVOID, w.DWORD]
        class Attributes(c.Structure):
            _fields_ = [('attributes', w.DWORD), ('tag', w.DWORD)]
        handle = kernel.CreateFileW(str(self.path), 0x80000000, 1, None, 3, 0x00200000, None)
        if handle == w.HANDLE(-1).value:
            raise OSError(c.get_last_error(), 'Cannot protect private snapshot')
        info = Attributes()
        if not kernel.GetFileInformationByHandleEx(handle, 9, c.byref(info), c.sizeof(info)) or info.attributes & (1024 | 16):
            kernel.CloseHandle(handle)
            raise ValueError('Private snapshot redirection rejected')
        self.kernel, self.handle = kernel, handle

    def close(self):
        self.active = False
        if self.handle is not None:
            self.kernel.CloseHandle(self.handle)
            self.handle = None


class SnapshotFingerprint:
    """Internal proof for semantic freshness checks on this pinned read view only."""
    def __init__(self, db, guard, value):
        if not guard.active or not db.in_transaction:
            raise ValueError('Private snapshot is not active')
        actual = Path(db.execute('PRAGMA database_list').fetchone()[2])
        if actual != guard.path:
            raise ValueError('Private snapshot connection mismatch')
        self.db, self.guard, self.fingerprint = db, guard, value

    def value(self, db):
        if db is not self.db or not db.in_transaction or not self.guard.active:
            raise ValueError('Private snapshot fingerprint is outside its read view')
        return self.fingerprint


def create(source, directory, deadline):
    """Backup from a SQLite read transaction includes committed WAL pages."""
    path = local_path(Path(directory) / 'snapshot.db')
    with DirectoryGuard(path.parent):
        # Never overwrite anything, including an existing or redirected target.
        with path.open('xb'):
            pass
        target = sqlite3.connect(path.as_uri() + '?mode=rw', uri=True)
        try:
            def progress(status, remaining, total):
                if time.monotonic() >= deadline:
                    raise TimeoutError('SNAPSHOT_TIMEOUT')
            source.backup(target, pages=256, progress=progress, sleep=.01)
            # Make the derived copy self-contained; never alter the live journal mode.
            target.execute('PRAGMA journal_mode=DELETE')
        finally:
            target.close()
    return path, path.stat().st_size

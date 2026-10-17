"""Local transcript directories: reject redirects and pin Windows ancestors."""
import os
from pathlib import Path
import stat


def local_path(value):
    path = Path(value)
    if '..' in path.parts or str(path).startswith(('\\\\', '//')):
        raise ValueError('Transcript destination must be a local path without traversal')
    path = path.absolute()
    if os.name == 'nt':
        import ctypes
        if ctypes.windll.kernel32.GetDriveTypeW(str(path.anchor)) == 4:
            raise ValueError('Transcript destination must be on local storage')
        if any(':' in part or part.rstrip(' .') != part for part in path.parts[1:]):
            raise ValueError('Ambiguous transcript path or alternate data stream rejected')
    for part in (*reversed(path.parents), path):
        if part.exists() or part.is_symlink():
            info = part.lstat()
            if stat.S_ISLNK(info.st_mode) or getattr(info, 'st_file_attributes', 0) & 1024:
                raise ValueError('Transcript redirection rejected')
    return path


class DirectoryGuard:
    """Deny directory renames/deletion while publishing on Windows.

    Never change ACLs. Handles are opened without FILE_SHARE_DELETE, with
    OPEN_REPARSE_POINT, then checked using the handle (not just a prior stat).
    """
    def __init__(self, path, create=False):
        self.handles = []
        self.path = local_path(path)
        try:
            for part in (*reversed(self.path.parents), self.path):
                if create:
                    part.mkdir(mode=0o700, exist_ok=True)
                local_path(part)
                if os.name == 'nt':
                    self._pin(part)
                elif not part.is_dir():
                    raise ValueError('Transcript parent is not a directory')
        except BaseException:
            self.close()
            raise

    def _pin(self, path):
        import ctypes
        from ctypes import wintypes as w
        kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        kernel.CreateFileW.argtypes = [w.LPCWSTR, w.DWORD, w.DWORD, w.LPVOID, w.DWORD, w.DWORD, w.HANDLE]
        kernel.CreateFileW.restype = w.HANDLE
        kernel.CloseHandle.argtypes = [w.HANDLE]
        kernel.GetFileInformationByHandleEx.argtypes = [w.HANDLE, ctypes.c_int, w.LPVOID, w.DWORD]
        class Attributes(ctypes.Structure):
            _fields_ = [('attributes', w.DWORD), ('tag', w.DWORD)]
        handle = kernel.CreateFileW(str(path), 0x80, 3, None, 3, 0x02200000, None)
        if handle == w.HANDLE(-1).value:
            raise OSError(ctypes.get_last_error(), 'Cannot pin transcript directory')
        self.handles.append((kernel, handle))
        info = Attributes()
        if not kernel.GetFileInformationByHandleEx(handle, 9, ctypes.byref(info), ctypes.sizeof(info)):
            raise OSError(ctypes.get_last_error(), 'Cannot validate transcript directory')
        if info.attributes & 1024 or not info.attributes & 16:
            raise ValueError('Transcript directory redirection rejected')

    def close(self):
        for kernel, handle in reversed(self.handles):
            kernel.CloseHandle(handle)
        self.handles.clear()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

import os
import ctypes
import sys
from typing import List

try:
    import win32api
except ImportError:
    win32api = None


def get_drives() -> List[str]:
    drives: List[str] = []
    try:
        if win32api is not None:
            bitmask = win32api.GetLogicalDrives()
            for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
                if bitmask & 1:
                    drives.append(letter + ":\\")
                bitmask >>= 1
        else:
            raise RuntimeError("win32api not available")
    except Exception:
        for letter in "CDEFGH":
            path = letter + ":\\"
            if os.path.exists(path):
                drives.append(path)
    return drives


def is_admin() -> bool:
    try:
        if os.name == "nt":
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        return False
    except Exception:
        return False


def request_admin_rerun() -> bool:
    if os.name != "nt" or is_admin():
        return False
    try:
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, " ".join(sys.argv), None, 1
        )
        return True
    except Exception:
        return False

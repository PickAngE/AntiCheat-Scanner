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
def get_file_properties(file_path: str) -> dict:
    properties = {"CompanyName": "", "ProductName": "", "FileDescription": ""}
    if not win32api or not os.path.exists(file_path):
        return properties
    try:
        info = win32api.GetFileVersionInfo(file_path, "\\")
        lang, codepage = win32api.GetFileVersionInfo(file_path, '\\VarFileInfo\\Translation')[0]
        str_info_path = u'\\StringFileInfo\\%04X%04X\\%s'
        for key in properties.keys():
            try:
                val = win32api.GetFileVersionInfo(file_path, str_info_path % (lang, codepage, key))
                properties[key] = val
            except:
                pass
    except Exception:
        pass
    return properties
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
        script = os.path.abspath(sys.argv[0])
        params = f'"{script}"'
        if len(sys.argv) > 1:
            params += " " + " ".join(f'"{a}"' for a in sys.argv[1:])
        work_dir = os.path.dirname(script)
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, params, work_dir, 1
        )
        return True
    except Exception:
        return False

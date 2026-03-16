import os
import subprocess
import ctypes
import sys
import hashlib
import time
from typing import List, Optional

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

def get_digital_signature(file_path: str) -> str:
    if not os.path.exists(file_path):
        return ""
    try:
        ps_cmd = f"(Get-AuthenticodeSignature '{file_path}').SignerCertificate.Subject"
        output = subprocess.check_output(["powershell", "-NoProfile", "-Command", ps_cmd], text=True, errors='ignore').strip()
        return output if output else "Unsigned/Self-signed"
    except Exception:
        return "Error checking"

def get_file_hash(file_path: str) -> str:
    if not os.path.exists(file_path):
        return ""
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception:
        return "N/A"

def get_file_properties(file_path: str) -> dict:
    properties = {
        "CompanyName": "", 
        "ProductName": "", 
        "FileDescription": "",
        "FileVersion": "",
        "InternalName": "",
        "OriginalFilename": ""
    }
    if not os.path.exists(file_path):
        return properties
    
    try:
        stat = os.stat(file_path)
        properties["CreatedAt"] = time.ctime(stat.st_ctime)
        properties["ModifiedAt"] = time.ctime(stat.st_mtime)
        properties["Size"] = f"{stat.st_size / 1024:.2f} KB"
    except Exception:
        pass

    if not win32api:
        return properties

    try:
        lang, codepage = win32api.GetFileVersionInfo(file_path, '\\VarFileInfo\\Translation')[0]
        str_info_path = u'\\StringFileInfo\\%04X%04X\\%s'
        for key in properties.keys():
            if key in ["CreatedAt", "ModifiedAt", "Size"]: continue
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

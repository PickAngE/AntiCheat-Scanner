import os
import subprocess
import ctypes
import sys
import hashlib
import time
from functools import lru_cache
from typing import Dict, List, Optional

try:
    import win32api
except ImportError:
    win32api = None

import logging

logger = logging.getLogger(__name__)


def ps_escape_path(path: str) -> str:
    return path.replace("'", "''")


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


@lru_cache(maxsize=256)
def get_digital_signature(file_path: str) -> str:
    if not os.path.exists(file_path):
        return ""
    try:
        safe_path = ps_escape_path(file_path)
        ps_cmd = (
            f"(Get-AuthenticodeSignature -LiteralPath '{safe_path}')"
            ".SignerCertificate.Subject"
        )
        output = subprocess.check_output(
            ["powershell", "-NoProfile", "-Command", ps_cmd],
            text=True,
            errors="ignore",
        ).strip()
        return output if output else "Unsigned/Self-signed"
    except Exception as e:
        logger.debug("Failed to get digital signature for %s: %s", file_path, e)
        return "Error checking"


def batch_get_digital_signatures(file_paths: List[str]) -> Dict[str, str]:
    result: Dict[str, str] = {}
    valid_paths = [p for p in file_paths if os.path.exists(p)]
    if not valid_paths:
        return result

    script_lines = [
        "$files = @(",
        *[f"    '{ps_escape_path(p)}'" for p in valid_paths],
        ");",
        "foreach ($f in $files) {",
        "  $sig = Get-AuthenticodeSignature -LiteralPath $f -ErrorAction SilentlyContinue;",
        "  if ($sig.SignerCertificate) {",
        "    Write-Output ($f + '|' + $sig.SignerCertificate.Subject);",
        "  } else {",
        "    Write-Output ($f + '|Unsigned/Self-signed');",
        "  }",
        "}",
    ]
    ps_script = "\n".join(script_lines)
    try:
        output = subprocess.check_output(
            ["powershell", "-NoProfile", "-Command", ps_script],
            text=True,
            errors="ignore",
            timeout=120,
        )
        for line in output.splitlines():
            parts = line.split("|", 1)
            if len(parts) == 2:
                result[parts[0].strip()] = parts[1].strip()
    except Exception as e:
        logger.debug("batch_get_digital_signatures failed: %s", e)
        for p in valid_paths:
            result[p] = get_digital_signature(p)
    return result


@lru_cache(maxsize=256)
def get_file_hash(file_path: str) -> str:
    if not os.path.exists(file_path):
        return ""
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception as e:
        logger.debug("Failed to hash %s: %s", file_path, e)
        return "N/A"


@lru_cache(maxsize=256)
def get_file_properties(file_path: str) -> dict:
    properties = {
        "CompanyName": "",
        "ProductName": "",
        "FileDescription": "",
        "FileVersion": "",
        "InternalName": "",
        "OriginalFilename": "",
    }
    if not os.path.exists(file_path):
        return properties

    try:
        stat = os.stat(file_path)
        properties["CreatedAt"] = time.ctime(stat.st_ctime)
        properties["ModifiedAt"] = time.ctime(stat.st_mtime)
        properties["Size"] = f"{stat.st_size / 1024:.2f} KB"
    except Exception as e:
        logger.debug("Failed to stat %s: %s", file_path, e)

    if not win32api:
        return properties

    try:
        lang, codepage = win32api.GetFileVersionInfo(file_path, "\\VarFileInfo\\Translation")[0]
        str_info_path = "\\StringFileInfo\\%04X%04X\\%s"
        for key in properties.keys():
            if key in ("CreatedAt", "ModifiedAt", "Size"):
                continue
            try:
                val = win32api.GetFileVersionInfo(file_path, str_info_path % (lang, codepage, key))
                properties[key] = val
            except Exception:
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

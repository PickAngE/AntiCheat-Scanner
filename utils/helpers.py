from __future__ import annotations

import ctypes
import hashlib
import logging
import os
import subprocess
import sys
import threading
import time
from ctypes import wintypes
from functools import lru_cache
from pathlib import Path

from utils.subprocess_helper import format_error, run_powershell

try:
    import win32api
except ImportError:
    win32api = None

logger = logging.getLogger(__name__)

PS_CMD_TIMEOUT = 120
BATCH_SIZE = 20
_PS_SEMAPHORE = threading.RLock()

CSIDL_PROGRAM_FILES = 0x0026
CSIDL_PROGRAM_FILESX86 = 0x002A
CSIDL_APP_DATA = 0x001A
CSIDL_LOCAL_APP_DATA = 0x001C
CSIDL_COMMON_PROGRAMS = 0x0017
CSIDL_SYSTEM = 0x0025
CSIDL_WINDOWS = 0x0024


class _ShellExecuteInfo(ctypes.Structure):
    _fields_ = [
        ("cbSize", wintypes.DWORD),
        ("fMask", ctypes.c_uint),
        ("hwnd", wintypes.HWND),
        ("lpVerb", wintypes.LPCWSTR),
        ("lpFile", wintypes.LPCWSTR),
        ("lpParameters", wintypes.LPCWSTR),
        ("lpDirectory", wintypes.LPCWSTR),
        ("nShow", ctypes.c_int),
        ("hInstApp", wintypes.HINSTANCE),
        ("lpIDList", ctypes.c_void_p),
        ("lpClass", wintypes.LPCWSTR),
        ("hKeyClass", wintypes.HKEY),
        ("dwHotKey", wintypes.DWORD),
        ("hIconOrMonitor", wintypes.HANDLE),
        ("hProcess", wintypes.HANDLE),
    ]


def ps_escape_path(path: str) -> str:
    return path.replace("'", "''")


def _get_default_windows_folder(csidl: int) -> str:
    defaults = {
        CSIDL_PROGRAM_FILES: os.environ.get("PROGRAMFILES", r"C:\Program Files"),
        CSIDL_PROGRAM_FILESX86: os.environ.get("PROGRAMFILES(X86)", r"C:\Program Files (x86)"),
        CSIDL_APP_DATA: os.environ.get("APPDATA", r"C:\Users\Default\AppData\Roaming"),
        CSIDL_LOCAL_APP_DATA: os.environ.get("LOCALAPPDATA", r"C:\Users\Default\AppData\Local"),
        CSIDL_COMMON_PROGRAMS: r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs",
        CSIDL_SYSTEM: os.environ.get("SYSTEMROOT", r"C:\Windows") + r"\System32",
        CSIDL_WINDOWS: os.environ.get("SYSTEMROOT", r"C:\Windows"),
    }
    return defaults.get(csidl, r"C:\Windows")


@lru_cache(maxsize=32)
def get_windows_folder(csidl: int) -> str:
    windll = getattr(ctypes, "windll", None)
    if windll is None:
        return _get_default_windows_folder(csidl)
    try:
        shell32 = windll.shell32
        get_folder_path = shell32.SHGetFolderPathW
        get_folder_path.argtypes = [
            ctypes.c_void_p,
            ctypes.c_int,
            ctypes.c_void_p,
            ctypes.c_uint,
            ctypes.c_wchar_p,
        ]
        path = ctypes.create_unicode_buffer(1024)
        result = get_folder_path(None, csidl, None, 0, path)
        if result != 0:
            logger.debug("SHGetFolderPath failed for %s with code %s", csidl, result)
            return _get_default_windows_folder(csidl)
        return path.value
    except (AttributeError, OSError, ValueError) as exc:
        logger.debug("Unable to resolve Windows folder %s: %s", csidl, format_error(exc))
        return _get_default_windows_folder(csidl)


def get_drives() -> list[str]:
    drives: list[str] = []
    if win32api is None:
        return [f"{letter}:\\" for letter in "CDEFGH" if os.path.exists(f"{letter}:\\")]
    try:
        bitmask = int(win32api.GetLogicalDrives())
    except (OSError, ValueError):
        return [f"{letter}:\\" for letter in "CDEFGH" if os.path.exists(f"{letter}:\\")]
    for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
        if bitmask & 1:
            drives.append(f"{letter}:\\")
        bitmask >>= 1
    return drives


@lru_cache(maxsize=256)
def get_digital_signature(file_path: str) -> str:
    if not os.path.exists(file_path):
        return ""
    safe_path = ps_escape_path(file_path)
    script = f"(Get-AuthenticodeSignature -LiteralPath '{safe_path}').SignerCertificate.Subject"
    try:
        with _PS_SEMAPHORE:
            output = run_powershell(script, timeout=PS_CMD_TIMEOUT).strip()
    except subprocess.TimeoutExpired:
        logger.warning("Signature timeout for %s", file_path)
        return "Signature timeout"
    except (OSError, ValueError, subprocess.CalledProcessError) as exc:
        logger.debug("Unable to read signature for %s: %s", file_path, format_error(exc))
        return "Error checking"
    return output or "Unsigned/Self-signed"


def _batch_chunk(valid_paths: list[str]) -> dict[str, str]:
    script_lines = [
        "$files = @(",
        *[f"    '{ps_escape_path(path)}'" for path in valid_paths],
        ");",
        "foreach ($file in $files) {",
        "  $signature = Get-AuthenticodeSignature -LiteralPath $file -ErrorAction SilentlyContinue;",
        "  if ($signature.SignerCertificate) {",
        "    Write-Output ($file + '|' + $signature.SignerCertificate.Subject);",
        "  } else {",
        "    Write-Output ($file + '|Unsigned/Self-signed');",
        "  }",
        "}",
    ]
    try:
        output = run_powershell("\n".join(script_lines), timeout=PS_CMD_TIMEOUT)
    except (OSError, ValueError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        logger.debug("Batch signature lookup failed: %s", format_error(exc))
        return {path: get_digital_signature(path) for path in valid_paths}
    result: dict[str, str] = {}
    for line in output.splitlines():
        parts = line.split("|", 1)
        if len(parts) == 2:
            result[parts[0].strip()] = parts[1].strip()
    return result


def batch_get_digital_signatures(file_paths: list[str]) -> dict[str, str]:
    valid_paths = [path for path in file_paths if os.path.exists(path)]
    if not valid_paths:
        return {}
    result: dict[str, str] = {}
    with _PS_SEMAPHORE:
        for start in range(0, len(valid_paths), BATCH_SIZE):
            result.update(_batch_chunk(valid_paths[start : start + BATCH_SIZE]))
    return result


@lru_cache(maxsize=256)
def get_file_hash(file_path: str) -> str:
    if not os.path.exists(file_path):
        return ""
    digest = hashlib.sha256()
    try:
        with open(file_path, "rb") as handle:
            for block in iter(lambda: handle.read(4096), b""):
                digest.update(block)
        return digest.hexdigest()
    except OSError as exc:
        logger.debug("Unable to hash %s: %s", file_path, format_error(exc))
        return "N/A"


@lru_cache(maxsize=256)
def get_file_properties(file_path: str) -> dict[str, object]:
    properties: dict[str, object] = {
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
    except OSError as exc:
        logger.debug("Unable to stat %s: %s", file_path, format_error(exc))
    if win32api is None:
        return properties
    try:
        translation = win32api.GetFileVersionInfo(file_path, "\\VarFileInfo\\Translation")[0]
        language, codepage = translation
        string_path = "\\StringFileInfo\\%04X%04X\\%s"
        for key in tuple(properties):
            if key in {"CreatedAt", "ModifiedAt", "Size"}:
                continue
            try:
                properties[key] = win32api.GetFileVersionInfo(
                    file_path,
                    string_path % (language, codepage, key),
                )
            except Exception as exc:
                logger.debug(
                    "Unable to read version property %s from %s: %s",
                    key,
                    file_path,
                    format_error(exc),
                )
    except Exception as exc:
        logger.debug("Unable to read version information from %s: %s", file_path, format_error(exc))
    return properties


def is_admin() -> bool:
    if os.name != "nt":
        return False
    windll = getattr(ctypes, "windll", None)
    if windll is None:
        return False
    try:
        return bool(windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False


def request_admin_rerun() -> int | None:
    if os.name != "nt" or is_admin():
        return None
    try:
        script = os.path.abspath(sys.argv[0])
        parameters = subprocess.list2cmdline(["-u", script, *sys.argv[1:]])
        windll = getattr(ctypes, "windll", None)
        if windll is None:
            return None
        shell_execute_ex = windll.shell32.ShellExecuteExW
        shell_execute_ex.argtypes = [ctypes.POINTER(_ShellExecuteInfo)]
        shell_execute_ex.restype = wintypes.BOOL
        execute_info = _ShellExecuteInfo()
        execute_info.cbSize = ctypes.sizeof(execute_info)
        execute_info.fMask = 0x00000040
        execute_info.lpVerb = "runas"
        execute_info.lpFile = sys.executable
        execute_info.lpParameters = parameters
        execute_info.lpDirectory = str(Path(script).parent)
        execute_info.nShow = 1
        if not shell_execute_ex(ctypes.byref(execute_info)):
            return None
        process_handle = execute_info.hProcess
        if not process_handle:
            return None
        wait_for_single_object = windll.kernel32.WaitForSingleObject
        wait_for_single_object.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        wait_for_single_object.restype = wintypes.DWORD
        get_exit_code_process = windll.kernel32.GetExitCodeProcess
        get_exit_code_process.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
        get_exit_code_process.restype = wintypes.BOOL
        close_handle = windll.kernel32.CloseHandle
        close_handle.argtypes = [wintypes.HANDLE]
        close_handle.restype = wintypes.BOOL
        wait_result = wait_for_single_object(process_handle, 0xFFFFFFFF)
        if wait_result != 0:
            close_handle(process_handle)
            return None
        exit_code = wintypes.DWORD()
        if not get_exit_code_process(process_handle, ctypes.byref(exit_code)):
            close_handle(process_handle)
            return None
        close_handle(process_handle)
        return int(exit_code.value)
    except (OSError, TypeError, ValueError):
        return None

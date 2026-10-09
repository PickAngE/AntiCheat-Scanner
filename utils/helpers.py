from __future__ import annotations

import ctypes
import hashlib
import logging
import os
import subprocess
import sys
import threading
import time
from collections.abc import Iterator
from ctypes import wintypes
from functools import lru_cache
from pathlib import Path

from utils.subprocess_helper import format_error, run_powershell

try:
    import win32api
except ImportError:
    win32api = None

logger = logging.getLogger(__name__)

SIGNATURE_TIMEOUT = "Signature timeout"
SIGNATURE_ERROR = "Error checking"
SIGNATURE_UNSIGNED = "Unsigned/Self-signed"

PS_CMD_TIMEOUT = 120
BATCH_SIZE = 20
_PS_MAX_SCRIPT_CHARS = 6000
_PS_SEMAPHORE = threading.RLock()

ADMIN_WAIT_TIMEOUT_MS = 300000

_HASH_BLOCK_SIZE = 65536

_FILE_PROPERTY_KEYS = (
    "CompanyName",
    "ProductName",
    "FileDescription",
    "FileVersion",
    "InternalName",
    "OriginalFilename",
)

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


def _ps_quote(path: str) -> str:
    cleaned = path.replace("\r", "").replace("\n", "").replace("\x00", "")
    return "'" + cleaned.replace("'", "''") + "'"


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


def _existing_drives() -> list[str]:
    return [
        f"{letter}:\\"
        for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        if os.path.exists(f"{letter}:\\")
    ]


def get_drives() -> list[str]:
    drives: list[str] = []
    if win32api is None:
        return _existing_drives()
    try:
        bitmask = int(win32api.GetLogicalDrives())
    except (OSError, ValueError) as exc:
        logger.debug("Unable to list logical drives: %s", format_error(exc))
        return _existing_drives()
    except Exception as exc:
        logger.debug("Unable to list logical drives: %s", format_error(exc))
        return _existing_drives()
    for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
        if bitmask & 1:
            drives.append(f"{letter}:\\")
        bitmask >>= 1
    return drives


@lru_cache(maxsize=256)
def get_digital_signature(file_path: str) -> str:
    if not os.path.exists(file_path):
        return ""
    script = f"(Get-AuthenticodeSignature -LiteralPath {_ps_quote(file_path)}).SignerCertificate.Subject"
    try:
        with _PS_SEMAPHORE:
            output = run_powershell(script, timeout=PS_CMD_TIMEOUT).strip()
    except subprocess.TimeoutExpired:
        logger.warning("Signature timeout for %s", file_path)
        return SIGNATURE_TIMEOUT
    except (OSError, ValueError, subprocess.CalledProcessError) as exc:
        logger.debug("Unable to read signature for %s: %s", file_path, format_error(exc))
        return SIGNATURE_ERROR
    return output or SIGNATURE_UNSIGNED


def _build_signature_script(valid_paths: list[str]) -> str:
    script_lines = [
        "$files = @(",
        *[f"    {_ps_quote(path)}" for path in valid_paths],
        ");",
        "foreach ($file in $files) {",
        "  $signature = Get-AuthenticodeSignature -LiteralPath $file -ErrorAction SilentlyContinue;",
        "  if ($signature.SignerCertificate) {",
        "    Write-Output ($file + '|' + $signature.SignerCertificate.Subject);",
        "  } else {",
        f"    Write-Output ($file + '|{SIGNATURE_UNSIGNED}');",
        "  }",
        "}",
    ]
    return "\n".join(script_lines)


def _batch_chunk(valid_paths: list[str]) -> dict[str, str]:
    if not valid_paths:
        return {}
    if len(_build_signature_script(valid_paths)) > _PS_MAX_SCRIPT_CHARS and len(valid_paths) > 1:
        middle = len(valid_paths) // 2
        merged = _batch_chunk(valid_paths[:middle])
        merged.update(_batch_chunk(valid_paths[middle:]))
        return merged
    try:
        output = run_powershell(_build_signature_script(valid_paths), timeout=PS_CMD_TIMEOUT)
    except (OSError, ValueError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        logger.debug("Batch signature lookup failed: %s", format_error(exc))
        return {path: get_digital_signature(path) for path in valid_paths}
    result: dict[str, str] = {}
    for line in output.splitlines():
        parts = line.split("|", 1)
        if len(parts) == 2:
            result[parts[0].strip()] = parts[1].strip()
    return result


def _iter_batches(valid_paths: list[str]) -> Iterator[list[str]]:
    chunk: list[str] = []
    chunk_chars = 0
    for path in valid_paths:
        cost = len(path) + 16
        if chunk and (len(chunk) >= BATCH_SIZE or chunk_chars + cost > _PS_MAX_SCRIPT_CHARS):
            yield chunk
            chunk = []
            chunk_chars = 0
        chunk.append(path)
        chunk_chars += cost
    if chunk:
        yield chunk


def batch_get_digital_signatures(file_paths: list[str]) -> dict[str, str]:
    valid_paths = [path for path in file_paths if os.path.exists(path)]
    if not valid_paths:
        return {}
    result: dict[str, str] = {}
    with _PS_SEMAPHORE:
        for chunk in _iter_batches(valid_paths):
            result.update(_batch_chunk(chunk))
    return result


@lru_cache(maxsize=256)
def get_file_hash(file_path: str) -> str:
    if not os.path.exists(file_path):
        return ""
    digest = hashlib.sha256()
    try:
        with open(file_path, "rb") as handle:
            for block in iter(lambda: handle.read(_HASH_BLOCK_SIZE), b""):
                digest.update(block)
        return digest.hexdigest()
    except OSError as exc:
        logger.debug("Unable to hash %s: %s", file_path, format_error(exc))
        return "N/A"


@lru_cache(maxsize=256)
def _cached_file_properties(file_path: str) -> dict[str, object]:
    properties: dict[str, object] = {key: "" for key in _FILE_PROPERTY_KEYS}
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
        translations = win32api.GetFileVersionInfo(file_path, "\\VarFileInfo\\Translation")
    except (OSError, ValueError, TypeError) as exc:
        logger.debug("Unable to read version information from %s: %s", file_path, format_error(exc))
        return properties
    except Exception as exc:
        logger.debug("Unable to read version information from %s: %s", file_path, format_error(exc))
        return properties
    if not translations:
        return properties
    string_path = "\\StringFileInfo\\%04X%04X\\%s"
    for key in _FILE_PROPERTY_KEYS:
        for translation in translations:
            try:
                language, codepage = translation
                value = win32api.GetFileVersionInfo(
                    file_path,
                    string_path % (language, codepage, key),
                )
            except (OSError, ValueError, TypeError):
                continue
            except Exception:
                continue
            if value:
                properties[key] = value
                break
        else:
            logger.debug("Unable to read version property %s from %s", key, file_path)
    return properties


def get_file_properties(file_path: str) -> dict[str, object]:
    return dict(_cached_file_properties(file_path))


def _clear_caches() -> None:
    get_digital_signature.cache_clear()
    get_file_hash.cache_clear()
    _cached_file_properties.cache_clear()


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
        frozen = bool(getattr(sys, "frozen", False))
        if frozen:
            target = sys.executable
            parameters = subprocess.list2cmdline(sys.argv[1:])
            directory = str(Path(sys.executable).parent)
        elif len(sys.argv) > 0 and sys.argv[0] == "-m":
            target = sys.executable
            parameters = subprocess.list2cmdline(["-u", "-m", *sys.argv[1:]])
            directory = os.path.abspath(os.getcwd())
        else:
            script = os.path.abspath(sys.argv[0])
            parameters = subprocess.list2cmdline(["-u", script, *sys.argv[1:]])
            target = sys.executable
            directory = str(Path(script).parent)
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
        execute_info.lpFile = target
        execute_info.lpParameters = parameters
        execute_info.lpDirectory = directory
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
        wait_result = wait_for_single_object(process_handle, ADMIN_WAIT_TIMEOUT_MS)
        if wait_result != 0:



            logger.debug("Timed out or failed waiting for the elevated process")
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

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
from concurrent.futures import ThreadPoolExecutor
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
BATCH_SIZE = 64
_PS_MAX_SCRIPT_CHARS = 6000
SIGNATURE_WORKERS = 4
_PS_SLOTS = threading.BoundedSemaphore(SIGNATURE_WORKERS)

ADMIN_WAIT_INFINITE = 0xFFFFFFFF

_HASH_BLOCK_SIZE = 65536
_MAX_HASH_BYTES = 1024**3

_FILE_PROPERTY_KEYS = (
    "CompanyName",
    "ProductName",
    "FileDescription",
    "FileVersion",
    "InternalName",
    "OriginalFilename",
)


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


def _run_powershell(script: str) -> str:
    with _PS_SLOTS:
        return run_powershell(script, timeout=PS_CMD_TIMEOUT)


@lru_cache(maxsize=2048)
def get_digital_signature(file_path: str) -> str:
    if not os.path.exists(file_path):
        return ""
    script = f"(Get-AuthenticodeSignature -LiteralPath {_ps_quote(file_path)}).SignerCertificate.Subject"
    try:
        output = _run_powershell(script).strip()
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
        output = _run_powershell(_build_signature_script(valid_paths))
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
    chunks = list(_iter_batches(valid_paths))
    if len(chunks) == 1:
        return _batch_chunk(chunks[0])
    result: dict[str, str] = {}
    with ThreadPoolExecutor(max_workers=min(len(chunks), SIGNATURE_WORKERS)) as pool:
        for chunk_result in pool.map(_batch_chunk, chunks):
            result.update(chunk_result)
    return result


@lru_cache(maxsize=2048)
def get_file_hash(file_path: str) -> str:
    if not os.path.exists(file_path):
        return ""
    try:
        if os.path.getsize(file_path) > _MAX_HASH_BYTES:
            logger.debug("Skipping hash for %s: file too large", file_path)
            return ""
    except OSError as exc:
        logger.debug("Unable to size %s: %s", file_path, format_error(exc))
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


@lru_cache(maxsize=2048)
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
        wait_result = wait_for_single_object(process_handle, ADMIN_WAIT_INFINITE)
        if wait_result != 0:
            logger.debug("Waiting for the elevated process failed")
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

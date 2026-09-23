from __future__ import annotations

import csv
import ctypes
import logging
import os
import subprocess
from collections.abc import Sequence
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

logger = logging.getLogger(__name__)


def format_error(error: BaseException) -> str:
    if isinstance(error, FileNotFoundError):
        label = "file not found"
    elif isinstance(error, PermissionError):
        label = "permission denied"
    elif isinstance(error, subprocess.TimeoutExpired):
        label = "operation timed out"
    elif isinstance(error, subprocess.CalledProcessError):
        return f"command failed with exit code {error.returncode}"
    elif isinstance(error, ValueError):
        label = "invalid value"
    elif isinstance(error, csv.Error):
        label = "CSV parse error"
    elif error.__class__.__module__ == "pywintypes":
        label = "Windows API error"
    else:
        label = error.__class__.__name__
    code = getattr(error, "winerror", None) or getattr(error, "errno", None)
    return f"{label} (code {code})" if code is not None else label


@dataclass(frozen=True, slots=True)
class CommandResult:
    output: str
    available: bool
    error: str | None = None


def _windows_directory() -> Path:
    windll = getattr(ctypes, "windll", None)
    if windll is not None:
        buffer = ctypes.create_unicode_buffer(32768)
        length = windll.kernel32.GetWindowsDirectoryW(buffer, len(buffer))
        if length:
            return Path(buffer.value)
    return Path(os.environ.get("SYSTEMROOT", r"C:\Windows"))


def _system_environment() -> dict[str, str]:
    windows_directory = _windows_directory()
    system32 = str(windows_directory / "System32")
    windows = str(windows_directory)
    environment = os.environ.copy()
    environment["PATH"] = os.pathsep.join((system32, windows))
    environment["SystemRoot"] = windows
    return environment


@lru_cache(maxsize=32)
def system_tool(name: str) -> str:
    if not name or Path(name).name != name:
        raise ValueError(f"Invalid system tool name: {name}")
    if name.casefold() == "powershell.exe":
        relative_path = Path("System32") / "WindowsPowerShell" / "v1.0" / name
    else:
        relative_path = Path("System32") / name
    return str((_windows_directory() / relative_path).resolve())


def _validated_executable(arguments: Sequence[str]) -> Path:
    if not arguments:
        raise ValueError("A command is required")
    executable = Path(arguments[0])
    if not executable.is_absolute():
        raise ValueError("System commands must use absolute executable paths")
    windows_directory = _windows_directory().resolve()
    try:
        executable.resolve().relative_to(windows_directory)
    except ValueError as exc:
        raise ValueError("System commands must be located inside the Windows directory") from exc
    return executable


def run_cmd(arguments: Sequence[str], timeout: int = 60) -> CommandResult:
    try:
        executable = _validated_executable(arguments)
        process = subprocess.run(
            list(arguments),
            capture_output=True,
            text=True,
            errors="ignore",
            timeout=timeout,
            check=False,
            shell=False,
            cwd=str(executable.parent),
            env=_system_environment(),
            stdin=subprocess.DEVNULL,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
        error = format_error(exc)
        logger.warning("System command failed: %s", error)
        return CommandResult(output="", available=False, error=error)
    if process.returncode != 0:
        error = f"command exited with code {process.returncode}"
        logger.warning("%s failed: %s", arguments[0], error)
        return CommandResult(output="", available=False, error=error)
    return CommandResult(output=process.stdout, available=True)


def run_powershell(script: str, timeout: int = 120) -> str:
    executable = system_tool("powershell.exe")
    process = subprocess.run(
        [executable, "-NoProfile", "-NonInteractive", "-Command", script],
        capture_output=True,
        text=True,
        errors="ignore",
        timeout=timeout,
        check=True,
        shell=False,
        cwd=str(Path(executable).parent),
        env=_system_environment(),
        stdin=subprocess.DEVNULL,
    )
    return process.stdout

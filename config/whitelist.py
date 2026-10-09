from __future__ import annotations

import json
import logging
import re
import threading
from pathlib import Path, PureWindowsPath
from typing import TypedDict

from utils.subprocess_helper import format_error

logger = logging.getLogger(__name__)

_WHITELIST_PATH = Path(__file__).with_name("whitelist.json")
_REQUIRED_WHITELIST_KEYS = ("files", "processes", "services", "folders")

_OPTIONAL_WHITELIST_KEYS = ("drivers", "registry", "tasks", "traces")
_ALL_WHITELIST_KEYS = _REQUIRED_WHITELIST_KEYS + _OPTIONAL_WHITELIST_KEYS

_PATH_CATEGORIES = frozenset({"files", "folders", "drivers", "registry", "tasks", "traces"})
_NAME_CATEGORIES = frozenset({"processes", "services"})
_CATEGORY_ALIASES = {
    "file": "files",
    "folder": "folders",
    "process": "processes",
    "service": "services",
    "driver": "drivers",
    "task": "tasks",
    "trace": "traces",
}
_STATUS_SUFFIX = re.compile(r"\s+\[(?:RUNNING|STOPPED)\]$", re.IGNORECASE)
_PAREN_SUFFIX = re.compile(r"\s+\([^()]*\)\s*$")
_PREFIX_LABEL = re.compile(r"[A-Za-z][A-Za-z ]*")
_whitelist_lock = threading.Lock()
_disabled = False
_whitelist_cache: WhitelistData | None = None
_whitelist_sets: dict[str, frozenset[str]] | None = None
_whitelist_sets_source: WhitelistData | None = None


class WhitelistData(TypedDict):
    files: list[str]
    processes: list[str]
    services: list[str]
    folders: list[str]
    drivers: list[str]
    registry: list[str]
    tasks: list[str]
    traces: list[str]


def _empty_whitelist() -> WhitelistData:
    return WhitelistData(
        files=[],
        processes=[],
        services=[],
        folders=[],
        drivers=[],
        registry=[],
        tasks=[],
        traces=[],
    )


def _normalize_path(value: str) -> str:
    return value.strip().replace("/", "\\").rstrip("\\").lower()


def _string_list(value: object, field_name: str) -> list[str]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise ValueError(f"Whitelist field {field_name} must be a list of strings")
    result: list[str] = []
    seen: set[str] = set()
    for item in value:
        stripped = item.strip()
        if not stripped:
            continue

        normalized = _normalize_path(stripped) if field_name in _PATH_CATEGORIES else stripped.lower()
        if normalized and normalized not in seen:
            seen.add(normalized)
            result.append(normalized)
    return result


def _build_sets(data: WhitelistData) -> dict[str, frozenset[str]]:
    return {
        "files": frozenset(data["files"]),
        "processes": frozenset(data["processes"]),
        "services": frozenset(data["services"]),
        "folders": frozenset(data["folders"]),
        "drivers": frozenset(data["drivers"]),
        "registry": frozenset(data["registry"]),
        "tasks": frozenset(data["tasks"]),
        "traces": frozenset(data["traces"]),
    }


def _load_whitelist() -> WhitelistData:
    global _whitelist_cache, _whitelist_sets, _whitelist_sets_source
    with _whitelist_lock:
        if _whitelist_cache is not None:


            if _whitelist_sets is None or _whitelist_sets_source is not _whitelist_cache:
                _whitelist_sets = _build_sets(_whitelist_cache)
                _whitelist_sets_source = _whitelist_cache
            return _whitelist_cache
        try:
            with _WHITELIST_PATH.open(encoding="utf-8") as handle:
                data = json.load(handle)
            if not isinstance(data, dict):
                raise ValueError("Whitelist root must be an object")
            missing = [key for key in _REQUIRED_WHITELIST_KEYS if key not in data]
            if missing:
                raise ValueError(f"Whitelist is missing fields: {', '.join(missing)}")
            result = WhitelistData(
                files=_string_list(data["files"], "files"),
                processes=_string_list(data["processes"], "processes"),
                services=_string_list(data["services"], "services"),
                folders=_string_list(data["folders"], "folders"),
                drivers=_string_list(data.get("drivers", []), "drivers"),
                registry=_string_list(data.get("registry", []), "registry"),
                tasks=_string_list(data.get("tasks", []), "tasks"),
                traces=_string_list(data.get("traces", []), "traces"),
            )
            _whitelist_cache = result
            _whitelist_sets = _build_sets(result)
            _whitelist_sets_source = result
            logger.info("Whitelist loaded from %s", _WHITELIST_PATH)
            return result
        except (OSError, json.JSONDecodeError, TypeError, ValueError) as exc:
            logger.warning("Unable to load whitelist %s: %s", _WHITELIST_PATH, format_error(exc))
            _whitelist_cache = _empty_whitelist()
            _whitelist_sets = _build_sets(_whitelist_cache)
            _whitelist_sets_source = _whitelist_cache
            return _whitelist_cache


def _load_whitelist_sets() -> dict[str, frozenset[str]]:
    _load_whitelist()
    assert _whitelist_sets is not None
    return _whitelist_sets


def _clear_cache() -> None:
    global _whitelist_cache, _whitelist_sets, _whitelist_sets_source
    with _whitelist_lock:
        _whitelist_cache = None
        _whitelist_sets = None
        _whitelist_sets_source = None


def set_disabled(disabled: bool = True) -> None:
    global _disabled
    with _whitelist_lock:
        _disabled = disabled


def is_disabled() -> bool:
    with _whitelist_lock:
        return _disabled


def _candidate_text(text: str) -> str:
    candidate = _STATUS_SUFFIX.sub("", text.strip()).strip()





    if ": " in candidate:
        head, tail = candidate.split(": ", 1)
        if tail.strip() and head.strip() and _PREFIX_LABEL.fullmatch(head.strip()):
            candidate = tail.strip()


    previous: str | None = None
    while previous != candidate:
        previous = candidate
        candidate = _PAREN_SUFFIX.sub("", candidate).strip()
    candidate = _STATUS_SUFFIX.sub("", candidate).strip()
    return _normalize_path(candidate.strip("\"'").strip())


def _normalize_category(category: str) -> str:
    key = category.strip().lower()
    return _CATEGORY_ALIASES.get(key, key)


def _is_under_whitelisted_folder(candidate: str, folders: frozenset[str]) -> bool:
    if candidate in folders:
        return True

    current = str(PureWindowsPath(candidate).parent)
    while current and current not in (".", "\\", ""):
        if current in folders:
            return True
        parent = str(PureWindowsPath(current).parent)
        if parent == current:
            break
        current = parent
    return False


def is_whitelisted(text: str, category: str) -> bool:
    if is_disabled():
        return False
    key = _normalize_category(category)
    if key not in _ALL_WHITELIST_KEYS:
        return False
    whitelist_sets = _load_whitelist_sets()
    candidate = _candidate_text(text)
    if not candidate:
        return False
    if key in _NAME_CATEGORIES:
        items = whitelist_sets[key]
        if not items:
            return False
        basename = PureWindowsPath(candidate).name
        return candidate in items or basename in items
    if key == "files":
        items = whitelist_sets["files"]
        if items:
            basename = PureWindowsPath(candidate).name
            if candidate in items or basename in items:
                return True

        return _is_under_whitelisted_folder(candidate, whitelist_sets["folders"])
    if key == "folders":
        if _is_under_whitelisted_folder(candidate, whitelist_sets["folders"]):
            return True

        return candidate in whitelist_sets["files"]

    return _is_under_whitelisted_folder(candidate, whitelist_sets[key])


def get_whitelist() -> WhitelistData:
    whitelist = _load_whitelist()
    return WhitelistData(
        files=list(whitelist["files"]),
        processes=list(whitelist["processes"]),
        services=list(whitelist["services"]),
        folders=list(whitelist["folders"]),
        drivers=list(whitelist["drivers"]),
        registry=list(whitelist["registry"]),
        tasks=list(whitelist["tasks"]),
        traces=list(whitelist["traces"]),
    )

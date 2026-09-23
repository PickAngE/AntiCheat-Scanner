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
_WHITELIST_KEYS = ("files", "processes", "services", "folders")
_STATUS_SUFFIX = re.compile(r"\s+\[(?:RUNNING|STOPPED)\]$", re.IGNORECASE)
_whitelist_lock = threading.Lock()
_whitelist_cache: WhitelistData | None = None


class WhitelistData(TypedDict):
    files: list[str]
    processes: list[str]
    services: list[str]
    folders: list[str]


def _empty_whitelist() -> WhitelistData:
    return WhitelistData(files=[], processes=[], services=[], folders=[])


def _normalize_path(value: str) -> str:
    return value.strip().replace("/", "\\").rstrip("\\").lower()


def _string_list(value: object, field_name: str) -> list[str]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise ValueError(f"Whitelist field {field_name} must be a list of strings")
    result: list[str] = []
    seen: set[str] = set()
    for item in value:
        normalized = item.strip()
        if not normalized:
            continue
        if field_name in {"files", "folders"}:
            normalized = _normalize_path(normalized)
        else:
            normalized = normalized.lower()
        if normalized and normalized not in seen:
            seen.add(normalized)
            result.append(normalized)
    return result


def _load_whitelist() -> WhitelistData:
    global _whitelist_cache
    with _whitelist_lock:
        if _whitelist_cache is not None:
            return _whitelist_cache
        try:
            with _WHITELIST_PATH.open(encoding="utf-8") as handle:
                data = json.load(handle)
            if not isinstance(data, dict):
                raise ValueError("Whitelist root must be an object")
            missing = [key for key in _WHITELIST_KEYS if key not in data]
            if missing:
                raise ValueError(f"Whitelist is missing fields: {', '.join(missing)}")
            result = WhitelistData(
                files=_string_list(data["files"], "files"),
                processes=_string_list(data["processes"], "processes"),
                services=_string_list(data["services"], "services"),
                folders=_string_list(data["folders"], "folders"),
            )
            _whitelist_cache = result
            logger.info("Whitelist loaded from %s", _WHITELIST_PATH)
            return result
        except (OSError, json.JSONDecodeError, TypeError, ValueError) as exc:
            logger.warning("Unable to load whitelist %s: %s", _WHITELIST_PATH, format_error(exc))
            _whitelist_cache = _empty_whitelist()
            return _whitelist_cache


def _candidate_text(text: str) -> str:
    candidate = _STATUS_SUFFIX.sub("", text).strip().lower()
    for prefix in (
        "metadata match:",
        "driver metadata:",
        "driver cert:",
        "task file metadata:",
    ):
        if candidate.startswith(prefix):
            candidate = candidate[len(prefix) :].strip()
    if candidate.endswith(")") and " (" in candidate:
        candidate = candidate.split(" (", 1)[0].strip()
    return _normalize_path(candidate.strip('"'))


def is_whitelisted(text: str, category: str) -> bool:
    whitelist = _load_whitelist()
    if category not in whitelist:
        return False
    if category == "files":
        items = whitelist["files"]
    elif category == "processes":
        items = whitelist["processes"]
    elif category == "services":
        items = whitelist["services"]
    elif category == "folders":
        items = whitelist["folders"]
    else:
        return False
    if not items:
        return False
    candidate = _candidate_text(text)
    basename = PureWindowsPath(candidate).name
    for item in items:
        normalized_item = (
            _normalize_path(item) if category in {"files", "folders"} else item.lower()
        )
        if category in {"processes", "services"}:
            if basename == normalized_item or candidate == normalized_item:
                return True
        elif category == "files":
            if candidate == normalized_item or basename == normalized_item:
                return True
        elif category == "folders" and (
            candidate == normalized_item or candidate.startswith(normalized_item + "\\")
        ):
            return True
    return False


def get_whitelist() -> WhitelistData:
    whitelist = _load_whitelist()
    return WhitelistData(
        files=list(whitelist["files"]),
        processes=list(whitelist["processes"]),
        services=list(whitelist["services"]),
        folders=list(whitelist["folders"]),
    )

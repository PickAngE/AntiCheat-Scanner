from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any


@dataclass(slots=True)
class AntiCheatInfo:
    name: str
    services: list[str] = field(default_factory=list)
    processes: list[str] = field(default_factory=list)
    drivers: list[str] = field(default_factory=list)
    folders: list[str] = field(default_factory=list)
    registry: list[tuple[str, str]] = field(default_factory=list)
    companies: list[str] = field(default_factory=list)
    products: list[str] = field(default_factory=list)
    notes: str = ""


def _string_list(value: Any, field_name: str, index: int) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise ValueError(f"Signature entry {index} has an invalid {field_name} list")
    result: list[str] = []
    seen: set[str] = set()
    for item in value:
        if not isinstance(item, str):
            raise ValueError(f"Signature entry {index} has a non-string {field_name} value")
        normalized = item.strip()
        if normalized and normalized.casefold() not in seen:
            seen.add(normalized.casefold())
            result.append(normalized)
    return result


def _notes_text(value: Any, index: int) -> str:
    if value is None:
        return ""
    if not isinstance(value, str):
        raise ValueError(f"Signature entry {index} has a non-string notes value")
    return value.strip()


def _registry_list(value: Any, index: int) -> list[tuple[str, str]]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise ValueError(f"Signature entry {index} has an invalid registry list")
    result: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for pair in value:
        if not isinstance(pair, (list, tuple)) or len(pair) != 2:
            raise ValueError(f"Signature entry {index} has an invalid registry pair")
        hive, subkey = pair
        if not isinstance(hive, str) or not isinstance(subkey, str):
            raise ValueError(f"Signature entry {index} has a non-string registry pair")
        hive_normalized = hive.strip()
        subkey_normalized = subkey.strip()
        if not hive_normalized or not subkey_normalized:
            raise ValueError(f"Signature entry {index} has an empty registry pair")


        hive_upper = hive_normalized.upper()
        dedup_key = (hive_upper.casefold(), subkey_normalized.casefold())
        if dedup_key not in seen:
            seen.add(dedup_key)
            result.append((hive_upper, subkey_normalized))
    return result


def get_signatures_path() -> Path:
    return Path(__file__).with_name("signatures.json")


def signatures_sha256() -> str:
    digest = hashlib.sha256()
    try:
        with get_signatures_path().open("rb") as handle:
            for block in iter(lambda: handle.read(65536), b""):
                digest.update(block)
    except OSError:
        return ""
    return digest.hexdigest()


def _parse_database(raw: Any, data_path: Path) -> list[AntiCheatInfo]:


    entries: Any = raw
    if isinstance(raw, dict):
        entries = raw.get("entries")
        schema = raw.get("schema", 1)
        if schema != 1:
            raise ValueError(f"Unsupported signatures schema in {data_path}: {schema!r}")
    if not isinstance(entries, list):
        raise ValueError(f"The signatures database at {data_path} must contain a list")

    database: list[AntiCheatInfo] = []
    names: set[str] = set()
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise ValueError(f"Signature entry {index} in {data_path} must be an object")
        name = entry.get("name")
        if not isinstance(name, str) or not name.strip():
            raise ValueError(f"Signature entry {index} in {data_path} has no valid name")
        normalized_name = name.strip()
        if normalized_name.casefold() in names:
            raise ValueError(f"Duplicate signature name in {data_path}: {normalized_name}")
        names.add(normalized_name.casefold())
        database.append(
            AntiCheatInfo(
                name=normalized_name,
                services=_string_list(entry.get("services"), "services", index),
                processes=_string_list(entry.get("processes"), "processes", index),
                drivers=_string_list(entry.get("drivers"), "drivers", index),
                folders=_string_list(entry.get("folders"), "folders", index),
                registry=_registry_list(entry.get("registry"), index),
                companies=_string_list(entry.get("companies"), "companies", index),
                products=_string_list(entry.get("products"), "products", index),
                notes=_notes_text(entry.get("notes"), index),
            )
        )
    return database


def validate_signatures(data_path: Path | None = None) -> list[str]:
    path = data_path or get_signatures_path()
    errors: list[str] = []
    try:
        with path.open(encoding="utf-8") as handle:
            raw = json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        return [f"Unable to load signatures database at {path}: {exc}"]
    try:
        database = _parse_database(raw, path)
    except ValueError as exc:
        return [str(exc)]


    for ac in database:
        for field_name in ("services", "processes", "drivers"):
            for value in getattr(ac, field_name):
                if len(value.strip()) < 4 and not ac.notes:
                    errors.append(
                        f"warning: short {field_name} signature {value!r} for "
                        f"{ac.name!r} has no justification in 'notes'"
                    )
    return errors


@lru_cache(maxsize=1)
def get_ac_database() -> list[AntiCheatInfo]:
    data_path = get_signatures_path()
    try:
        with data_path.open(encoding="utf-8") as handle:
            raw = json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"Unable to load signatures database at {data_path}: {exc}") from exc

    return _parse_database(raw, data_path)


def clear_ac_database_cache() -> None:
    get_ac_database.cache_clear()

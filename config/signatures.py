from __future__ import annotations

import json
from dataclasses import dataclass, field
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
        normalized_pair = (hive.strip().casefold(), subkey.strip().casefold())
        if all(normalized_pair) and normalized_pair not in seen:
            seen.add(normalized_pair)
            result.append((hive.strip(), subkey.strip()))
    return result


def get_ac_database() -> list[AntiCheatInfo]:
    data_path = Path(__file__).with_name("signatures.json")
    with data_path.open(encoding="utf-8") as handle:
        raw = json.load(handle)

    if not isinstance(raw, list):
        raise ValueError("The signatures database must contain a list")

    database: list[AntiCheatInfo] = []
    names: set[str] = set()
    for index, entry in enumerate(raw):
        if not isinstance(entry, dict):
            raise ValueError(f"Signature entry {index} must be an object")
        name = entry.get("name")
        if not isinstance(name, str) or not name.strip():
            raise ValueError(f"Signature entry {index} has no valid name")
        normalized_name = name.strip()
        if normalized_name.casefold() in names:
            raise ValueError(f"Duplicate signature name: {normalized_name}")
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
            )
        )
    return database

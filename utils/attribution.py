from __future__ import annotations

import re
from collections.abc import Sequence
from functools import lru_cache

from checkers.matchers import path_has_folder_segment, registry_path_matches, target_matches
from config.sig_index import SignatureIndex
from config.signatures import AntiCheatInfo

_EXTENSION_END = re.compile(r"\.(exe|sys|dll)(?![a-z0-9])", re.IGNORECASE)

_resolve_database: Sequence[AntiCheatInfo] | None = None


def _extract_token(text: str) -> str:
    cleaned = text.strip()
    if len(cleaned) >= 2 and cleaned[0] in {"'", '"'} and cleaned[-1] == cleaned[0]:
        cleaned = cleaned[1:-1].strip()
    if cleaned.startswith("\\??\\"):
        cleaned = cleaned[4:]
    if ": " in cleaned:
        cleaned = cleaned.rsplit(": ", 1)[-1].strip()
    if len(cleaned) >= 2 and cleaned[0] in {"'", '"'}:
        end = cleaned.find(cleaned[0], 1)
        if end != -1:
            return cleaned[1:end]
    match = _EXTENSION_END.search(cleaned)
    if match:
        return cleaned[: match.end()].strip().strip("'\"")
    tokens = cleaned.split()
    return tokens[0].strip("'\"") if tokens else ""


def _candidates(text: str) -> list[str]:
    token = _extract_token(text)
    if token and token != text:
        return [text, token]
    return [text]


def _anchor_database(ac_database: Sequence[AntiCheatInfo]) -> None:
    global _resolve_database
    if _resolve_database is not ac_database:
        _resolve_cached.cache_clear()
        _resolve_database = ac_database


@lru_cache(maxsize=4096)
def _resolve_cached(text_lower: str, kinds: tuple[str, ...]) -> str | None:
    database = _resolve_database
    if database is None:
        return None
    for ac in database:
        signatures: list[str] = []
        if "services" in kinds:
            signatures.extend(ac.services)
        if "processes" in kinds:
            signatures.extend(ac.processes)
        if "drivers" in kinds:
            signatures.extend(ac.drivers)
        if "products" in kinds:
            signatures.extend(ac.products)
        if "name" in kinds:
            signatures.append(ac.name)
        if signatures and target_matches(text_lower, signatures):
            return ac.name
    return None


def clear_cache() -> None:
    _resolve_cached.cache_clear()


def resolve_ac_name(
    text: str,
    ac_database: Sequence[AntiCheatInfo],
    sig_index: SignatureIndex | None = None,
    *,
    include_services: bool = True,
    include_processes: bool = True,
    include_drivers: bool = True,
    include_products: bool = False,
    include_name: bool = False,
) -> str | None:
    if not text:
        return None
    _anchor_database(ac_database)
    kinds: list[str] = []
    if include_services:
        kinds.append("services")
    if include_processes:
        kinds.append("processes")
    if include_drivers:
        kinds.append("drivers")
    candidates = _candidates(text)
    if sig_index is not None and kinds:
        for candidate in candidates:
            indexed = sig_index.lookup(candidate, kinds)
            if indexed:
                return indexed
    kinds_tuple = tuple(kinds)
    if include_products:
        kinds_tuple += ("products",)
    if include_name:
        kinds_tuple += ("name",)
    if not kinds_tuple:
        return None
    for candidate in candidates:
        hit = _resolve_cached(candidate.lower(), kinds_tuple)
        if hit is not None:
            return hit
    return None


def resolve_ac_from_registry(
    entry: str,
    ac_database: Sequence[AntiCheatInfo],
    sig_index: SignatureIndex | None = None,
) -> str | None:
    if not entry:
        return None
    for ac in ac_database:
        for hive, subkey in ac.registry:
            if registry_path_matches(entry, hive, subkey):
                return ac.name
    return resolve_ac_name(
        entry,
        ac_database,
        sig_index,
        include_products=True,
        include_name=True,
    )


def resolve_ac_from_folder(
    path: str,
    ac_database: Sequence[AntiCheatInfo],
) -> str | None:
    if not path:
        return None
    for ac in ac_database:
        if any(path_has_folder_segment(path, folder) for folder in ac.folders):
            return ac.name
    for ac in ac_database:
        if ac.folders and target_matches(path, ac.folders):
            return ac.name
    return None

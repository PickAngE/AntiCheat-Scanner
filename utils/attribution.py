from __future__ import annotations

from collections.abc import Sequence

from checkers.matchers import path_has_folder_segment, registry_path_matches, target_matches
from config.sig_index import SignatureIndex
from config.signatures import AntiCheatInfo


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
    if sig_index is not None:
        kinds = []
        if include_services:
            kinds.append("services")
        if include_processes:
            kinds.append("processes")
        if include_drivers:
            kinds.append("drivers")
        indexed = sig_index.lookup(text, kinds) if kinds else None
        if indexed:
            return indexed
    for ac in ac_database:
        signatures: list[str] = []
        if include_services:
            signatures.extend(ac.services)
        if include_processes:
            signatures.extend(ac.processes)
        if include_drivers:
            signatures.extend(ac.drivers)
        if include_products:
            signatures.extend(ac.products)
        if include_name:
            signatures.append(ac.name)
        if signatures and target_matches(text, signatures):
            return ac.name
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
    return None

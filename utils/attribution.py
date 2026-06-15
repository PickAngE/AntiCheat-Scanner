from typing import List, Optional

from config.signatures import AntiCheatInfo
from config.sig_index import SignatureIndex
from checkers.matchers import path_has_folder_segment, registry_path_matches, target_matches


def resolve_ac_name(
    text: str,
    ac_database: List[AntiCheatInfo],
    sig_index: Optional[SignatureIndex] = None,
    *,
    include_services: bool = True,
    include_processes: bool = True,
    include_drivers: bool = True,
) -> Optional[str]:
    if not text:
        return None

    if sig_index is not None:
        resolved = sig_index.lookup(text)
        if resolved:
            return resolved

    for ac in ac_database:
        sigs: List[str] = []
        if include_services:
            sigs.extend(ac.services)
        if include_processes:
            sigs.extend(ac.processes)
        if include_drivers:
            sigs.extend(ac.drivers)
        if sigs and target_matches(text, sigs):
            return ac.name

    return None


def resolve_ac_from_registry(
    entry: str,
    ac_database: List[AntiCheatInfo],
    sig_index: Optional[SignatureIndex] = None,
) -> Optional[str]:
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
        include_services=True,
        include_processes=True,
        include_drivers=False,
    )


def resolve_ac_from_folder(path: str, ac_database: List[AntiCheatInfo]) -> Optional[str]:
    if not path:
        return None

    for ac in ac_database:
        if any(path_has_folder_segment(path, folder) for folder in ac.folders):
            return ac.name

    return None

from typing import Any, Dict, List
from config.signatures import AntiCheatInfo
from utils.logger import logger
from checkers.matchers import target_matches, path_has_folder_segment
def _service_matches(ac: AntiCheatInfo, name: str) -> bool:
    return target_matches(name, ac.services)
def _process_matches(ac: AntiCheatInfo, name: str) -> bool:
    return target_matches(name, ac.processes)
def _driver_matches(ac: AntiCheatInfo, path_or_name: str) -> bool:
    return target_matches(path_or_name, ac.drivers)
def _folder_matches(ac: AntiCheatInfo, path_str: str) -> bool:
    for f in ac.folders:
        if path_has_folder_segment(path_str, f):
            return True
    return False
def _registry_matches(ac: AntiCheatInfo, key_path: str) -> bool:
    if not key_path:
        return False
    key_lower = key_path.lower()
    for _, subkey in ac.registry:
        if subkey.lower() in key_lower:
            return True
    return False
def build_found_map(
    ac_database: List[AntiCheatInfo],
    svc_found: List[dict],
    proc_found: List[dict],
    driver_found: List[str],
    folder_found: List[str],
    reg_found: List[str],
    task_found: List[str],
    trace_found: List[str],
) -> Dict[str, Dict[str, Any]]:
    found_map: Dict[str, Dict[str, Any]] = {}
    for item in svc_found:
        name = str(item.get("display_name") or item.get("name") or "")
        for ac in ac_database:
            if _service_matches(ac, name):
                if ac.name not in found_map:
                    found_map[ac.name] = {"items": []}
                found_map[ac.name]["items"].append(f"SERVICE {name}")
                break
    for item in proc_found:
        name = str(item.get("name") or "")
        for ac in ac_database:
            if _process_matches(ac, name):
                if ac.name not in found_map:
                    found_map[ac.name] = {"items": []}
                found_map[ac.name]["items"].append(f"PROCESS {name}")
                break
    for path in folder_found:
        for ac in ac_database:
            if _folder_matches(ac, path):
                if ac.name not in found_map:
                    found_map[ac.name] = {"items": []}
                found_map[ac.name]["items"].append(f"FOLDER {path}")
                break
    for path in reg_found:
        for ac in ac_database:
            if _registry_matches(ac, path):
                if ac.name not in found_map:
                    found_map[ac.name] = {"items": []}
                found_map[ac.name]["items"].append(f"REGISTRY {path}")
                break
    for drv in driver_found:
        for ac in ac_database:
            if _driver_matches(ac, drv):
                if ac.name not in found_map:
                    found_map[ac.name] = {"items": []}
                found_map[ac.name]["items"].append(f"DRIVER {drv}")
                break
    for task in task_found:
        for ac in ac_database:
            if target_matches(task, ac.processes + ac.services + ac.drivers):
                if ac.name not in found_map:
                    found_map[ac.name] = {"items": []}
                found_map[ac.name]["items"].append(f"TASK/HISTORY {task}")
                break
    for trace in trace_found:
        for ac in ac_database:
            if target_matches(trace, ac.processes + ac.services + ac.drivers):
                if ac.name not in found_map:
                    found_map[ac.name] = {"items": []}
                found_map[ac.name]["items"].append(f"TRACE {trace}")
                break
    return found_map
def write_report(found_map: Dict[str, Dict[str, Any]], total_found: int) -> None:
    if found_map:
        for name, data in found_map.items():
            logger.log(name)
            for item in data["items"]:
                logger.log(item, indent=2)
            logger.log("")
    logger.log(f"TOTAL {total_found}")
def get_total_found(
    svc_found: List,
    proc_found: List,
    driver_found: List,
    folder_found: List,
    reg_found: List,
    task_found: List,
    trace_found: List,
) -> int:
    return (
        len(svc_found)
        + len(proc_found)
        + len(driver_found)
        + len(folder_found)
        + len(reg_found)
        + len(task_found)
        + len(trace_found)
    )

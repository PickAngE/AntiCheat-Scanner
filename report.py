import subprocess
import os
from typing import Any, Dict, List, Optional
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
) -> Dict[str, Any]:
    found_map: Dict[str, Dict[str, Any]] = {}
    technical_info: List[Dict[str, Any]] = []

    def _init_ac(name: str):
        if name not in found_map:
            found_map[name] = {"items": [], "is_running": False, "active_indicators": []}

    for item in svc_found:
        name = str(item.get("display_name") or item.get("name") or "")
        is_running = item.get("status") == "running"
        for ac in ac_database:
            if _service_matches(ac, name):
                _init_ac(ac.name)
                status_str = " [RUNNING]" if is_running else ""
                if is_running:
                    found_map[ac.name]["is_running"] = True
                    found_map[ac.name]["active_indicators"].append(f"Service: {name}")
                found_map[ac.name]["items"].append(f"SERVICE {name}{status_str}")
                break

    for item in proc_found:
        name = str(item.get("name") or "")
        ac_name_attr = item.get("ac_name")
        p_exe = item.get("exe") or ""
        
        detail = f"PROCESS {name} [RUNNING]"
        
        if ac_name_attr:
            _init_ac(ac_name_attr)
            found_map[ac_name_attr]["is_running"] = True
            found_map[ac_name_attr]["active_indicators"].append(f"Process: {name}")
            found_map[ac_name_attr]["items"].append(detail)
            
            technical_info.append({
                "ac": ac_name_attr,
                "name": name,
                "path": p_exe,
                "meta": item.get("metadata", {}),
                "sha": item.get("sha256", ""),
                "sig": item.get("signature", "")
            })
        else:
            for ac in ac_database:
                if _process_matches(ac, name):
                    _init_ac(ac.name)
                    found_map[ac.name]["is_running"] = True
                    found_map[ac.name]["active_indicators"].append(f"Process: {name}")
                    found_map[ac.name]["items"].append(detail)
                    
                    technical_info.append({
                        "ac": ac.name,
                        "name": name,
                        "path": p_exe,
                        "meta": item.get("metadata", {}),
                        "sha": item.get("sha256", ""),
                        "sig": item.get("signature", "")
                    })
                    break

    for path in folder_found:
        for ac in ac_database:
            if _folder_matches(ac, path):
                _init_ac(ac.name)
                found_map[ac.name]["items"].append(f"FOLDER {path}")
                break

    for path in reg_found:
        for ac in ac_database:
            if _registry_matches(ac, path):
                _init_ac(ac.name)
                found_map[ac.name]["items"].append(f"REGISTRY {path}")
                break

    for path in driver_found:
        for ac in ac_database:
            if _driver_matches(ac, path):
                _init_ac(ac.name)
                found_map[ac.name]["items"].append(f"DRIVER {path}")
                break

    for trace in trace_found:
        is_active_indicator = "DRIVERQUERY: Active loaded driver" in trace or "FILTER DRIVER:" in trace
        for ac in ac_database:
            if target_matches(trace, ac.processes + ac.services + ac.drivers):
                _init_ac(ac.name)
                found_map[ac.name]["items"].append(f"TRACE {trace}")
                if is_active_indicator:
                    found_map[ac.name]["is_running"] = True
                    found_map[ac.name]["active_indicators"].append(f"Driver: {trace.split('-')[-1].strip()}")
                break

    for task in task_found:
        for ac in ac_database:
            if target_matches(task, ac.processes + ac.services + ac.drivers):
                _init_ac(ac.name)
                found_map[ac.name]["items"].append(f"TASK/HISTORY {task}")
                break
                
    return {"found_map": found_map, "technical_info": technical_info}

def write_report(data_package: Dict[str, Any], total_found: int) -> None:
    found_map = data_package["found_map"]
    technical_info = data_package["technical_info"]
    
    running_acs = []
    
    if found_map:
        for name, data in found_map.items():
            is_running = data.get("is_running", False)
            running_str = " (CURRENTLY RUNNING)" if is_running else ""
            if is_running:
                running_acs.append((name, data.get("active_indicators", [])))
            
            logger.log(f"{name}{running_str}")
            for item in data["items"]:
                logger.log(item, indent=2)
            logger.log("")

    if running_acs:
        logger.log(">>> CURRENTLY RUNNING ANTI-CHEATS <<<")
        for ac_name, indicators in running_acs:
            logger.log(f"[!] {ac_name} is ACTIVE", indent=2)
            if indicators:
                unique_indicators = sorted(list(set(indicators)))
                for ind in unique_indicators:
                    logger.log(f"-> {ind}", indent=4)
        logger.log("")

    logger.log("="*50)
    logger.log(">>> TECHNICAL DETAILS <<<")
    
    if technical_info:
        logger.log("FILE ANALYSIS:")
        for file in technical_info:
            logger.log(f"[{file['ac']}] {file['name']}:")
            if file['path']:
                logger.log(f"Path: {file['path']}", indent=2)
            if file['sha']:
                logger.log(f"SHA256: {file['sha']}", indent=2)
            if file['sig']:
                logger.log(f"Signer: {file['sig']}", indent=2)
            
            meta = file['meta']
            if meta:
                if meta.get('CompanyName'): logger.log(f"Company: {meta['CompanyName']}", indent=2)
                if meta.get('FileVersion'): logger.log(f"Version: {meta['FileVersion']}", indent=2)
                if meta.get('CreatedAt'): logger.log(f"Created: {meta['CreatedAt']}", indent=2)
            logger.log("")

    logger.log(f"TOTAL DETECTIONS: {total_found}")

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

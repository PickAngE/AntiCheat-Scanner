import os
from typing import Any, Dict, List
from config.signatures import AntiCheatInfo
from utils.logger import logger
from checkers.matchers import target_matches, path_has_folder_segment
from utils.helpers import get_file_hash, get_file_properties, get_digital_signature

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
    found_map = {}
    tech_info = []

    def _add(ac_name, desc, active=False, tech=None):
        if ac_name not in found_map:
            found_map[ac_name] = {"items": set(), "running": False}
        found_map[ac_name]["items"].add(desc)
        if active: found_map[ac_name]["running"] = True
        if tech:
            tech["ac"] = ac_name
            tech_info.append(tech)

    for s in svc_found:
        name = s.get("display_name") or s.get("name")
        active = s.get("status") == "running"
        for ac in ac_database:
            if target_matches(name, ac.services):
                _add(ac.name, f"Service: {name} {'[RUNNING]' if active else '[STOPPED]'}", active)
                break

    for p in proc_found:
        name = p.get("name", "")
        ac_attr = p.get("ac_name")
        for ac in ac_database:
            if ac_attr == ac.name or target_matches(name, ac.processes):
                path = p.get("exe") or ""
                tech = {"name": name, "path": path, "sha": p.get("sha256"), "sig": p.get("signature"), "meta": p.get("metadata")} if path else None
                _add(ac.name, f"Process: {name} [ACTIVE]", True, tech)
                break

    for path in folder_found:
        for ac in ac_database:
            if any(path_has_folder_segment(path, f) for f in ac.folders):
                _add(ac.name, f"Folder: {path}")
                break

    for key in reg_found:
        k_lower = key.lower()
        for ac in ac_database:
            if any(subkey.lower() in k_lower for _, subkey in ac.registry):
                _add(ac.name, f"Registry: {key}")
                break

    for path in driver_found:
        for ac in ac_database:
            if target_matches(path, ac.drivers):
                tech = None
                if os.path.exists(path):
                    tech = {"name": os.path.basename(path), "path": path, "sha": get_file_hash(path), "sig": get_digital_signature(path), "meta": get_file_properties(path)}
                _add(ac.name, f"Driver: {path}", True, tech)
                break

    for trace in trace_found:
        is_active = "DRIVERQUERY: Active" in trace or "FILTER DRIVER:" in trace
        for ac in ac_database:
            if target_matches(trace, ac.processes + ac.services + ac.drivers):
                _add(ac.name, f"Trace: {trace}", is_active)
                break

    for task in task_found:
        for ac in ac_database:
            if target_matches(task, ac.processes + ac.services + ac.drivers):
                _add(ac.name, f"Task: {task}")
                break

    return {"found_map": found_map, "technical_info": tech_info}

def write_report(data_package: Dict[str, Any], total_found: int) -> None:
    found_map = data_package["found_map"]
    tech_info = data_package["technical_info"]

    logger.log("\n" + "="*60)
    logger.log(" ANTI-CHEAT REPORT ".center(60))
    logger.log("="*60)
    logger.log(f" [+] Unique detections found: {total_found}\n")

    if not found_map:
        logger.log(" [!] No anti-cheat traces detected.\n")
    else:
        sorted_acs = sorted(found_map.items(), key=lambda x: x[1]["running"], reverse=True)
        for name, data in sorted_acs:
            status = "[ACTIVE]" if data["running"] else "[TRACES]"
            logger.log(f" * {name} {status}")
            for item in sorted(data["items"]):
                logger.log(f"   - {item}")
            logger.log("")

    if tech_info:
        logger.log("-" * 60)
        logger.log(" TECHNICAL ANALYSIS ".center(60))
        logger.log("-" * 60)
        for info in tech_info:
            logger.log(f" [{info['ac']}] {info['name']}:")
            if info.get('path'): logger.log(f"   Path: {info['path']}")
            if info.get('sha'):  logger.log(f"   SHA256: {info['sha']}")
            if info.get('sig'):  logger.log(f"   Signer: {info['sig']}")
            meta = info.get('meta', {})
            if meta and meta.get('CompanyName'): 
                logger.log(f"   Company: {meta['CompanyName']}")
            logger.log("")

    logger.log("="*60)
    logger.log(" SCAN COMPLETE ".center(60))
    logger.log("="*60 + "\n")

def get_total_found(svc_f, proc_f, drv_f, folder_f, reg_f, task_f, trace_f) -> int:
    return sum(len(l) for l in [svc_f, proc_f, drv_f, folder_f, reg_f, task_f, trace_f])

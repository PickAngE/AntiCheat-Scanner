import os
from typing import Any, Dict, List, Optional, Union

from config.signatures import AntiCheatInfo
from config.sig_index import SignatureIndex
from utils.logger import logger
from utils.attribution import resolve_ac_from_folder, resolve_ac_from_registry, resolve_ac_name
from utils.helpers import batch_get_digital_signatures, get_file_hash, get_file_properties
from checkers.matchers import extract_exe_path, target_matches

CATEGORY_SVC = "services"
CATEGORY_PROC = "processes"
CATEGORY_DRV = "drivers"
CATEGORY_FOLDER = "folders"
CATEGORY_REG = "registry"
CATEGORY_TASK = "tasks"
CATEGORY_TRACE = "traces"

TraceEntry = Union[str, Dict[str, Any]]
TaskEntry = Union[str, Dict[str, Any]]


def _trace_text(entry: TraceEntry) -> str:
    if isinstance(entry, dict):
        return str(entry.get("text", ""))
    return str(entry)


def _trace_ac_name(entry: TraceEntry) -> Optional[str]:
    if isinstance(entry, dict):
        return entry.get("ac_name")
    return None


def _trace_active(entry: TraceEntry) -> bool:
    if isinstance(entry, dict):
        return bool(entry.get("active"))
    text = _trace_text(entry)
    return "DRIVERQUERY: Active" in text or "FILTER DRIVER:" in text


def _task_text(entry: TaskEntry) -> str:
    if isinstance(entry, dict):
        return str(entry.get("text", ""))
    return str(entry)


def _task_ac_name(entry: TaskEntry) -> Optional[str]:
    if isinstance(entry, dict):
        return entry.get("ac_name")
    return None


def _driver_fs_path(path: str) -> Optional[str]:
    if os.path.exists(path):
        return path
    for prefix in ("DRIVER METADATA:", "DRIVER CERT:"):
        if path.startswith(prefix):
            remainder = path[len(prefix):].strip()
            candidate = remainder.split(" (", 1)[0].strip()
            if os.path.exists(candidate):
                return candidate
    return None


def build_found_map(
    ac_database: List[AntiCheatInfo],
    svc_found: List[dict],
    proc_found: List[dict],
    driver_found: List[str],
    folder_found: List[str],
    reg_found: List[str],
    task_found: List[TaskEntry],
    trace_found: List[TraceEntry],
    sig_index: Optional[SignatureIndex] = None,
) -> Dict[str, Any]:
    found_map: Dict[str, Any] = {}
    tech_info: List[dict] = []

    def _add(ac_name: str, category: str, desc: str, active: bool = False, tech: Optional[dict] = None) -> None:
        if not ac_name:
            return
        entry = found_map.setdefault(
            ac_name,
            {
                "running": False,
                CATEGORY_SVC: set(),
                CATEGORY_PROC: set(),
                CATEGORY_DRV: set(),
                CATEGORY_FOLDER: set(),
                CATEGORY_REG: set(),
                CATEGORY_TASK: set(),
                CATEGORY_TRACE: set(),
            },
        )
        entry[category].add(desc)
        if active:
            entry["running"] = True
        if tech:
            tech["ac"] = ac_name
            tech_info.append(tech)

    for s in svc_found:
        svc_name = str(s.get("name") or "")
        svc_display = str(s.get("display_name") or "")
        label = svc_display or svc_name
        active = s.get("status") == "running"
        ac_name = s.get("ac_name") or resolve_ac_name(
            svc_name,
            ac_database,
            sig_index,
        ) or resolve_ac_name(
            svc_display,
            ac_database,
            sig_index,
        ) or resolve_ac_name(
            extract_exe_path(str(s.get("binpath") or "")),
            ac_database,
            sig_index,
        )
        _add(
            ac_name,
            CATEGORY_SVC,
            f"{label} {'[RUNNING]' if active else '[STOPPED]'}",
            active,
        )

    for p in proc_found:
        name = p.get("name", "")
        ac_name = p.get("ac_name") or resolve_ac_name(
            name,
            ac_database,
            sig_index,
            include_drivers=False,
        ) or resolve_ac_name(
            str(p.get("exe") or ""),
            ac_database,
            sig_index,
            include_drivers=False,
        )
        path = p.get("exe") or ""
        tech = (
            {
                "name": name,
                "path": path,
                "sha": p.get("sha256"),
                "sig": p.get("signature"),
                "meta": p.get("metadata"),
            }
            if path
            else None
        )
        _add(ac_name, CATEGORY_PROC, f"{name}", True, tech)

    for path in folder_found:
        ac_name = resolve_ac_from_folder(path, ac_database)
        if not ac_name:
            for ac in ac_database:
                if target_matches(path, ac.folders):
                    ac_name = ac.name
                    break
        _add(ac_name, CATEGORY_FOLDER, f"{path}")

    for key in reg_found:
        ac_name = resolve_ac_from_registry(key, ac_database, sig_index)
        _add(ac_name, CATEGORY_REG, f"{key}")

    driver_paths = [
        fs_path
        for path in driver_found
        if (fs_path := _driver_fs_path(path)) is not None
    ]
    driver_signatures = batch_get_digital_signatures(driver_paths)

    for path in driver_found:
        ac_name = resolve_ac_name(path, ac_database, sig_index, include_processes=False)
        fs_path = _driver_fs_path(path)
        tech = None
        if fs_path:
            tech = {
                "name": os.path.basename(fs_path),
                "path": fs_path,
                "sha": get_file_hash(fs_path),
                "sig": driver_signatures.get(fs_path, ""),
                "meta": get_file_properties(fs_path),
            }
        _add(ac_name, CATEGORY_DRV, f"{path}", bool(fs_path), tech)

    for trace in trace_found:
        text = _trace_text(trace)
        ac_name = _trace_ac_name(trace) or resolve_ac_name(text, ac_database, sig_index)
        _add(ac_name, CATEGORY_TRACE, text, _trace_active(trace))

    for task in task_found:
        text = _task_text(task)
        ac_name = _task_ac_name(task) or resolve_ac_name(text, ac_database, sig_index)
        _add(ac_name, CATEGORY_TASK, text)

    return {"found_map": found_map, "technical_info": tech_info}


_CATEGORY_LABELS = {
    CATEGORY_PROC: "Processes",
    CATEGORY_SVC: "Services",
    CATEGORY_DRV: "Drivers",
    CATEGORY_REG: "Registry",
    CATEGORY_FOLDER: "Files / Folders",
    CATEGORY_TASK: "Scheduled Tasks / Prefetch",
    CATEGORY_TRACE: "Forensic Traces",
}
_CATEGORY_ORDER = [
    CATEGORY_PROC,
    CATEGORY_SVC,
    CATEGORY_DRV,
    CATEGORY_REG,
    CATEGORY_FOLDER,
    CATEGORY_TASK,
    CATEGORY_TRACE,
]


def count_unique_detections(found_map: Dict[str, Any]) -> int:
    total = 0
    for data in found_map.values():
        for cat in _CATEGORY_ORDER:
            total += len(data.get(cat, set()))
    return total


def write_report(data_package: Dict[str, Any], total_found: int) -> None:
    found_map = data_package["found_map"]
    tech_info = data_package["technical_info"]

    logger.log("\n" + "=" * 60)
    logger.log(" ANTI-CHEAT REPORT ".center(60))
    logger.log("=" * 60)
    logger.log(f" [+] Unique detections found: {total_found}\n")

    if not found_map:
        logger.log(" [!] No anti-cheat traces detected.\n")
    else:
        sorted_acs = sorted(found_map.items(), key=lambda x: x[1]["running"], reverse=True)
        for ac_name, data in sorted_acs:
            status = "[ACTIVE]" if data["running"] else "[TRACES]"
            logger.log(f" * {ac_name} {status}")
            has_any = False
            for cat in _CATEGORY_ORDER:
                items = data.get(cat, set())
                if not items:
                    continue
                has_any = True
                label = _CATEGORY_LABELS.get(cat, cat)
                logger.log(f"    [{label}]")
                for item in sorted(items):
                    logger.log(f"      - {item}")
            if has_any:
                logger.log("")

    if tech_info:
        logger.log("-" * 60)
        logger.log(" CURRENTLY RUNNING ".center(60))
        logger.log("-" * 60)
        for info in tech_info:
            logger.log(f" [{info['ac']}] {info['name']}:")
            if info.get("path"):
                logger.log(f"   Path: {info['path']}")
            if info.get("sha"):
                logger.log(f"   SHA256: {info['sha']}")
            if info.get("sig"):
                logger.log(f"   Signer: {info['sig']}")
            meta = info.get("meta", {})
            if meta and meta.get("CompanyName"):
                logger.log(f"   Company: {meta['CompanyName']}")
            logger.log("")

    logger.log("=" * 60)
    logger.log(" SCAN COMPLETE ".center(60))
    logger.log("=" * 60 + "\n")

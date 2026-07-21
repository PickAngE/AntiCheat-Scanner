import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

from checkers.detection import (
    CATEGORY_DRV,
    CATEGORY_FOLDER,
    CATEGORY_PROC,
    CATEGORY_REG,
    CATEGORY_SVC,
    CATEGORY_TASK,
    CATEGORY_TRACE,
    CheckerResults,
    Detection,
)
from config.signatures import AntiCheatInfo
from config.sig_index import SignatureIndex
from utils.logger import logger
from utils.attribution import resolve_ac_from_folder, resolve_ac_from_registry, resolve_ac_name
from utils.helpers import batch_get_digital_signatures, get_file_hash, get_file_properties
from checkers.matchers import target_matches


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


def _build_tech_from_detection(det: Detection) -> Optional[dict]:
    if det.tech:
        return det.tech
    if det.raw and isinstance(det.raw, dict):
        return {
            "name": det.raw.get("name", det.text),
            "path": det.raw.get("exe", ""),
        }
    return None


def build_found_map(
    ac_database: List[AntiCheatInfo],
    checker_results: CheckerResults,
    sig_index: Optional[SignatureIndex] = None,
) -> Dict[str, Any]:
    found_map: Dict[str, Any] = {}
    tech_info: List[dict] = []

    def _add(ac_name: Optional[str], category: str, desc: str, active: bool = False, tech: Optional[dict] = None) -> None:
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

    for det in checker_results.get(CATEGORY_SVC, []):
        raw = det.raw or {}
        svc_name = str(raw.get("name") or "")
        svc_display = str(raw.get("display_name") or "")
        ac_name = det.ac_name or resolve_ac_name(
            svc_name, ac_database, sig_index,
        ) or resolve_ac_name(
            svc_display, ac_database, sig_index,
        )
        _add(ac_name, CATEGORY_SVC, det.text, det.active)

    for det in checker_results.get(CATEGORY_PROC, []):
        raw = det.raw or {}
        ac_name = det.ac_name or resolve_ac_name(
            str(raw.get("name", "")), ac_database, sig_index, include_drivers=False,
        ) or resolve_ac_name(
            str(raw.get("exe", "")), ac_database, sig_index, include_drivers=False,
        )
        _add(ac_name, CATEGORY_PROC, det.text, True, _build_tech_from_detection(det))

    for det in checker_results.get(CATEGORY_FOLDER, []):
        path = det.text
        ac_name = det.ac_name or resolve_ac_from_folder(path, ac_database)
        if not ac_name:
            for ac in ac_database:
                if target_matches(path, ac.folders):
                    ac_name = ac.name
                    break
        _add(ac_name, CATEGORY_FOLDER, path)

    for det in checker_results.get(CATEGORY_REG, []):
        ac_name = det.ac_name or resolve_ac_from_registry(det.text, ac_database, sig_index)
        _add(ac_name, CATEGORY_REG, det.text)

    driver_detections = checker_results.get(CATEGORY_DRV, [])
    driver_fs_paths = [
        fs_path
        for det in driver_detections
        if (fs_path := _driver_fs_path(det.raw if isinstance(det.raw, str) else det.text)) is not None
    ]
    driver_signatures = batch_get_digital_signatures(driver_fs_paths)

    for det in driver_detections:
        path = det.raw if isinstance(det.raw, str) else det.text
        ac_name = det.ac_name or resolve_ac_name(path, ac_database, sig_index, include_processes=False)
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
        _add(ac_name, CATEGORY_DRV, det.text, det.active, tech)

    for det in checker_results.get(CATEGORY_TRACE, []):
        ac_name = det.ac_name or resolve_ac_name(det.text, ac_database, sig_index)
        _add(ac_name, CATEGORY_TRACE, det.text, det.active)

    for det in checker_results.get(CATEGORY_TASK, []):
        ac_name = det.ac_name or resolve_ac_name(det.text, ac_database, sig_index)
        _add(ac_name, CATEGORY_TASK, det.text)

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


def _serialize_found_map(found_map: Dict[str, Any]) -> Dict[str, Any]:
    serialized: Dict[str, Any] = {}
    for ac_name, data in found_map.items():
        serialized[ac_name] = {
            "running": data.get("running", False),
        }
        for cat in _CATEGORY_ORDER:
            items = data.get(cat, set())
            if items:
                serialized[ac_name][cat] = sorted(items)
    return serialized


def write_json_report(data_package: Dict[str, Any], total_found: int, output_path: Path) -> None:
    payload = {
        "total_detections": total_found,
        "anti_cheats": _serialize_found_map(data_package["found_map"]),
        "technical_info": data_package.get("technical_info", []),
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, ensure_ascii=False)

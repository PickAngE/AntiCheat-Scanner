from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

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
from checkers.matchers import target_matches
from config.sig_index import SignatureIndex
from config.signatures import AntiCheatInfo
from utils.attribution import resolve_ac_from_folder, resolve_ac_from_registry, resolve_ac_name
from utils.helpers import batch_get_digital_signatures, get_file_hash, get_file_properties
from utils.logger import logger


def _driver_fs_path(path: str) -> str | None:
    if os.path.exists(path):
        return path
    for prefix in ("DRIVER METADATA:", "DRIVER CERT:"):
        if path.startswith(prefix):
            candidate = path[len(prefix) :].split(" (", 1)[0].strip()
            if os.path.exists(candidate):
                return candidate
    return None


def _build_tech_from_detection(detection: Detection) -> dict[str, Any] | None:
    if detection.tech:
        return detection.tech
    if isinstance(detection.raw, dict):
        return {
            "name": detection.raw.get("name", detection.text),
            "path": detection.raw.get("exe", ""),
        }
    return None


def build_found_map(
    ac_database: list[AntiCheatInfo],
    checker_results: CheckerResults,
    sig_index: SignatureIndex | None = None,
) -> dict[str, Any]:
    found_map: dict[str, Any] = {}
    technical_info: list[dict[str, Any]] = []

    def add(
        ac_name: str | None,
        category: str,
        description: str,
        active: bool = False,
        tech: dict[str, Any] | None = None,
    ) -> None:
        target = ac_name or "(unattributed)"
        entry = found_map.setdefault(
            target,
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
        entry[category].add(description)
        if active:
            entry["running"] = True
        if tech:
            tech["ac"] = target
            technical_info.append(tech)

    for detection in checker_results.get(CATEGORY_SVC, []):
        raw = detection.raw if isinstance(detection.raw, dict) else {}
        service_name = str(raw.get("name", ""))
        display_name = str(raw.get("display_name", ""))
        ac_name = (
            detection.ac_name
            or resolve_ac_name(service_name, ac_database, sig_index)
            or resolve_ac_name(
                display_name,
                ac_database,
                sig_index,
            )
        )
        add(ac_name, CATEGORY_SVC, detection.text, detection.active)

    for detection in checker_results.get(CATEGORY_PROC, []):
        raw = detection.raw if isinstance(detection.raw, dict) else {}
        ac_name = (
            detection.ac_name
            or resolve_ac_name(
                str(raw.get("name", "")),
                ac_database,
                sig_index,
                include_drivers=False,
            )
            or resolve_ac_name(
                str(raw.get("exe", "")),
                ac_database,
                sig_index,
                include_drivers=False,
            )
        )
        add(ac_name, CATEGORY_PROC, detection.text, True, _build_tech_from_detection(detection))

    for detection in checker_results.get(CATEGORY_FOLDER, []):
        path = detection.text
        ac_name = detection.ac_name or resolve_ac_from_folder(path, ac_database)
        if not ac_name:
            for ac in ac_database:
                if target_matches(path, ac.folders):
                    ac_name = ac.name
                    break
        add(ac_name, CATEGORY_FOLDER, path)

    for detection in checker_results.get(CATEGORY_REG, []):
        ac_name = detection.ac_name or resolve_ac_from_registry(
            detection.text, ac_database, sig_index
        )
        add(ac_name, CATEGORY_REG, detection.text)

    driver_detections = checker_results.get(CATEGORY_DRV, [])
    driver_paths = [
        fs_path
        for detection in driver_detections
        if (
            fs_path := _driver_fs_path(
                detection.raw if isinstance(detection.raw, str) else detection.text
            )
        )
        is not None
    ]
    driver_signatures = batch_get_digital_signatures(driver_paths)
    for detection in driver_detections:
        path = detection.raw if isinstance(detection.raw, str) else detection.text
        ac_name = detection.ac_name or resolve_ac_name(
            path,
            ac_database,
            sig_index,
            include_processes=False,
            include_products=True,
            include_name=True,
        )
        fs_path = _driver_fs_path(path)
        tech = None
        if fs_path:
            tech = {
                "name": os.path.basename(fs_path),
                "path": fs_path,
                "sha": get_file_hash(fs_path),
                "sig": driver_signatures.get(fs_path, ""),
                "meta": get_file_properties(fs_path),
                "state": "running" if detection.active else "present",
            }
        add(ac_name, CATEGORY_DRV, detection.text, detection.active, tech)

    for detection in checker_results.get(CATEGORY_TRACE, []):
        ac_name = detection.ac_name or resolve_ac_name(detection.text, ac_database, sig_index)
        add(ac_name, CATEGORY_TRACE, detection.text, detection.active)

    for detection in checker_results.get(CATEGORY_TASK, []):
        ac_name = detection.ac_name or resolve_ac_name(detection.text, ac_database, sig_index)
        add(ac_name, CATEGORY_TASK, detection.text)

    return {"found_map": found_map, "technical_info": technical_info}


_CATEGORY_LABELS = {
    CATEGORY_PROC: "Processes",
    CATEGORY_SVC: "Services",
    CATEGORY_DRV: "Drivers",
    CATEGORY_REG: "Registry",
    CATEGORY_FOLDER: "Files / Folders",
    CATEGORY_TASK: "Scheduled Tasks / Prefetch",
    CATEGORY_TRACE: "Forensic Traces",
}
_CATEGORY_ORDER = (
    CATEGORY_PROC,
    CATEGORY_SVC,
    CATEGORY_DRV,
    CATEGORY_REG,
    CATEGORY_FOLDER,
    CATEGORY_TASK,
    CATEGORY_TRACE,
)


def count_unique_detections(found_map: dict[str, Any]) -> int:
    return sum(
        len(data.get(category, set()))
        for data in found_map.values()
        for category in _CATEGORY_ORDER
    )


def write_report(data_package: dict[str, Any], total_found: int) -> None:
    found_map = data_package["found_map"]
    technical_info = data_package["technical_info"]
    logger.log("\n" + "=" * 60)
    logger.log(" ANTI-CHEAT REPORT ".center(60))
    logger.log("=" * 60)
    logger.log(f" [+] Detection records: {total_found}")
    logger.log(f" [+] Scan status: {data_package.get('scan_status', 'unknown')}")
    logger.log(f" [+] Duration: {data_package.get('duration_seconds', 'unknown')} seconds\n")
    if not found_map:
        logger.log(" [!] No anti-cheat traces detected.\n")
    else:
        for ac_name, data in sorted(
            found_map.items(), key=lambda item: item[1]["running"], reverse=True
        ):
            logger.log(f" * {ac_name} {'[ACTIVE]' if data['running'] else '[TRACES]'}")
            for category in _CATEGORY_ORDER:
                items = data.get(category, set())
                if not items:
                    continue
                logger.log(f"    [{_CATEGORY_LABELS[category]}]")
                for item in sorted(items):
                    logger.log(f"      - {item}")
            logger.log("")
    if technical_info:
        logger.log("-" * 60)
        logger.log(" BINARY DETAILS ".center(60))
        logger.log("-" * 60)
        for info in technical_info:
            logger.log(f" [{info['ac']}] {info['name']}:")
            if info.get("state"):
                logger.log(f"   State: {info['state']}")
            if info.get("path"):
                logger.log(f"   Path: {info['path']}")
            if info.get("sha"):
                logger.log(f"   SHA256: {info['sha']}")
            if info.get("sig"):
                logger.log(f"   Signer: {info['sig']}")
            metadata = info.get("meta", {})
            if metadata.get("CompanyName"):
                logger.log(f"   Company: {metadata['CompanyName']}")
            logger.log("")
    logger.log("=" * 60)
    logger.log(" SCAN COMPLETE ".center(60))
    logger.log("=" * 60 + "\n")


def _serialize_found_map(found_map: dict[str, Any]) -> dict[str, Any]:
    serialized: dict[str, Any] = {}
    for ac_name, data in found_map.items():
        entry: dict[str, Any] = {"running": data.get("running", False)}
        for category in _CATEGORY_ORDER:
            items = data.get(category, set())
            if items:
                entry[category] = sorted(items)
        serialized[ac_name] = entry
    return serialized


def write_json_report(data_package: dict[str, Any], total_found: int, output_path: Path) -> None:
    payload = {
        "total_detections": total_found,
        "scan_status": data_package.get("scan_status", "unknown"),
        "duration_seconds": data_package.get("duration_seconds"),
        "checker_stats": data_package.get("checker_stats", {}),
        "anti_cheats": _serialize_found_map(data_package["found_map"]),
        "technical_info": data_package.get("technical_info", []),
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, ensure_ascii=False)

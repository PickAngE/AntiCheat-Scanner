from __future__ import annotations

import json
import os
import platform
import re
import socket
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, TypedDict

from checkers.detection import (
    CATEGORY_ACTIVE,
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
from checkers.driver_checker import DRIVER_PREFIXES
from checkers.matchers import extract_exe_path
from config.sig_index import SignatureIndex
from config.signatures import AntiCheatInfo, signatures_sha256
from utils.attribution import resolve_ac_from_folder, resolve_ac_from_registry, resolve_ac_name
from utils.helpers import batch_get_digital_signatures, get_file_hash, get_file_properties, is_admin
from utils.logger import logger

REPORT_SCHEMA = 1


class ScanContext(TypedDict, total=False):
    schema: int
    scanner_version: str
    generated_at: str
    hostname: str
    windows_version: str
    admin: bool
    cli: dict[str, Any]
    config_sha256: str


class DataPackage(TypedDict, total=False):
    found_map: dict[str, Any]
    technical_info: list[dict[str, Any]]
    scan_status: str
    checker_stats: dict[str, dict[str, Any]]
    duration_seconds: float
    context: ScanContext


def build_context(cli_info: dict[str, Any], scanner_version: str) -> ScanContext:
    try:
        hostname = socket.gethostname()
    except OSError:
        hostname = "unknown"
    return ScanContext(
        schema=REPORT_SCHEMA,
        scanner_version=scanner_version,
        generated_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        hostname=hostname,
        windows_version=platform.version(),
        admin=is_admin(),
        cli=cli_info,
        config_sha256=signatures_sha256(),
    )


def _driver_fs_path(path: str) -> str | None:
    if os.path.exists(path):
        return path
    for prefix in DRIVER_PREFIXES:
        if path.startswith(prefix):
            candidate = path[len(prefix) :].split(" (", 1)[0].strip()
            if os.path.exists(candidate):
                return candidate
    return None


def _tech_for_file(name: str, fs_path: str, state: str, sig: str = "") -> dict[str, Any]:
    return {
        "name": name,
        "path": fs_path,
        "sha": get_file_hash(fs_path),
        "sig": sig,
        "meta": get_file_properties(fs_path),
        "state": state,
    }


def _build_tech_from_detection(detection: Detection) -> dict[str, Any] | None:
    if detection.tech:
        return dict(detection.tech)
    if isinstance(detection.raw, dict):
        return {
            "name": detection.raw.get("name", detection.text),
            "path": detection.raw.get("exe", ""),
        }
    return None


def _service_exe(raw: dict[str, Any]) -> str:
    binpath = str(raw.get("binpath", "") or raw.get("exe", "") or "")
    exe_path = extract_exe_path(binpath) if binpath else str(raw.get("exe", "") or "")
    if exe_path and os.path.exists(exe_path):
        return exe_path
    return ""


def _folder_fs_path(text: str) -> str | None:
    if text and os.path.exists(text):
        return text
    candidate = text
    if ": " in candidate:
        head, tail = candidate.split(": ", 1)
        if tail.strip() and head.strip().replace(" ", "").isalpha():
            candidate = tail.strip()
    candidate = candidate.strip()
    if candidate and os.path.exists(candidate):
        return candidate



    stripped = re.sub(r"\s+\([^()]*\)$", "", candidate).strip().strip("\"'")
    if stripped and stripped != candidate and os.path.exists(stripped):
        return stripped
    return None


def build_found_map(
    ac_database: list[AntiCheatInfo],
    checker_results: CheckerResults,
    sig_index: SignatureIndex | None = None,
) -> DataPackage:
    found_map: dict[str, Any] = {}
    technical_info: list[dict[str, Any]] = []


    service_exes: dict[str, str] = {}
    driver_paths: dict[str, str] = {}
    folder_files: dict[str, str] = {}

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
                CATEGORY_ACTIVE: set(),
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


            entry[CATEGORY_ACTIVE].add(description)
        if tech:


            tech_copy = dict(tech)
            tech_copy["ac"] = target
            technical_info.append(tech_copy)




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
        exe_path = _service_exe(raw)
        tech = None
        if exe_path:
            service_exes[exe_path] = exe_path
            tech = _tech_for_file(
                os.path.basename(exe_path),
                exe_path,
                "running" if detection.active else "present",
            )
        add(ac_name, CATEGORY_SVC, detection.text, detection.active, tech)

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
        add(
            ac_name,
            CATEGORY_PROC,
            detection.text,
            detection.active,
            _build_tech_from_detection(detection),
        )

    for detection in checker_results.get(CATEGORY_FOLDER, []):
        path = detection.text


        ac_name = detection.ac_name or resolve_ac_from_folder(path, ac_database)
        tech = dict(detection.tech) if detection.tech else None
        if tech is None:
            fs_path = _folder_fs_path(path)
            if fs_path:
                if os.path.isfile(fs_path):
                    folder_files[fs_path] = fs_path
                    tech = _tech_for_file(
                        os.path.basename(fs_path), fs_path, "present"
                    )
                else:
                    tech = {"name": fs_path, "path": fs_path, "state": "present"}
        add(ac_name, CATEGORY_FOLDER, path, tech=tech)

    for detection in checker_results.get(CATEGORY_REG, []):
        ac_name = detection.ac_name or resolve_ac_from_registry(
            detection.text, ac_database, sig_index
        )
        add(ac_name, CATEGORY_REG, detection.text)

    driver_detections = checker_results.get(CATEGORY_DRV, [])

    resolved_drivers: list[tuple[Detection, str | None]] = []
    for detection in driver_detections:
        path = detection.raw if isinstance(detection.raw, str) else detection.text
        fs_path = _driver_fs_path(path)
        if fs_path:
            driver_paths[fs_path] = fs_path
        resolved_drivers.append((detection, fs_path))
    driver_signatures = batch_get_digital_signatures(sorted(driver_paths))
    service_signatures = batch_get_digital_signatures(sorted(service_exes))
    folder_signatures = batch_get_digital_signatures(sorted(folder_files))
    for tech in technical_info:
        path = str(tech.get("path", ""))
        if not tech.get("sig") and path:
            tech["sig"] = (
                service_signatures.get(path)
                or driver_signatures.get(path)
                or folder_signatures.get(path, "")
            )
    for detection, fs_path in resolved_drivers:
        path = detection.raw if isinstance(detection.raw, str) else detection.text
        ac_name = detection.ac_name or resolve_ac_name(
            path,
            ac_database,
            sig_index,
            include_processes=False,
            include_products=True,
            include_name=True,
        )
        tech = None
        if fs_path:
            tech = _tech_for_file(
                os.path.basename(fs_path),
                fs_path,
                "running" if detection.active else "present",
            )
            tech["sig"] = driver_signatures.get(fs_path, "")
        add(ac_name, CATEGORY_DRV, detection.text, detection.active, tech)

    for detection in checker_results.get(CATEGORY_TRACE, []):
        ac_name = detection.ac_name or resolve_ac_name(
            detection.text,
            ac_database,
            sig_index,
            include_products=True,
            include_name=True,
        )
        add(ac_name, CATEGORY_TRACE, detection.text, detection.active)

    for detection in checker_results.get(CATEGORY_TASK, []):
        ac_name = detection.ac_name or resolve_ac_name(
            detection.text,
            ac_database,
            sig_index,
            include_products=True,
            include_name=True,
        )
        add(ac_name, CATEGORY_TASK, detection.text)

    technical_info.sort(key=lambda info: (str(info.get("ac", "")), str(info.get("name", ""))))


    deduped: list[dict[str, Any]] = []
    seen_tech: set[str] = set()
    for tech in technical_info:
        fingerprint = json.dumps(tech, sort_keys=True, default=str)
        if fingerprint not in seen_tech:
            seen_tech.add(fingerprint)
            deduped.append(tech)
    technical_info[:] = deduped
    return DataPackage(found_map=found_map, technical_info=technical_info)


_CATEGORY_LABELS = {
    CATEGORY_ACTIVE: "Active Evidence",
    CATEGORY_PROC: "Processes",
    CATEGORY_SVC: "Services",
    CATEGORY_DRV: "Drivers",
    CATEGORY_REG: "Registry",
    CATEGORY_FOLDER: "Files / Folders",
    CATEGORY_TASK: "Scheduled Tasks / Prefetch",
    CATEGORY_TRACE: "Forensic Traces",
}
_CATEGORY_ORDER = (
    CATEGORY_ACTIVE,
    CATEGORY_PROC,
    CATEGORY_SVC,
    CATEGORY_DRV,
    CATEGORY_REG,
    CATEGORY_FOLDER,
    CATEGORY_TASK,
    CATEGORY_TRACE,
)


_COUNTED_CATEGORIES = tuple(c for c in _CATEGORY_ORDER if c != CATEGORY_ACTIVE)


def count_unique_detections(found_map: dict[str, Any]) -> int:
    return sum(
        len(data.get(category, set()))
        for data in found_map.values()
        for category in _COUNTED_CATEGORIES
    )


def write_report(data_package: DataPackage, total_found: int) -> None:
    found_map = data_package["found_map"]
    technical_info = data_package["technical_info"]
    context = data_package.get("context")
    logger.log("\n" + "=" * 60)
    logger.log(" ANTI-CHEAT REPORT ".center(60))
    logger.log("=" * 60)
    logger.log(f" [+] Detection records: {total_found}")
    logger.log(f" [+] Scan status: {data_package.get('scan_status', 'unknown')}")
    logger.log(f" [+] Duration: {data_package.get('duration_seconds', 'unknown')} seconds")
    if context:
        logger.log(f" [+] Scanner: {context.get('scanner_version', '?')} (schema {context.get('schema', '?')})")
        logger.log(
            f" [+] Host: {context.get('hostname', '?')} "
            f"| admin: {context.get('admin', '?')} "
            f"| config: {str(context.get('config_sha256', ''))[:12]}"
        )
    logger.log("")
    if not found_map:
        logger.log(" [!] No anti-cheat traces detected.\n")
    else:
        for ac_name, data in sorted(
            found_map.items(), key=lambda item: (not item[1]["running"], item[0])
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
        for info in sorted(technical_info, key=lambda i: (str(i.get("ac")), str(i.get("name")))):
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
            if isinstance(metadata, dict) and metadata.get("CompanyName"):
                logger.log(f"   Company: {metadata['CompanyName']}")
            logger.log("")
    logger.log("=" * 60)
    logger.log(" SCAN COMPLETE ".center(60))
    logger.log("=" * 60 + "\n")


def _serialize_found_map(found_map: dict[str, Any]) -> dict[str, Any]:
    serialized: dict[str, Any] = {}
    for ac_name in sorted(found_map):
        data = found_map[ac_name]
        entry: dict[str, Any] = {"running": data.get("running", False)}
        for category in _CATEGORY_ORDER:
            items = data.get(category, set())
            if items:
                entry[category] = sorted(items)
        serialized[ac_name] = entry
    return serialized


def write_json_report(data_package: DataPackage, total_found: int, output_path: Path) -> None:
    context = data_package.get("context") or {}
    payload = {
        "schema": context.get("schema", REPORT_SCHEMA),
        "scanner_version": context.get("scanner_version"),
        "generated_at": context.get("generated_at"),
        "host": {
            "hostname": context.get("hostname"),
            "windows_version": context.get("windows_version"),
            "admin": context.get("admin"),
        },
        "cli": context.get("cli"),
        "config_sha256": context.get("config_sha256"),
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

from __future__ import annotations

import argparse
import concurrent.futures
import contextlib
import importlib.metadata
import json
import logging
import os
import sys
import time
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from checkers.base import BaseChecker
from checkers.detection import ALL_CATEGORIES
from checkers.registry import CHECKER_CLASSES, build_checkers
from config.sig_index import SignatureIndex
from config.signatures import AntiCheatInfo, get_ac_database, validate_signatures
from config.whitelist import get_whitelist
from config.whitelist import set_disabled as set_whitelist_disabled
from report import (
    build_context,
    build_found_map,
    count_unique_detections,
    write_json_report,
    write_report,
)
from utils.helpers import is_admin, request_admin_rerun
from utils.logger import logger
from utils.subprocess_helper import format_error

EXIT_PARTIAL_OR_ERROR = 1
EXIT_USAGE_OR_PLATFORM = 2
EXIT_INTERRUPTED = 130

DEFAULT_OUTPUT_DIR = Path.cwd()
DEFAULT_TIMEOUT = 300


def get_scanner_version() -> str:
    try:
        return importlib.metadata.version("anti-cheat-scanner")
    except importlib.metadata.PackageNotFoundError:
        pass
    try:
        from pathlib import Path as _Path

        for line in (_Path(__file__).resolve().parent / "pyproject.toml").read_text(
            encoding="utf-8"
        ).splitlines():
            stripped = line.strip()
            if stripped.startswith("version"):
                return stripped.split("=", 1)[1].strip().strip("\"'")
    except OSError:
        pass
    return "0.0.0+unknown"


def _positive_int(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("value must be an integer") from exc
    if parsed < 1:
        raise argparse.ArgumentTypeError("value must be greater than zero")
    return parsed


def _non_negative_int(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("value must be an integer") from exc
    if parsed < 0:
        raise argparse.ArgumentTypeError("value must be zero or greater")
    return parsed


def _category_set(value: str) -> set[str]:
    parts = {part.strip().lower() for part in value.split(",") if part.strip()}
    unknown = sorted(parts - set(ALL_CATEGORIES))
    if unknown:
        raise argparse.ArgumentTypeError(
            f"unknown categories: {', '.join(unknown)} (choose from {', '.join(ALL_CATEGORIES)})"
        )
    return parts


def parse_args(arguments: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Scan a Windows system for anti-cheat software and traces"
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {get_scanner_version()}"
    )
    parser.add_argument(
        "--json", dest="json_output", action="store_true", help="write a JSON report"
    )
    parser.add_argument(
        "--workers", type=_positive_int, default=5, help="number of concurrent checkers"
    )
    parser.add_argument(
        "--timeout",
        type=_positive_int,
        default=DEFAULT_TIMEOUT,
        help="per-checker timeout in seconds (default: %(default)s)",
    )
    parser.add_argument(
        "--eventlog-limit",
        type=_positive_int,
        default=300,
        dest="eventlog_limit",
        help="number of System event-log records inspected (default: %(default)s)",
    )
    depth_group = parser.add_mutually_exclusive_group()
    depth_group.add_argument(
        "--max-depth", type=_non_negative_int, default=1, help="maximum filesystem search depth"
    )
    depth_group.add_argument(
        "--full",
        dest="max_depth",
        action="store_const",
        const=None,
        help="scan configured roots recursively without a depth limit",
    )
    parser.add_argument(
        "--include",
        type=_category_set,
        default=None,
        metavar="CAT,...",
        help=f"run only these checker categories: {', '.join(ALL_CATEGORIES)}",
    )
    parser.add_argument(
        "--exclude",
        type=_category_set,
        default=None,
        metavar="CAT,...",
        help="skip these checker categories (wins over --include)",
    )
    parser.add_argument(
        "--list-checkers", action="store_true", help="list checker classes and exit"
    )
    parser.add_argument(
        "--list-ac", action="store_true", help="list known anti-cheat names and exit"
    )
    parser.add_argument(
        "--validate-config",
        action="store_true",
        help="validate signatures/whitelist configuration and exit",
    )
    parser.add_argument(
        "--print-whitelist", action="store_true", help="print the active whitelist and exit"
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=DEFAULT_OUTPUT_DIR,
        help="directory for generated reports (default: current directory)",
    )
    parser.add_argument(
        "--pause", dest="pause", action="store_true", help="wait for Enter before exiting"
    )
    parser.add_argument(
        "--no-pause", dest="pause", action="store_false", help="exit without waiting for Enter"
    )
    parser.set_defaults(pause=True)
    parser.add_argument(
        "--strict", action="store_true", help="return a non-zero code for partial scans"
    )
    parser.add_argument(
        "--verbose", action="store_true", help="enable debug logging on the console"
    )
    parser.add_argument(
        "--no-elevate",
        dest="no_elevate",
        action="store_true",
        help="skip the admin-elevation check (CI / non-admin runs)",
    )
    parser.add_argument(
        "--no-whitelist",
        dest="no_whitelist",
        action="store_true",
        help="bypass whitelist filtering (audit runs)",
    )
    return parser.parse_args(arguments)


def _build_checkers(
    ac_database: list[AntiCheatInfo],
    sig_index: SignatureIndex,
    max_depth: int | None = 1,
    include: set[str] | None = None,
    exclude: set[str] | None = None,
    eventlog_limit: int = 300,
) -> list[BaseChecker]:

    return build_checkers(
        ac_database,
        sig_index,
        max_depth=max_depth,
        include=include,
        exclude=exclude,
        eventlog_limit=eventlog_limit,
    )


def _run_list_checkers() -> int:
    for checker_cls in CHECKER_CLASSES:
        print(f"{checker_cls.__name__}: {checker_cls.CATEGORY}")
    return 0


def _run_list_ac() -> int:
    try:
        for ac in get_ac_database():
            print(ac.name)
    except ValueError as exc:
        print(f"Invalid signatures database: {exc}", file=sys.stderr)
        return EXIT_PARTIAL_OR_ERROR
    return 0


def _run_print_whitelist() -> int:
    print(json.dumps(get_whitelist(), indent=2, ensure_ascii=False))
    return 0


def _run_validate_config() -> int:
    messages = validate_signatures()
    errors = [m for m in messages if not m.startswith("warning:")]
    warnings = [m for m in messages if m.startswith("warning:")]
    try:
        get_whitelist()
    except Exception as exc:
        errors.append(f"Invalid whitelist: {format_error(exc)}")
    for message in [*errors, *warnings]:
        print(message)
    if errors:
        print("Configuration INVALID.", file=sys.stderr)
        return EXIT_PARTIAL_OR_ERROR
    if warnings:
        print("Configuration valid with warnings.")
    else:
        print("Configuration valid.")
    return 0


def _run_checkers(
    checkers: list[BaseChecker], workers: int, timeout: int
) -> dict[str, dict[str, Any]]:
    stats: dict[str, dict[str, Any]] = {}
    if not checkers:
        return stats
    max_workers = max(1, min(len(checkers), workers))
    logger.log("[*] Running subsystem checks in parallel...")
    submitted_at = time.perf_counter()
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        future_map = {pool.submit(checker.check): checker for checker in checkers}
        pending = set(future_map)
        while pending:
            done, pending = concurrent.futures.wait(
                pending,
                timeout=timeout,
                return_when=concurrent.futures.FIRST_COMPLETED,
            )
            for future in done:
                checker = future_map[future]
                checker_name = type(checker).__name__
                stats[checker_name] = {
                    "duration_s": round(time.perf_counter() - submitted_at, 3)
                }
                try:
                    future.result()
                    suffix = (
                        f" ({checker.skipped_count} paths skipped)"
                        if checker.skipped_count
                        else ""
                    )
                    logger.log(f"  [+] {checker_name} complete{suffix}")
                except Exception as exc:


                    checker.fail_count += 1
                    logger.log(f"  [!] {checker_name} failed: {format_error(exc)}")
                    logger.log(f"  [!] Error type: {type(exc).__name__}")
                if checker.fail_count:
                    logger.log(f"  [!] {checker_name} reported {checker.fail_count} item errors")
                if checker.whitelisted_count:
                    logger.log(
                        f"  [*] {checker_name} ignored {checker.whitelisted_count} whitelisted items"
                    )
            if not done and pending:
                for future in pending:
                    checker = future_map[future]
                    checker_name = type(checker).__name__
                    checker.fail_count += 1
                    stats[checker_name] = {
                        "duration_s": round(time.perf_counter() - submitted_at, 3)
                    }
                    logger.log(
                        f"  [!] {checker_name} timed out after {timeout} seconds; skipped."
                    )
                    future.cancel()
                break
    for checker in checkers:
        entry = stats.setdefault(type(checker).__name__, {"duration_s": 0.0})
        entry.update(
            {
                "failures": checker.fail_count,
                "skipped": checker.skipped_count,
                "whitelisted": checker.whitelisted_count,

                **getattr(checker, "extra_stats", {}),
            }
        )
    return stats


def main(arguments: Sequence[str] | None = None) -> int:
    args = parse_args(arguments)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)-7s %(name)s: %(message)s",
    )
    if args.list_checkers:
        return _run_list_checkers()
    if args.list_ac:
        return _run_list_ac()
    if args.print_whitelist:
        return _run_print_whitelist()
    if args.validate_config:
        return _run_validate_config()

    if os.name != "nt":
        logger.log("[!] This scanner only runs on Windows (win32 APIs required).")
        return EXIT_USAGE_OR_PLATFORM

    scan_started = time.perf_counter()
    exit_code = 0
    try:
        if not args.no_elevate and not is_admin():
            logger.log("[!] Administrator privileges are required for complete coverage.")
            rerun_exit_code = request_admin_rerun()
            if rerun_exit_code is not None:
                if rerun_exit_code:
                    logger.log(f"[!] Elevated scan failed with exit code {rerun_exit_code}.")
                else:
                    logger.log("[*] Elevated scan completed.")
                return rerun_exit_code


            logger.log("[!] UAC elevation was denied or timed out. Scan cancelled.")
            return EXIT_PARTIAL_OR_ERROR

        if args.no_whitelist:
            set_whitelist_disabled(True)

        logger.log("[*] Starting Anti-Cheat Scanner...")
        report_path = Path(logger.start_logging(str(args.output_dir))).resolve()
        ac_database = get_ac_database()
        sig_index = SignatureIndex.build(ac_database)
        checkers = _build_checkers(
            ac_database,
            sig_index,
            max_depth=args.max_depth,
            include=args.include,
            exclude=args.exclude,
            eventlog_limit=args.eventlog_limit,
        )
        if not checkers:
            logger.log("[!] No checkers configured; nothing to scan.")
            return 0
        checker_stats = _run_checkers(checkers, args.workers, args.timeout)
        checker_results = {checker.CATEGORY: checker.found for checker in checkers}
        data_package = build_found_map(ac_database, checker_results, sig_index=sig_index)


        data_package["scan_status"] = (
            "partial" if any(checker.fail_count for checker in checkers) else "complete"
        )
        if args.strict and data_package["scan_status"] == "partial":
            exit_code = EXIT_PARTIAL_OR_ERROR
        data_package["checker_stats"] = checker_stats
        data_package["duration_seconds"] = round(time.perf_counter() - scan_started, 3)
        data_package["context"] = build_context(
            {
                "workers": args.workers,
                "timeout": args.timeout,
                "eventlog_limit": args.eventlog_limit,
                "max_depth": args.max_depth,
                "include": sorted(args.include) if args.include else None,
                "exclude": sorted(args.exclude) if args.exclude else None,
                "strict": args.strict,
                "no_elevate": args.no_elevate,
                "no_whitelist": args.no_whitelist,
                "output_dir": str(args.output_dir),
            },
            get_scanner_version(),
        )
        total = count_unique_detections(data_package["found_map"])
        write_report(data_package, total)
        logger.log(f" [+] Text report written to {report_path}")
        if args.json_output:
            json_path = report_path.with_suffix(".json")
            write_json_report(data_package, total, json_path)
            logger.log(f" [+] JSON report written to {json_path}")
    except KeyboardInterrupt:
        logger.log("\n [!] Scan interrupted by the user.")
        return EXIT_INTERRUPTED
    except Exception as exc:
        exit_code = EXIT_PARTIAL_OR_ERROR
        logger.log(f"\n [!] Critical error: {format_error(exc)}")
        logger.log(f"[*] Scan duration: {time.perf_counter() - scan_started:.3f} seconds")
        logger.log(f"  [!] Error type: {type(exc).__name__}")
    finally:
        logger.close()
    if args.pause and sys.stdin.isatty():
        with contextlib.suppress(EOFError):
            input("\nPress Enter to exit...")
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())

from __future__ import annotations

import argparse
import concurrent.futures
import contextlib
import logging
import sys
import time
from collections.abc import Sequence
from pathlib import Path

from checkers.base import BaseChecker
from checkers.registry import build_checkers
from config.sig_index import SignatureIndex
from config.signatures import AntiCheatInfo, get_ac_database
from report import build_found_map, count_unique_detections, write_json_report, write_report
from utils.helpers import is_admin, request_admin_rerun
from utils.logger import logger
from utils.subprocess_helper import format_error

DEFAULT_OUTPUT_DIR = Path(__file__).resolve().parent


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


def parse_args(arguments: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Scan a Windows system for anti-cheat software and traces"
    )
    parser.add_argument(
        "--json", dest="json_output", action="store_true", help="write a JSON report"
    )
    parser.add_argument(
        "--workers", type=_positive_int, default=3, help="number of concurrent checkers"
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
        "--output-dir",
        type=Path,
        default=DEFAULT_OUTPUT_DIR,
        help="directory for generated reports",
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
    return parser.parse_args(arguments)


def _build_checkers(
    ac_database: list[AntiCheatInfo],
    sig_index: SignatureIndex,
    max_depth: int | None = 1,
) -> list[BaseChecker]:
    return build_checkers(ac_database, sig_index, max_depth=max_depth)


def main(arguments: Sequence[str] | None = None) -> int:
    args = parse_args(arguments)
    logging.basicConfig(level=logging.INFO, format="%(levelname)-7s %(name)s: %(message)s")
    scan_started = time.perf_counter()
    exit_code = 0
    try:
        if not is_admin():
            logger.log("[!] Administrator privileges are required for complete coverage.")
            rerun_exit_code = request_admin_rerun()
            if rerun_exit_code is not None:
                if rerun_exit_code:
                    logger.log(f"[!] Elevated scan failed with exit code {rerun_exit_code}.")
                else:
                    logger.log(f"[*] Elevated scan completed. Reports: {args.output_dir}")
                return rerun_exit_code
            logger.log("[!] UAC elevation was denied. Scan cancelled.")
            return 1

        logger.log("[*] Starting Anti-Cheat Scanner...")
        report_path = logger.start_logging(str(args.output_dir))
        ac_database = get_ac_database()
        sig_index = SignatureIndex.build(ac_database)
        checkers = _build_checkers(ac_database, sig_index, max_depth=args.max_depth)
        logger.log("[*] Running subsystem checks in parallel...")
        max_workers = min(len(checkers), args.workers)
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
            future_map = {pool.submit(checker.check): checker for checker in checkers}
            for future in concurrent.futures.as_completed(future_map):
                checker = future_map[future]
                checker_name = type(checker).__name__
                try:
                    future.result()
                    suffix = (
                        f" ({checker.skipped_count} paths skipped)" if checker.skipped_count else ""
                    )
                    logger.log(f"  [+] {checker_name} complete{suffix}")
                except Exception as exc:
                    exit_code = 1
                    checker.fail_count += 1
                    logger.log(f"  [!] {checker_name} failed: {format_error(exc)}")
                    logger.log(f"  [!] Error type: {type(exc).__name__}")
                if checker.fail_count:
                    logger.log(f"  [!] {checker_name} reported {checker.fail_count} item errors")
                if checker.whitelisted_count:
                    logger.log(
                        f"  [*] {checker_name} ignored {checker.whitelisted_count} whitelisted items"
                    )
        checker_results = {checker.CATEGORY: checker.found for checker in checkers}
        data_package = build_found_map(ac_database, checker_results, sig_index=sig_index)
        data_package["scan_status"] = (
            "partial"
            if any(checker.fail_count or checker.skipped_count for checker in checkers)
            else "complete"
        )
        if args.strict and data_package["scan_status"] == "partial":
            exit_code = 1
        data_package["checker_stats"] = {
            type(checker).__name__: {
                "failures": checker.fail_count,
                "skipped": checker.skipped_count,
                "whitelisted": checker.whitelisted_count,
            }
            for checker in checkers
        }
        data_package["duration_seconds"] = round(time.perf_counter() - scan_started, 3)
        total = count_unique_detections(data_package["found_map"])
        write_report(data_package, total)
        logger.log(f" [+] Text report written to {report_path}")
        if args.json_output:
            json_path = report_path.with_suffix(".json")
            write_json_report(data_package, total, json_path)
            logger.log(f" [+] JSON report written to {json_path}")
    except Exception as exc:
        exit_code = 1
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

import argparse
import concurrent.futures
import logging
import sys
import traceback

sys.dont_write_bytecode = True

from config.signatures import get_ac_database
from config.sig_index import SignatureIndex
from utils.helpers import is_admin, request_admin_rerun
from utils.logger import logger
from checkers.registry import CHECKER_CLASSES
from checkers.file_checker import FileChecker
from report import build_found_map, count_unique_detections, write_json_report, write_report


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Anti-Cheat Scanner for Windows")
    parser.add_argument(
        "--no-pause",
        action="store_true",
        help="Exit immediately without waiting for Enter (useful for automation)",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Reduce console debug output (logging level WARNING)",
    )
    parser.add_argument(
        "--output",
        metavar="PATH",
        help="Report output file or directory (default: AntiCheat_Report_<timestamp>.txt in cwd)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Also write a JSON report alongside the text report",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=3,
        metavar="N",
        help="Maximum parallel checker workers (default: 3)",
    )
    parser.add_argument(
        "--depth",
        type=int,
        default=1,
        metavar="N",
        help="FileChecker recursive scan depth (default: 1)",
    )
    return parser.parse_args()


def _build_checkers(ac_database, sig_index, scan_depth: int):  # type: ignore[no-untyped-def]
    checkers = []
    for cls in CHECKER_CLASSES:
        if cls is FileChecker:
            checkers.append(cls(ac_database, sig_index, max_depth=scan_depth))  # type: ignore[abstract,call-arg]
        else:
            checkers.append(cls(ac_database, sig_index))  # type: ignore[abstract]
    return checkers


def main() -> int:
    args = parse_args()
    log_level = logging.WARNING if args.quiet else logging.INFO
    logging.basicConfig(level=log_level, format="%(levelname)-7s %(name)s: %(message)s")

    exit_code = 0
    try:
        if not is_admin() and request_admin_rerun():
            return 0

        logger.log("[*] Starting Anti-Cheat Scanner...")
        report_path = logger.start_logging(args.output)

        ac_database = get_ac_database()
        sig_index = SignatureIndex.build(ac_database)

        logger.log("[*] Running subsystem checks in parallel (this may take a minute)...")

        checkers = _build_checkers(ac_database, sig_index, args.depth)
        max_workers = min(len(checkers), max(1, args.workers))

        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
            fut_map = {pool.submit(c.check): c for c in checkers}
            for future in concurrent.futures.as_completed(fut_map):
                checker = fut_map[future]
                checker_name = type(checker).__name__
                try:
                    future.result()
                    suffix = ""
                    if checker.skipped_count:
                        suffix = f" ({checker.skipped_count} paths skipped)"
                    logger.log(f"  [+] {checker_name} complete{suffix}")
                except Exception as e:
                    exit_code = 1
                    logger.log(f"  [!] {checker_name} failed: {e}")
                    tb = traceback.format_exc()
                    logger.log("  [!] " + "\n  [!] ".join(line for line in tb.splitlines()))
                    logger.log("  [!] " + "-" * 50)
                if checker.fail_count:
                    logger.log(f"  [!] {checker_name} skipped {checker.fail_count} items due to errors")

        checker_results = {checker.CATEGORY: checker.found for checker in checkers}
        data_package = build_found_map(ac_database, checker_results, sig_index=sig_index)

        total = count_unique_detections(data_package["found_map"])
        write_report(data_package, total)

        if args.json and report_path is not None:
            json_path = report_path.with_suffix(".json")
            write_json_report(data_package, total, json_path)
            logger.log(f" [+] JSON report written to: {json_path}")

    except Exception as e:
        exit_code = 1
        logger.log(f"\n [!] CRITICAL ERROR: {e}")
        logger.log("  [!] See traceback above for details")
        traceback.print_exc()

    finally:
        logger.close()

    if not args.no_pause:
        try:
            input("\nPress Enter to exit...")
        except EOFError:
            pass

    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())

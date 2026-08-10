import concurrent.futures
import logging
import sys
import traceback
from pathlib import Path

sys.dont_write_bytecode = True

from config.signatures import get_ac_database
from config.sig_index import SignatureIndex
from utils.helpers import is_admin, request_admin_rerun
from utils.logger import logger
from checkers.registry import CHECKER_CLASSES
from checkers.file_checker import FileChecker
from report import build_found_map, count_unique_detections, write_report


def _build_checkers(ac_database, sig_index):
    """Build all checkers with default settings (full scan)."""
    checkers = []
    for cls in CHECKER_CLASSES:
        if cls is FileChecker:
            checkers.append(cls(ac_database, sig_index, max_depth=1))
        else:
            checkers.append(cls(ac_database, sig_index))
    return checkers


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)-7s %(name)s: %(message)s")

    exit_code = 0
    try:
        if not is_admin():
            logger.log("[!] This script requires administrator privileges to run.")
            logger.log("[!] Please accept UAC elevation to continue.")
            if request_admin_rerun():
                return 0
            else:
                logger.log("[!] UAC elevation denied. Cannot continue without admin rights.")
                return 1

        logger.log("[*] Starting Anti-Cheat Scanner...")
        
        script_dir = Path(__file__).parent
        report_path = logger.start_logging(str(script_dir))

        ac_database = get_ac_database()
        sig_index = SignatureIndex.build(ac_database)

        logger.log("[*] Running subsystem checks in parallel (this may take a minute)...")

        checkers = _build_checkers(ac_database, sig_index)
        max_workers = min(len(checkers), 3)  # Default to 3 workers

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

    except Exception as e:
        exit_code = 1
        logger.log(f"\n [!] CRITICAL ERROR: {e}")
        logger.log("  [!] See traceback above for details")
        traceback.print_exc()

    finally:
        logger.close()

    try:
        input("\nPress Enter to exit...")
    except EOFError:
        pass

    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())

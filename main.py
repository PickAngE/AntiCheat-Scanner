<<<<<<< HEAD
=======
<<<<<<< HEAD
>>>>>>> 979330d (update 2026-06-15 16:33:37)
import argparse
import concurrent.futures
import logging
import sys
import traceback
<<<<<<< HEAD
=======
=======
import sys
>>>>>>> e285a17f27e49403e5e4eb37a3f873a4bc5e00ae
>>>>>>> 979330d (update 2026-06-15 16:33:37)

sys.dont_write_bytecode = True

from config.signatures import get_ac_database
<<<<<<< HEAD
=======
<<<<<<< HEAD
>>>>>>> 979330d (update 2026-06-15 16:33:37)
from config.sig_index import SignatureIndex
from utils.helpers import is_admin, request_admin_rerun
from utils.logger import logger
from checkers import (
    ServiceChecker,
    ProcessChecker,
    DriverFileChecker,
    FileChecker,
    RegistryChecker,
    TaskChecker,
    TraceChecker,
)
from report import build_found_map, count_unique_detections, write_report


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
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    log_level = logging.WARNING if args.quiet else logging.DEBUG
    logging.basicConfig(level=log_level, format="%(levelname)-7s %(name)s: %(message)s")

    exit_code = 0
    try:
        if not is_admin():
            if request_admin_rerun():
                return 0
            logger.log("[!] Administrator privileges are recommended for full scan coverage.")

        logger.log("[*] Starting Anti-Cheat Scanner...")
        logger.start_logging()

        ac_database = get_ac_database()
        sig_index = SignatureIndex.build(ac_database)

        logger.log("[*] Running subsystem checks in parallel (this may take a minute)...")

        checkers = [
            ServiceChecker(ac_database, sig_index),
            ProcessChecker(ac_database, sig_index),
            DriverFileChecker(ac_database, sig_index),
            FileChecker(ac_database, sig_index),
            RegistryChecker(ac_database, sig_index),
            TaskChecker(ac_database, sig_index),
            TraceChecker(ac_database, sig_index),
        ]

        max_workers = min(len(checkers), 4)
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
            fut_map = {pool.submit(c.check): c for c in checkers}
            for future in concurrent.futures.as_completed(fut_map):
                checker = fut_map[future]
                try:
                    future.result()
                except Exception as e:
                    exit_code = 1
                    logger.log(f"  [!] {type(checker).__name__} failed: {e}")
                    logging.debug("Checker failure details:", exc_info=True)

        svc_checker, proc_checker, driver_checker, file_checker, reg_checker, task_checker, trace_checker = checkers

        data_package = build_found_map(
            ac_database,
            svc_checker.found,
            proc_checker.found,
            driver_checker.found,
            file_checker.found,
            reg_checker.found,
            task_checker.found,
            trace_checker.found,
            sig_index=sig_index,
        )

        total = count_unique_detections(data_package["found_map"])
        write_report(data_package, total)

    except Exception as e:
        exit_code = 1
        logger.log(f"\n [!] CRITICAL ERROR: {e}")
        logging.error("Critical failure", exc_info=True)
        traceback.print_exc()

    finally:
        logger.close()

    if not args.no_pause:
        input("\nPress Enter to exit...")

    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
<<<<<<< HEAD
=======
=======
from utils.helpers import is_admin, request_admin_rerun
from utils.logger import logger
from checkers import (
    ServiceChecker, ProcessChecker, DriverFileChecker,
    FileChecker, RegistryChecker, TaskChecker, TraceChecker
)

from report import build_found_map, write_report, get_total_found

def main() -> None:
    try:
        if not is_admin():
            if request_admin_rerun():
                sys.exit(0)

        print("[*] Starting Anti-Cheat Scanner...")
        logger.start_logging()
        
        ac_database = get_ac_database()
        all_sigs = []
        for ac in ac_database:
            all_sigs.extend(ac.services + ac.processes + ac.drivers)

        print("[*] Running subsystem checks (this may take a minute)...")
        
        svc_checker = ServiceChecker(all_sigs); svc_checker.check()
        proc_checker = ProcessChecker(ac_database); proc_checker.check()
        driver_checker = DriverFileChecker(ac_database); driver_checker.check()
        file_checker = FileChecker(ac_database); file_checker.check()
        reg_checker = RegistryChecker(ac_database); reg_checker.check()
        task_checker = TaskChecker(ac_database); task_checker.check()
        trace_checker = TraceChecker(list(set(all_sigs))); trace_checker.check()

        data_package = build_found_map(
            ac_database, 
            svc_checker.found, proc_checker.found, driver_checker.found,
            file_checker.found, reg_checker.found, task_checker.found, trace_checker.found
        )
        
        total = get_total_found(
            svc_checker.found, proc_checker.found, driver_checker.found, 
            file_checker.found, reg_checker.found, task_checker.found, trace_checker.found
        )

        write_report(data_package, total)
        logger.close()

    except Exception as e:
        print(f"\n [!] CRITICAL ERROR: {e}")

    input("\nAppuyez sur Entrée pour quitter...")

if __name__ == "__main__":
    main()
>>>>>>> e285a17f27e49403e5e4eb37a3f873a4bc5e00ae
>>>>>>> 979330d (update 2026-06-15 16:33:37)

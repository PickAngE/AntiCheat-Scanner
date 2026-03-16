import sys
import os

sys.dont_write_bytecode = True
os.environ["PYTHONDONTWRITEBYTECODE"] = "1"

from config.signatures import get_ac_database
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
from report import build_found_map, write_report, get_total_found

def main() -> None:
    try:
        if not is_admin():
            if request_admin_rerun():
                sys.exit(0)

        logger.start_logging()
        ac_database = get_ac_database()

        all_services = []
        all_processes = []
        all_drivers = []
        for ac in ac_database:
            all_services.extend(ac.services)
            all_processes.extend(ac.processes)
            all_drivers.extend(ac.drivers)

        svc_checker = ServiceChecker(all_services)
        svc_checker.check()

        proc_checker = ProcessChecker(ac_database)
        proc_checker.check()

        driver_checker = DriverFileChecker(ac_database)
        driver_checker.check()

        file_checker = FileChecker(ac_database)
        file_checker.check()

        reg_checker = RegistryChecker(ac_database)
        reg_checker.check()

        task_checker = TaskChecker(ac_database)
        task_checker.check()

        trace_checker = TraceChecker(list(set(all_processes + all_services + all_drivers)))
        trace_checker.check()

        report_data = build_found_map(
            ac_database,
            svc_checker.found,
            proc_checker.found,
            driver_checker.found,
            file_checker.found,
            reg_checker.found,
            task_checker.found,
            trace_checker.found,
        )

        total = get_total_found(
            svc_checker.found,
            proc_checker.found,
            driver_checker.found,
            file_checker.found,
            reg_checker.found,
            task_checker.found,
            trace_checker.found,
        )

        write_report(report_data, total)
        logger.close()

    except Exception as e:
        print(f"\n[!] CRITICAL ERROR: {e}")
        try:
            logger.log(f"CRASH: {e}")
            logger.close()
        except Exception:
            pass

    import shutil
    import pathlib
    def _cleanup_pycache():
        try:
            for p in pathlib.Path(__file__).parent.rglob("__pycache__"):
                shutil.rmtree(p, ignore_errors=True)
        except Exception:
            pass

    _cleanup_pycache()
    input("\nPress Enter to exit...")

if __name__ == "__main__":
    main()

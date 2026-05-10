import sys

sys.dont_write_bytecode = True

from config.signatures import get_ac_database
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

import sys
sys.dont_write_bytecode = True

from config.signatures import get_ac_database
from utils.helpers import is_admin, request_admin_rerun
from utils.logger import logger
from checkers import (
    ServiceChecker,
    ProcessChecker,
    DriverFileChecker,
    FileChecker,
    RegistryChecker,
)
from report import build_found_map, write_report, get_total_found


def _aggregate_signatures():
    ac_database = get_ac_database()
    all_services = []
    all_processes = []
    all_drivers = []
    all_folders = []
    all_registry = []
    for ac in ac_database:
        all_services.extend(ac.services)
        all_processes.extend(ac.processes)
        all_drivers.extend(ac.drivers)
        all_folders.extend(ac.folders)
        all_registry.extend(ac.registry)
    return (
        ac_database,
        list(set(all_services)),
        list(set(all_processes)),
        list(set(all_drivers)),
        list(set(all_folders)),
        list(set(all_registry)),
    )


def main() -> None:
    if not is_admin():
        request_admin_rerun()
    logger.start_logging()
    ac_database, all_services, all_processes, all_drivers, all_folders, all_registry = _aggregate_signatures()
    svc_checker = ServiceChecker(all_services)
    svc_checker.check()
    proc_checker = ProcessChecker(all_processes)
    proc_checker.check()
    driver_checker = DriverFileChecker(all_drivers)
    driver_checker.check()
    file_checker = FileChecker(all_folders)
    file_checker.check()
    reg_checker = RegistryChecker(all_registry)
    reg_checker.check()
    found_map = build_found_map(
        ac_database,
        svc_checker.found,
        proc_checker.found,
        driver_checker.found,
        file_checker.found,
        reg_checker.found,
    )
    total = get_total_found(
        svc_checker.found,
        proc_checker.found,
        driver_checker.found,
        file_checker.found,
        reg_checker.found,
    )
    write_report(found_map, total)
    logger.close()


if __name__ == "__main__":
    main()

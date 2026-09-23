from __future__ import annotations

from checkers.base import BaseChecker
from checkers.driver_checker import DriverFileChecker
from checkers.file_checker import FileChecker
from checkers.process_checker import ProcessChecker
from checkers.registry_checker import RegistryChecker
from checkers.service_checker import ServiceChecker
from checkers.task_checker import TaskChecker
from checkers.trace_checker import TraceChecker
from config.sig_index import SignatureIndex
from config.signatures import AntiCheatInfo

CHECKER_CLASSES: list[type[BaseChecker]] = [
    ServiceChecker,
    ProcessChecker,
    DriverFileChecker,
    FileChecker,
    RegistryChecker,
    TaskChecker,
    TraceChecker,
]


def build_checkers(
    ac_database: list[AntiCheatInfo],
    sig_index: SignatureIndex | None = None,
    max_depth: int | None = 1,
) -> list[BaseChecker]:
    checkers: list[BaseChecker] = [
        ServiceChecker(ac_database, sig_index),
        ProcessChecker(ac_database, sig_index),
        DriverFileChecker(ac_database, sig_index),
        FileChecker(ac_database, sig_index, max_depth=max_depth),
        RegistryChecker(ac_database, sig_index),
        TaskChecker(ac_database, sig_index),
        TraceChecker(ac_database, sig_index),
    ]
    return checkers

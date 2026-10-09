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
    include: set[str] | None = None,
    exclude: set[str] | None = None,
    eventlog_limit: int = 300,
) -> list[BaseChecker]:
    checkers: list[BaseChecker] = []
    for checker_cls in CHECKER_CLASSES:
        if include is not None and checker_cls.CATEGORY not in include:
            continue
        if exclude is not None and checker_cls.CATEGORY in exclude:
            continue
        if checker_cls is FileChecker:
            checkers.append(checker_cls(ac_database, sig_index, max_depth=max_depth))
        elif checker_cls is TraceChecker:
            checkers.append(
                checker_cls(ac_database, sig_index, eventlog_limit=eventlog_limit)
            )
        else:
            checkers.append(checker_cls(ac_database, sig_index))
    return checkers

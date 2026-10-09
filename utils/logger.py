from __future__ import annotations

import contextlib
import logging
import threading
from datetime import datetime
from pathlib import Path
from typing import TextIO

_REPORT_LOGGER = "acs.report"


class ReportLogger:
    def __init__(self) -> None:
        self.log_file: TextIO | None = None
        self._report_path: Path | None = None
        self._lock = threading.RLock()
        self._logger = logging.getLogger(_REPORT_LOGGER)
        self._logger.setLevel(logging.INFO)
        self._logger.propagate = False
        if not self._logger.handlers:
            console = logging.StreamHandler()
            console.setFormatter(logging.Formatter("%(message)s"))
            self._logger.addHandler(console)

    @staticmethod
    def _is_reparse_point(path: Path) -> bool:
        if path.is_symlink():
            return True
        is_junction = getattr(path, "is_junction", None)
        if is_junction is not None:
            with contextlib.suppress(OSError):
                if is_junction():
                    return True
        return False

    def start_logging(self, output_path: str | None = None) -> Path:
        with self._lock:
            if output_path:
                path = Path(output_path)
                if path.is_dir() or not path.suffix:
                    timestamp = datetime.now().astimezone().strftime("%Y%m%d_%H%M%S_%f")
                    path = path / f"AntiCheat_Report_{timestamp}.txt"
            else:
                timestamp = datetime.now().astimezone().strftime("%Y%m%d_%H%M%S_%f")
                path = Path(f"AntiCheat_Report_{timestamp}.txt")
            path.parent.mkdir(parents=True, exist_ok=True)
            if self._is_reparse_point(path):
                raise OSError(f"Report path is a reparse point: {path}")
            with path.open("x", encoding="utf-8"):
                pass
            if self._is_reparse_point(path):
                with contextlib.suppress(OSError):
                    path.unlink()
                raise OSError(f"Report path became a reparse point: {path}")
            self.close()
            resolved = path.resolve()
            self._report_path = resolved
            file_handler = logging.FileHandler(path, encoding="utf-8")
            file_handler.setFormatter(logging.Formatter("%(message)s"))
            self._logger.addHandler(file_handler)
            self.log_file = file_handler.stream
            self.log(datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S%z"))
            self.log("")
            return resolved

    @property
    def report_path(self) -> Path | None:
        return self._report_path

    def log(self, text: str, indent: int = 0) -> None:
        with self._lock:
            self._logger.info(" " * indent + text)
            for handler in self._logger.handlers:
                if isinstance(handler, logging.FileHandler):
                    with contextlib.suppress(OSError, ValueError):
                        handler.flush()

    def close(self) -> None:
        with self._lock:
            for handler in list(self._logger.handlers):
                if isinstance(handler, logging.FileHandler):
                    with contextlib.suppress(OSError, ValueError):
                        handler.flush()
                    handler.close()
                    self._logger.removeHandler(handler)
            self.log_file = None


logger = ReportLogger()

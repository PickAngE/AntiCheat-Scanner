from __future__ import annotations

import logging
from datetime import datetime
from pathlib import Path
from typing import TextIO

_REPORT_LOGGER = "acs.report"


class ReportLogger:
    def __init__(self) -> None:
        self.log_file: TextIO | None = None
        self._report_path: Path | None = None
        self._logger = logging.getLogger(_REPORT_LOGGER)
        self._logger.setLevel(logging.INFO)
        self._logger.propagate = False
        if not self._logger.handlers:
            console = logging.StreamHandler()
            console.setFormatter(logging.Formatter("%(message)s"))
            self._logger.addHandler(console)

    def start_logging(self, output_path: str | None = None) -> Path:
        if output_path:
            path = Path(output_path)
            if path.is_dir() or not path.suffix:
                timestamp = datetime.now().astimezone().strftime("%Y%m%d_%H%M%S_%f")
                path = path / f"AntiCheat_Report_{timestamp}.txt"
        else:
            timestamp = datetime.now().astimezone().strftime("%Y%m%d_%H%M%S_%f")
            path = Path(f"AntiCheat_Report_{timestamp}.txt")
        path.parent.mkdir(parents=True, exist_ok=True)
        is_junction = getattr(path, "is_junction", lambda: False)
        if path.is_symlink() or is_junction():
            raise OSError(f"Report path is a reparse point: {path}")
        with path.open("x", encoding="utf-8"):
            pass
        self.close()
        self._report_path = path
        file_handler = logging.FileHandler(path, encoding="utf-8")
        file_handler.setFormatter(logging.Formatter("%(message)s"))
        self._logger.addHandler(file_handler)
        self.log_file = file_handler.stream
        self.log(datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S%z"))
        self.log("")
        return path

    @property
    def report_path(self) -> Path | None:
        return self._report_path

    def log(self, text: str, indent: int = 0) -> None:
        self._logger.info(" " * indent + text)

    def close(self) -> None:
        for handler in list(self._logger.handlers):
            if isinstance(handler, logging.FileHandler):
                handler.close()
                self._logger.removeHandler(handler)
        self.log_file = None


logger = ReportLogger()

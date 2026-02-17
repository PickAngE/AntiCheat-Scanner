from datetime import datetime
from typing import Optional, TextIO


class Logger:
    def __init__(self) -> None:
        self.log_file: Optional[TextIO] = None

    def start_logging(self) -> None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"AntiCheat_Report_{timestamp}.txt"
        try:
            self.log_file = open(filename, "w", encoding="utf-8")
            self.log(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
            self.log("")
        except Exception:
            self.log_file = None

    def log(self, text: str, indent: int = 0) -> None:
        if self.log_file is None:
            return
        self.log_file.write(" " * indent + text + "\n")
        self.log_file.flush()

    def close(self) -> None:
        if self.log_file is not None:
            self.log_file.close()
            self.log_file = None


logger = Logger()

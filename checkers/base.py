from abc import ABC, abstractmethod
from typing import ClassVar, List, Set

from config.signatures import AntiCheatInfo
from config.sig_index import SignatureIndex
from config.whitelist import is_whitelisted
from checkers.detection import Detection


class BaseChecker(ABC):
    CATEGORY: ClassVar[str] = ""

    def __init__(
        self,
        ac_database: List[AntiCheatInfo],
        sig_index: SignatureIndex | None = None,
    ) -> None:
        self.ac_database = ac_database
        self.sig_index = sig_index
        self.found: List[Detection] = []
        self._found_keys: Set[str] = set()
        self.fail_count: int = 0
        self.skipped_count: int = 0

    def append_detection(self, det: Detection) -> bool:
        
        if is_whitelisted(det.text, det.category):
            return False
        
        key = f"{det.category}::{det.text}"
        if key in self._found_keys:
            return False
        self._found_keys.add(key)
        self.found.append(det)
        return True

    @abstractmethod
    def check(self) -> None:
        ...

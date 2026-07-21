from abc import ABC, abstractmethod
from typing import ClassVar, List

from config.signatures import AntiCheatInfo
from config.sig_index import SignatureIndex
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

    @abstractmethod
    def check(self) -> None:
        ...

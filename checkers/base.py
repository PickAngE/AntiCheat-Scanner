from abc import ABC, abstractmethod
from typing import Any, List

from config.signatures import AntiCheatInfo
from config.sig_index import SignatureIndex


class BaseChecker(ABC):

    def __init__(
        self,
        ac_database: List[AntiCheatInfo],
        sig_index: SignatureIndex | None = None,
    ) -> None:
        self.ac_database = ac_database
        self.sig_index = sig_index
        self.found: List[Any] = []

    @abstractmethod
    def check(self) -> None:
        ...

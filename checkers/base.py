from __future__ import annotations

import os
from abc import ABC, abstractmethod
from collections.abc import Mapping
from typing import ClassVar

from checkers.detection import (
    CATEGORY_FOLDER,
    CATEGORY_PROC,
    CATEGORY_SVC,
    Detection,
)
from config.sig_index import SignatureIndex
from config.signatures import AntiCheatInfo
from config.whitelist import is_whitelisted


class BaseChecker(ABC):

    CATEGORY: ClassVar[str] = ""

    def __init__(
        self,
        ac_database: list[AntiCheatInfo],
        sig_index: SignatureIndex | None = None,
    ) -> None:
        if not self.CATEGORY:
            raise ValueError(f"Checker {type(self).__name__} must define a CATEGORY")
        self.ac_database = ac_database
        self.sig_index = sig_index
        self.found: list[Detection] = []
        self._found_keys: set[str] = set()
        self.fail_count = 0
        self.skipped_count = 0
        self.whitelisted_count = 0
        self.extra_stats: dict[str, int] = {}

    def _dedup_key(self, detection: Detection) -> str:
        raw = detection.raw
        if isinstance(raw, Mapping):
            if detection.category == CATEGORY_PROC:
                identity = raw.get("pid") or raw.get("exe") or detection.text
                if isinstance(identity, str):
                    identity = identity.casefold()
                return f"{detection.category}::{identity}"
            if detection.category == CATEGORY_SVC:
                identity = raw.get("name") or detection.text
                if isinstance(identity, str):
                    identity = identity.casefold()
                return f"{detection.category}::{identity}"
        return f"{detection.category}::{self._normalize_text(detection)}"

    @staticmethod
    def _normalize_text(detection: Detection) -> str:


        text = os.path.normcase(detection.text.casefold())
        if detection.category == CATEGORY_FOLDER:
            return text.rstrip("\\")
        return text.strip()

    def append_detection(self, detection: Detection) -> bool:
        ignored = is_whitelisted(detection.text, detection.category)
        if detection.category == CATEGORY_FOLDER:
            ignored = ignored or is_whitelisted(detection.text, "files")
        if ignored:
            self.whitelisted_count += 1
            return False
        key = self._dedup_key(detection)
        if key in self._found_keys:
            return False
        self._found_keys.add(key)
        self.found.append(detection)
        return True

    @abstractmethod
    def check(self) -> None:
        raise NotImplementedError

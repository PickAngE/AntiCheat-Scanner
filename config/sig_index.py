from __future__ import annotations

import logging
import re
from collections.abc import Iterable, Sequence

from config.signatures import AntiCheatInfo

logger = logging.getLogger(__name__)

_EXTENSION_PATTERN = re.compile(r"\.(?:exe|sys|dll)", re.IGNORECASE)
_EXECUTABLE_EXTENSIONS = (".exe", ".sys", ".dll")


class SignatureIndex:
    __slots__ = ("_index",)

    def __init__(self) -> None:
        self._index: dict[str, dict[str, set[str]]] = {}

    @classmethod
    def build(cls, ac_database: Sequence[AntiCheatInfo]) -> SignatureIndex:
        instance = cls()
        for ac in ac_database:
            for kind, signatures in (
                ("services", ac.services),
                ("processes", ac.processes),
                ("drivers", ac.drivers),
            ):
                for signature in signatures:
                    key = cls._normalize(signature)
                    if not key:
                        continue
                    products = instance._index.setdefault(key, {}).setdefault(kind, set())
                    if products and ac.name not in products:
                        logger.warning(
                            "Signature collision for %r between %s and %s",
                            key,
                            ", ".join(sorted(products)),
                            ac.name,
                        )
                    products.add(ac.name)
        return instance

    def lookup(self, text: str, kinds: Iterable[str] | None = None) -> str | None:
        if not text:
            return None
        full_key = self._normalize(text)
        keys: list[str] = []
        if full_key:
            keys.append(full_key)


            if "\\" in full_key:
                basename_key = full_key.rsplit("\\", 1)[-1]
                if basename_key and basename_key not in keys:
                    keys.append(basename_key)

        raw_basename = text.replace("/", "\\").rsplit("\\", 1)[-1]
        base_key = self._normalize(raw_basename)
        if base_key and base_key not in keys:
            keys.append(base_key)
        allowed = set(kinds) if kinds is not None else None
        for key in keys:
            products_by_kind = self._index.get(key)
            if not products_by_kind:
                continue
            products = {
                product
                for kind, values in products_by_kind.items()
                if allowed is None or kind in allowed
                for product in values
            }
            if products:

                return sorted(products)[0]
        return None

    @staticmethod
    def _normalize(signature: str) -> str:
        text = signature.strip()
        if not text:
            return ""

        if text.startswith('"'):
            end = text.find('"', 1)
            text = text[1:end] if end != -1 else text[1:].strip()
        text = text.strip().strip("\"'").strip()
        if not text:
            return ""

        if text.startswith("\\??\\"):
            text = text[4:]



        match = _EXTENSION_PATTERN.search(text)
        text = text[: match.end()] if match else (text.split()[0] if text else "")
        normalized = text.strip().strip("\"'").lower().replace("/", "\\")

        changed = True
        while changed:
            changed = False
            for extension in _EXECUTABLE_EXTENSIONS:
                if normalized.endswith(extension):
                    normalized = normalized[: -len(extension)]
                    changed = True
                    break
        return normalized

    def __len__(self) -> int:

        return len(self._index)

    def __contains__(self, key: str) -> bool:
        return self._normalize(key) in self._index

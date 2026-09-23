from __future__ import annotations

import logging
from collections.abc import Iterable, Sequence

from config.signatures import AntiCheatInfo

logger = logging.getLogger(__name__)


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
        normalized_text = text.replace("/", "\\")
        keys: tuple[str, ...] = (self._normalize(normalized_text),)
        basename = normalized_text.rsplit("\\", 1)[-1]
        if basename != normalized_text:
            keys += (self._normalize(basename),)
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
        normalized = signature.strip().lower().replace("/", "\\")
        for extension in (".exe", ".sys", ".dll"):
            if normalized.endswith(extension):
                return normalized[: -len(extension)]
        return normalized

    def __len__(self) -> int:
        return len(self._index)

    def __contains__(self, key: str) -> bool:
        return self._normalize(key) in self._index

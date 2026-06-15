from typing import Dict, List, Optional
from config.signatures import AntiCheatInfo


class SignatureIndex:
    __slots__ = ("_index",)

    def __init__(self) -> None:
        self._index: Dict[str, str] = {}

    @classmethod
    def build(cls, ac_database: List[AntiCheatInfo]) -> "SignatureIndex":
        instance = cls()
        for ac in ac_database:
            for sig in ac.services + ac.processes + ac.drivers:
                key = cls._normalize(sig)
                if not key:
                    continue
                existing = instance._index.get(key)
                if existing and existing != ac.name:
                    continue
                instance._index[key] = ac.name
        return instance

    def lookup(self, text: str) -> Optional[str]:
        if not text:
            return None

        key_full = self._normalize(text)
        result = self._index.get(key_full)
        if result:
            return result

        basename = text.rsplit("\\", 1)[-1] if "\\" in text else None
        if basename:
            key_base = self._normalize(basename)
            result = self._index.get(key_base)
            if result:
                return result

        return None

    @staticmethod
    def _normalize(sig: str) -> str:
        s = sig.strip().lower()
        for ext in (".exe", ".sys", ".dll"):
            if s.endswith(ext):
                s = s[: -len(ext)]
                break
        return s

    def __len__(self) -> int:
        return len(self._index)

    def __contains__(self, key: str) -> bool:
        return self._normalize(key) in self._index

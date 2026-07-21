import json
import logging
from pathlib import Path
from typing import List, Optional, Tuple

logger = logging.getLogger(__name__)

_DATA_PATH = Path(__file__).with_name("signatures.json")


class AntiCheatInfo:
    __slots__ = ("name", "services", "processes", "drivers", "folders", "registry", "companies", "products")

    def __init__(
        self,
        name: str,
        *,
        services: Optional[List[str]] = None,
        processes: Optional[List[str]] = None,
        drivers: Optional[List[str]] = None,
        folders: Optional[List[str]] = None,
        registry: Optional[List[Tuple[str, str]]] = None,
        companies: Optional[List[str]] = None,
        products: Optional[List[str]] = None,
    ):
        self.name = name
        self.services = services if services is not None else []
        self.processes = processes if processes is not None else []
        self.drivers = drivers if drivers is not None else []
        self.folders = folders if folders is not None else []
        self.registry = registry if registry is not None else []
        self.companies = companies if companies is not None else []
        self.products = products if products is not None else []


def get_ac_database() -> List[AntiCheatInfo]:
    with _DATA_PATH.open(encoding="utf-8") as handle:
        raw = json.load(handle)

    database: List[AntiCheatInfo] = []
    for entry in raw:
        registry = [tuple(pair) for pair in entry.get("registry", [])]
        database.append(
            AntiCheatInfo(
                entry["name"],
                services=entry.get("services", []),
                processes=entry.get("processes", []),
                drivers=entry.get("drivers", []),
                folders=entry.get("folders", []),
                registry=registry,
                companies=entry.get("companies", []),
                products=entry.get("products", []),
            )
        )
    return database

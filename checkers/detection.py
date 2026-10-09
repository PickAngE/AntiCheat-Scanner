from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

CATEGORY_SVC = "services"
CATEGORY_PROC = "processes"
CATEGORY_DRV = "drivers"
CATEGORY_FOLDER = "folders"
CATEGORY_REG = "registry"
CATEGORY_TASK = "tasks"
CATEGORY_TRACE = "traces"


CATEGORY_ACTIVE = "active"

ALL_CATEGORIES = (
    CATEGORY_SVC,
    CATEGORY_PROC,
    CATEGORY_DRV,
    CATEGORY_FOLDER,
    CATEGORY_REG,
    CATEGORY_TASK,
    CATEGORY_TRACE,
)



@dataclass(slots=True)
class Detection:
    category: str
    text: str
    ac_name: str | None = None
    active: bool = False
    raw: Any = field(default=None, repr=False)
    tech: dict[str, Any] | None = None

    def __post_init__(self) -> None:
        if self.category not in ALL_CATEGORIES:
            raise ValueError(f"Unknown detection category: {self.category!r}")
        if not self.text.strip():
            raise ValueError("Detection text must be non-empty")


CheckerResults = dict[str, list[Detection]]

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


CheckerResults = dict[str, list[Detection]]

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

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


@dataclass
class Detection:
    category: str
    text: str
    ac_name: Optional[str] = None
    active: bool = False
    raw: Any = field(default=None, repr=False)
    tech: Optional[Dict[str, Any]] = None


CheckerResults = Dict[str, List[Detection]]

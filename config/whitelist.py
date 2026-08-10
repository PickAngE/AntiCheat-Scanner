import json
import logging
from pathlib import Path, PureWindowsPath
from typing import List, Optional, Set

logger = logging.getLogger(__name__)

_WHITELIST_PATH = Path(__file__).with_name("whitelist.json")

_whitelist_cache: Optional[dict] = None

def _load_whitelist() -> dict:
    
    global _whitelist_cache
    if _whitelist_cache is not None:
        return _whitelist_cache
    try:
        if not _WHITELIST_PATH.exists():
            logger.warning(
                "Whitelist file not found: %s. Scan will continue without whitelist.",
                _WHITELIST_PATH
            )
            _whitelist_cache = {"files": [], "processes": [], "services": [], "folders": []}
            return _whitelist_cache
        
        with _WHITELIST_PATH.open(encoding="utf-8") as f:
            data = json.load(f)
        
        
        expected_keys = {"files", "processes", "services", "folders"}
        if not all(key in data for key in expected_keys):
            logger.warning(
                "Malformed whitelist file: %s. Expected structure: %s",
                _WHITELIST_PATH,
                expected_keys
            )
            _whitelist_cache = {key: [] for key in expected_keys}
        else:
            _whitelist_cache = {
                "files": list(set(data.get("files", []))),
                "processes": [p.lower() for p in set(data.get("processes", []))],
                "services": [s.lower() for s in set(data.get("services", []))],
                "folders": list(set(data.get("folders", [])))
            }
        
        logger.info("Whitelist loaded from %s", _WHITELIST_PATH)
        return _whitelist_cache
    except json.JSONDecodeError as e:
        logger.warning(
            "Error parsing whitelist file %s: %s. Scan will continue without whitelist.",
            _WHITELIST_PATH,
            e
        )
        _whitelist_cache = {"files": [], "processes": [], "services": [], "folders": []}
        return _whitelist_cache
    except Exception as e:
        logger.warning(
            "Unexpected error loading whitelist: %s. Scan will continue without whitelist.",
            e
        )
        _whitelist_cache = {"files": [], "processes": [], "services": [], "folders": []}
        return _whitelist_cache

def is_whitelisted(text: str, category: str) -> bool:

    whitelist = _load_whitelist()
    if category not in whitelist:
        return False
    whitelist_items = whitelist[category]
    if not whitelist_items:
        return False
    
    text_lower = text.lower()
    for item in whitelist_items:
        item_lower = item.lower()
        
        
        if category in ("processes", "services"):
            basename = PureWindowsPath(text_lower).name
            
            if basename == item_lower or text_lower == item_lower:
                return True
        
        
        elif category == "files":
            if text_lower == item_lower:
                return True
            
            if PureWindowsPath(text_lower).name == item_lower:
                return True
        
        
        elif category == "folders":
            if text_lower == item_lower:
                return True
            
            if text_lower.startswith(item_lower + "\\") or text_lower.startswith(item_lower + "/"):
                return True
    return False

def get_whitelist() -> dict:
    
    return _load_whitelist()

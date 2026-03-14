from typing import List
import re
def content_matches(text: str, targets: List[str], min_length: int = 3) -> bool:
    if not text:
        return False
    text_lower = text.lower()
    for target in targets:
        t_clean = target.strip()
        if not t_clean or len(t_clean) < min_length:
            continue
        t_base = t_clean.lower().replace(".exe", "").replace(".sys", "").replace(".dll", "")
        if not t_base or len(t_base) < min_length:
            continue
        if re.search(rf"\b{re.escape(t_base)}\b", text_lower):
            return True
    return False
def folder_name_matches_target(folder_name: str, targets: List[str]) -> bool:
    if not folder_name or not targets:
        return False
    name_lower = folder_name.lower().strip()
    for target in targets:
        t_clean = target.replace("/", "\\").strip().lower()
        if not t_clean:
            continue
        if "\\" in t_clean:
            parts = t_clean.split("\\")
            if parts and parts[-1] == name_lower:
                return True
            if t_clean == name_lower:
                return True
        else:
            if t_clean == name_lower:
                return True
    return False
def target_matches(text: str, targets: List[str], exact_for_short: int = 3) -> bool:
    if not text:
        return False
    text_lower = text.lower()
    for target in targets:
        if "*" in target:
            pattern = re.escape(target).replace(r"\*", ".*")
            if re.search(f"^{pattern}$", text, re.IGNORECASE):
                return True
            continue
        t_clean = target.strip()
        if not t_clean:
            continue
        t_lower = t_clean.lower()
        if len(t_clean) <= exact_for_short:
            if t_lower == text_lower:
                return True
            if re.search(rf"\b{re.escape(t_lower)}\b", text_lower):
                return True
        else:
            if t_lower in text_lower:
                return True
    return False
def path_has_folder_segment(path_str: str, folder_signature: str) -> bool:
    if not path_str or not folder_signature:
        return False
    path_norm = path_str.replace("/", "\\").lower()
    sig_norm = folder_signature.replace("/", "\\").lower().strip()
    if not sig_norm:
        return False
    parts = path_norm.rstrip("\\").split("\\")
    sig_parts = sig_norm.rstrip("\\").split("\\")
    for i in range(len(parts) - len(sig_parts) + 1):
        if parts[i:i + len(sig_parts)] == sig_parts:
            return True
    return False
def metadata_matches(properties: dict, target_companies: List[str], target_products: List[str]) -> bool:
    if not properties:
        return False
    comp = str(properties.get("CompanyName", "")).lower()
    prod = str(properties.get("ProductName", "")).lower()
    desc = str(properties.get("FileDescription", "")).lower()
    if "microsoft" in comp:
        return False
    if comp:
        for target in target_companies:
            if target.lower() in comp:
                return True
    if prod:
        for target in target_products:
            if target.lower() in prod:
                return True
    if desc:
        for target in target_products:
            if target.lower() in desc:
                return True
    return False
def fuzzy_matches(text: str, target: str, threshold: float = 0.8) -> bool:
    if not text or not target:
        return False
    t1 = text.lower().strip()
    t2 = target.lower().strip()
    if t1 == t2:
        return True
    if len(t1) < 4 or len(t2) < 4:
        return t1 == t2
    from difflib import SequenceMatcher
    ratio = SequenceMatcher(None, t1, t2).ratio()
    return ratio >= threshold

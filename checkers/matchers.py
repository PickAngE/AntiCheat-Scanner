from typing import List


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
        t_clean = target.replace("*", "").strip()
        if not t_clean:
            continue
        t_lower = t_clean.lower()
        if len(t_clean) <= exact_for_short:
            if t_lower == text_lower:
                return True
            if f" {t_lower} " in f" {text_lower} ":
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

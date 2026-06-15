import logging
import re
from typing import List

logger = logging.getLogger(__name__)

try:
    from rapidfuzz.fuzz import ratio as _fuzzy_ratio_raw
    def fuzzy_ratio(s1: str, s2: str) -> float:
        return _fuzzy_ratio_raw(s1, s2) / 100.0
except ImportError:
    from difflib import SequenceMatcher
    def fuzzy_ratio(s1: str, s2: str) -> float:
        return SequenceMatcher(None, s1, s2).ratio()

WINDOWS_WHITELIST = frozenset([
    "services.exe", "svchost.exe", "lsass.exe", "wininit.exe",
    "winlogon.exe", "csrss.exe", "explorer.exe", "smss.exe",
    "spoolsv.exe", "searchindexer.exe", "runtimebroker.exe",
    "fontdrvhost.exe", "dwm.exe", "ctfmon.exe", "taskhostw.exe",
    "sihost.exe", "smartscreen.exe", "conhost.exe", "audiodg.exe",
    "cmd.exe", "powershell.exe", "pwsh.exe", "wt.exe",
    "vds.exe", "wmiprvse.exe", "dllhost.exe", "werfault.exe",
    "wermgr.exe", "taskmgr.exe", "regedit.exe", "perfmon.exe",
    "system", "registry", "net.exe", "net1.exe", "reg.exe",
])

_EXT_PAT = re.compile(r"(\.exe|\.sys)", re.IGNORECASE)

def extract_exe_path(binpath: str) -> str:
    if not binpath:
        return ""
    text = binpath.strip()

    if text.startswith("\\??\\"):
        text = text[4:]

    if text.startswith('"'):
        end = text.find('"', 1)
        if end != -1:
            return text[1:end]
        return text[1:].strip()

    m = _EXT_PAT.search(text)
    if m:
        return text[: m.end()]

    return text.split()[0] if text else ""

def content_matches(text: str, targets: List[str], min_length: int = 4) -> bool:
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

_WORD_BOUNDARY = re.compile(r"[^a-z0-9]+")

def target_matches(text: str, targets: List[str]) -> bool:
    if not text:
        return False
    text_lower = text.lower()

    basename = text_lower.split("\\")[-1]
    if basename in WINDOWS_WHITELIST:
        return False

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
        t_base = t_lower.replace(".exe", "").replace(".sys", "").replace(".dll", "").strip()
        if not t_base or len(t_base) < 3:
            continue

        name_stripped = basename.replace(".exe", "").replace(".sys", "").replace(".dll", "")

        if t_lower == basename or name_stripped == t_base:
            return True

        name_for_regex = _WORD_BOUNDARY.sub(" ", name_stripped)
        if re.search(rf"\b{re.escape(t_base)}\b", name_for_regex):
            return True
    return False

def _normalize_registry_path(path_str: str) -> str:
    text = path_str.strip().replace("/", "\\")
    if ":" in text and not text.upper().startswith(("HKEY_", "HKLM", "HKCU")):
        text = text.split(":", 1)[1].strip()
    return text.lower().rstrip("\\")


def registry_path_matches(entry: str, hive: str, subkey: str) -> bool:
    if not entry or not hive or not subkey:
        return False
    entry_norm = _normalize_registry_path(entry)
    expected = _normalize_registry_path(f"{hive}\\{subkey}")
    if entry_norm == expected or entry_norm.endswith("\\" + expected):
        return True
    return path_has_folder_segment(entry_norm, expected)


def path_has_folder_segment(path_str: str, folder_signature: str) -> bool:
    if not path_str or not folder_signature:
        return False
    path_norm = path_str.replace("/", "\\").lower()
    sig_norm = folder_signature.replace("/", "\\").lower().strip()
    if not sig_norm:
        return False
    parts = path_norm.rstrip("\\").split("\\")
    sig_parts = sig_norm.rstrip("\\").split("\\")
    len_sig = len(sig_parts)
    for i in range(len(parts) - len_sig + 1):
        match = True
        for j in range(len_sig):
            if parts[i + j] != sig_parts[j]:
                match = False
                break
        if match:
            return True
    return False

def metadata_matches(properties: dict, target_companies: List[str], target_products: List[str]) -> bool:
    if not properties:
        return False
    comp = str(properties.get("CompanyName", "")).lower()
    prod = str(properties.get("ProductName", "")).lower()
    if "microsoft" in comp:
        return False
    if comp:
        for target in target_companies:
            t = target.lower()
            if len(t) >= 4 and t in comp:
                return True
    if prod:
        for target in target_products:
            t = target.lower()
            if len(t) >= 4 and t in prod:
                return True
    return False

def fuzzy_matches(text: str, target: str, threshold: float = 0.8) -> bool:
    if not text or not target:
        return False
    t1 = text.lower().strip()
    t2 = target.lower().strip()
    
    basename = t1.split("\\")[-1]
    if basename in WINDOWS_WHITELIST:
        return False

    if t1 == t2:
        return True
    if len(t1) < 4 or len(t2) < 4:
        return t1 == t2
    return fuzzy_ratio(t1, t2) >= threshold

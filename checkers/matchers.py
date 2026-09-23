from __future__ import annotations

import re
from collections.abc import Sequence

WINDOWS_WHITELIST = frozenset(
    {
        "services.exe",
        "svchost.exe",
        "lsass.exe",
        "wininit.exe",
        "winlogon.exe",
        "csrss.exe",
        "explorer.exe",
        "smss.exe",
        "spoolsv.exe",
        "searchindexer.exe",
        "runtimebroker.exe",
        "fontdrvhost.exe",
        "dwm.exe",
        "ctfmon.exe",
        "taskhostw.exe",
        "sihost.exe",
        "smartscreen.exe",
        "conhost.exe",
        "audiodg.exe",
        "cmd.exe",
        "powershell.exe",
        "pwsh.exe",
        "wt.exe",
        "vds.exe",
        "wmiprvse.exe",
        "dllhost.exe",
        "werfault.exe",
        "wermgr.exe",
        "taskmgr.exe",
        "regedit.exe",
        "perfmon.exe",
        "system",
        "registry",
        "net.exe",
        "net1.exe",
        "reg.exe",
    }
)

_EXTENSIONS = (".exe", ".sys", ".dll")
_MINIMUM_SIGNATURE_LENGTH = 3
_WORD_BOUNDARY = re.compile(r"[^a-z0-9]+")
_EXTENSION_PATTERN = re.compile(r"(\.exe|\.sys|\.dll)", re.IGNORECASE)


def _strip_extensions(value: str) -> str:
    normalized = value.lower()
    for extension in _EXTENSIONS:
        if normalized.endswith(extension):
            return normalized[: -len(extension)]
    return normalized


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
    match = _EXTENSION_PATTERN.search(text)
    if match:
        return text[: match.end()]
    return text.split()[0] if text else ""


def content_matches(
    text: str, targets: Sequence[str], min_length: int = _MINIMUM_SIGNATURE_LENGTH
) -> bool:
    if not text:
        return False
    text_lower = text.lower()
    for target in targets:
        normalized = _strip_extensions(target.strip())
        if len(normalized) < min_length:
            continue
        if re.search(rf"\b{re.escape(normalized)}\b", text_lower):
            return True
    return False


def folder_name_matches_target(folder_name: str, targets: Sequence[str]) -> bool:
    if not folder_name or not targets:
        return False
    name_lower = folder_name.lower().strip()
    for target in targets:
        normalized = target.replace("/", "\\").strip().lower()
        if not normalized:
            continue
        if "\\" in normalized:
            if path_has_folder_segment(folder_name, normalized):
                return True
        elif normalized == name_lower:
            return True
    return False


def target_matches(text: str, targets: Sequence[str]) -> bool:
    if not text:
        return False
    text_lower = text.lower()
    basename = text_lower.replace("/", "\\").rsplit("\\", 1)[-1]
    if basename in WINDOWS_WHITELIST:
        return False
    for target in targets:
        if not target:
            continue
        if "*" in target:
            pattern = re.escape(target).replace(r"\*", ".*")
            if re.search(f"^{pattern}$", text, re.IGNORECASE):
                return True
            continue
        normalized = target.strip().lower()
        target_base = _strip_extensions(normalized)
        if len(target_base) < _MINIMUM_SIGNATURE_LENGTH:
            continue
        name_base = _strip_extensions(basename)
        if normalized == basename or name_base == target_base:
            return True
        normalized_name = _WORD_BOUNDARY.sub(" ", name_base)
        if re.search(rf"\b{re.escape(target_base)}\b", normalized_name):
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
    entry_normalized = _normalize_registry_path(entry)
    expected = _normalize_registry_path(f"{hive}\\{subkey}")
    if entry_normalized == expected or entry_normalized.endswith("\\" + expected):
        return True
    return path_has_folder_segment(entry_normalized, expected)


def path_has_folder_segment(path_str: str, folder_signature: str) -> bool:
    if not path_str or not folder_signature:
        return False
    path_normalized = path_str.replace("/", "\\").lower().rstrip("\\")
    signature_normalized = folder_signature.replace("/", "\\").lower().strip().rstrip("\\")
    if not signature_normalized:
        return False
    path_parts = path_normalized.split("\\")
    signature_parts = signature_normalized.split("\\")
    signature_length = len(signature_parts)
    for start in range(len(path_parts) - signature_length + 1):
        if path_parts[start : start + signature_length] == signature_parts:
            return True
    return False


def _phrase_matches(text: str, target: str) -> bool:
    normalized = target.strip().lower()
    if len(normalized) < 4:
        return False
    return bool(re.search(rf"(?<![a-z0-9]){re.escape(normalized)}(?![a-z0-9])", text))


def metadata_matches(
    properties: dict[str, object], target_companies: Sequence[str], target_products: Sequence[str]
) -> bool:
    if not properties:
        return False
    company = str(properties.get("CompanyName", "")).lower()
    product = str(properties.get("ProductName", "")).lower()
    if "microsoft" in company:
        return False
    if company and any(_phrase_matches(company, target) for target in target_companies):
        return True
    return bool(product and any(_phrase_matches(product, target) for target in target_products))

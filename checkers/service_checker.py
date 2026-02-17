from typing import List

import psutil

from .matchers import target_matches


class ServiceChecker:
    def __init__(self, target_services: List[str]) -> None:
        self.target_services = target_services
        self.found: List[dict] = []

    def check(self) -> None:
        try:
            for service in psutil.win_service_iter():
                try:
                    svc_name = service.name()
                    svc_display = service.display_name()
                    found_match = target_matches(svc_name, self.target_services) or target_matches(
                        svc_display, self.target_services
                    )
                    if not found_match:
                        try:
                            binpath = service.binpath() or ""
                            if binpath:
                                binpath_lower = binpath.lower()
                                for s in self.target_services:
                                    s_lower = s.lower()
                                    if len(s_lower) > 4 and s_lower in binpath_lower:
                                        found_match = True
                                        break
                        except Exception:
                            pass
                    if found_match:
                        self.found.append(service.as_dict())
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except Exception:
            pass

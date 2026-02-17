from typing import List, Tuple


class AntiCheatInfo:
    __slots__ = ("name", "services", "processes", "drivers", "folders", "registry")

    def __init__(
        self,
        name: str,
        *,
        services: List[str] = None,
        processes: List[str] = None,
        drivers: List[str] = None,
        folders: List[str] = None,
        registry: List[Tuple[str, str]] = None,
    ):
        self.name = name
        self.services = services or []
        self.processes = processes or []
        self.drivers = drivers or []
        self.folders = folders or []
        self.registry = registry or []


def get_ac_database() -> List[AntiCheatInfo]:
    return [
        AntiCheatInfo(
            "ACE (AnticheatExpert)",
            services=["ACE", "ACEDRV", "ACEService", "AntiCheatExpert"],
            processes=["ACE.exe", "ACEDRV.exe", "ACEService.exe", "AntiCheatExpert.exe"],
            drivers=["ACE-Base.sys", "ACEDRV.sys", "ACE.sys"],
            folders=["ACE", "AntiCheatExpert", "Tencent\\ACE"],
            registry=[
                ("HKEY_LOCAL_MACHINE", r"SOFTWARE\ACE"),
                ("HKEY_LOCAL_MACHINE", r"SYSTEM\CurrentControlSet\Services\ACE"),
                ("HKEY_LOCAL_MACHINE", r"SYSTEM\CurrentControlSet\Services\ACEDRV"),
            ],
        ),
        AntiCheatInfo(
            "VGK (Vanguard Valorant/LoL)",
            services=["vgc", "vgk", "Riot Vanguard"],
            processes=["vgtray.exe", "vgc.exe", "vgk.sys", "RiotClientServices.exe", "RiotClientUx.exe", "VALORANT.exe", "League of Legends.exe"],
            drivers=["vgk.sys", "vgc.sys", "vanguard.sys"],
            folders=["Riot Vanguard", "Riot Games\\VALORANT", "Riot Games\\League of Legends", "Riot Games", "ProgramData\\Riot Games", "LocalAppData\\Riot Games"],
            registry=[
                ("HKEY_LOCAL_MACHINE", r"SYSTEM\CurrentControlSet\Services\vgc"),
                ("HKEY_LOCAL_MACHINE", r"SYSTEM\CurrentControlSet\Services\vgk"),
                ("HKEY_LOCAL_MACHINE", r"SOFTWARE\Riot Games"),
                ("HKEY_LOCAL_MACHINE", r"SOFTWARE\Riot Games\\Riot Client"),
                ("HKEY_LOCAL_MACHINE", r"SOFTWARE\Riot Games\VALORANT"),
                ("HKEY_LOCAL_MACHINE", r"SOFTWARE\WOW6432Node\Riot Games"),
            ],
        ),
        AntiCheatInfo(
            "Vanguard (Call of Duty Ricochet)",
            services=["codricochet", "Ricochet", "CallOfDutyRicochet"],
            processes=["cod.exe", "ModernWarfare.exe", "cod Ricochet", "RicochetAntiCheat.exe", "randgrid"],
            drivers=["randgrid.sys", "randgrid_sys.sys", "ricochet.sys", "codac.sys"],
            folders=["Call of Duty", "Call of Duty HQ", "Program Files\\Call of Duty", "Program Files (x86)\\Call of Duty", "Activision\\Call of Duty", "Ricochet"],
            registry=[
                ("HKEY_LOCAL_MACHINE", r"SYSTEM\CurrentControlSet\Services\randgrid"),
                ("HKEY_LOCAL_MACHINE", r"SOFTWARE\Activision"),
                ("HKEY_LOCAL_MACHINE", r"SOFTWARE\WOW6432Node\Activision"),
                ("HKEY_LOCAL_MACHINE", r"SOFTWARE\Call of Duty"),
            ],
        ),
        AntiCheatInfo(
            "EA Javelin (Battlefield etc)",
            services=["EAAntiCheat", "EAAntiCheatService", "Javelin", "JavService", "EAC"],
            processes=["EAAntiCheat.GameService.exe", "EAAntiCheat.Installer.exe", "EAAntiCheat.exe", "Javelin.exe", "JavCS.exe", "bf2042.exe", "BFV.exe"],
            drivers=["EAAntiCheat.sys", "Javelin.sys", "Jav.sys", "EAC.sys"],
            folders=["EAAntiCheat", "EA Anti-Cheat", "Electronic Arts\\EAAntiCheat", "Javelin", "JavelinAntiCheat", "Origin Games", "EA Games", "Battlefield"],
            registry=[
                ("HKEY_LOCAL_MACHINE", r"SYSTEM\CurrentControlSet\Services\EAAntiCheat"),
                ("HKEY_LOCAL_MACHINE", r"SYSTEM\CurrentControlSet\Services\Javelin"),
                ("HKEY_LOCAL_MACHINE", r"SOFTWARE\Electronic Arts"),
                ("HKEY_LOCAL_MACHINE", r"SOFTWARE\WOW6432Node\Electronic Arts"),
            ],
        ),
        AntiCheatInfo(
            "EAC (EasyAntiCheat)",
            services=["EasyAntiCheat", "EasyAntiCheat_EOS", "EasyAntiCheat_SOS", "EasyAntiCheatSetup"],
            processes=["EasyAntiCheat.exe", "EasyAntiCheat_EOS.exe", "EasyAntiCheat_SOS.exe", "EasyAntiCheat_Setup.exe"],
            drivers=["EasyAntiCheat.sys", "EasyAntiCheat_EOS.sys", "EasyAntiCheat_SOS.sys"],
            folders=["EasyAntiCheat", "EasyAntiCheat_EOS", "EasyAntiCheat_SOS", "Epic Games\\EasyAntiCheat", "Steam\\EasyAntiCheat"],
            registry=[
                ("HKEY_LOCAL_MACHINE", r"SYSTEM\CurrentControlSet\Services\EasyAntiCheat"),
                ("HKEY_LOCAL_MACHINE", r"SYSTEM\CurrentControlSet\Services\EasyAntiCheat_EOS"),
                ("HKEY_LOCAL_MACHINE", r"SYSTEM\CurrentControlSet\Services\EasyAntiCheat_SOS"),
                ("HKEY_LOCAL_MACHINE", r"SOFTWARE\EasyAntiCheat"),
                ("HKEY_LOCAL_MACHINE", r"SOFTWARE\WOW6432Node\EasyAntiCheat"),
            ],
        ),
        AntiCheatInfo(
            "BE (BattlEye)",
            services=["BEService", "BattlEye", "BEServer", "BEClient"],
            processes=["BEService.exe", "BattlEye.exe", "BEClient.exe", "BEServer_x64.exe", "BEServer_x86.exe"],
            drivers=["BEDaisy.sys", "BattlEye.sys", "BE.sys"],
            folders=["BattlEye", "BEService", "Program Files (x86)\\Common Files\\BattlEye"],
            registry=[
                ("HKEY_LOCAL_MACHINE", r"SYSTEM\CurrentControlSet\Services\BEService"),
                ("HKEY_LOCAL_MACHINE", r"SYSTEM\CurrentControlSet\Services\BattlEye"),
                ("HKEY_LOCAL_MACHINE", r"SOFTWARE\BattlEye"),
                ("HKEY_LOCAL_MACHINE", r"SOFTWARE\WOW6432Node\BattlEye"),
            ],
        ),
        AntiCheatInfo(
            "Genshin Impact (HoYoProtect / mhyprot)",
            services=["mhyprot2", "mhyprot3", "HoYoProtect", "mhyprot", "GenshinImpact"],
            processes=["GenshinImpact.exe", "Honkai Star Rail.exe", "ZenlessZoneZero.exe", "mhyprot2.sys", "HoYoProtect.exe", "YuanShen.exe"],
            drivers=["mhyprot2.sys", "mhyprot3.sys", "HoYoProtect.sys", "mhyprot.sys"],
            folders=["Genshin Impact", "Honkai Star Rail", "ZenlessZoneZero", "miHoYo", "HoYoverse", "Genshin Impact Game", "YuanShen"],
            registry=[
                ("HKEY_LOCAL_MACHINE", r"SOFTWARE\miHoYo"),
                ("HKEY_LOCAL_MACHINE", r"SOFTWARE\HoYoverse"),
                ("HKEY_LOCAL_MACHINE", r"SYSTEM\CurrentControlSet\Services\mhyprot2"),
                ("HKEY_LOCAL_MACHINE", r"SYSTEM\CurrentControlSet\Services\mhyprot3"),
                ("HKEY_LOCAL_MACHINE", r"SOFTWARE\WOW6432Node\miHoYo"),
                ("HKEY_LOCAL_MACHINE", r"SOFTWARE\WOW6432Node\HoYoverse"),
            ],
        ),
    ]

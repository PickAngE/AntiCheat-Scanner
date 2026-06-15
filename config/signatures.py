from typing import List, Optional, Tuple
class AntiCheatInfo:
    __slots__ = ("name", "services", "processes", "drivers", "folders", "registry", "companies", "products")
    def __init__(
        self,
        name: str,
        *,
        services: Optional[List[str]] = None,
        processes: Optional[List[str]] = None,
        drivers: Optional[List[str]] = None,
        folders: Optional[List[str]] = None,
        registry: Optional[List[Tuple[str, str]]] = None,
        companies: Optional[List[str]] = None,
        products: Optional[List[str]] = None,
    ):
        self.name = name
        self.services = services if services is not None else []
        self.processes = processes if processes is not None else []
        self.drivers = drivers if drivers is not None else []
        self.folders = folders if folders is not None else []
        self.registry = registry if registry is not None else []
        self.companies = companies if companies is not None else []
        self.products = products if products is not None else []
def get_ac_database() -> List[AntiCheatInfo]:
    return [
        AntiCheatInfo(
            "ACE (AnticheatExpert)",
<<<<<<< HEAD
            services=["ACE", "ACEDRV", "ACEService", "AntiCheatExpert", "ACE-BASE", "SGuard", "sgameguard", "TPHelper", "ACEClient", "UniRTCX", "SGuardSvc", "TesSafe", "TenSafe", "TP2Helper", "ACELoader", "ACE-Service32", "ACE-Service64"],
            processes=["ACE.exe", "ACEDRV.exe", "ACEService.exe", "AntiCheatExpert.exe", "ACE-BASE.exe", "SGuard64.exe", "SGuard32.exe", "ACELoader.exe", "TPHelper.exe", "TenSafe.exe", "TenSafe_1.exe", "TP2Helper.exe", "UniRTCX.exe", "ACE-Service64.exe", "ACE-Service32.exe", "SGuardSvc.exe", "ACE-Guard.exe", "TesSafe.exe"],
            drivers=["ACE-Base.sys", "ACEDRV.sys", "ACE.sys", "ACE-Guard.sys", "SGuard64.sys", "AntiCheatExpert.sys", "TesSafe.sys", "TenSafe.sys", "UniRTCX.sys", "ACELoader.sys", "TP2Helper.sys", "SGuard32.sys"],
=======
<<<<<<< HEAD
            services=["ACE", "ACEDRV", "ACEService", "AntiCheatExpert", "ACE-BASE", "SGuard", "sgameguard", "TPHelper", "ACEClient", "UniRTCX", "SGuardSvc", "TesSafe", "TenSafe", "TP2Helper", "ACELoader", "ACE-Service32", "ACE-Service64"],
            processes=["ACE.exe", "ACEDRV.exe", "ACEService.exe", "AntiCheatExpert.exe", "ACE-BASE.exe", "SGuard64.exe", "SGuard32.exe", "ACELoader.exe", "TPHelper.exe", "TenSafe.exe", "TenSafe_1.exe", "TP2Helper.exe", "UniRTCX.exe", "ACE-Service64.exe", "ACE-Service32.exe", "SGuardSvc.exe", "ACE-Guard.exe", "TesSafe.exe"],
            drivers=["ACE-Base.sys", "ACEDRV.sys", "ACE.sys", "ACE-Guard.sys", "SGuard64.sys", "AntiCheatExpert.sys", "TesSafe.sys", "TenSafe.sys", "UniRTCX.sys", "ACELoader.sys", "TP2Helper.sys", "SGuard32.sys"],
=======
            services=["ACE", "ACEDRV", "ACEService", "AntiCheatExpert", "ACE-BASE", "SGuard", "sgameguard", "TPHelper", "ACEClient", "UniRTCX", "SGuardSvc"],
            processes=["ACE.exe", "ACEDRV.exe", "ACEService.exe", "AntiCheatExpert.exe", "ACE-BASE.exe", "SGuard64.exe", "SGuard32.exe", "ACELoader.exe", "TPHelper.exe", "TenSafe.exe", "TenSafe_1.exe", "TP2Helper.exe", "UniRTCX.exe", "ACE-Service64.exe", "ACE-Service32.exe", "SGuardSvc.exe"],
            drivers=["ACE-Base.sys", "ACEDRV.sys", "ACE.sys", "ACE-Guard.sys", "SGuard64.sys", "AntiCheatExpert.sys", "TesSafe.sys", "TenSafe.sys", "UniRTCX.sys"],
>>>>>>> e285a17f27e49403e5e4eb37a3f873a4bc5e00ae
>>>>>>> 979330d (update 2026-06-15 16:33:37)
            folders=[
                "ACE", "AntiCheatExpert", "Tencent\\ACE", "Tencent\\AntiCheatExpert",
                "Tencent\\TPHelper", "Tencent\\TenSafe", "UniRTCX",
                "AppData\\Local\\ACE", "AppData\\Local\\AntiCheatExpert",
<<<<<<< HEAD
=======
<<<<<<< HEAD
>>>>>>> 979330d (update 2026-06-15 16:33:37)
                "AppData\\Roaming\\Tencent\\ACE", "AppData\\Roaming\\AntiCheatExpert",
                "AppData\\LocalLow\\Tencent",
                "ProgramData\\ACE", "ProgramData\\AntiCheatExpert",
                "ProgramData\\Tencent\\ACE", "ProgramData\\Tencent\\AntiCheatExpert",
                "Temp\\ACE", "Windows\\Temp\\ACE",
                "Common Files\\Tencent",
                "Program Files\\AntiCheatExpert", "Program Files (x86)\\AntiCheatExpert",
<<<<<<< HEAD
=======
=======
                "ProgramData\\ACE", "ProgramData\\AntiCheatExpert",
>>>>>>> e285a17f27e49403e5e4eb37a3f873a4bc5e00ae
>>>>>>> 979330d (update 2026-06-15 16:33:37)
            ],
            registry=[
                ("HKEY_LOCAL_MACHINE", r"SOFTWARE\ACE"),
                ("HKEY_LOCAL_MACHINE", r"SYSTEM\CurrentControlSet\Services\ACE"),
                ("HKEY_LOCAL_MACHINE", r"SYSTEM\CurrentControlSet\Services\ACEDRV"),
                ("HKEY_LOCAL_MACHINE", r"SYSTEM\CurrentControlSet\Services\ACE-BASE"),
                ("HKEY_LOCAL_MACHINE", r"SYSTEM\CurrentControlSet\Services\SGuard"),
                ("HKEY_LOCAL_MACHINE", r"SYSTEM\CurrentControlSet\Services\AntiCheatExpert"),
                ("HKEY_LOCAL_MACHINE", r"SYSTEM\CurrentControlSet\Services\UniRTCX"),
                ("HKEY_LOCAL_MACHINE", r"SOFTWARE\Tencent\ACE"),
                ("HKEY_LOCAL_MACHINE", r"SOFTWARE\AntiCheatExpert"),
<<<<<<< HEAD
=======
<<<<<<< HEAD
>>>>>>> 979330d (update 2026-06-15 16:33:37)
                ("HKEY_LOCAL_MACHINE", r"SOFTWARE\WOW6432Node\Tencent"),
                ("HKEY_LOCAL_MACHINE", r"SOFTWARE\WOW6432Node\Tencent\ACE"),
                ("HKEY_LOCAL_MACHINE", r"SOFTWARE\Tencent\ACE\Core"),
                ("HKEY_CURRENT_USER", r"Software\Tencent\ACE"),
                ("HKEY_CURRENT_USER", r"Software\AntiCheatExpert"),
<<<<<<< HEAD
=======
=======
>>>>>>> e285a17f27e49403e5e4eb37a3f873a4bc5e00ae
>>>>>>> 979330d (update 2026-06-15 16:33:37)
            ],
            companies=["Tencent", "AntiCheatExpert", "Tencent Technology", "Tencent Technology (Shenzhen) Company Limited"],
            products=["ACE", "AntiCheatExpert", "Anti Cheat Expert", "Tencent Anti-Cheat", "SGuard", "UniRTCX"],
        ),
<<<<<<< HEAD

=======
<<<<<<< HEAD

=======
        AntiCheatInfo(
            "VGK (Vanguard Valorant/LoL)",
            services=["vgc", "vgk", "Riot Vanguard"],
            processes=[
                "vgtray.exe", "vgc.exe", "vgk.sys",
                "RiotClientServices.exe", "RiotClientUx.exe", "RiotClientCrashHandler.exe", "RiotClientUxRender.exe",
                "VALORANT.exe", "VALORANT-Win64-Shipping.exe",
                "League of Legends.exe", "LeagueClient.exe", "LeagueClientUx.exe", "LeagueClientUxRender.exe",
            ],
            drivers=["vgk.sys", "vgc.sys", "vanguard.sys"],
            folders=[
                "Riot Vanguard",
                "Riot Games", "Riot Games\\VALORANT", "Riot Games\\VALORANT\\live",
                "Riot Games\\League of Legends",
                "Riot Games\\Riot Client",
                "ProgramData\\Riot Games", "ProgramData\\Riot Games\\Metadata",
                "AppData\\Local\\Riot Games", "AppData\\Local\\Riot Games\\Riot Client",
                "AppData\\Local\\VALORANT",
            ],
            registry=[
                ("HKEY_LOCAL_MACHINE", r"SYSTEM\CurrentControlSet\Services\vgc"),
                ("HKEY_LOCAL_MACHINE", r"SYSTEM\CurrentControlSet\Services\vgk"),
                ("HKEY_LOCAL_MACHINE", r"SYSTEM\CurrentControlSet\Services\Riot Vanguard"),
                ("HKEY_LOCAL_MACHINE", r"SOFTWARE\Riot Games"),
                ("HKEY_LOCAL_MACHINE", r"SOFTWARE\Riot Games\Riot Client"),
                ("HKEY_LOCAL_MACHINE", r"SOFTWARE\Riot Games\VALORANT"),
                ("HKEY_LOCAL_MACHINE", r"SOFTWARE\Riot Games\League of Legends"),
                ("HKEY_LOCAL_MACHINE", r"SOFTWARE\WOW6432Node\Riot Games"),
                ("HKEY_CURRENT_USER", r"Software\Riot Games"),
                ("HKEY_CURRENT_USER", r"Software\Riot Games\Riot Client"),
            ],
            companies=["Riot Games", "Riot Games, Inc."],
            products=["Vanguard", "Riot Vanguard", "Riot Client", "VALORANT", "League of Legends"],
        ),
        AntiCheatInfo(
            "Vanguard (Call of Duty Ricochet)",
            services=["codricochet", "Ricochet", "CallOfDutyRicochet", "randgrid"],
            processes=[
                "cod.exe", "ModernWarfare.exe", "ModernWarfare2.exe", "ModernWarfareII.exe",
                "BlackOpsColdWar.exe", "BlackOps6.exe",
                "Warzone.exe", "Warzone2.exe",
                "cod Ricochet", "RicochetAntiCheat.exe", "randgrid",
                "CodHQTray.exe", "CoDHQ.exe",
                "Battle.net.exe", "Battle.net Helper.exe",
            ],
            drivers=["randgrid.sys", "randgrid_sys.sys", "ricochet.sys", "codac.sys", "atvi.sys"],
            folders=[
                "Call of Duty", "Call of Duty HQ",
                "Program Files\\Call of Duty", "Program Files (x86)\\Call of Duty",
                "Activision\\Call of Duty", "Activision\\Call of Duty HQ",
                "Ricochet",
                "Battle.net", "Blizzard Entertainment",
                "ProgramData\\Battle.net", "ProgramData\\Activision",
                "ProgramData\\Blizzard Entertainment",
                "AppData\\Local\\Battle.net", "AppData\\Local\\Activision",
                "AppData\\Local\\Blizzard Entertainment",
            ],
            registry=[
                ("HKEY_LOCAL_MACHINE", r"SYSTEM\CurrentControlSet\Services\randgrid"),
                ("HKEY_LOCAL_MACHINE", r"SYSTEM\CurrentControlSet\Services\codricochet"),
                ("HKEY_LOCAL_MACHINE", r"SOFTWARE\Activision"),
                ("HKEY_LOCAL_MACHINE", r"SOFTWARE\Activision Blizzard"),
                ("HKEY_LOCAL_MACHINE", r"SOFTWARE\Blizzard Entertainment"),
                ("HKEY_LOCAL_MACHINE", r"SOFTWARE\Battle.net"),
                ("HKEY_LOCAL_MACHINE", r"SOFTWARE\WOW6432Node\Activision"),
                ("HKEY_LOCAL_MACHINE", r"SOFTWARE\WOW6432Node\Activision Blizzard"),
                ("HKEY_LOCAL_MACHINE", r"SOFTWARE\WOW6432Node\Blizzard Entertainment"),
                ("HKEY_LOCAL_MACHINE", r"SOFTWARE\Call of Duty"),
                ("HKEY_CURRENT_USER", r"Software\Activision"),
                ("HKEY_CURRENT_USER", r"Software\Blizzard Entertainment"),
            ],
            companies=["Activision", "Activision Publishing", "Activision Blizzard", "Blizzard Entertainment", "Activision Publishing, Inc."],
            products=["Call of Duty", "Ricochet Anti-Cheat", "Ricochet", "Battle.net", "Call of Duty HQ"],
        ),
>>>>>>> e285a17f27e49403e5e4eb37a3f873a4bc5e00ae
>>>>>>> 979330d (update 2026-06-15 16:33:37)
        AntiCheatInfo(
            "EA Javelin",
            services=[
                "EAAntiCheat", "EAAntiCheatService", "Javelin", "JavService", "EAC",
                "EAAntiCheat.GameServiceV1", "EAAntiCheat.GlobalServiceV1",
<<<<<<< HEAD
                "EABackgroundService", "EADesktop", "EALocalHostSvc",
                "Origin Client Service", "OriginWebHelperService",
=======
<<<<<<< HEAD
                "EABackgroundService", "EADesktop", "EALocalHostSvc",
                "Origin Client Service", "OriginWebHelperService",
=======
                "EABackgroundService", "EADesktop",
>>>>>>> e285a17f27e49403e5e4eb37a3f873a4bc5e00ae
>>>>>>> 979330d (update 2026-06-15 16:33:37)
            ],
            processes=[
                "EAAntiCheat.GameService.exe", "EAAntiCheat.Installer.exe", "EAAntiCheat.exe",
                "EAAntiCheat.GameServiceV1.exe",
                "Javelin.exe", "JavCS.exe",
                "bf2042.exe", "BFV.exe",
                "EADesktop.exe", "EABackgroundService.exe",
                "EAConnect_microsoft.exe", "EALauncher.exe",
                "Origin.exe", "OriginWebHelperService.exe",
<<<<<<< HEAD
=======
<<<<<<< HEAD
>>>>>>> 979330d (update 2026-06-15 16:33:37)
                "EALocalHostSvc.exe", "EAUpdate.exe",
                "EAUpdater.exe", "EAHelp.exe",
            ],
            drivers=["EAAntiCheat.sys", "EAAntiCheatService.sys", "Javelin.sys", "JavelinAntiCheat.sys", "Jav.sys", "EAC.sys", "EAAntiCheat_EOS.sys"],
            folders=[
                "EAAntiCheat", "EA Anti-Cheat", "Electronic Arts\\EAAntiCheat",
                "Javelin", "JavelinAntiCheat",
                "Electronic Arts\\EA Desktop",
                "Electronic Arts\\Origin",
                "ProgramData\\Electronic Arts",
                "ProgramData\\Electronic Arts\\EA Desktop",
                "ProgramData\\EA\\AC",
                "ProgramData\\eaanticheat\\Crashdumps",
                "ProgramData\\Origin",
                "ProgramData\\EA Desktop",
                "Program Files\\EA\\AC",
                "AppData\\Local\\Electronic Arts", "AppData\\Local\\Origin",
                "AppData\\Local\\EA Desktop", "AppData\\Local\\EADesktop",
                "AppData\\Roaming\\Electronic Arts",
                "AppData\\Roaming\\Origin",
                "AppData\\Roaming\\EA Desktop",
                "Temp\\Electronic Arts", "Windows\\Temp\\EA",
                "Common Files\\Electronic Arts",
<<<<<<< HEAD
=======
=======
                "EALocalHostSvc.exe",
            ],
            drivers=["EAAntiCheat.sys", "Javelin.sys", "Jav.sys", "EAC.sys"],
            folders=[
                "EAAntiCheat", "EA Anti-Cheat", "Electronic Arts\\EAAntiCheat",
                "Javelin", "JavelinAntiCheat",
                "Origin Games", "EA Games", "Battlefield",
                "Electronic Arts", "Electronic Arts\\EA Desktop",
                "Origin", "ProgramData\\Electronic Arts",
                "ProgramData\\Origin", "ProgramData\\EA Desktop",
                "AppData\\Local\\Electronic Arts", "AppData\\Local\\Origin",
                "AppData\\Local\\EA Desktop", "AppData\\Local\\EADesktop",
>>>>>>> e285a17f27e49403e5e4eb37a3f873a4bc5e00ae
>>>>>>> 979330d (update 2026-06-15 16:33:37)
            ],
            registry=[
                ("HKEY_LOCAL_MACHINE", r"SYSTEM\CurrentControlSet\Services\EAAntiCheat"),
                ("HKEY_LOCAL_MACHINE", r"SYSTEM\CurrentControlSet\Services\EAAntiCheat.GameServiceV1"),
                ("HKEY_LOCAL_MACHINE", r"SYSTEM\CurrentControlSet\Services\EAAntiCheat.GlobalServiceV1"),
<<<<<<< HEAD
                ("HKEY_LOCAL_MACHINE", r"SYSTEM\CurrentControlSet\Services\EAAntiCheatService"),
=======
<<<<<<< HEAD
                ("HKEY_LOCAL_MACHINE", r"SYSTEM\CurrentControlSet\Services\EAAntiCheatService"),
=======
>>>>>>> e285a17f27e49403e5e4eb37a3f873a4bc5e00ae
>>>>>>> 979330d (update 2026-06-15 16:33:37)
                ("HKEY_LOCAL_MACHINE", r"SYSTEM\CurrentControlSet\Services\Javelin"),
                ("HKEY_LOCAL_MACHINE", r"SYSTEM\CurrentControlSet\Services\EABackgroundService"),
                ("HKEY_LOCAL_MACHINE", r"SOFTWARE\Electronic Arts"),
                ("HKEY_LOCAL_MACHINE", r"SOFTWARE\Electronic Arts\EA Desktop"),
<<<<<<< HEAD
=======
<<<<<<< HEAD
>>>>>>> 979330d (update 2026-06-15 16:33:37)
                ("HKEY_LOCAL_MACHINE", r"SOFTWARE\Electronic Arts\EAAntiCheat"),
                ("HKEY_LOCAL_MACHINE", r"SOFTWARE\EA Anti-Cheat"),
                ("HKEY_LOCAL_MACHINE", r"SOFTWARE\Origin"),
                ("HKEY_LOCAL_MACHINE", r"SOFTWARE\WOW6432Node\Electronic Arts"),
                ("HKEY_LOCAL_MACHINE", r"SOFTWARE\WOW6432Node\Electronic Arts\EA Desktop"),
                ("HKEY_LOCAL_MACHINE", r"SOFTWARE\WOW6432Node\EA Anti-Cheat"),
                ("HKEY_LOCAL_MACHINE", r"SOFTWARE\WOW6432Node\Origin"),
                ("HKEY_CURRENT_USER", r"Software\Electronic Arts"),
                ("HKEY_CURRENT_USER", r"Software\Electronic Arts\EA Desktop"),
                ("HKEY_CURRENT_USER", r"Software\EA Anti-Cheat"),
                ("HKEY_CURRENT_USER", r"Software\Origin"),
            ],
            companies=["Electronic Arts", "Electronic Arts Inc.", "EA Digital Illusions CE AB", "EA Swiss Sarl"],
            products=["EA Anti-Cheat", "EAAntiCheat", "Javelin", "EA Desktop", "Origin", "EA Anti-Cheat Service", "EA App"],
        ),
        AntiCheatInfo(
            "EAC (EasyAntiCheat)",
            services=[
                "EasyAntiCheat", "EasyAntiCheat_EOS", "EasyAntiCheat_EOS_Service",
                "EasyAntiCheat_SOS", "EasyAntiCheatSetup",
                "EasyAntiCheat_EOSLauncher", "EasyAntiCheat_EOSLauncherService",
            ],
<<<<<<< HEAD
=======
=======
                ("HKEY_LOCAL_MACHINE", r"SOFTWARE\Origin"),
                ("HKEY_LOCAL_MACHINE", r"SOFTWARE\WOW6432Node\Electronic Arts"),
                ("HKEY_LOCAL_MACHINE", r"SOFTWARE\WOW6432Node\Origin"),
                ("HKEY_CURRENT_USER", r"Software\Electronic Arts"),
                ("HKEY_CURRENT_USER", r"Software\Origin"),
            ],
            companies=["Electronic Arts", "Electronic Arts Inc.", "EA Digital Illusions CE AB"],
            products=["EA Anti-Cheat", "EAAntiCheat", "Javelin", "EA Desktop", "Origin", "EA Anti-Cheat Service"],
        ),
        AntiCheatInfo(
            "EAC (EasyAntiCheat)",
            services=["EasyAntiCheat", "EasyAntiCheat_EOS", "EasyAntiCheat_SOS", "EasyAntiCheatSetup"],
>>>>>>> e285a17f27e49403e5e4eb37a3f873a4bc5e00ae
>>>>>>> 979330d (update 2026-06-15 16:33:37)
            processes=[
                "EasyAntiCheat.exe", "EasyAntiCheat_EOS.exe", "EasyAntiCheat_SOS.exe",
                "EasyAntiCheat_Setup.exe", "EasyAntiCheat_Launcher.exe",
                "start_protected_game.exe",
<<<<<<< HEAD
=======
<<<<<<< HEAD
>>>>>>> 979330d (update 2026-06-15 16:33:37)
                "EasyAntiCheat_x64.exe", "EasyAntiCheat_x86.exe",
                "EasyAntiCheat_EOS_Setup.exe", "EasyAntiCheat_Service.exe",
                "EasyAntiCheat_Service_x64.exe", "EasyAntiCheat_Service_x86.exe",
            ],
            drivers=["EasyAntiCheat.sys", "EasyAntiCheat_EOS.sys", "EasyAntiCheat_SOS.sys", "EasyAntiCheat_EOSA.sys"],
            folders=[
                "EasyAntiCheat", "EasyAntiCheat_EOS", "EasyAntiCheat_SOS",
                "EasyAntiCheat\\Certificates", "EasyAntiCheat_EOS\\Certificates",
                "Epic Games\\EasyAntiCheat", "Epic Games\\EasyAntiCheat_EOS",
                "Steam\\EasyAntiCheat",
                "Program Files\\EasyAntiCheat",
                "Program Files (x86)\\EasyAntiCheat",
                "Program Files (x86)\\EasyAntiCheat_EOS",
                "Common Files\\EasyAntiCheat",
                "ProgramData\\EasyAntiCheat",
                "ProgramData\\EasyAntiCheat_EOS",
                "Program Files (x86)\\EasyAntiCheat_EOS\\Logs",
                "AppData\\Local\\EasyAntiCheat",
                "AppData\\Roaming\\EasyAntiCheat",
                "steamapps\\common\\EasyAntiCheat",
                "steamapps\\common\\EasyAntiCheat_EOS",
                "Temp\\EasyAntiCheat", "Windows\\Temp\\EasyAntiCheat",
<<<<<<< HEAD
=======
=======
            ],
            drivers=["EasyAntiCheat.sys", "EasyAntiCheat_EOS.sys", "EasyAntiCheat_SOS.sys"],
            folders=[
                "EasyAntiCheat", "EasyAntiCheat_EOS", "EasyAntiCheat_SOS",
                "EasyAntiCheat\\Certificates",
                "Epic Games\\EasyAntiCheat", "Steam\\EasyAntiCheat",
                "Program Files (x86)\\EasyAntiCheat",
                "Common Files\\EasyAntiCheat",
                "ProgramData\\EasyAntiCheat",
                "AppData\\Local\\EasyAntiCheat",
>>>>>>> e285a17f27e49403e5e4eb37a3f873a4bc5e00ae
>>>>>>> 979330d (update 2026-06-15 16:33:37)
            ],
            registry=[
                ("HKEY_LOCAL_MACHINE", r"SYSTEM\CurrentControlSet\Services\EasyAntiCheat"),
                ("HKEY_LOCAL_MACHINE", r"SYSTEM\CurrentControlSet\Services\EasyAntiCheat_EOS"),
                ("HKEY_LOCAL_MACHINE", r"SYSTEM\CurrentControlSet\Services\EasyAntiCheat_SOS"),
                ("HKEY_LOCAL_MACHINE", r"SOFTWARE\EasyAntiCheat"),
                ("HKEY_LOCAL_MACHINE", r"SOFTWARE\WOW6432Node\EasyAntiCheat"),
<<<<<<< HEAD
=======
<<<<<<< HEAD
>>>>>>> 979330d (update 2026-06-15 16:33:37)
                ("HKEY_LOCAL_MACHINE", r"SOFTWARE\EpicGames\EasyAntiCheat"),
                ("HKEY_LOCAL_MACHINE", r"SOFTWARE\EpicGames\EasyAntiCheat\Logs"),
                ("HKEY_LOCAL_MACHINE", r"SYSTEM\CurrentControlSet\Services\EasyAntiCheat_EOS\Parameters"),
                ("HKEY_CURRENT_USER", r"Software\EasyAntiCheat"),
                ("HKEY_CURRENT_USER", r"Software\Epic Games\EasyAntiCheat"),
            ],
            companies=["EasyAntiCheat", "Epic Games", "Kamu", "EasyAntiCheat Oy", "Epic Games, Inc.", "Epic Games AB"],
            products=["EasyAntiCheat", "Easy Anti-Cheat", "EasyAntiCheat Service", "Easy Anti-Cheat Service", "EasyAntiCheat_EOS"],
        ),
        AntiCheatInfo(
            "BE (BattlEye)",
            services=[
                "BEService", "BattlEye", "BEServer", "BEClient", "BattlEyeService", "BEDaisy",
                "BEService_arma3", "BEService_pubg", "BEService_r5apex",
                "BEService_dayz", "BEService_unturned",
            ],
            processes=[
                "BEService.exe", "BattlEye.exe", "BEClient.exe",
                "BEServer_x64.exe", "BEServer_x86.exe",
                "BEService_x64.exe", "BEService_x86.exe",
                "BattlEye_Update.exe", "BattlEye_Install.exe",
                "BEClient_x64.exe", "BEClient_x86.exe",
                "BattlEyeLauncher.exe", "BattlEyeService.exe",
            ],
            drivers=["BEDaisy.sys", "BattlEye.sys", "BE.sys", "bedaisy.sys", "battleye_x64.sys", "battleye_x86.sys"],
<<<<<<< HEAD
=======
=======
                ("HKEY_CURRENT_USER", r"Software\EasyAntiCheat"),
            ],
            companies=["EasyAntiCheat", "Epic Games", "Kamu", "EasyAntiCheat Oy", "Epic Games, Inc."],
            products=["EasyAntiCheat", "Easy Anti-Cheat", "EasyAntiCheat Service", "Easy Anti-Cheat Service"],
        ),
        AntiCheatInfo(
            "BE (BattlEye)",
            services=["BEService", "BattlEye", "BEServer", "BEClient", "BattlEyeService", "BEDaisy"],
            processes=[
                "BEService.exe", "BattlEye.exe", "BEClient.exe",
                "BEServer_x64.exe", "BEServer_x86.exe",
                "BEService_x64.exe",
                "BattlEye_Update.exe", "BattlEye_Install.exe",
            ],
            drivers=["BEDaisy.sys", "BattlEye.sys", "BE.sys", "bedaisy.sys"],
>>>>>>> e285a17f27e49403e5e4eb37a3f873a4bc5e00ae
>>>>>>> 979330d (update 2026-06-15 16:33:37)
            folders=[
                "BattlEye", "BEService",
                "Program Files (x86)\\Common Files\\BattlEye",
                "Program Files\\Common Files\\BattlEye",
                "Common Files\\BattlEye",
<<<<<<< HEAD
=======
<<<<<<< HEAD
>>>>>>> 979330d (update 2026-06-15 16:33:37)
                "Common Files\\BattlEye\\BEService",
                "Common Files\\BattlEye\\Logs",
                "ProgramData\\BattlEye",
                "ProgramData\\BattlEye\\BEService",
                "AppData\\Local\\BattlEye",
                "AppData\\Roaming\\BattlEye",
                "BattlEye\\BEService",
                "Temp\\BattlEye", "Temp\\BEService",
                "Windows\\Temp\\BattlEye",
<<<<<<< HEAD
=======
=======
                "ProgramData\\BattlEye",
                "AppData\\Local\\BattlEye",
>>>>>>> e285a17f27e49403e5e4eb37a3f873a4bc5e00ae
>>>>>>> 979330d (update 2026-06-15 16:33:37)
            ],
            registry=[
                ("HKEY_LOCAL_MACHINE", r"SYSTEM\CurrentControlSet\Services\BEService"),
                ("HKEY_LOCAL_MACHINE", r"SYSTEM\CurrentControlSet\Services\BattlEye"),
                ("HKEY_LOCAL_MACHINE", r"SYSTEM\CurrentControlSet\Services\BEDaisy"),
                ("HKEY_LOCAL_MACHINE", r"SOFTWARE\BattlEye"),
<<<<<<< HEAD
=======
<<<<<<< HEAD
>>>>>>> 979330d (update 2026-06-15 16:33:37)
                ("HKEY_LOCAL_MACHINE", r"SYSTEM\CurrentControlSet\Services\BEDaisy\Parameters"),
                ("HKEY_LOCAL_MACHINE", r"SOFTWARE\WOW6432Node\BattlEye"),
                ("HKEY_LOCAL_MACHINE", r"SOFTWARE\WOW6432Node\BattlEye\BEService"),
                ("HKEY_CURRENT_USER", r"Software\BattlEye"),
            ],
            companies=["BattlEye Innovations e.K.", "BattlEye Innovations", "BattlEye GmbH", "BattlEye Innovations e.K"],
            products=["BattlEye", "BattlEye Anti-Cheat", "BattlEye Service", "BEService", "BEDaisy"],
        ),
        AntiCheatInfo(
            "HoYoProtect",
            services=["mhyprot2", "mhyprot3", "HoYoProtect", "mhyprot", "GenshinImpact", "mhypbase", "HoYoKProtect", "UniRTC", "HoYoBase", "mhyprot1", "mhyprot2_3"],
<<<<<<< HEAD
=======
=======
                ("HKEY_LOCAL_MACHINE", r"SOFTWARE\WOW6432Node\BattlEye"),
                ("HKEY_CURRENT_USER", r"Software\BattlEye"),
            ],
            companies=["BattlEye Innovations e.K.", "BattlEye Innovations", "BattlEye GmbH"],
            products=["BattlEye", "BattlEye Anti-Cheat", "BattlEye Service", "BEService", "BEDaisy"],
        ),
        AntiCheatInfo(
            "Genshin Impact (HoYoProtect / mhyprot)",
            services=["mhyprot2", "mhyprot3", "HoYoProtect", "mhyprot", "GenshinImpact", "mhypbase", "HoYoKProtect", "UniRTC", "HoYoBase"],
>>>>>>> e285a17f27e49403e5e4eb37a3f873a4bc5e00ae
>>>>>>> 979330d (update 2026-06-15 16:33:37)
            processes=[
                "GenshinImpact.exe", "YuanShen.exe",
                "Honkai Star Rail.exe", "StarRail.exe",
                "ZenlessZoneZero.exe",
                "HoYoProtect.exe", "mhyprot2.sys", "mhyprot3.sys",
                "HYPLauncher.exe", "HoYoPlay.exe", "HoYoBase.exe",
<<<<<<< HEAD
                "HoYoShield.exe", "HoYoKProtect.exe",
            ],
            drivers=["mhyprot2.sys", "mhyprot3.sys", "HoYoProtect.sys", "mhyprot.sys", "mhypbase.sys", "HoYoKProtect.sys", "mhyprot2_3.sys", "mhyprot1.sys", "HoYoShield.sys"],
=======
<<<<<<< HEAD
                "HoYoShield.exe", "HoYoKProtect.exe",
            ],
            drivers=["mhyprot2.sys", "mhyprot3.sys", "HoYoProtect.sys", "mhyprot.sys", "mhypbase.sys", "HoYoKProtect.sys", "mhyprot2_3.sys", "mhyprot1.sys", "HoYoShield.sys"],
=======
            ],
            drivers=["mhyprot2.sys", "mhyprot3.sys", "HoYoProtect.sys", "mhyprot.sys", "mhypbase.sys", "HoYoKProtect.sys", "mhyprot2_3.sys"],
>>>>>>> e285a17f27e49403e5e4eb37a3f873a4bc5e00ae
>>>>>>> 979330d (update 2026-06-15 16:33:37)
            folders=[
                "Genshin Impact", "Genshin Impact Game", "YuanShen",
                "Honkai Star Rail", "Honkai Star Rail Game",
                "ZenlessZoneZero", "ZenlessZoneZero Game",
                "miHoYo", "HoYoverse",
                "miHoYo\\Genshin Impact", "HoYoverse\\Genshin Impact",
                "miHoYo\\Honkai Star Rail", "HoYoverse\\Honkai Star Rail",
                "miHoYo\\ZenlessZoneZero", "HoYoverse\\ZenlessZoneZero",
                "ProgramData\\miHoYo", "ProgramData\\HoYoverse",
<<<<<<< HEAD
=======
<<<<<<< HEAD
>>>>>>> 979330d (update 2026-06-15 16:33:37)
                "ProgramData\\miHoYo\\Genshin Impact", "ProgramData\\HoYoverse\\Genshin Impact",
                "ProgramData\\miHoYo\\Genshin Impact\\CrashReports",
                "ProgramData\\HoYoverse\\CrashReports",
                "AppData\\Local\\Temp\\mhyprot",
                "AppData\\LocalLow\\miHoYo", "AppData\\LocalLow\\HoYoverse",
                "AppData\\LocalLow\\miHoYo\\Genshin Impact",
                "AppData\\LocalLow\\miHoYo\\Honkai Star Rail",
                "AppData\\LocalLow\\miHoYo\\ZenlessZoneZero",
                "AppData\\Local\\miHoYo", "AppData\\Local\\HoYoverse",
                "AppData\\Local\\HoYoPlay",
                "AppData\\Roaming\\miHoYo", "AppData\\Roaming\\HoYoverse",
                "Temp\\miHoYo", "Windows\\Temp\\miHoYo",
                "Common Files\\miHoYo",
<<<<<<< HEAD
=======
=======
                "AppData\\LocalLow\\miHoYo", "AppData\\LocalLow\\HoYoverse",
                "AppData\\Local\\miHoYo", "AppData\\Local\\HoYoverse",
                "AppData\\Local\\HoYoPlay",
>>>>>>> e285a17f27e49403e5e4eb37a3f873a4bc5e00ae
>>>>>>> 979330d (update 2026-06-15 16:33:37)
            ],
            registry=[
                ("HKEY_LOCAL_MACHINE", r"SOFTWARE\miHoYo"),
                ("HKEY_LOCAL_MACHINE", r"SOFTWARE\HoYoverse"),
<<<<<<< HEAD
                ("HKEY_LOCAL_MACHINE", r"SYSTEM\CurrentControlSet\Services\mhyprot"),
=======
<<<<<<< HEAD
                ("HKEY_LOCAL_MACHINE", r"SYSTEM\CurrentControlSet\Services\mhyprot"),
=======
>>>>>>> e285a17f27e49403e5e4eb37a3f873a4bc5e00ae
>>>>>>> 979330d (update 2026-06-15 16:33:37)
                ("HKEY_LOCAL_MACHINE", r"SYSTEM\CurrentControlSet\Services\mhyprot2"),
                ("HKEY_LOCAL_MACHINE", r"SYSTEM\CurrentControlSet\Services\mhyprot3"),
                ("HKEY_LOCAL_MACHINE", r"SYSTEM\CurrentControlSet\Services\HoYoProtect"),
                ("HKEY_LOCAL_MACHINE", r"SYSTEM\CurrentControlSet\Services\mhypbase"),
                ("HKEY_LOCAL_MACHINE", r"SYSTEM\CurrentControlSet\Services\HoYoKProtect"),
<<<<<<< HEAD
=======
<<<<<<< HEAD
>>>>>>> 979330d (update 2026-06-15 16:33:37)
                ("HKEY_LOCAL_MACHINE", r"SYSTEM\CurrentControlSet\Services\HoYoShield"),
                ("HKEY_LOCAL_MACHINE", r"SOFTWARE\WOW6432Node\miHoYo"),
                ("HKEY_LOCAL_MACHINE", r"SOFTWARE\WOW6432Node\miHoYo\Genshin Impact"),
                ("HKEY_LOCAL_MACHINE", r"SOFTWARE\WOW6432Node\HoYoverse"),
                ("HKEY_LOCAL_MACHINE", r"SOFTWARE\miHoYo\Genshin Impact\Settings"),
                ("HKEY_CURRENT_USER", r"Software\miHoYo"),
                ("HKEY_CURRENT_USER", r"Software\HoYoverse"),
                ("HKEY_CURRENT_USER", r"Software\miHoYo\Genshin Impact"),
                ("HKEY_CURRENT_USER", r"Software\HoYoverse\Genshin Impact"),
            ],
            companies=["miHoYo Co.,Ltd.", "COGNOSPHERE PTE. LTD.", "Cognosphere", "miHoYo", "HoYoverse", "Shanghai miHoYo"],
            products=["Genshin Impact", "Honkai Star Rail", "Zenless Zone Zero", "HoYoPlay", "mhyprot", "HoYoProtect", "HoYoBase", "HoYoShield"],
        ),
<<<<<<< HEAD
    ]
=======
    ]
=======
                ("HKEY_LOCAL_MACHINE", r"SOFTWARE\WOW6432Node\miHoYo"),
                ("HKEY_LOCAL_MACHINE", r"SOFTWARE\WOW6432Node\HoYoverse"),
                ("HKEY_CURRENT_USER", r"Software\miHoYo"),
                ("HKEY_CURRENT_USER", r"Software\HoYoverse"),
            ],
            companies=["miHoYo Co.,Ltd.", "COGNOSPHERE PTE. LTD.", "Cognosphere", "miHoYo", "HoYoverse"],
            products=["Genshin Impact", "Honkai Star Rail", "Zenless Zone Zero", "HoYoPlay", "mhyprot", "HoYoProtect", "HoYoBase"],
        ),
    ]
>>>>>>> e285a17f27e49403e5e4eb37a3f873a4bc5e00ae
>>>>>>> 979330d (update 2026-06-15 16:33:37)

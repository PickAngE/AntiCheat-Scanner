# Anti-Cheat Scanner

Scans Windows for seven supported anti-cheats. Writes results to a timestamped `.txt` in the script folder. No console output.

**Supported:** ACE, VGK (Riot Vanguard), Vanguard (CoD Ricochet), EA Javelin, EAC, BattlEye, HoYoProtect (Genshin / Honkai / Zenless).

| AC | Typical use |
|----|--------------|
| ACE | PUBG Mobile, emulators |
| VGK | Valorant, League of Legends |
| Vanguard | Call of Duty |
| EA Javelin | Battlefield, EA titles |
| EAC | Fortnite, Apex, others |
| BattlEye | R6, PUBG, Destiny 2 |
| HoYoProtect | Genshin, Honkai Star Rail, Zenless Zone Zero |

**Requirements:** Python 3, Windows. Admin recommended for services/drivers/registry.

**Install:**
```bash
pip install -r requirements.txt
```

**Run (admin for full scan):**
```bash
python main.py
```
Output file: `AntiCheat_Report_YYYYMMDD_HHMMSS.txt`. Each line is a finding (service, process, driver, folder, or registry key) grouped by AC, then a total.

**License:** Proprietary. Copyright (c) 2026 PickAngE. See [LICENSE](LICENSE). No redistribution, no modification, no commercial use. As-is; use at your own risk.

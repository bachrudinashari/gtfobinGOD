#!/usr/bin/env python3
"""
gtfobinSUID-improved v2.0.0
============================
Improved fork of strikoder's gtfobinSUID for OSCP exam use.

Preserved features:
  - Online/offline GTFOBins checking
  - db.txt update via scraping
  - Non-standard path warnings
  - Binary normalization
  - Hints for known vulnerable binaries

New features:
  - Embedded exploit commands database (instant copy-paste)
  - Sudo mode (parse sudo -l output)
  - Capabilities mode (parse getcap output)
  - Pipe-friendly (auto-detect stdin pipe, skip interactive prompts)
  - Priority-sorted output (shell > revshell > file_read > file_write)
  - Better normalization (regex-based + aliases)
  - --exam flag (minimal noise, only actionable results)
  - JSON output (--json)
  - Single binary check (--check BINARY)

Usage:
  # Pipe SUID output directly:
  find / -perm -u=s -type f 2>/dev/null | python3 gtfobinsuid.py

  # Pipe sudo -l output:
  sudo -l | python3 gtfobinsuid.py --sudo

  # Pipe getcap output:
  getcap -r / 2>/dev/null | python3 gtfobinsuid.py --capabilities

  # Quick single check:
  python3 gtfobinsuid.py --check python3

  # Exam mode (clean output only):
  find / -perm -u=s -type f 2>/dev/null | python3 gtfobinsuid.py --exam
"""

import sys
import re
import os
import argparse
import json

# Determine script directory for relative imports
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SCRIPT_DIR)

from db_commands import COMMANDS, ALIASES
from db_hints import CUSTOM_HINTS, CAPABILITIES_HINTS

DEFAULT_DB = os.path.join(SCRIPT_DIR, "db.txt")

# Priority labels
PRIORITY_LABELS = {
    1: "CRITICAL",
    2: "HIGH",
    3: "MEDIUM",
    4: "LOW",
    5: "INFO",
}

PRIORITY_COLORS = {
    1: "\033[91m",  # Red
    2: "\033[93m",  # Yellow
    3: "\033[96m",  # Cyan
    4: "\033[94m",  # Blue
    5: "\033[90m",  # Gray
}
RESET = "\033[0m"
GREEN = "\033[92m"
BOLD = "\033[1m"



# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def is_pipe():
    """Detect if stdin is a pipe (not interactive terminal)."""
    try:
        return not sys.stdin.isatty()
    except AttributeError:
        return False


def supports_color():
    """Check if terminal supports ANSI colors."""
    if os.name == "nt":
        return os.environ.get("ANSICON") or "WT_SESSION" in os.environ
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()


USE_COLOR = supports_color()


def c(color, text):
    """Apply color if supported."""
    if USE_COLOR:
        return f"{color}{text}{RESET}"
    return text


def normalize_binary(name):
    """
    Normalize binary names to their base GTFOBins entry.
    Handles versioned names, suffixes, and known aliases.
    """
    name_lower = name.lower().strip()

    # Direct alias match first
    if name_lower in ALIASES:
        return ALIASES[name_lower]

    # Check if in COMMANDS directly
    if name_lower in COMMANDS:
        return name_lower

    # Strip version suffixes: python3.11, perl5.30.0, php7.4, lua5.4
    stripped = re.sub(r'[\d]+\.[\d.]+$', '', name_lower)
    if stripped and stripped in COMMANDS:
        return stripped
    if stripped and stripped in ALIASES:
        return ALIASES[stripped]

    # Strip trailing digits: python3, ruby2, php8
    stripped = re.sub(r'\d+$', '', name_lower)
    if stripped and stripped in COMMANDS:
        return stripped
    if stripped and stripped in ALIASES:
        return ALIASES[stripped]

    # Strip common suffixes: vim.basic, vim.tiny, busybox.nosuid
    stripped = name_lower.split('.')[0]
    if stripped and stripped in COMMANDS:
        return stripped
    if stripped and stripped in ALIASES:
        return ALIASES[stripped]

    # Strip -dbg, -static and similar
    stripped = re.sub(r'-(dbg|static|bin|gnu|nox)$', '', name_lower)
    if stripped and stripped in COMMANDS:
        return stripped

    return name_lower


def extract_basenames_suid(text):
    """Extract binary basenames from find -perm -u=s output."""
    paths = re.findall(r'(/(?:[A-Za-z0-9_\-./]+))', text)
    names = []
    seen = set()
    nonstandard_paths = set()

    for p in paths:
        dir_path = os.path.dirname(p)
        if dir_path and not dir_path.startswith(('/bin', '/sbin', '/usr/bin', '/usr/sbin', '/usr/lib', '/usr/libexec')):
            nonstandard_paths.add(p)

        name = os.path.basename(p)
        if not name or name in seen:
            continue
        seen.add(name)
        names.append(name)

    return names, nonstandard_paths


def extract_binaries_sudo(text):
    """
    Parse sudo -l output to extract allowed binaries.
    Handles formats like:
      (root) NOPASSWD: /usr/bin/vim
      (ALL) /usr/bin/find *
      (root) NOPASSWD: /usr/bin/env python3
    """
    binaries = []
    seen = set()

    for line in text.strip().splitlines():
        # Match lines with binary paths after NOPASSWD: or after (user)
        matches = re.findall(r'(?:NOPASSWD:\s*|(?:\([^)]+\)\s+))(/[A-Za-z0-9_\-./]+)', line)
        for path in matches:
            name = os.path.basename(path)
            if name and name not in seen:
                seen.add(name)
                binaries.append((name, path, line.strip()))

    # Fallback: just find any absolute paths
    if not binaries:
        for line in text.strip().splitlines():
            paths = re.findall(r'(/(?:usr/)?(?:local/)?(?:s?bin)/[A-Za-z0-9_\-./]+)', line)
            for path in paths:
                name = os.path.basename(path)
                if name and name not in seen:
                    seen.add(name)
                    binaries.append((name, path, line.strip()))

    return binaries


def extract_binaries_capabilities(text):
    """
    Parse getcap output to extract binaries with capabilities.
    Format: /usr/bin/python3.8 = cap_setuid+ep
    """
    results = []
    for line in text.strip().splitlines():
        match = re.match(r'(/[^\s]+)\s*=\s*(.+)', line.strip())
        if match:
            path = match.group(1)
            caps = match.group(2).strip()
            name = os.path.basename(path)
            results.append((name, path, caps))
    return results



# ============================================================================
# ONLINE / DB FUNCTIONS (preserved from original + enhanced)
# ============================================================================

def check_gtfobin_online(name, timeout=3):
    """Check one binary on GTFOBins website."""
    try:
        import requests
    except ImportError:
        return None

    url = f"https://gtfobins.github.io/gtfobins/{name}/"
    try:
        r = requests.get(url, timeout=timeout)
        if r.status_code != 200:
            return None
        html = r.text.lower()
        has_suid = "suid" in html
        has_limited = "limited suid" in html or "limited-suid" in html
        has_sudo = "sudo" in html
        has_capabilities = "capabilities" in html
        return {
            "suid": has_suid,
            "limited_suid": has_limited,
            "sudo": has_sudo,
            "capabilities": has_capabilities,
            "url": url,
        }
    except Exception:
        return None


def load_db(path):
    """Load db.txt — split normal vs limited SUID entries."""
    suid = set()
    limited = set()
    if not os.path.isfile(path):
        return suid, limited
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip().lower()
            if not line or line.startswith("#"):
                continue
            if "(limited)" in line or " limited" in line or "-limited" in line:
                limited.add(line.split()[0].replace("(limited)", "").replace("-limited", "").strip())
            else:
                suid.add(line)
    return suid, limited


def update_db(db_path="db.txt"):
    """Fetch latest SUID/Limited-SUID entries from GTFOBins and rebuild db.txt."""
    try:
        import requests
        from bs4 import BeautifulSoup
    except ImportError:
        print("[!] requests and beautifulsoup4 required for --update-db")
        print("    pip install requests beautifulsoup4")
        return

    url = "https://gtfobins.github.io/"
    print("[*] Fetching GTFOBins list...")
    collected_suid = set()
    collected_limited = set()

    try:
        r = requests.get(url, timeout=10)
        if r.status_code != 200:
            print(f"[!] Could not fetch {url}")
            return
        soup = BeautifulSoup(r.text, "html.parser")

        # GTFOBins uses a table with data-function-contexts attribute on <li> elements
        # Structure: <tr data-gtfobin-name="xxx"><th><a>name</a></th><td><ul><li data-function-contexts="SUID,Sudo">...</li></ul></td></tr>
        table = soup.select_one("#gtfobin-table")
        if not table:
            # Fallback: try old method
            table = soup

        rows = table.select("tr[data-gtfobin-name]")
        if rows:
            print(f"[*] Found {len(rows)} binaries, parsing...")
            for row in rows:
                name = row.get("data-gtfobin-name", "").lower().strip()
                if not name:
                    continue
                li_items = row.select("li[data-function-contexts]")
                for li in li_items:
                    contexts = li.get("data-function-contexts", "").lower()
                    if "suid" in contexts and "limited" not in li.get("data-function-name", "").lower():
                        collected_suid.add(name)
                    if "limited suid" in li.get("data-function-name", "").lower():
                        collected_limited.add(name)
                    elif "suid" in contexts:
                        # Check if the function name itself indicates limited
                        fname = li.get("data-function-name", "").lower()
                        if "limited" in fname:
                            collected_limited.add(name)
        else:
            # Fallback: parse all links with old method
            items = soup.select('a[href^="/gtfobins/"]')
            print(f"[*] Found {len(items)} links, parsing (fallback mode)...")
            for a in items:
                name = a.get_text(strip=True).lower()
                ul = a.find_next("ul")
                if not ul:
                    continue
                funcs = [li.get_text(strip=True).lower() for li in ul.select("a")]
                if "suid" in funcs:
                    collected_suid.add(name)
                if "limited suid" in funcs:
                    collected_limited.add(name)

        if not collected_suid and not collected_limited:
            print("[!] Nothing collected, aborting.")
            return

        with open(db_path, "w", encoding="utf-8") as f:
            f.write("# Auto-generated GTFOBins SUID and Limited SUID database\n")
            f.write("# Generated by gtfobinSUID-improved\n\n")
            for name in sorted(collected_suid):
                f.write(f"{name}\n")
            for name in sorted(collected_limited):
                f.write(f"{name} (limited)\n")

        print(f"[+] Database updated: {db_path}")
        print(f"    {len(collected_suid)} SUID entries")
        print(f"    {len(collected_limited)} Limited SUID entries")
    except Exception as e:
        print(f"[!] Error updating db: {e}")



# ============================================================================
# OUTPUT FUNCTIONS
# ============================================================================

def print_banner():
    """Print startup banner."""
    banner = """
 ██████╗ ████████╗███████╗ ██████╗ ██████╗ ██╗███╗   ██╗
██╔════╝ ╚══██╔══╝██╔════╝██╔═══██╗██╔══██╗██║████╗  ██║
██║  ███╗   ██║   █████╗  ██║   ██║██████╔╝██║██╔██╗ ██║
██║   ██║   ██║   ██╔══╝  ██║   ██║██╔══██╗██║██║╚██╗██║
╚██████╔╝   ██║   ██║     ╚██████╔╝██████╔╝██║██║ ╚████║
 ╚═════╝    ╚═╝   ╚═╝      ╚═════╝ ╚═════╝ ╚═╝╚═╝  ╚═══╝
              ██████╗  ██████╗ ██████╗
             ██╔════╝ ██╔═══██╗██╔══██╗
             ██║  ███╗██║   ██║██║  ██║
             ██║   ██║██║   ██║██║  ██║
             ╚██████╔╝╚██████╔╝██████╔╝
              ╚═════╝  ╚═════╝ ╚═════╝
        gtfobinGOD v2.0 — OSCP Exam Edition
      github.com/bachrudinashari/gtfobinGOD
    """
    print(banner)


def format_result(binary_name, mode, function, priority, command, url=None):
    """Format a single result entry."""
    label = PRIORITY_LABELS.get(priority, "INFO")
    color = PRIORITY_COLORS.get(priority, "")

    header = f"[{label}] {binary_name} — {mode.upper()} {function.replace('_', ' ').title()}"
    if url:
        header += f" | {url}"

    lines = [c(color, header)]
    for cmd_line in command.split('\n'):
        lines.append(f"  {c(GREEN, cmd_line)}")
    return lines


def print_results_sorted(results, exam_mode=False):
    """Print results sorted by priority (most critical first)."""
    if not results:
        print("\n[*] No exploitable binaries found in database.")
        return

    # Sort by priority
    results.sort(key=lambda r: r["priority"])

    current_priority = None
    for r in results:
        if not exam_mode and current_priority != r["priority"]:
            current_priority = r["priority"]
            label = PRIORITY_LABELS.get(current_priority, "INFO")
            print(f"\n{'='*60}")
            print(f" {label} — Priority {current_priority}")
            print(f"{'='*60}")

        lines = format_result(
            r["binary"], r["mode"], r["function"],
            r["priority"], r["command"], r.get("url")
        )
        print()
        for line in lines:
            print(line)


def print_nonstandard_paths_warning(paths):
    """Print warning about binaries in non-standard paths."""
    if not paths:
        return
    print(f"\n{'='*60}")
    print(c(PRIORITY_COLORS[2], "[!] BINARIES IN NON-STANDARD PATHS (investigate manually):"))
    print(f"{'='*60}")
    for path in sorted(paths):
        print(f"  {path}")
    print()
    print("  These may be custom/vulnerable binaries. Check:")
    print("  - file <binary>    # what type?")
    print("  - strings <binary> # hardcoded paths/commands?")
    print("  - ltrace <binary>  # library calls?")
    print("  - strace <binary>  # syscalls?")


def print_custom_hint(name):
    """Print custom hints for known-vulnerable binaries."""
    name_lower = name.lower()
    if name_lower in CUSTOM_HINTS:
        h = CUSTOM_HINTS[name_lower]
        print(f"  {c(PRIORITY_COLORS[1], '[!] ' + h['hint'])}")
        for line in h["exploit"].split('\n'):
            print(f"      {line}")
        return True
    return False



# ============================================================================
# CORE PROCESSING
# ============================================================================

def process_suid(names, nonstandard_paths, use_online=False, db_path=DEFAULT_DB, exam_mode=False):
    """Process SUID binary list and return results."""
    results = []
    suid_db, limited_db = load_db(db_path)

    for name in names:
        normalized = normalize_binary(name)

        # Check embedded commands database first
        if normalized in COMMANDS and COMMANDS[normalized].get("suid"):
            cmds = COMMANDS[normalized]["suid"]
            url = f"https://gtfobins.github.io/gtfobins/{normalized}/"
            for func, (priority, command) in cmds.items():
                results.append({
                    "binary": name,
                    "normalized": normalized,
                    "mode": "suid",
                    "function": func,
                    "priority": priority,
                    "command": command,
                    "url": url,
                })
        elif use_online:
            # Fallback to online check
            info = check_gtfobin_online(normalized)
            if info and info["suid"]:
                results.append({
                    "binary": name,
                    "normalized": normalized,
                    "mode": "suid",
                    "function": "check_link",
                    "priority": 5,
                    "command": f"# Visit: {info['url']}",
                    "url": info["url"],
                })
        else:
            # Fallback to db.txt
            lnorm = normalized.lower()
            if lnorm in suid_db:
                url = f"https://gtfobins.github.io/gtfobins/{lnorm}/"
                results.append({
                    "binary": name,
                    "normalized": normalized,
                    "mode": "suid",
                    "function": "found_in_db",
                    "priority": 5,
                    "command": f"# No embedded commands. Visit: {url}",
                    "url": url,
                })
            elif lnorm in limited_db:
                url = f"https://gtfobins.github.io/gtfobins/{lnorm}/"
                results.append({
                    "binary": name,
                    "normalized": normalized,
                    "mode": "suid",
                    "function": "limited_suid",
                    "priority": 5,
                    "command": f"# Limited SUID. Visit: {url}",
                    "url": url,
                })

        # Check custom hints
        if name.lower() in CUSTOM_HINTS:
            h = CUSTOM_HINTS[name.lower()]
            results.append({
                "binary": name,
                "normalized": normalized,
                "mode": "suid",
                "function": "known_vuln",
                "priority": h["priority"],
                "command": f"# {h['hint']}\n{h['exploit']}",
                "url": None,
            })

    return results


def process_sudo(binaries, exam_mode=False):
    """Process sudo -l parsed binaries and return results."""
    results = []

    for name, path, original_line in binaries:
        normalized = normalize_binary(name)

        if normalized in COMMANDS and COMMANDS[normalized].get("sudo"):
            cmds = COMMANDS[normalized]["sudo"]
            url = f"https://gtfobins.github.io/gtfobins/{normalized}/"
            for func, (priority, command) in cmds.items():
                # Replace generic sudo with the actual allowed path
                actual_cmd = command.replace(f"sudo {normalized}", f"sudo {path}")
                results.append({
                    "binary": name,
                    "normalized": normalized,
                    "mode": "sudo",
                    "function": func,
                    "priority": priority,
                    "command": actual_cmd,
                    "url": url,
                    "context": original_line,
                })
        else:
            # Not in our DB but still worth noting
            results.append({
                "binary": name,
                "normalized": normalized,
                "mode": "sudo",
                "function": "not_in_db",
                "priority": 5,
                "command": f"# {original_line}\n# Manual check: https://gtfobins.github.io/gtfobins/{normalized}/",
                "url": None,
                "context": original_line,
            })

        # Custom hints
        if name.lower() in CUSTOM_HINTS:
            h = CUSTOM_HINTS[name.lower()]
            results.append({
                "binary": name,
                "normalized": normalized,
                "mode": "sudo",
                "function": "known_vuln",
                "priority": h["priority"],
                "command": f"# {h['hint']}\n{h['exploit']}",
                "url": None,
            })

    return results


def process_capabilities(cap_binaries, exam_mode=False):
    """Process getcap parsed binaries and return results."""
    results = []

    for name, path, caps in cap_binaries:
        normalized = normalize_binary(name)

        # Check if we have capability-specific commands
        if normalized in COMMANDS and COMMANDS[normalized].get("capabilities"):
            cmds = COMMANDS[normalized]["capabilities"]
            url = f"https://gtfobins.github.io/gtfobins/{normalized}/"
            for func, (priority, command) in cmds.items():
                results.append({
                    "binary": name,
                    "normalized": normalized,
                    "mode": "capabilities",
                    "function": func,
                    "priority": priority,
                    "command": f"# Caps: {caps}\n{command}",
                    "url": url,
                })
        elif "cap_setuid" in caps.lower():
            # Generic cap_setuid advice
            url = f"https://gtfobins.github.io/gtfobins/{normalized}/"
            results.append({
                "binary": name,
                "normalized": normalized,
                "mode": "capabilities",
                "function": "cap_setuid",
                "priority": 1,
                "command": f"# {path} has {caps}\n# Binary can setuid(0) — check GTFOBins for specific command\n# Generic: {normalized} <call setuid(0) then spawn /bin/sh>",
                "url": url,
            })
        elif "cap_dac_override" in caps.lower() or "cap_dac_read_search" in caps.lower():
            results.append({
                "binary": name,
                "normalized": normalized,
                "mode": "capabilities",
                "function": "file_access",
                "priority": 2,
                "command": f"# {path} has {caps}\n# Can read/write any file regardless of permissions\n# Try reading: /etc/shadow, /root/.ssh/id_rsa, /root/proof.txt",
                "url": None,
            })
        else:
            results.append({
                "binary": name,
                "normalized": normalized,
                "mode": "capabilities",
                "function": "other_cap",
                "priority": 4,
                "command": f"# {path} has {caps}\n# Check manually for exploitation potential",
                "url": None,
            })

        # Capability hint
        for cap_name, hint in CAPABILITIES_HINTS.items():
            if cap_name in caps.lower():
                results.append({
                    "binary": name,
                    "normalized": normalized,
                    "mode": "capabilities",
                    "function": "hint",
                    "priority": 5,
                    "command": f"# {cap_name}: {hint}",
                    "url": None,
                })
                break

    return results



# ============================================================================
# AUTO-RUN MODE
# ============================================================================

# ============================================================================
# LINENUM-NG STYLE ENUMERATION
# ============================================================================

def run_enum(args):
    """Run LinEnum-ng style enumeration checks after SUID/sudo/cap analysis."""
    import subprocess
    import platform

    SEP = "=" * 60
    SUBSEP = "-" * 60

    def header(title):
        print(f"\n{c(BOLD, SEP)}")
        print(c(BOLD, f" {title}"))
        print(c(BOLD, SEP))

    def info(label, value=""):
        if value:
            print(f"  {label}: {c(GREEN, value)}")
        else:
            print(f"  {label}")

    def critical(msg):
        print(f"  {c(PRIORITY_COLORS[1], '[!!!] ' + msg)}")

    def warn(msg):
        print(f"  {c(PRIORITY_COLORS[2], '[!] ' + msg)}")

    def cmd(command, timeout=15):
        """Run a command and return stdout."""
        try:
            r = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=timeout)
            return r.stdout.strip()
        except Exception:
            return ""

    # ─── SYSTEM INFO ─────────────────────────────────────────────
    header("SYSTEM INFORMATION")
    info("Hostname", cmd("hostname"))
    info("Kernel", cmd("uname -r"))
    info("OS", cmd("cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d'\"' -f2"))
    info("Architecture", cmd("uname -m"))
    info("Current user", cmd("id"))

    # ─── KERNEL CVE CHECK ────────────────────────────────────────
    header("KERNEL CVE CHECK")
    kernel = cmd("uname -r")
    kparts = kernel.split("-")[0].split(".")
    v1, v2, v3 = int(kparts[0]) if len(kparts) > 0 else 0, int(kparts[1]) if len(kparts) > 1 else 0, int(kparts[2]) if len(kparts) > 2 else 0

    # PwnKit
    pkexec_ver = cmd("pkexec --version 2>/dev/null | grep -oP '[0-9]+\\.[0-9]+'")
    if pkexec_ver:
        try:
            if float(pkexec_ver) < 0.120 and cmd("find /usr/bin/pkexec -perm -4000 2>/dev/null"):
                critical(f"CVE-2021-4034 PwnKit — pkexec {pkexec_ver} < 0.120 + SUID")
                info("  Exploit: https://github.com/ly4k/PwnKit")
            else:
                info("PwnKit: Not vulnerable")
        except ValueError:
            pass
    else:
        info("PwnKit: pkexec not found")

    # Dirty Pipe
    if v1 == 5 and 8 <= v2 <= 16:
        if not (v2 == 16 and v3 >= 11):
            critical(f"CVE-2022-0847 Dirty Pipe — kernel {kernel}")
            info("  Exploit: https://github.com/Arinerron/CVE-2022-0847-DirtyPipe-Exploit")
        else:
            info("Dirty Pipe: Not vulnerable (patched)")
    else:
        info("Dirty Pipe: Not vulnerable")

    # Dirty COW
    if v1 < 4 or (v1 == 4 and v2 < 9):
        if v1 < 3 or (v1 == 3 and v2 <= 19) or (v1 == 4 and v2 < 9):
            critical(f"CVE-2016-5195 Dirty COW possible — kernel {kernel}")
            info("  Exploit: gcc -pthread dirty.c -o dirty -lcrypt")
    else:
        info("Dirty COW: Not vulnerable")

    # Baron Samedit
    sudo_ver = cmd("sudo -V 2>/dev/null | head -1 | grep -oP '[0-9]+\\.[0-9]+\\.[0-9p]+'")
    if sudo_ver:
        test = cmd("sudoedit -s '\\' $(python3 -c \"print('A'*100)\") 2>&1 | grep -c 'not a regular file'")
        if test == "1":
            critical(f"CVE-2021-3156 Baron Samedit — sudo {sudo_ver}")
            info("  Exploit: https://github.com/blasty/CVE-2021-3156")
        else:
            info(f"Baron Samedit: sudo {sudo_ver} — not vulnerable or patched")

    # Sudo CVEs
    if sudo_ver:
        # CVE-2019-18634
        s_parts = sudo_ver.replace("p", ".").split(".")
        try:
            if len(s_parts) >= 3 and int(s_parts[0]) == 1 and int(s_parts[1]) == 8 and int(s_parts[2]) < 26:
                warn(f"CVE-2019-18634 (pwfeedback) — sudo {sudo_ver}")
        except ValueError:
            pass

    # Compilers available
    compilers = []
    for comp in ["gcc", "cc", "g++", "make", "python3", "perl"]:
        if cmd(f"which {comp} 2>/dev/null"):
            compilers.append(comp)
    if compilers:
        info("Compilers/Interpreters", ", ".join(compilers))

    # ─── USER / GROUP ────────────────────────────────────────────
    header("USER / GROUP / PERMISSIONS")

    # Writable /etc/passwd
    if cmd("test -w /etc/passwd && echo yes"):
        critical("/etc/passwd is WRITABLE — can add root user!")
        info("  openssl passwd -1 -salt hacker password123")
        info("  echo 'hacker:HASH:0:0::/root:/bin/bash' >> /etc/passwd")
    else:
        info("/etc/passwd: not writable")

    # Readable /etc/shadow
    if cmd("test -r /etc/shadow && echo yes"):
        critical("/etc/shadow is READABLE — crack hashes!")
        shadow_top = cmd("head -3 /etc/shadow 2>/dev/null")
        if shadow_top:
            for line in shadow_top.split("\n"):
                info(f"  {line}")
    else:
        info("/etc/shadow: not readable")

    # Hashes in /etc/passwd
    hashes = cmd("grep -v '^[^:]*:[x*]' /etc/passwd 2>/dev/null | grep -v '^#'")
    if hashes:
        critical("Password hashes in /etc/passwd!")
        for line in hashes.split("\n")[:3]:
            info(f"  {line}")

    # Interesting groups
    my_groups = cmd("id")
    for g in ["docker", "lxd", "lxc", "disk", "adm", "shadow", "video"]:
        if g in my_groups:
            critical(f"Current user is in '{g}' group!")
            if g == "docker":
                info("  docker run -v /:/mnt --rm -it alpine chroot /mnt sh")
            elif g in ("lxd", "lxc"):
                info("  lxc init IMAGE privesc -c security.privileged=true")
                info("  lxc config device add privesc host-root disk source=/ path=/mnt/root recursive=true")
            elif g == "disk":
                info("  debugfs /dev/sda1 → cat /etc/shadow")

    # Users with login shells
    users = cmd("grep -E '(/bin/bash|/bin/sh|/bin/zsh|/bin/fish)' /etc/passwd 2>/dev/null | cut -d: -f1")
    if users:
        info("Login shell users", users.replace("\n", ", "))

    # ─── ENVIRONMENT ─────────────────────────────────────────────
    header("ENVIRONMENT")

    # Writable PATH dirs
    path_dirs = os.environ.get("PATH", "").split(":")
    writable_paths = [d for d in path_dirs if os.path.isdir(d) and os.access(d, os.W_OK)]
    if writable_paths:
        critical("Writable PATH directories — path hijacking possible!")
        for d in writable_paths:
            info(f"  {d}")
    else:
        info("PATH: no writable directories")

    # Sensitive env vars
    sensitive = cmd("env 2>/dev/null | grep -iE 'pass|pwd|key|secret|token|api' | grep -v '_=/'")
    if sensitive:
        warn("Sensitive environment variables found:")
        for line in sensitive.split("\n")[:5]:
            info(f"  {line}")

    # ─── CRON / TIMERS ───────────────────────────────────────────
    header("CRON & SCHEDULED TASKS")

    crontab = cmd("cat /etc/crontab 2>/dev/null | grep -v '^#' | grep -v '^$'")
    if crontab:
        info("System crontab:")
        for line in crontab.split("\n"):
            info(f"  {line}")

    # Writable cron files
    ww_cron = cmd("find /etc/cron* -perm -0002 -type f 2>/dev/null")
    if ww_cron:
        critical("World-writable cron files!")
        for line in ww_cron.split("\n"):
            info(f"  {line}")

    # Writable cron dirs
    ww_cron_dirs = cmd("find /etc/cron* -type d -writable 2>/dev/null")
    if ww_cron_dirs:
        critical("Writable cron directories!")
        for line in ww_cron_dirs.split("\n"):
            info(f"  {line}")

    # Systemd timers
    timers = cmd("systemctl list-timers --no-pager 2>/dev/null | head -15")
    if timers:
        info("Systemd timers:")
        for line in timers.split("\n")[:10]:
            info(f"  {line}")

    # ─── NETWORK ─────────────────────────────────────────────────
    header("NETWORK")

    # Listening ports
    ports = cmd("ss -tunlp 2>/dev/null | grep LISTEN") or cmd("netstat -tunlp 2>/dev/null | grep LISTEN")
    if ports:
        info("Listening services:")
        for line in ports.split("\n")[:15]:
            info(f"  {line}")

    # ─── INTERESTING FILES ───────────────────────────────────────
    header("INTERESTING FILES")

    # SSH keys
    ssh_keys = cmd("find / -name 'id_rsa' -o -name 'id_ecdsa' -o -name 'id_ed25519' 2>/dev/null | head -10")
    if ssh_keys:
        critical("SSH private keys found!")
        for key in ssh_keys.split("\n"):
            readable = " [READABLE]" if cmd(f"test -r '{key}' && echo yes") else ""
            info(f"  {key}{readable}")

    # Writable authorized_keys
    auth_keys = cmd("find / -name authorized_keys -writable 2>/dev/null | head -5")
    if auth_keys:
        critical("Writable authorized_keys files!")
        for f in auth_keys.split("\n"):
            info(f"  {f}")

    # Readable /root
    if cmd("test -r /root && echo yes"):
        critical("/root is readable!")
        info("  " + cmd("ls /root 2>/dev/null | head -5").replace("\n", ", "))

    # Hidden files owned by current user in /home
    me = cmd("whoami")
    hidden = cmd(f"find /home /opt /tmp /var -name '.*' -type f -user {me} 2>/dev/null | head -15")
    if hidden:
        info("Hidden files owned by you:")
        for f in hidden.split("\n"):
            info(f"  {f}")

    # Backup files
    backups = cmd("find / -type f \\( -name '*.bak' -o -name '*.old' -o -name '*.backup' -o -name '*.orig' \\) 2>/dev/null | grep -v '/usr/' | head -10")
    if backups:
        warn("Backup files found:")
        for f in backups.split("\n"):
            info(f"  {f}")

    # ─── PASSWORD HUNTING ────────────────────────────────────────
    header("PASSWORD HUNTING")

    # Config files with passwords
    pw_hits = cmd("grep -rlI --include='*.conf' --include='*.config' --include='*.ini' --include='*.env' --include='*.yml' --include='*.yaml' --include='*.xml' --include='*.php' --include='*.py' 'password\\|passwd\\|pwd' /var/www /opt /etc 2>/dev/null | grep -v '/usr/' | head -10")
    if pw_hits:
        warn("Files containing password strings:")
        for f in pw_hits.split("\n"):
            info(f"  {f}")

    # WordPress
    wp = cmd("find / -name wp-config.php -readable 2>/dev/null | head -3")
    if wp:
        critical("Readable wp-config.php found!")
        for f in wp.split("\n"):
            info(f"  {f}")
            creds = cmd(f"grep -E 'DB_USER|DB_PASSWORD' '{f}' 2>/dev/null")
            if creds:
                for line in creds.split("\n"):
                    info(f"    {line.strip()}")

    # .git-credentials
    gitcreds = cmd("find / -name .git-credentials -readable 2>/dev/null | head -3")
    if gitcreds:
        critical(".git-credentials found!")
        for f in gitcreds.split("\n"):
            info(f"  {f}")

    # htpasswd
    htpw = cmd("find / -name .htpasswd -readable 2>/dev/null | head -3")
    if htpw:
        critical(".htpasswd files found!")
        for f in htpw.split("\n"):
            info(f"  {f}")
            info(f"    {cmd(f'head -2 {f} 2>/dev/null')}")

    # Bash history
    histories = cmd("find /home /root -name '.bash_history' -readable 2>/dev/null | head -5")
    if histories:
        warn("Readable bash history:")
        for f in histories.split("\n"):
            info(f"  {f}")
            interesting = cmd(f"grep -iE 'pass|ssh|mysql|su |sudo|token|secret|curl.*-u' '{f}' 2>/dev/null | tail -5")
            if interesting:
                for line in interesting.split("\n"):
                    info(f"    {line}")

    # ─── WRITABLE LOCATIONS ──────────────────────────────────────
    header("WRITABLE FILES & DIRS")

    # Writable /etc files
    ww_etc = cmd("find /etc -writable -type f 2>/dev/null | grep -v '/proc' | head -10")
    if ww_etc:
        warn("Writable files in /etc:")
        for f in ww_etc.split("\n"):
            info(f"  {f}")

    # Writable service files
    ww_svc = cmd("find /etc/systemd /lib/systemd -writable -type f 2>/dev/null | head -5")
    if ww_svc:
        critical("Writable systemd service files!")
        for f in ww_svc.split("\n"):
            info(f"  {f}")

    # ─── SERVICES ────────────────────────────────────────────────
    header("RUNNING SERVICES (as root)")
    root_procs = cmd("ps aux 2>/dev/null | grep '^root' | grep -vE 'kthread|\\[' | head -15")
    if root_procs:
        for line in root_procs.split("\n"):
            info(f"  {line[:120]}")

    # ─── DATABASE ────────────────────────────────────────────────
    header("DATABASE")
    # MySQL no-pass
    if cmd("which mysql 2>/dev/null"):
        if cmd("mysqladmin -uroot version 2>/dev/null"):
            critical("MySQL root has NO PASSWORD!")
        elif cmd("mysqladmin -uroot -proot version 2>/dev/null"):
            critical("MySQL root password is 'root'!")
        else:
            info("MySQL: default creds failed")
    # PostgreSQL
    if cmd("which psql 2>/dev/null"):
        if cmd("psql -U postgres -w -c 'SELECT 1' template1 2>/dev/null"):
            critical("PostgreSQL postgres user has NO PASSWORD!")
        else:
            info("PostgreSQL: no-password login failed")

    # ─── NFS / FSTAB ────────────────────────────────────────────
    header("NFS & MOUNTS")
    exports = cmd("cat /etc/exports 2>/dev/null | grep -v '^#' | grep -v '^$'")
    if exports:
        warn("NFS exports found:")
        for line in exports.split("\n"):
            info(f"  {line}")
            if "no_root_squash" in line:
                critical("  ^ no_root_squash — mount and create SUID binary!")

    fstab_creds = cmd("grep -iE 'username|password|cred' /etc/fstab 2>/dev/null")
    if fstab_creds:
        critical("Credentials in /etc/fstab!")
        for line in fstab_creds.split("\n"):
            info(f"  {line}")

    print(f"\n{c(BOLD, SEP)}")
    print(c(BOLD, " ENUMERATION COMPLETE"))
    print(c(BOLD, SEP))


def run_auto(args):
    """Auto-run SUID + sudo + capabilities checks."""
    import subprocess

    all_results = []
    nonstandard_paths = set()

    # 1. SUID
    if not args.exam:
        print(c(BOLD, "\n[*] Running SUID check..."))
    try:
        out = subprocess.run(
            ["find", "/", "-perm", "-u=s", "-type", "f"],
            capture_output=True, text=True, timeout=30
        )
        text = out.stdout
        if text.strip():
            names, nsp = extract_basenames_suid(text)
            nonstandard_paths.update(nsp)
            if names:
                results = process_suid(names, nsp, False, args.db, args.exam)
                all_results.extend(results)
    except (subprocess.TimeoutExpired, FileNotFoundError, Exception) as e:
        if not args.exam:
            print(f"  [!] SUID check failed: {e}")

    # 2. Sudo
    if not args.exam:
        print(c(BOLD, "\n[*] Running sudo -l check..."))
    try:
        out = subprocess.run(
            ["sudo", "-n", "-l"],
            capture_output=True, text=True, timeout=10
        )
        text = out.stdout
        if text.strip():
            binaries = extract_binaries_sudo(text)
            if binaries:
                results = process_sudo(binaries, args.exam)
                all_results.extend(results)
    except (subprocess.TimeoutExpired, FileNotFoundError, Exception) as e:
        if not args.exam:
            print(f"  [!] Sudo check failed: {e}")

    # 3. Capabilities
    if not args.exam:
        print(c(BOLD, "\n[*] Running capabilities check..."))
    try:
        out = subprocess.run(
            ["getcap", "-r", "/"],
            capture_output=True, text=True, timeout=30
        )
        text = out.stdout + out.stderr  # getcap sometimes outputs to stderr
        if text.strip():
            cap_binaries = extract_binaries_capabilities(text)
            if cap_binaries:
                results = process_capabilities(cap_binaries, args.exam)
                all_results.extend(results)
    except (subprocess.TimeoutExpired, FileNotFoundError, Exception) as e:
        if not args.exam:
            print(f"  [!] Capabilities check failed: {e}")

    # Output
    if args.json:
        json_results = []
        for r in sorted(all_results, key=lambda x: x["priority"]):
            json_results.append({
                "binary": r["binary"],
                "normalized": r["normalized"],
                "mode": r["mode"],
                "function": r["function"],
                "priority": r["priority"],
                "priority_label": PRIORITY_LABELS.get(r["priority"], "INFO"),
                "command": r["command"],
                "url": r.get("url"),
            })
        print(json.dumps(json_results, indent=2))
    else:
        if args.exam:
            all_results = [r for r in all_results if r["priority"] <= 3]
        print_results_sorted(all_results, args.exam)
        print_nonstandard_paths_warning(nonstandard_paths)
        if all_results:
            shells = sum(1 for r in all_results if r["function"] == "shell")
            reads = sum(1 for r in all_results if r["function"] == "file_read")
            print(f"\n[*] Summary: {len(all_results)} findings | {shells} shells | {reads} file reads")

    # Run LinEnum-ng style enumeration
    if not args.json and not args.no_enum:
        run_enum(args)

    return 0 if all_results else 1


# ============================================================================
# MAIN
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Check binaries against GTFOBins — SUID, Sudo, Capabilities.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  find / -perm -u=s -type f 2>/dev/null | python3 gtfobinsuid.py
  sudo -l | python3 gtfobinsuid.py --sudo
  getcap -r / 2>/dev/null | python3 gtfobinsuid.py --capabilities
  python3 gtfobinsuid.py --check python3
  python3 gtfobinsuid.py --check vim --mode sudo
"""
    )

    # Mode selection
    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument("--sudo", action="store_true",
                           help="Parse sudo -l output instead of SUID enumeration")
    mode_group.add_argument("--capabilities", "--cap", dest="capabilities", action="store_true",
                           help="Parse getcap output instead of SUID enumeration")
    mode_group.add_argument("--auto", action="store_true",
                           help="Auto-run all 3 checks (SUID + sudo + capabilities). Default when no pipe.")

    # Source selection
    parser.add_argument("--online", action="store_true",
                       help="Query GTFOBins website for binaries not in local DB")
    parser.add_argument("--offline", "--fline", dest="offline", action="store_true",
                       help="Force offline mode (local db only)")
    parser.add_argument("--db", default=DEFAULT_DB,
                       help="Path to local database file (default: ./db.txt)")
    parser.add_argument("--update-db", action="store_true",
                       help="Fetch latest entries from GTFOBins and rebuild db.txt")

    # Quick check
    parser.add_argument("--check", metavar="BINARY",
                       help="Quick check a single binary name")
    parser.add_argument("--mode", choices=["suid", "sudo", "capabilities"], default="suid",
                       help="Mode for --check (default: suid)")

    # Output options
    parser.add_argument("--exam", action="store_true",
                       help="Exam mode: no banner, no noise, only actionable results")
    parser.add_argument("--json", action="store_true",
                       help="Output results as JSON")
    parser.add_argument("--no-banner", action="store_true",
                       help="Suppress banner")
    parser.add_argument("--no-color", action="store_true",
                       help="Disable colors")
    parser.add_argument("--no-enum", action="store_true",
                       help="Skip LinEnum-ng enumeration (only SUID/sudo/cap)")
    parser.add_argument("--enum-only", action="store_true",
                       help="Run ONLY LinEnum-ng enumeration (skip SUID/sudo/cap)")

    args = parser.parse_args()

    # Handle color
    global USE_COLOR
    if args.no_color or args.json or args.exam:
        USE_COLOR = False

    # Handle update-db
    if args.update_db:
        if not args.exam:
            print_banner()
        update_db(args.db)
        return 0

    # Print banner
    if not args.exam and not args.no_banner and not args.json:
        print_banner()

    # Quick single check mode
    if args.check:
        return handle_single_check(args)

    # Enum-only mode
    if args.enum_only:
        run_enum(args)
        return 0

    # Read input
    if is_pipe():
        text = sys.stdin.read()
    else:
        # No pipe: auto-run all checks (like the god wrapper but built-in)
        if args.auto or (not args.sudo and not args.capabilities):
            return run_auto(args)

        sys.stdout.write("Paste output (end with Ctrl-D on Linux, Ctrl-Z+Enter on Windows):\n")
        sys.stdout.flush()
        try:
            text = sys.stdin.read()
        except EOFError:
            text = ""

    if not text.strip():
        if not args.json:
            print("[!] No input provided.")
        return 1

    # Process based on mode
    results = []
    nonstandard_paths = set()

    if args.sudo:
        binaries = extract_binaries_sudo(text)
        if not binaries:
            if not args.json:
                print("[!] No binaries found in sudo -l output.")
            return 1
        if not args.exam and not args.json:
            print(f"\n[*] Found {len(binaries)} binary(ies) in sudo -l output")
        results = process_sudo(binaries, args.exam)

    elif args.capabilities:
        cap_binaries = extract_binaries_capabilities(text)
        if not cap_binaries:
            if not args.json:
                print("[!] No binaries found in getcap output.")
            return 1
        if not args.exam and not args.json:
            print(f"\n[*] Found {len(cap_binaries)} binary(ies) with capabilities")
        results = process_capabilities(cap_binaries, args.exam)

    else:
        # SUID mode (default)
        names, nonstandard_paths = extract_basenames_suid(text)
        if not names:
            if not args.json:
                print("[!] No binaries found in input.")
            return 1
        if not args.exam and not args.json:
            print(f"\n[*] Found {len(names)} unique binary(ies)")

        use_online = args.online
        if not args.offline and not args.online:
            # Auto-detect: try online, fallback offline
            try:
                import requests
                requests.head("https://gtfobins.github.io", timeout=3)
                use_online = True
            except Exception:
                use_online = False

        if not args.exam and not args.json:
            mode_str = "ONLINE+DB" if use_online else "OFFLINE (embedded DB)"
            print(f"[*] Mode: {mode_str}")

        results = process_suid(names, nonstandard_paths, use_online, args.db, args.exam)

    # Output
    if args.json:
        # Clean results for JSON (remove non-serializable)
        json_results = []
        for r in sorted(results, key=lambda x: x["priority"]):
            json_results.append({
                "binary": r["binary"],
                "normalized": r["normalized"],
                "mode": r["mode"],
                "function": r["function"],
                "priority": r["priority"],
                "priority_label": PRIORITY_LABELS.get(r["priority"], "INFO"),
                "command": r["command"],
                "url": r.get("url"),
            })
        print(json.dumps(json_results, indent=2))
    else:
        # Filter for exam mode: only show priority 1-3
        if args.exam:
            results = [r for r in results if r["priority"] <= 3]

        print_results_sorted(results, args.exam)
        print_nonstandard_paths_warning(nonstandard_paths)

        # Summary
        if results:
            shells = sum(1 for r in results if r["function"] == "shell")
            reads = sum(1 for r in results if r["function"] == "file_read")
            print(f"\n[*] Summary: {len(results)} findings | {shells} shells | {reads} file reads")

    return 0 if results else 1


def handle_single_check(args):
    """Handle --check BINARY quick lookup."""
    name = args.check
    normalized = normalize_binary(name)
    mode = args.mode

    if args.sudo:
        mode = "sudo"
    elif args.capabilities:
        mode = "capabilities"

    if not args.json:
        print(f"[*] Checking: {name} (normalized: {normalized}) — mode: {mode}")

    if normalized in COMMANDS and COMMANDS[normalized].get(mode):
        cmds = COMMANDS[normalized][mode]
        if args.json:
            results = []
            for func, (priority, command) in cmds.items():
                results.append({
                    "binary": name,
                    "normalized": normalized,
                    "mode": mode,
                    "function": func,
                    "priority": priority,
                    "command": command,
                })
            print(json.dumps(results, indent=2))
        else:
            for func, (priority, command) in sorted(cmds.items(), key=lambda x: x[1][0]):
                lines = format_result(name, mode, func, priority, command)
                print()
                for line in lines:
                    print(line)
        return 0
    else:
        if not args.json:
            print(f"[!] '{name}' not found in embedded DB for mode '{mode}'")
            if name.lower() in CUSTOM_HINTS:
                print_custom_hint(name)
            else:
                print(f"    Try: https://gtfobins.github.io/gtfobins/{normalized}/")
        return 1


if __name__ == "__main__":
    sys.exit(main())

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

    # Read input
    if is_pipe():
        text = sys.stdin.read()
    else:
        # Interactive mode (preserved from original)
        if not args.exam:
            sys.stdout.write("\nDo you want to see enumeration commands? (y/n): ")
            sys.stdout.flush()
            try:
                response = input().strip().lower()
            except EOFError:
                response = "n"
            if response in ('y', 'yes'):
                print("\n[*] SUID/SGID Enumeration:")
                print("  find / -perm -u=s -type f 2>/dev/null")
                print("  find / -perm -g=s -type f 2>/dev/null")
                print("\n[*] Sudo:")
                print("  sudo -l")
                print("\n[*] Capabilities:")
                print("  getcap -r / 2>/dev/null")
                print()

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

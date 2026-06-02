#!/bin/bash
# gtfobinGOD - Simple wrapper
# Usage:
#   god           → auto run all 3 checks (SUID + sudo + cap)
#   god suid      → SUID only
#   god sudo      → sudo -l check
#   god cap       → capabilities check
#   god check vim → quick check single binary
#   god update    → update database

DIR="$(cd "$(dirname "$0")" && pwd)"
PY="python3 $DIR/gtfobinsuid.py"

case "${1:-all}" in
    all)
        echo "=== SUID ===" 
        find / -perm -u=s -type f 2>/dev/null | $PY --exam
        echo -e "\n=== SUDO ==="
        sudo -l 2>/dev/null | $PY --sudo --exam
        echo -e "\n=== CAPABILITIES ==="
        getcap -r / 2>/dev/null | $PY --cap --exam
        ;;
    suid)
        find / -perm -u=s -type f 2>/dev/null | $PY --exam
        ;;
    sudo)
        sudo -l 2>/dev/null | $PY --sudo --exam
        ;;
    cap|capabilities)
        getcap -r / 2>/dev/null | $PY --cap --exam
        ;;
    check)
        shift
        $PY --check "$@"
        ;;
    update)
        $PY --update-db
        ;;
    *)
        echo "Usage: god [all|suid|sudo|cap|check <binary>|update]"
        ;;
esac

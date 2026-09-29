#!/usr/bin/env bash
#=====================================================================
# server_audit_readonly.sh
# READ-ONLY Linux / cPanel / CloudLinux server audit collector
#
# Produces (in OUTDIR):
#   1. Audit_<host>_<date>.html   -> report in the Activelobby sample format
#                                    (open in browser, or open in MS Word
#                                     and Save As .docx / PDF)
#   2. Evidence_<host>_<date>.txt -> raw command output (secrets masked),
#                                    ready to paste into the Master Prompt
#
# SAFETY:
#   * Runs only inspection commands (cat, grep, ss, df, systemctl status,
#     rpm -q, mysql SELECT/SHOW, etc.). No service restarts, no config
#     edits, no package installs, no firewall changes, no network calls.
#   * The ONLY files it writes are the two report files in OUTDIR.
#   * Package update check uses local cache only, unless you pass -u
#     (which lets dnf/apt refresh repo metadata - still no install).
#
# USAGE:
#   sudo bash server_audit_readonly.sh [-o outdir] [-u] [-a "Author"] [-w "Owner"]
#     -o  output directory (default: /root/audit_reports)
#     -u  allow package manager to refresh repo metadata (live update check)
#     -a  document author   (default: current user)
#     -w  document owner    (default: "-")
#=====================================================================

export LC_ALL=C
umask 077
# (nounset intentionally off: empty arrays are expected)

OUTDIR="/root/audit_reports"
LIVE_UPDATES=0
AUTHOR="${SUDO_USER:-$(whoami)}"
OWNER="-"
CLIENT_LABEL="SERVER"           # shown in title, e.g. USMENU
ACCOUNTABILITY="Activelobby Team"
REMARK="Requires confirmation to proceed."
ETA="To be confirmed"

while getopts "o:ua:w:" opt; do
  case $opt in
    o) OUTDIR="$OPTARG" ;;
    u) LIVE_UPDATES=1 ;;
    a) AUTHOR="$OPTARG" ;;
    w) OWNER="$OPTARG" ;;
    *) echo "Usage: $0 [-o outdir] [-u] [-a author] [-w owner]"; exit 1 ;;
  esac
done

if [ "$(id -u)" -ne 0 ]; then
  echo "WARNING: not running as root - many checks will show 'Not Checked'." >&2
fi

HOST="$(hostname -f 2>/dev/null || hostname)"
STAMP="$(date +%Y-%m-%d)"
NOW="$(date '+%Y-%m-%d %H:%M:%S %Z')"
mkdir -p "$OUTDIR" || { echo "Cannot create $OUTDIR"; exit 1; }
REPORT="$OUTDIR/Audit_${HOST}_${STAMP}.html"
EVID="$OUTDIR/Evidence_${HOST}_${STAMP}.txt"
: > "$EVID"

T="timeout 25"
have() { command -v "$1" >/dev/null 2>&1; }
esc()  { sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g'; }
clean(){ printf '%s' "$1" | tr '\n|' ' /' | sed 's/  */ /g'; }

# Mask secrets in evidence
mask() {
  sed -E \
   -e 's/((pass(word|wd)?|secret|token|api[_-]?key|apikey|accesshash)[[:space:]]*[=:][[:space:]]*)[^[:space:]]+/\1****MASKED****/Ig' \
   -e 's/-----BEGIN [A-Z ]*PRIVATE KEY-----.*/****PRIVATE KEY MASKED****/g'
}

# ev "Title" command...   -> append raw output to evidence file
ev() {
  local title="$1"; shift
  {
    echo "=================================================================="
    echo "## $title"
    echo "Command: $*"
    echo "------------------------------------------------------------------"
    $T bash -c "$*" 2>&1 | head -n 200 | mask
    echo
  } >> "$EVID"
}

# ---------- result stores ----------
declare -a FIND PASS KV SEC FW NET_PUB NET_LOC INFO
add_find() { FIND+=("$1|$2|$(clean "$3")|$(clean "$4")"); }   # sev|cat|assessment|solution
add_pass() { PASS+=("$(clean "$1")|$(clean "$2")|$(clean "$3")"); }
add_kv()   { KV+=("$(clean "$1")|$(clean "$2")"); }
add_sec()  { SEC+=("$(clean "$1")|$(clean "$2")"); }
add_fw()   { FW+=("$1|$2|$3|$4|$5|$(clean "$6")"); }
add_info() { INFO+=("$(clean "$1")|$(clean "$2")|$(clean "$3")"); }

svc_active() { systemctl is-active "$1" 2>/dev/null; }
svc_enabled(){ systemctl is-enabled "$1" 2>/dev/null; }
unit_exists(){ systemctl list-unit-files 2>/dev/null | grep -q "^$1"; }

echo "[*] Collecting data on $HOST ... (read-only)"

#=====================================================================
# 1. GENERAL INFORMATION
#=====================================================================
OS_PRETTY="$(. /etc/os-release 2>/dev/null; echo "${PRETTY_NAME:-unknown}")"
KERNEL="$(uname -r)"; ARCH="$(uname -m)"
CORES="$(nproc 2>/dev/null || echo 1)"
CPU_MODEL="$(awk -F: '/model name/{gsub(/^ /,"",$2);print $2;exit}' /proc/cpuinfo)"
MEM_TOTAL_MB="$(awk '/MemTotal/{printf "%d",$2/1024}' /proc/meminfo)"
MEM_AVAIL_MB="$(awk '/MemAvailable/{printf "%d",$2/1024}' /proc/meminfo)"
SWAP_TOTAL_MB="$(awk '/SwapTotal/{printf "%d",$2/1024}' /proc/meminfo)"
SWAP_FREE_MB="$(awk '/SwapFree/{printf "%d",$2/1024}' /proc/meminfo)"
VIRT="$(systemd-detect-virt 2>/dev/null || echo unknown)"
UPTIME_H="$(uptime -p 2>/dev/null)"
PRIV_IPS="$(ip -4 -o addr show scope global 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | paste -sd, -)"

CP_VER="Not Installed"
[ -x /usr/local/cpanel/cpanel ] && CP_VER="$($T /usr/local/cpanel/cpanel -V 2>/dev/null)"
CL_STATE="Not Installed"
[ -f /etc/cloudlinux-release ] && CL_STATE="$(cat /etc/cloudlinux-release)"

add_kv "Server Hostname" "$HOST"
add_kv "Server IP Address" "${PRIV_IPS:-Not Available}  (public IP not queried - no outbound calls made)"
add_kv "Server OS Version" "$OS_PRETTY"
add_kv "Current Kernel Version" "$KERNEL ($ARCH)"
add_kv "Environment" "$VIRT"
add_kv "CPU" "$CPU_MODEL ($CORES vCPU)"
add_kv "Memory / Swap" "RAM ${MEM_TOTAL_MB} MB (available ${MEM_AVAIL_MB} MB) / Swap ${SWAP_TOTAL_MB} MB (free ${SWAP_FREE_MB} MB)"
add_kv "Uptime" "$UPTIME_H"
add_kv "Control Panel / cPanel/WHM Version" "$CP_VER"
add_kv "CloudLinux" "$CL_STATE"
add_kv "Audit Date/Time" "$NOW"

ev "Basic info" "hostnamectl; hostname -f; uname -a; cat /etc/os-release; uptime; lscpu | head -20; free -h; ip -br addr; ip route"

#---------------- Kernel / updates ----------------
PKG=""; have dnf && PKG=dnf; [ -z "$PKG" ] && have yum && PKG=yum; [ -z "$PKG" ] && have apt && PKG=apt
KUPD=""; UPD_COUNT="n/a"
case "$PKG" in
  dnf|yum)
    CO="--cacheonly"; [ "$LIVE_UPDATES" -eq 1 ] && CO=""
    UPD_RAW="$($T $PKG -q $CO check-update 2>/dev/null)"
    KUPD="$(echo "$UPD_RAW" | awk '/^kernel(-core|-modules)?\./{print $1" "$2}' | paste -sd' ' -)"
    UPD_COUNT="$(echo "$UPD_RAW" | awk 'NF==3 && $1 ~ /\./' | wc -l)"
    ;;
  apt)
    KUPD="$($T apt list --upgradable 2>/dev/null | grep -E 'linux-(image|generic)' | awk -F/ '{print $1}' | paste -sd' ' -)"
    UPD_COUNT="$($T apt list --upgradable 2>/dev/null | grep -c upgradable)"
    ;;
esac
UPD_NOTE="local cache"; [ "$LIVE_UPDATES" -eq 1 ] && UPD_NOTE="live repo metadata"
add_kv "Pending package updates" "$UPD_COUNT (source: $UPD_NOTE)"
if [ -n "$KUPD" ]; then
  add_kv "Kernel update available" "Kernel package update detected: $KUPD"
  add_find High "KERNEL UPDATES" "Kernel Update Available: $KUPD" "Schedule a maintenance window and update the kernel. Reboot when required (take backup / snapshot first; plan rollback via previous kernel in GRUB)."
else
  add_kv "Kernel update available" "None detected ($UPD_NOTE)"
  add_pass "Kernel" "Kernel update" "No kernel update detected ($UPD_NOTE)"
fi

# newest installed kernel vs running
if have rpm; then
  NEWEST_K="$(rpm -q kernel --last 2>/dev/null | head -1 | awk '{print $1}' | sed 's/^kernel-//')"
  if [ -n "$NEWEST_K" ] && [ "$NEWEST_K" != "$KERNEL" ]; then
    add_find Medium "KERNEL UPDATES" "Reboot pending: running kernel $KERNEL, newest installed $NEWEST_K" "Reboot during a maintenance window to load the newest installed kernel."
  fi
fi
ev "Updates" "$PKG -q --cacheonly check-update 2>&1 | head -60; rpm -q kernel --last 2>/dev/null | head -5"

#=====================================================================
# 2. RESOURCE HEALTH (CPU / MEM / DISK / IO)
#=====================================================================
read -r L1 L5 L15 _ < /proc/loadavg
LOAD_HIGH=$(awk -v l="$L15" -v c="$CORES" 'BEGIN{print (l>c)?1:0}')
add_kv "Load average (1/5/15m) vs ${CORES} cores" "$L1 / $L5 / $L15"
[ "$LOAD_HIGH" -eq 1 ] && add_find Medium "RESOURCE USAGE" "Sustained high load: 15-min load $L15 exceeds $CORES CPU cores" "Identify top CPU consumers (see evidence file) and high-resource accounts (CloudLinux LVE / cPanel)."

MEM_USED_PCT=$(( (MEM_TOTAL_MB-MEM_AVAIL_MB)*100/ (MEM_TOTAL_MB>0?MEM_TOTAL_MB:1) ))
add_kv "Memory used (excl. cache)" "${MEM_USED_PCT}%"
[ "$MEM_USED_PCT" -ge 90 ] && add_find High "RESOURCE USAGE" "Memory pressure: ${MEM_USED_PCT}% used" "Review top memory processes; consider tuning PHP/MariaDB or adding RAM."
if [ "$SWAP_TOTAL_MB" -gt 0 ]; then
  SW_USED=$(( (SWAP_TOTAL_MB-SWAP_FREE_MB)*100/SWAP_TOTAL_MB ))
  [ "$SW_USED" -ge 50 ] && add_find Medium "RESOURCE USAGE" "Swap usage ${SW_USED}%" "Check for memory leaks / oversized processes; monitor swap in/out (vmstat)."
fi

IOWAIT="$(vmstat 1 3 2>/dev/null | tail -1 | awk '{print $16}')"
add_kv "CPU iowait (3s sample)" "${IOWAIT:-n/a}%"

# Disk
DISK_ROWS=""
while read -r fs type size used avail pct mnt; do
  p="${pct%\%}"
  DISK_ROWS+="$mnt ($fs,$type): ${pct} used, ${avail} free; "
  if   [ "$p" -ge 95 ]; then add_find Critical "DISK USAGE" "Filesystem $mnt is ${p}% full" "Free space immediately (logs, old backups, large files) - see evidence."
  elif [ "$p" -ge 90 ]; then add_find High     "DISK USAGE" "Filesystem $mnt is ${p}% full" "Clean up or extend the volume."
  elif [ "$p" -ge 80 ]; then add_find Medium   "DISK USAGE" "Filesystem $mnt is ${p}% full" "Plan cleanup / capacity increase."
  fi
done < <(df -PT -x tmpfs -x devtmpfs -x squashfs -x overlay 2>/dev/null | tail -n +2)
add_kv "Disk usage" "${DISK_ROWS:-Not Available}"

# Inodes
while read -r fs inodes iused ifree ipct mnt; do
  p="${ipct%\%}"; [[ "$p" =~ ^[0-9]+$ ]] || continue
  [ "$p" -ge 90 ] && add_find High "DISK USAGE" "Inode usage on $mnt is ${p}%" "Find directories with many small files (mail queues, sessions, caches)."
done < <(df -Pi -x tmpfs -x devtmpfs -x squashfs -x overlay 2>/dev/null | tail -n +2)

# Read-only FS
RO="$(awk '$4 ~ /(^|,)ro(,|$)/ && $3 !~ /^(squashfs|iso9660|tmpfs|devtmpfs|cgroup2?|proc|sysfs|securityfs|selinuxfs|bpf|debugfs|tracefs|configfs|fusectl|mqueue|hugetlbfs|pstore|autofs|binfmt_misc)$/ {print $2}' /proc/mounts | paste -sd, -)"
[ -n "$RO" ] && add_find High "DISK USAGE" "Read-only filesystem(s) detected: $RO" "Investigate filesystem errors (dmesg) - possible disk fault."

# Deleted-but-open files
if have lsof; then
  DEL="$($T lsof +L1 2>/dev/null | tail -n +2 | wc -l)"
  [ "$DEL" -gt 20 ] && add_find Low "DISK USAGE" "$DEL deleted files still held open by processes" "Restart the owning services in a maintenance window to release space."
fi

ev "CPU/Mem"        "top -b -n1 | head -25; vmstat 1 5; ps aux --sort=-%cpu | head -15; ps aux --sort=-%mem | head -15"
ev "Disk"           "df -hT; df -i; lsblk; findmnt -o TARGET,SOURCE,FSTYPE,OPTIONS | head -40"
ev "Disk large dirs" "du -xhd1 / 2>/dev/null | sort -rh | head -15"
ev "IO"             "iostat -xz 1 3"
ev "Deleted open files" "lsof +L1 | head -30"

#=====================================================================
# 3. NETWORK
#=====================================================================
ev "Network" "ip -s link; ss -s; ip route"

while read -r local proc; do
  addr="${local%:*}"; port="${local##*:}"
  name="$(echo "$proc" | sed -n 's/.*(("\([^"]*\)".*/\1/p')"; [ -z "$name" ] && name="unknown"
  case "$addr" in
    127.*|::1|"[::1]") NET_LOC+=("$port|$name") ;;
    *)                 NET_PUB+=("$port|$name") ;;
  esac
done < <(ss -H -ltnp 2>/dev/null | awk '{print $4, $NF}')

fmt_ports() { # list of "port|name" -> "21 (pure-ftpd), ..."
  printf '%s\n' "$@" | sort -t'|' -k1,1n -u | awk -F'|' 'NF==2{printf "%s%s (%s)", (n++?", ":""), $1, $2}'
}
PUB_STR="$(fmt_ports "${NET_PUB[@]:-}")"
LOC_STR="$(fmt_ports "${NET_LOC[@]:-}")"

# Exposed risky ports
for pp in "${NET_PUB[@]:-}"; do
  port="${pp%%|*}"; nm="${pp##*|}"
  case "$port" in
    3306) add_find Medium "NETWORK EXPOSURE" "MariaDB/MySQL (3306, $nm) listens on a public interface" "Bind to 127.0.0.1 or restrict with firewall to required source IPs." ;;
    27017|6379|11211|9200) add_find High "NETWORK EXPOSURE" "Data service on port $port ($nm) listens on a public interface" "Bind to localhost or restrict by firewall." ;;
    23) add_find High "NETWORK EXPOSURE" "Telnet (23) is listening" "Disable telnet; use SSH." ;;
    21) add_info "Network" "FTP (21) publicly listening" "Confirm FTP is required; prefer SFTP/FTPS-only." ;;
  esac
done

#=====================================================================
# 4. FIREWALL & SECURITY LAYERS
#=====================================================================
fwrow() { # name unit
  local inst="No" en="-" run="-"
  if unit_exists "$2"; then inst="Yes"; en="$(svc_enabled "$2")"; run="$(svc_active "$2")"; fi
  echo "$inst|$en|$run"
}
# CSF / LFD
if [ -x /usr/sbin/csf ]; then
  CSF_V="$($T csf -v 2>/dev/null | head -1)"
  CSF_TESTING="$(grep -E '^TESTING *=' /etc/csf/csf.conf 2>/dev/null | tr -d ' "')"
  CSF_ACTIVE="$(svc_active csf)"; LFD_ACTIVE="$(svc_active lfd)"
  add_fw CSF Yes "$(svc_enabled csf)" "$CSF_ACTIVE" "$CSF_V $CSF_TESTING" "$( [ "$CSF_ACTIVE" = active ] && echo Running || echo 'Running status could not be confirmed')"
  add_fw LFD Yes "$(svc_enabled lfd)" "$LFD_ACTIVE" "Login failure daemon" "$( [ "$LFD_ACTIVE" = active ] && echo Running || echo 'Not running / unconfirmed')"
  if [ "$CSF_ACTIVE" != active ]; then
    add_find Medium "CONFIGSERVER SECURITY & FIREWALL" "CSF: CSF is installed but running status could not be confirmed" "Review CSF status using the WHM/cPanel interface."
  else
    add_pass "CSF" "CSF service" "csf is active"
  fi
  [ "$LFD_ACTIVE" = active ] && add_pass "CSF" "LFD service" "lfd is active"
  echo "$CSF_TESTING" | grep -q '=1' && add_find High "CONFIGSERVER SECURITY & FIREWALL" "CSF is in TESTING mode (rules flushed by cron)" "Set TESTING=0 after validation, in a maintenance window."
else
  add_fw CSF No - - "-" "Not Installed"
  add_fw LFD No - - "-" "Not Installed"
fi

# Imunify
IMU="No"; IMU_RUN="-"
if pgrep -f 'imunify' >/dev/null 2>&1 || unit_exists imunify; then IMU="Yes"; IMU_RUN="$(pgrep -f imunify360 >/dev/null && echo 'imunify360 running' || (pgrep -f imunify >/dev/null && echo 'imunify (AV) running' || echo stopped))"; fi
add_fw Imunify360/AV "$IMU" "-" "$IMU_RUN" "$( have imunify360-agent && $T imunify360-agent version 2>/dev/null | head -1 || echo 'version n/a')" "$( [ "$IMU" = No ] && echo 'Not Installed' || echo "$IMU_RUN")"
[ "$IMU" = Yes ] && add_pass "ImunifyAV" "ImunifyAV" "Imunify process is running" || add_find Medium "MALWARE PROTECTION" "No Imunify process detected" "Confirm which malware scanner protects the server."

# firewalld / ufw / iptables / nftables
IFS='|' read -r i e r <<< "$(fwrow firewalld firewalld.service)"; add_fw firewalld "$i" "$e" "$r" "$(have firewall-cmd && $T firewall-cmd --get-active-zones 2>/dev/null | paste -sd' ' - )" "$( [ "$i" = No ] && echo 'Not Installed' || echo "$r")"
IFS='|' read -r i e r <<< "$(fwrow ufw ufw.service)";           add_fw UFW "$i" "$e" "$r" "$(have ufw && $T ufw status 2>/dev/null | head -1)" "$( [ "$i" = No ] && echo 'Not Installed' || echo "$r")"
IPT_RULES=0; have iptables && IPT_RULES="$($T iptables -S 2>/dev/null | grep -c '^-A')"
add_fw iptables "$(have iptables && echo Yes || echo No)" "-" "$( [ "$IPT_RULES" -gt 0 ] && echo active || echo 'no rules')" "$IPT_RULES rule(s)" "$( [ "$IPT_RULES" -gt 0 ] && echo 'Rules present' || echo 'No rules loaded')"
NFT_RULES=0; have nft && NFT_RULES="$($T nft list ruleset 2>/dev/null | grep -c 'chain')"
IFS='|' read -r i e r <<< "$(fwrow nftables nftables.service)"
add_fw nftables "$(have nft && echo Yes || echo No)" "$e" "$( [ "$NFT_RULES" -gt 0 ] && echo 'active (ruleset loaded)' || echo "$r")" "$NFT_RULES chain(s)" "$( [ "$NFT_RULES" -gt 0 ] && echo 'nftables rules detected' || echo 'No ruleset')"

FW_PROVIDER="None detected"
if [ "$NFT_RULES" -gt 0 ]; then FW_PROVIDER="nftables rules detected (active)"; add_pass "Host Firewall" "Firewall Provider" "nftables rules detected"
elif [ "$IPT_RULES" -gt 0 ]; then FW_PROVIDER="iptables rules detected (active)"; add_pass "Host Firewall" "Firewall Provider" "iptables rules detected"
elif [ "$(svc_active firewalld)" = active ]; then FW_PROVIDER="firewalld (active)"
elif [ "$(svc_active ufw)" = active ]; then FW_PROVIDER="ufw (active)"
else add_find Critical "FIREWALL" "No active host firewall detected (nftables/iptables/firewalld/ufw)" "Enable and configure a firewall (CSF or firewalld/nftables) - test rules to avoid SSH lockout."; fi
add_sec "Firewall Status" "$FW_PROVIDER"

ev "Firewall" "csf -v; systemctl status csf lfd --no-pager | head -30; firewall-cmd --state; ufw status verbose; iptables -S | head -80; nft list ruleset | head -120"

#=====================================================================
# 5. SSH
#=====================================================================
SSHD_T="$($T sshd -T 2>/dev/null)"
sshv() { echo "$SSHD_T" | awk -v k="$1" '$1==k{print $2; exit}'; }
if [ -n "$SSHD_T" ]; then
  SSH_PORT="$(sshv port)"; PRL="$(sshv permitrootlogin)"; PWA="$(sshv passwordauthentication)"; PKA="$(sshv pubkeyauthentication)"; MAT="$(sshv maxauthtries)"
  add_sec "SSH port Number" "$SSH_PORT"
  add_sec "SSH Root Login" "$( [ "$PRL" = no ] && echo Disabled || echo "$PRL")"
  add_sec "SSH Password Authentication" "$( [ "$PWA" = no ] && echo Disabled || echo Enabled)"
  [ "$SSH_PORT" != 22 ] && add_pass "SSH Security" "SSH Port" "SSH is using port $SSH_PORT"
  [ "$PRL" = no ] && add_pass "SSH Security" "Direct Root SSH Login" "PermitRootLogin = no"
  [ "$PKA" = yes ] && add_pass "SSH Security" "SSH Key Authentication" "PubkeyAuthentication = yes"
  [ "$PWA" = no ] && add_pass "SSH Security" "SSH Password Authentication" "PasswordAuthentication = no"
  [ "$PRL" = yes ] && add_find High "SSH SECURITY" "PermitRootLogin = yes" "Set PermitRootLogin no (or prohibit-password) and use sudo users; keep a second session open while testing."
  [ "$PWA" = yes ] && add_find Medium "SSH SECURITY" "SSH PasswordAuthentication = yes" "Use key-based auth and disable passwords, after confirming all admins have working keys."
  [ "$SSH_PORT" = 22 ] && add_info "SSH" "SSH on default port 22" "Informational - ensure brute-force protection (cPHulk/CSF) is active."
else
  add_sec "SSH" "Not Checked (sshd -T needs root)"
fi

# Failed logins (counts only; correlate before calling any IP malicious)
AUTHLOG=/var/log/secure; [ -f /var/log/auth.log ] && AUTHLOG=/var/log/auth.log
if [ -r "$AUTHLOG" ]; then
  FAILS="$(grep -cE 'Failed password|Invalid user' "$AUTHLOG" 2>/dev/null)"
  TOPIP="$(grep -E 'Failed password|Invalid user' "$AUTHLOG" 2>/dev/null | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | sort | uniq -c | sort -rn | head -5 | awk '{printf "%s(%s) ",$2,$1}')"
  add_info "SSH failed logins ($AUTHLOG)" "$FAILS attempts in current log" "Top sources (count only, not proof of malice): ${TOPIP:-none}"
fi
ev "SSH" "sshd -T | grep -Ei '^(port|permitrootlogin|passwordauthentication|pubkeyauthentication|maxauthtries|allowusers|allowgroups|clientaliveinterval|clientalivecountmax) '; last -n 15; lastb -n 15"

#=====================================================================
# 6. USERS & PRIVILEGES
#=====================================================================
UID0="$(awk -F: '$3==0{print $1}' /etc/passwd | paste -sd, -)"
[ "$UID0" != "root" ] && add_find Critical "PRIVILEGED ACCOUNT REVIEW" "Extra UID 0 account(s): $UID0" "Investigate and remove non-root UID 0 accounts."
WHEEL="$(getent group wheel 2>/dev/null | cut -d: -f4)"; [ -z "$WHEEL" ] && WHEEL="$(getent group sudo 2>/dev/null | cut -d: -f4)"
[ -n "$WHEEL" ] && add_find Medium "PRIVILEGED ACCOUNT REVIEW" "Wheel/Sudo Group Users: $WHEEL" "Review group membership and remove users who do not require privileged access."
if [ -r /etc/shadow ]; then
  EMPTYPW="$(awk -F: '($2==""){print $1}' /etc/shadow | paste -sd, -)"
  [ -n "$EMPTYPW" ] && add_find Critical "PRIVILEGED ACCOUNT REVIEW" "Accounts with EMPTY password: $EMPTYPW" "Lock or set passwords immediately."
fi
NOPASS="$(grep -rhE '^[^#].*NOPASSWD' /etc/sudoers /etc/sudoers.d 2>/dev/null | wc -l)"
[ "$NOPASS" -gt 0 ] && add_info "Sudo" "$NOPASS NOPASSWD sudo rule(s) found" "Review /etc/sudoers.d - NOPASSWD grants passwordless root."
SHELLUSERS="$(awk -F: '$3>=1000 && $7 ~ /(bash|sh|zsh)$/ && $1!="nobody"{print $1}' /etc/passwd | paste -sd, -)"
if [ -n "$SHELLUSERS" ] && [ -x /usr/local/cpanel/cpanel ]; then
  add_info "Shell access users" "UID>=1000 with login shell: $SHELLUSERS" "Confirm each user requires shell access (cPanel accounts should use jailshell/noshell)."
else
  [ -z "$SHELLUSERS" ] && add_pass "Normal Shell Access Users" "Normal Shell Access Users" "No UID>=1000 accounts with a normal shell detected"
fi
ev "Users" "awk -F: '\$3==0{print \$1}' /etc/passwd; getent group wheel; grep -rE 'NOPASSWD' /etc/sudoers /etc/sudoers.d; awk -F: '\$3>=1000{print \$1,\$7}' /etc/passwd | head -50"

#=====================================================================
# 7. cPANEL / CLOUDLINUX / WEB / PHP / DB / MAIL
#=====================================================================
if [ -x /usr/local/cpanel/cpanel ]; then
  # cPHulk
  if [ -f /var/cpanel/hulkd/enabled ] || pgrep -x cphulkd >/dev/null; then
    add_sec "Brute Force Protection" "Enabled (cPHulk)"; add_pass "cPHulk" "cPHulk" "cPHulk is enabled"
  else add_sec "Brute Force Protection" "Not detected"; add_find Medium "CPANEL SECURITY" "cPHulk brute-force protection not detected" "Enable cPHulk in WHM > Security Center (whitelist admin IPs first)."; fi

  # ModSecurity
  if httpd -M 2>/dev/null | grep -q security2_module || [ -d /etc/apache2/conf.d/modsec ]; then
    add_sec "Mod-Security (WAF) Status" "Enabled"; add_pass "ModSecurity" "Apache ModSecurity Module" "security2_module is loaded / configured"
  else add_sec "Mod-Security (WAF) Status" "Not detected (may be N/A with LiteSpeed)"; fi

  # Imunify / AV
  pgrep -f imunify >/dev/null && add_sec "Antivirus / Malware Scanner" "Imunify (active)" || add_sec "Antivirus / Malware Scanner" "Not detected"

  # SMTP restrictions
  if grep -qE '^smtpmailgidonly=1' /var/cpanel/cpanel.config 2>/dev/null; then
    add_sec "SMTP Restrictions" "Enabled"; add_pass "SMTP Security" "SMTP Restrictions" "SMTP Restrictions is enabled"
  else add_sec "SMTP Restrictions" "Disabled / not confirmed"; add_find Medium "CPANEL SECURITY" "SMTP Restrictions not enabled" "Enable in WHM > Security Center > SMTP Restrictions to limit spam abuse."; fi

  # securetmp / tmp options
  TMPOPT="$(findmnt -no OPTIONS /tmp 2>/dev/null)"; TMPSRC="$(findmnt -no SOURCE /tmp 2>/dev/null)"
  if [ -n "$TMPOPT" ]; then
    add_sec "Temporary Directory Hardening" "Enabled ($TMPSRC: $TMPOPT)"
    add_pass "/tmp Security" "/tmp mount" "$TMPSRC mounted on /tmp with options: $TMPOPT"
  else add_sec "Temporary Directory Hardening" "/tmp is not a separate mount"; add_find Medium "FILESYSTEM SECURITY" "/tmp is not a separate hardened mount" "Enable securetmp / mount /tmp with nosuid,noexec,nodev (test application impact first)."; fi

  # Compiler
  if [ -e /usr/bin/gcc ]; then
    GM="$(stat -c '%a %U:%G' /usr/bin/gcc)"
    case "$GM" in *0\ *) add_pass "Compiler Security" "Compiler Access" "Compiler access restricted. /usr/bin/gcc = $GM" ;;
      *) add_find Medium "CPANEL SECURITY" "/usr/bin/gcc is world-executable ($GM)" "Restrict compilers (WHM > Compiler Access) to root/admin only." ;; esac
  fi
  # CageFS
  if have cagefsctl; then
    $T cagefsctl --cagefs-status 2>/dev/null | grep -qi enabled && add_pass "CloudLinux Security" "CageFS" "CageFS is enabled server-wide." \
      || add_find High "CLOUDLINUX SECURITY" "CageFS not enabled server-wide" "Enable CageFS (cagefsctl --enable-all) in a maintenance window."
  fi
  # Backups
  BCFG=/var/cpanel/backups/config
  if [ -r "$BCFG" ]; then
    BEN="$(awk -F': ' '$1=="BACKUPENABLE"{print $2}' "$BCFG" | tr -d "'")"
    BDIR="$(awk -F': ' '$1=="BACKUPDIR"{print $2}' "$BCFG" | tr -d "'")"
    BRET="$(awk -F': ' '$1=="BACKUPRETDAILY"{print $2}' "$BCFG" | tr -d "'")"
    LASTB="$(ls -1dt "$BDIR"/*/ 2>/dev/null | head -1)"
    add_kv "Backup (cPanel)" "Enabled=$BEN, Dir=$BDIR, Daily retention=$BRET, Latest set: ${LASTB:-not found}. Restore testing: Not Checked"
    [ "$BEN" != yes ] && add_find High "BACKUP" "cPanel backups are not enabled" "Enable and verify backups; configure a remote destination."
  else
    add_kv "Backup" "Not Checked (cPanel backup config not readable)"
  fi
fi

# Web server
for s in httpd apache2 nginx lsws litespeed; do [ "$(svc_active $s)" = active ] && add_pass "Service Review" "Service: $s" "Service is active"; done
if have httpd; then
  A_CFG="$(httpd -T 2>/dev/null; grep -rhE '^(ServerTokens|ServerSignature|TraceEnable)' /etc/apache2/conf* /etc/httpd/conf* 2>/dev/null)"
  echo "$A_CFG" | grep -q 'ServerTokens Prod'    && add_pass "Apache Security" "Apache ServerTokens" "ServerTokens Prod detected"
  echo "$A_CFG" | grep -q 'ServerSignature Off'  && add_pass "Apache Security" "Apache ServerSignature" "ServerSignature Off detected"
  echo "$A_CFG" | grep -q 'TraceEnable Off'      && add_pass "Apache Security" "Apache TRACE Method" "TraceEnable Off detected"
fi

# Core services
for s in sshd crond cpanel cphulkd mysqld mariadb exim dovecot named pdns; do
  st="$(svc_active $s)"; [ "$st" = active ] && add_pass "Service Review" "Service: $s" "Service is active"
done
FAILED_SVC="$(systemctl --failed --no-legend 2>/dev/null | awk '{print $2}' | paste -sd, -)"
[ -n "$FAILED_SVC" ] && add_find Medium "SERVICES" "Failed systemd unit(s): $FAILED_SVC" "Review with 'systemctl status <unit>' and journalctl; restart or disable as appropriate."

# PHP
for ini in /opt/cpanel/ea-php*/root/etc/php.ini /opt/alt/php*/etc/php.ini /etc/php.ini; do
  [ -r "$ini" ] || continue
  ver="$(echo "$ini" | sed -nE 's#.*/ea-php([0-9]+)/.*#PHP \1#p; s#.*/alt/php([0-9]+)/.*#Alt-PHP \1#p')"; [ -z "$ver" ] && ver="System PHP"
  df_v="$(grep -E '^disable_functions' "$ini" | head -1 | cut -d= -f2- | cut -c1-60)"
  eu="$(grep -E '^expose_php' "$ini" | head -1 | awk -F= '{gsub(/ /,"",$2);print $2}')"
  aui="$(grep -E '^allow_url_include' "$ini" | head -1 | awk -F= '{gsub(/ /,"",$2);print $2}')"
  [ -n "$df_v" ] && add_pass "PHP Security" "$ver - disable_functions" "$df_v ..." || add_find Medium "PHP SECURITY" "$ver: disable_functions is empty" "Set disable_functions (exec, shell_exec, system, passthru, etc.) after checking app needs."
  [ "$eu" = Off ] && add_pass "PHP Security" "$ver - expose_php" "Off" || add_info "PHP" "$ver expose_php=${eu:-default(On)}" "Set expose_php = Off."
  [ "$aui" = Off ] && add_pass "PHP Security" "$ver - allow_url_include" "Off" || add_info "PHP" "$ver allow_url_include=${aui:-default}" "Set allow_url_include = Off."
done
# EOL PHP note
ls -d /opt/cpanel/ea-php5* /opt/cpanel/ea-php70 /opt/cpanel/ea-php71 /opt/cpanel/ea-php72 /opt/cpanel/ea-php73 /opt/cpanel/ea-php74 /opt/cpanel/ea-php80 /opt/alt/php5* /opt/alt/php7* /opt/alt/php80 2>/dev/null | grep -q . && \
  add_info "PHP" "End-of-life PHP versions are installed (<= 8.0 / 5.x-7.x)" "Confirm no accounts use them; plan migration to supported versions."

# Database
DBCLI=""; have mysql && DBCLI=mysql; have mariadb && DBCLI=mariadb
if [ -n "$DBCLI" ]; then
  DBV="$($T $DBCLI -NBe 'SELECT VERSION()' 2>/dev/null)"
  if [ -n "$DBV" ]; then
    MAXC="$($T $DBCLI -NBe "SHOW VARIABLES LIKE 'max_connections'" | awk '{print $2}')"
    MAXU="$($T $DBCLI -NBe "SHOW GLOBAL STATUS LIKE 'Max_used_connections'" | awk '{print $2}')"
    SLOW="$($T $DBCLI -NBe "SHOW GLOBAL STATUS LIKE 'Slow_queries'" | awk '{print $2}')"
    add_kv "Database" "$DBV; max_connections=$MAXC; peak used=$MAXU; slow queries=$SLOW"
    [ -n "$MAXC" ] && [ -n "$MAXU" ] && [ "$MAXU" -ge $((MAXC*90/100)) ] && add_find Medium "DATABASE" "Peak DB connections ($MAXU) near max_connections ($MAXC)" "Review max_connections, slow queries and hosting accounts."
  else add_kv "Database" "Not Checked (client cannot authenticate non-interactively)"; fi
  ev "Database (read-only)" "$DBCLI -e \"SELECT VERSION(); SHOW GLOBAL STATUS LIKE 'Uptime'; SHOW GLOBAL STATUS LIKE 'Threads_connected'; SHOW GLOBAL STATUS LIKE 'Max_used_connections'; SHOW VARIABLES LIKE 'max_connections'; SHOW GLOBAL STATUS LIKE 'Slow_queries';\""
fi

# Mail
if have exim; then
  Q="$($T exim -bpc 2>/dev/null)"
  add_kv "Mail queue (exim)" "${Q:-Not Checked} message(s)"
  [ -n "${Q:-}" ] && [ "$Q" -ge 500 ] && add_find High "MAIL" "Exim queue has $Q messages" "Inspect for spam/compromised accounts (exim -bp | exiqsumm)."
  [ -n "${Q:-}" ] && [ "$Q" -ge 100 ] && [ "$Q" -lt 500 ] && add_find Medium "MAIL" "Exim queue has $Q messages" "Review queue for deferred/failed deliveries."
fi

# Malware / security tools
for t in clamd maldet auditd fail2ban ossec wazuh-agent bitninja aide; do
  unit_exists "$t" && add_info "Security tool" "$t: $(svc_active $t)" "-"
done

# SELinux / AppArmor
have getenforce && add_info "SELinux" "$(getenforce 2>/dev/null)" "Informational - cPanel servers typically run with SELinux disabled."

# Monitoring agents
MON=""
pgrep -x zabbix_agentd >/dev/null && MON+="Zabbix agent, "; pgrep -x nrpe >/dev/null && MON+="NRPE, "
pgrep -f zabbix_agent >/dev/null && ! echo "$MON" | grep -q Zabbix && MON+="Zabbix agent, "
add_kv "Monitoring agents" "${MON%, }${MON:+ running}${MON:-None detected}"
[ -z "$MON" ] && add_find Medium "MONITORING" "No monitoring agent detected (Zabbix/NRPE)" "Deploy monitoring for CPU, RAM, disk, inodes, services, SSL and backups."

# Cron
ev "Cron" "for u in \$(cut -d: -f1 /etc/passwd); do crontab -l -u \$u 2>/dev/null | grep -v '^#' | sed \"s/^/[\$u] /\"; done | head -60; ls -la /etc/cron.d /etc/cron.daily; systemctl list-timers --no-pager | head -20"

# Logs
ev "Logs" "journalctl --disk-usage; du -sh /var/log/* 2>/dev/null | sort -rh | head -15; ls /etc/logrotate.d | head -40"
ev "System errors" "journalctl -p err -b --no-pager | tail -40; dmesg -T | grep -iE 'error|fail|warn' | tail -30; systemctl --failed --no-pager"
ev "Listening ports" "ss -lntup"
ev "cPanel" "/usr/local/cpanel/cpanel -V; cat /var/cpanel/backups/config | grep -Ev 'PASS|KEY|SECRET'; grep -E '^(smtpmailgidonly|skiphulk)' /var/cpanel/cpanel.config"
ev "SSL (cPanel hostname cert)" "openssl x509 -noout -subject -enddate -in /var/cpanel/ssl/cpanel/cpanel.pem"
ev "Sysctl (selected)" "sysctl net.ipv4.ip_forward net.ipv4.tcp_syncookies net.ipv4.conf.all.rp_filter net.ipv4.conf.all.accept_source_route kernel.randomize_va_space fs.suid_dumpable"

# SSL expiry finding (cPanel hostname cert)
if [ -r /var/cpanel/ssl/cpanel/cpanel.pem ] && have openssl; then
  EXP="$(openssl x509 -noout -enddate -in /var/cpanel/ssl/cpanel/cpanel.pem 2>/dev/null | cut -d= -f2)"
  if [ -n "$EXP" ]; then
    DAYS=$(( ( $(date -d "$EXP" +%s) - $(date +%s) ) / 86400 ))
    add_kv "cPanel hostname SSL expiry" "$EXP ($DAYS days)"
    [ "$DAYS" -le 7 ] && add_find High "SSL/TLS" "Hostname certificate expires in $DAYS days" "Renew via AutoSSL/WHM."
    [ "$DAYS" -gt 7 ] && [ "$DAYS" -le 30 ] && add_find Medium "SSL/TLS" "Hostname certificate expires in $DAYS days" "Verify AutoSSL renewal."
  fi
fi

#=====================================================================
# BUILD HTML REPORT (same layout as sample)
#=====================================================================
CRIT=0; HIGH=0; MED=0; LOW=0
for f in "${FIND[@]:-}"; do case "${f%%|*}" in Critical) CRIT=$((CRIT+1));; High) HIGH=$((HIGH+1));; Medium) MED=$((MED+1));; Low) LOW=$((LOW+1));; esac; done
TOTAL=${#FIND[@]}

sev_class() { echo "sev-$(echo "$1" | tr 'A-Z' 'a-z')"; }
h() { printf '%s' "$1" | esc; }

{
cat <<'CSS'
<!DOCTYPE html><html><head><meta charset="utf-8">
<style>
body{font-family:Calibri,Arial,sans-serif;font-size:11pt;color:#222;margin:30px}
h1,h2{color:#1f3864} h2{border-bottom:2px solid #1f3864;padding-bottom:3px;margin-top:28px}
table{border-collapse:collapse;width:100%;margin:10px 0;font-size:10pt}
th{background:#1f3864;color:#fff;text-align:left;padding:6px;border:1px solid #999}
td{padding:5px 6px;border:1px solid #bbb;vertical-align:top;word-break:break-word}
.hdr{background:#1f3864;color:#fff;padding:8px;font-size:9pt}
.center{text-align:center}
.sev-critical{color:#c00000;font-weight:bold}.sev-high{color:#e36c09;font-weight:bold}
.sev-medium{color:#bf8f00;font-weight:bold}.sev-low{color:#2e75b6;font-weight:bold}
.foot{margin-top:30px;font-size:9pt;color:#555;text-align:center}
</style></head><body>
CSS
echo "<div class='hdr'>Activelobby Information Systems Pvt.Ltd. 14/1729, NITCAA Workspace, Chakkalapadam Road, Thrikkakara, Kakkanad, Kochi, Ernakulam, Kerala - 682021</div>"
echo "<div class='center'><h1>Activelobby Information Systems Pvt Ltd</h1><i>A whole new lobby for Managed Services</i>"
echo "<h1>$(h "$CLIENT_LABEL") &ldquo;Audit Report Of The Server $(h "$HOST") | x.x.x.x&rdquo;</h1></div>"

echo "<table><tr><th colspan=3>DOCUMENT CONTROL</th></tr>
<tr><td>DOCUMENT CLASSIFICATION</td><td>:</td><td>Restricted / Confidential</td></tr>
<tr><td>DOCUMENT DESCRIPTION</td><td>:</td><td>$(h "$CLIENT_LABEL") ($(h "$HOST"))</td></tr>
<tr><td>DOCUMENT VERSION</td><td>:</td><td>1.0</td></tr>
<tr><td>DOCUMENT AUTHOR</td><td>:</td><td>$(h "$AUTHOR")</td></tr>
<tr><td>DOCUMENT OWNER</td><td>:</td><td>$(h "$OWNER")</td></tr>
<tr><td>REVIEW DATE</td><td>:</td><td>$(date '+%d %B %Y')</td></tr></table>
<table><tr><th colspan=2>REVIEW HISTORY</th></tr><tr><td><b>REVISION AUTHOR</b></td><td><b>SUMMARY OF CHANGES</b></td></tr>
<tr><td>$(h "$AUTHOR")</td><td>Initial Draft (auto-generated, read-only audit)</td></tr></table>"

echo "<h2>Table of Contents</h2><ol><li>Summary</li><li>General Information</li><li>Security Settings</li><li>Security Audit Information</li><li>Security Checks Passed</li><li>Network Exposure</li></ol>"

# ---- Summary
echo "<h2>Summary</h2>"
echo "<p>We conducted a comprehensive scan and audit of the $(h "$CLIENT_LABEL") &quot;$(h "$HOST")&quot; focusing on server security and optimization (audit generated $(h "$NOW")). All checks were read-only.</p>"
if [ "$TOTAL" -eq 0 ]; then echo "<p>No issues were identified by the automated checks.</p>"
else echo "<p>Our analysis identified <b>$CRIT critical, $HIGH high, $MED medium and $LOW low</b>-level issue(s) that pose potential security and operational risks. These findings should be reviewed to ensure the integrity, confidentiality, and availability of the server.</p>"
echo "<table><tr><th>SL No:</th><th>Findings</th><th>Recommendations</th><th>Priority</th><th>ETA/Expected Down time</th><th>Accountability</th><th>Remarks</th></tr>"
n=0
for sev in Critical High Medium Low; do
  for f in "${FIND[@]}"; do
    IFS='|' read -r s cat a sol <<< "$f"; [ "$s" = "$sev" ] || continue; n=$((n+1))
    echo "<tr><td>$n.</td><td>$(h "$a")</td><td>$(h "$sol")</td><td class='$(sev_class "$s")'>$s</td><td>$ETA</td><td>$ACCOUNTABILITY</td><td>$REMARK</td></tr>"
  done
done
echo "</table>"; fi

# ---- General info
echo "<h2>General Information:</h2><table><tr><th>Category</th><th>Details</th></tr>"
for r in "${KV[@]}"; do IFS='|' read -r k v <<< "$r"; echo "<tr><td>$(h "$k")</td><td>$(h "$v")</td></tr>"; done
echo "</table>"

# ---- Security settings
echo "<h2>Security Settings:</h2><table><tr><th colspan=2>Settings</th></tr>"
for r in "${SEC[@]:-}"; do [ -z "$r" ] && continue; IFS='|' read -r k v <<< "$r"; echo "<tr><td>$(h "$k")</td><td>$(h "$v")</td></tr>"; done
echo "</table>"

echo "<h3>Firewall &amp; Security Layer Consolidation</h3><table><tr><th>Security Layer</th><th>Installed</th><th>Enabled</th><th>Running</th><th>Configuration</th><th>Finding</th></tr>"
for r in "${FW[@]:-}"; do IFS='|' read -r a b c d e f <<< "$r"; echo "<tr><td>$(h "$a")</td><td>$(h "$b")</td><td>$(h "$c")</td><td>$(h "$d")</td><td>$(h "$e")</td><td>$(h "$f")</td></tr>"; done
echo "</table><p><i>Multiple firewall technologies are not treated as a problem by themselves; review actual rule interaction.</i></p>"

# ---- Audit info grouped by category
echo "<h2>Security Audit Information:</h2>"
if [ "$TOTAL" -eq 0 ]; then echo "<p>No findings.</p>"; else
  CATS="$(for f in "${FIND[@]}"; do IFS='|' read -r s c _ <<< "$f"; echo "$c"; done | awk '!s[$0]++')"
  while IFS= read -r c; do
    echo "<p><b>$(h "$c")</b></p><table><tr><th>SL No:</th><th>Severity</th><th>Assessment</th><th>Solution</th><th>Accountability</th><th>Remarks</th></tr>"
    n=0
    for f in "${FIND[@]}"; do IFS='|' read -r s cat a sol <<< "$f"; [ "$cat" = "$c" ] || continue; n=$((n+1))
      echo "<tr><td>$n.</td><td class='$(sev_class "$s")'>$s</td><td>$(h "$a")</td><td>$(h "$sol")</td><td>$ACCOUNTABILITY</td><td>$REMARK</td></tr>"
    done; echo "</table>"
  done <<< "$CATS"
fi

if [ "${#INFO[@]}" -gt 0 ]; then
  echo "<p><b>INFORMATIONAL OBSERVATIONS</b></p><table><tr><th>Area</th><th>Observation</th><th>Note</th></tr>"
  for r in "${INFO[@]}"; do IFS='|' read -r a b c <<< "$r"; echo "<tr><td>$(h "$a")</td><td>$(h "$b")</td><td>$(h "$c")</td></tr>"; done
  echo "</table>"
fi

# ---- Passed
echo "<h2>Security Checks Passed:</h2><p>The following controls were verified and meet the recommended baseline.</p><table><tr><th>Area</th><th>Check</th><th>Current State</th></tr>"
for r in "${PASS[@]:-}"; do [ -z "$r" ] && continue; IFS='|' read -r a c s <<< "$r"; echo "<tr><td>$(h "$a")</td><td>$(h "$c")</td><td>$(h "$s")</td></tr>"; done
echo "</table>"

# ---- Network exposure
echo "<p><b>Network Exposure (informational)</b></p><table><tr><th>Scope</th><th>Listening TCP ports (service)</th></tr>
<tr><td>Publicly listening</td><td>$(h "${PUB_STR:-none}")</td></tr>
<tr><td>Local only</td><td>$(h "${LOC_STR:-none}")</td></tr></table>"

echo "<p class='foot'>- End of Documentation -<br>Activelobby Information Systems | Email: sales@supportlobby.com | Ph: (+91-484) 2425257<br>Evidence file: $(h "$(basename "$EVID")") &mdash; Items not listed above were <b>Not Checked</b> (no evidence collected).</p></body></html>"
} > "$REPORT"

chmod 600 "$REPORT" "$EVID"
echo
echo "[+] Report   : $REPORT"
echo "[+] Evidence : $EVID"
echo "[+] Findings : Critical=$CRIT High=$HIGH Medium=$MED Low=$LOW"
echo "[i] Read-only run complete. No system configuration was changed."

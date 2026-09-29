#!/usr/bin/env bash
[ -n "${BASH_VERSION:-}" ] || { echo "This script needs bash: run  bash $0" >&2; exit 3; }
# =============================================================================
#  Server Security Audit  v2.0.0
#  Linux hardening / health audit with PDF, HTML, JSON and TXT reports.
#  The PDF writer is built in (pure awk) - no wkhtmltopdf/python/etc required.
#
#  Run as root for complete results:   sudo ./security_audit.sh
#  Help:                               ./security_audit.sh --help
# =============================================================================

VERSION="2.0.0"
PHP_MIN_SUPPORTED="8.2"
DISK_WARN=80; DISK_CRIT=90   # % used thresholds
MAILQ_WARN=100; MAILQ_CRIT=1000
SYN_RECV_THRESHOLD=50; SYN_SENT_THRESHOLD=100
export LC_ALL=C

# ------------------------------- options -------------------------------------
OUTDIR="$PWD"; FORMATS="pdf,txt"; NOCOLOR=0; QUIET=0; ASSUME=""; DEEP=0
REFRESH=0; SKIP=""; RUN_RKH=""; RUN_CSI=""; COMPARE=1; STATE_DIR=""

usage() {
cat <<USAGE
Server Security Audit v$VERSION

Usage: $0 [options]

  -o, --output-dir DIR   Where to write reports            (default: current dir)
  -f, --format LIST      Comma list of: pdf,txt,html,json  (default: pdf,txt)
  -y, --yes              Answer "yes" to optional scan prompts
  -n, --non-interactive  Never prompt (optional scans are skipped)
      --rkhunter         Run rkhunter and include its warnings
      --csi              Run cPanel CSI (downloads a script from GitHub - see notes)
      --deep             Slower checks: SUID inventory, unowned files, world-writable scan
      --refresh          Refresh package metadata first (apt-get update / dnf makecache)
      --skip LIST        Skip sections: system,ssh,users,network,firewall,updates,
                         malware,web,php,cloudlinux,cpanel,mail,dns,tls,kernel,filesystem
      --no-compare       Do not compare with the previous scan
      --state-dir DIR    Where scan history is kept
      --no-color         Disable colours          -q, --quiet   Only print the summary
  -V, --version          Print version            -h, --help    This help

Exit status: 0 = no HIGH/CRITICAL findings, 1 = HIGH found, 2 = CRITICAL found,
             3 = usage error.  Handy for cron / CI use.
USAGE
}

while [ $# -gt 0 ]; do
  case "$1" in
    -o|--output-dir) OUTDIR="${2:-}"; shift 2 ;;
    --output-dir=*)  OUTDIR="${1#*=}"; shift ;;
    -f|--format)     FORMATS="${2:-}"; shift 2 ;;
    --format=*)      FORMATS="${1#*=}"; shift ;;
    -y|--yes)        ASSUME="yes"; shift ;;
    -n|--non-interactive) ASSUME="no"; shift ;;
    --rkhunter)      RUN_RKH="yes"; shift ;;
    --csi)           RUN_CSI="yes"; shift ;;
    --deep)          DEEP=1; shift ;;
    --refresh)       REFRESH=1; shift ;;
    --skip)          SKIP="${2:-}"; shift 2 ;;
    --skip=*)        SKIP="${1#*=}"; shift ;;
    --no-compare)    COMPARE=0; shift ;;
    --state-dir)     STATE_DIR="${2:-}"; shift 2 ;;
    --state-dir=*)   STATE_DIR="${1#*=}"; shift ;;
    --no-color)      NOCOLOR=1; shift ;;
    -q|--quiet)      QUIET=1; shift ;;
    -V|--version)    echo "security_audit $VERSION"; exit 0 ;;
    -h|--help)       usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage >&2; exit 3 ;;
  esac
done

for f in $(echo "$FORMATS" | tr ',' ' '); do
  case "$f" in pdf|txt|html|json) ;; *) echo "Unknown format: $f" >&2; exit 3 ;; esac
done
mkdir -p "$OUTDIR" 2>/dev/null || { echo "Cannot create $OUTDIR" >&2; exit 3; }

# ------------------------------- colours -------------------------------------
if [ -t 1 ] && [ "$NOCOLOR" -eq 0 ] && [ -z "${NO_COLOR:-}" ]; then
  C_RED=$'\033[1;31m'; C_ORG=$'\033[0;31m'; C_YEL=$'\033[0;33m'; C_BLU=$'\033[0;34m'
  C_GRN=$'\033[0;32m'; C_GRY=$'\033[0;90m'; C_BLD=$'\033[1m'; C_NC=$'\033[0m'
else
  C_RED=""; C_ORG=""; C_YEL=""; C_BLU=""; C_GRN=""; C_GRY=""; C_BLD=""; C_NC=""
fi

# ------------------------------- workspace -----------------------------------
WORK=$(mktemp -d /tmp/secaudit.XXXXXX) || exit 1
FINDINGS="$WORK/findings.tsv"; META="$WORK/meta.tsv"; : > "$FINDINGS"; : > "$META"
cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT
trap 'echo; echo "Interrupted."; exit 130' INT TERM

START_EPOCH=$(date +%s)
STAMP=$(date +%Y-%m-%d_%H-%M-%S)
HOSTN=$(hostname 2>/dev/null || echo unknown)
CAT="General"

# ------------------------------- helpers -------------------------------------
have()     { command -v "$1" >/dev/null 2>&1; }
skipped()  { case ",$SKIP," in *",$1,"*) return 0 ;; esac; return 1; }
run_to()   { local t="$1"; shift; if have timeout; then timeout "$t" "$@"; else "$@"; fi; }
meta()     { printf '%s\t%s\n' "$1" "$2" >> "$META"; }
squash()   { tr '\t\r' '  ' | awk 'NF{ if (n++) printf "; "; printf "%s", $0 }'; }
ask_yes()  {
  case "$ASSUME" in yes) return 0 ;; no) return 1 ;; esac
  [ -t 0 ] && [ -t 1 ] || return 1
  local a; read -r -p "$1 (yes/no): " a; case "$a" in y|Y|yes|YES) return 0 ;; esac; return 1
}

section() {
  CAT="$1"
  [ "$QUIET" -eq 1 ] && return
  printf '\n%s== %s ==%s\n' "$C_BLD" "$1" "$C_NC"
}

# add SEVERITY TITLE DETAIL [RECOMMENDATION]
add() {
  local sev="$1" title detail rec col tag
  title=$(printf '%s' "$2" | squash); detail=$(printf '%s' "$3" | squash); rec=$(printf '%s' "${4:-}" | squash)
  printf '%s\t%s\t%s\t%s\t%s\n' "$sev" "$CAT" "$title" "$detail" "$rec" >> "$FINDINGS"
  [ "$QUIET" -eq 1 ] && return 0
  case "$sev" in
    CRITICAL) col="$C_RED" ;; HIGH) col="$C_ORG" ;; MEDIUM) col="$C_YEL" ;;
    LOW) col="$C_BLU" ;; PASS) col="$C_GRN" ;; *) col="$C_GRY" ;;
  esac
  printf '  %s[%-8s]%s %s' "$col" "$sev" "$C_NC" "$title"
  [ -n "$detail" ] && printf ' - %s' "$detail"
  printf '\n'
  if [ -n "$rec" ] && [ "$sev" != "PASS" ] && [ "$sev" != "INFO" ]; then printf '             %s-> %s%s\n' "$C_GRY" "$rec" "$C_NC"; fi
  return 0
}
pass() { add PASS "$@"; }
info() { add INFO "$@"; }
low()  { add LOW "$@"; }
med()  { add MEDIUM "$@"; }
high() { add HIGH "$@"; }
crit() { add CRITICAL "$@"; }
checklist() { printf 'CHECKLIST\t%s\t%s\t\t\n' "$1" "$2" >> "$FINDINGS"; }

# ------------------------------- environment ---------------------------------
IS_ROOT=0; [ "$(id -u)" -eq 0 ] && IS_ROOT=1
HAS_SYSTEMD=0; [ -d /run/systemd/system ] && have systemctl && HAS_SYSTEMD=1
svc_active()  { [ "$HAS_SYSTEMD" -eq 1 ] && systemctl is-active --quiet "$1" 2>/dev/null; }
svc_enabled() { [ "$HAS_SYSTEMD" -eq 1 ] && [ "$(systemctl is-enabled "$1" 2>/dev/null)" = "enabled" ]; }

osr() { [ -r /etc/os-release ] && sed -n "s/^$1=//p" /etc/os-release | head -1 | tr -d '"'; }
OS_ID=$(osr ID); OS_LIKE=$(osr ID_LIKE); OS_VER=$(osr VERSION_ID); OS_PRETTY=$(osr PRETTY_NAME)
[ -z "$OS_ID" ] && OS_ID="unknown"
FAMILY="other"
case " $OS_ID $OS_LIKE " in
  *" debian "*|*" ubuntu "*) FAMILY="debian" ;;
  *" rhel "*|*" fedora "*|*" centos "*|*" rocky "*|*" almalinux "*|*" cloudlinux "*|*" amzn "*) FAMILY="rhel" ;;
esac
PKG=""; if [ "$FAMILY" = "debian" ]; then PKG="apt"; elif have dnf; then PKG="dnf"; elif have yum; then PKG="yum"; fi

IS_CLOUDLINUX=0; uname -r | grep -q lve && IS_CLOUDLINUX=1
PANEL="None detected"
if   [ -d /usr/local/cpanel ];      then PANEL="WHM/cPanel"
elif [ -d /usr/local/directadmin ]; then PANEL="DirectAdmin"
elif [ -d /usr/local/psa ];         then PANEL="Plesk"
elif [ -d /usr/local/cwpsrv ];      then PANEL="Control Web Panel"
elif [ -d /usr/local/webuzo ];      then PANEL="Webuzo"
fi

get_ips() {
  if have ip; then ip -4 -o addr show scope global 2>/dev/null | awk '{sub(/\/.*/,"",$4); print $4}'
  elif have hostname; then hostname -I 2>/dev/null | tr ' ' '\n' | grep -E '^[0-9]+\.'; fi
}
is_private_ip() {
  case "$1" in 10.*|192.168.*|127.*|169.254.*) return 0 ;; 172.1[6-9].*|172.2[0-9].*|172.3[01].*) return 0 ;;
    100.6[4-9].*|100.[7-9][0-9].*|100.1[01][0-9].*|100.12[0-7].*) return 0 ;; esac; return 1
}
MAIN_IP=$(get_ips | head -1)

# value of a key in "key = value" file: last uncommented assignment wins
ini_val() { awk -F= -v k="$2" '
  /^[ \t]*[;#]/ {next}
  { key=$1; gsub(/[ \t]/,"",key); if (tolower(key)==k) { v=substr($0,index($0,"=")+1); gsub(/^[ \t"'\'']+|[ \t"'\'']+$/,"",v); val=v } }
  END { print val }' "$1" 2>/dev/null; }

# ------------------------------- banner --------------------------------------
if [ "$QUIET" -eq 0 ]; then
  printf '%s\n  Server Security Audit v%s  |  %s  |  %s%s\n' "$C_BLD" "$VERSION" "$HOSTN" "${MAIN_IP:-no-ip}" "$C_NC"
  printf '  %s%s%s\n' "$C_GRY" "$(date)" "$C_NC"
fi
if [ "$IS_ROOT" -eq 0 ]; then
  [ "$QUIET" -eq 0 ] && printf '\n  %sNot running as root - some checks will be limited. Re-run with sudo for full results.%s\n' "$C_YEL" "$C_NC"
fi

# =============================================================================
#  1. SYSTEM & HARDWARE
# =============================================================================
if ! skipped system; then
section "System & Hardware"
[ "$IS_ROOT" -eq 0 ] && med "Not running as root" "Several checks (shadow, sshd -T, firewall, logs) are limited" "Re-run with sudo"

UPTIME_P=$(uptime -p 2>/dev/null || uptime)
UPTIME_DAYS=$(awk '{printf "%d", $1/86400}' /proc/uptime 2>/dev/null)
LOAD=$(awk '{print $1", "$2", "$3}' /proc/loadavg 2>/dev/null)
CORES=$(nproc 2>/dev/null || grep -c ^processor /proc/cpuinfo)
CPU_MODEL=$(awk -F: '/model name/{sub(/^ /,"",$2); print $2; exit}' /proc/cpuinfo 2>/dev/null)
MEM_TOTAL_MB=$(awk '/MemTotal/{printf "%d",$2/1024}' /proc/meminfo 2>/dev/null)
MEM_AVAIL_MB=$(awk '/MemAvailable/{printf "%d",$2/1024}' /proc/meminfo 2>/dev/null)
DISK_INFO=""
have lsblk && DISK_INFO=$(lsblk -b -d -n -o SIZE,TYPE 2>/dev/null | awk '$2=="disk"{n++; t+=$1} END{if(n) printf "%d disk(s), %.0f GB total", n, t/1024/1024/1024}')
KERNEL=$(uname -r)

meta "Hostname" "$HOSTN"; meta "Primary IP" "${MAIN_IP:-n/a}"; meta "OS" "${OS_PRETTY:-$OS_ID $OS_VER}"
meta "Kernel" "$KERNEL"; meta "Uptime" "$UPTIME_P"; meta "Control panel" "$PANEL"
meta "CloudLinux" "$([ $IS_CLOUDLINUX -eq 1 ] && echo Yes || echo No)"
meta "CPU" "${CPU_MODEL:-n/a} (${CORES:-?} cores)"; meta "Memory" "${MEM_TOTAL_MB:-?} MB total"
[ -n "$DISK_INFO" ] && meta "Disks" "$DISK_INFO"
meta "All server IPs" "$(get_ips | tr '\n' ' ')"

info "Operating system" "${OS_PRETTY:-$OS_ID $OS_VER} (kernel $KERNEL)"
info "Control panel" "$PANEL"
info "Uptime / load" "$UPTIME_P; load $LOAD on ${CORES:-?} core(s)"

# support status of the OS (dates are approximate - verify with your vendor)
case "$OS_ID:$OS_VER" in
  ubuntu:14.04|ubuntu:16.04|ubuntu:18.04|debian:8|debian:9|debian:10|centos:6|centos:7|centos:8|rhel:6*|rhel:7*|cloudlinux:6*|cloudlinux:7*)
    high "Operating system may be end-of-life" "$OS_ID $OS_VER" "Upgrade to a supported release (or buy extended support)";;
esac

if [ -n "$LOAD" ] && [ -n "$CORES" ]; then
  L1=${LOAD%%,*}
  if awk -v l="$L1" -v c="$CORES" 'BEGIN{exit !(l > c*2)}'; then
    med "System load is high" "1-min load $L1 on $CORES core(s)" "Investigate with top/ps; check for abuse or runaway processes"
  else pass "System load" "1-min load $L1 on $CORES core(s)"; fi
fi
if [ -n "$MEM_TOTAL_MB" ] && [ "$MEM_TOTAL_MB" -gt 0 ]; then
  PCT=$(( MEM_AVAIL_MB * 100 / MEM_TOTAL_MB ))
  if [ "$PCT" -lt 10 ]; then med "Low available memory" "${MEM_AVAIL_MB} MB free of ${MEM_TOTAL_MB} MB (${PCT}%)" "Add RAM/swap or reduce workloads"
  else pass "Available memory" "${MEM_AVAIL_MB} MB of ${MEM_TOTAL_MB} MB (${PCT}%)"; fi
fi
SWAP_TOTAL=$(awk '/SwapTotal/{print $2}' /proc/meminfo 2>/dev/null)
if [ "${SWAP_TOTAL:-0}" -eq 0 ]; then low "Swap is not enabled" "No swap configured" "Enable swap to reduce the risk of OOM kills"
else pass "Swap" "$(awk '/SwapTotal/{printf "%d MB", $2/1024}' /proc/meminfo) configured"; fi

[ "${UPTIME_DAYS:-0}" -gt 365 ] && low "Very long uptime" "${UPTIME_DAYS} days without reboot" "Kernel updates probably not applied - schedule a reboot (or use live patching)"
ZOMBIES=$(ps -eo stat= 2>/dev/null | grep -c '^Z')
[ "${ZOMBIES:-0}" -gt 10 ] && low "Many zombie processes" "$ZOMBIES zombie processes" "Find and fix the parent process that is not reaping children"

# OOM events
OOMLOG=""; for f in /var/log/messages /var/log/syslog /var/log/kern.log; do [ -r "$f" ] && OOMLOG="$f" && break; done
if [ -n "$OOMLOG" ]; then
  OOMS=$(grep -ci "out of memory\|oom-killer" "$OOMLOG" 2>/dev/null)
  if [ "${OOMS:-0}" -gt 0 ]; then med "Out-of-memory events in system log" "$OOMS matching lines in $OOMLOG" "Review memory limits, add RAM/swap, tune services"
  else pass "Out-of-memory events" "None found in $OOMLOG"; fi
elif [ "$HAS_SYSTEMD" -eq 1 ] && have journalctl; then
  OOMS=$(journalctl -k --no-pager -q 2>/dev/null | grep -ci "out of memory\|oom-killer")
  [ "${OOMS:-0}" -gt 0 ] && med "Out-of-memory events in kernel log" "$OOMS matching lines" "Review memory limits, add RAM/swap" || pass "Out-of-memory events" "None in kernel journal"
fi
fi

# =============================================================================
#  2. FILESYSTEM
# =============================================================================
if ! skipped filesystem; then
section "Filesystem & Permissions"
while read -r fs size used avail pct mnt; do
  p=${pct%\%}; case "$p" in ''|*[!0-9]*) continue ;; esac
  if   [ "$p" -ge "$DISK_CRIT" ]; then high "Disk almost full: $mnt" "$pct used ($used of $size), device $fs" "Free space or grow the volume immediately"
  elif [ "$p" -ge "$DISK_WARN" ]; then med  "Disk usage high: $mnt" "$pct used ($used of $size)" "Plan clean-up or expansion"
  else pass "Disk usage: $mnt" "$pct used ($used of $size)"; fi
done < <(df -Ph -x tmpfs -x devtmpfs -x squashfs -x overlay -x efivarfs 2>/dev/null | tail -n +2)
while read -r fs inodes iused ifree ipct mnt; do
  p=${ipct%\%}; case "$p" in ''|*[!0-9]*) continue ;; esac
  [ "$p" -ge 90 ] && med "Inode usage high: $mnt" "$ipct of inodes used" "Delete many small files (mail queues, sessions, caches)"
done < <(df -Pi -x tmpfs -x devtmpfs -x squashfs -x overlay 2>/dev/null | tail -n +2)

# mount options for temp dirs
mount_opts() { if have findmnt; then findmnt -no OPTIONS -T "$1" 2>/dev/null | head -1; else awk -v m="$1" '$2==m{print $4}' /proc/mounts; fi; }
mount_src()  { if have findmnt; then findmnt -no TARGET -T "$1" 2>/dev/null | head -1; else echo "$1"; fi; }
for d in /tmp /var/tmp /dev/shm; do
  [ -d "$d" ] || continue
  o=$(mount_opts "$d"); tgt=$(mount_src "$d"); miss=""
  case ",$o," in *,noexec,*) ;; *) miss="noexec" ;; esac
  case ",$o," in *,nosuid,*) ;; *) miss="$miss nosuid" ;; esac
  if [ -z "$miss" ]; then pass "$d mount options" "noexec,nosuid set"
  else med "$d lacks hardening options" "Missing:$miss (mounted on $tgt)" "Mount $d with nosuid,noexec (fstab / bind mount)"; fi
done

# suspicious files in world-writable temp dirs
SUS=$(find /tmp /var/tmp /dev/shm -xdev -maxdepth 3 -type f \( -perm -u+x -o -name '*.pl' -o -name '*.php' -o -name '*.py' -o -name '*.sh' \) \
      ! -path '*/systemd-private-*' ! -path '*/.X11-unix/*' 2>/dev/null | head -50)
if [ -n "$SUS" ]; then
  N=$(printf '%s\n' "$SUS" | wc -l)
  high "Executable/script files in temp directories" "$N file(s), e.g. $(printf '%s\n' "$SUS" | head -5 | tr '\n' ' ')" "Inspect these files (file, strings, sha256) - remove them if not legitimate, then find how they arrived"
else pass "Temp directories" "No executables/scripts found in /tmp, /var/tmp, /dev/shm"; fi

# SUID in writable places
SU=$(find /tmp /var/tmp /dev/shm /home /var/www -xdev -type f -perm -4000 2>/dev/null | head -20)
[ -n "$SU" ] && crit "SUID files in user-writable locations" "$(printf '%s\n' "$SU" | tr '\n' ' ')" "Remove immediately and investigate for compromise" || pass "SUID files in user-writable locations" "None"

# critical file permissions
chk_perm() { # file mode-rule
  local f="$1" mode owner o g; [ -e "$f" ] || return
  mode=$(stat -c '%a' "$f" 2>/dev/null); owner=$(stat -c '%U' "$f" 2>/dev/null)
  o=$(( 8#${mode: -1} )); g=$(( 8#${mode: -2:1} ))
  case "$2" in
    other0)  if [ "$o" -ne 0 ]; then high "Insecure permissions: $f" "mode $mode owner $owner - accessible by other users" "chmod o-rwx $f"; else pass "Permissions: $f" "mode $mode"; fi ;;
    nowrite) if [ $(( o & 2 )) -ne 0 ] || [ $(( g & 2 )) -ne 0 ]; then high "Insecure permissions: $f" "mode $mode - group/other writable" "chmod go-w $f"; else pass "Permissions: $f" "mode $mode"; fi ;;
  esac
}
chk_perm /etc/shadow other0; chk_perm /etc/gshadow other0
chk_perm /etc/passwd nowrite; chk_perm /etc/group nowrite; chk_perm /etc/ssh/sshd_config nowrite
[ -S /var/run/docker.sock ] && { m=$(stat -c '%a' /var/run/docker.sock); [ $(( 8#${m: -1} & 2 )) -ne 0 ] && crit "Docker socket is world-writable" "mode $m" "chmod 660 /var/run/docker.sock - anyone with access is root"; }

WW=$(find /etc /usr/bin /usr/sbin /usr/local/bin /bin /sbin -xdev -type f -perm -0002 2>/dev/null | head -10)
[ -n "$WW" ] && high "World-writable system files" "$(printf '%s\n' "$WW" | tr '\n' ' ')" "chmod o-w on each file and check for tampering" || pass "World-writable system files" "None in /etc and binary directories"
HOMEK=$(find /home /root -maxdepth 3 \( -name .rhosts -o -name .netrc -o -name .shosts \) -type f 2>/dev/null | head -5)
[ -n "$HOMEK" ] && med "Legacy trust files present" "$(printf '%s\n' "$HOMEK" | tr '\n' ' ')" "Remove .rhosts/.netrc/.shosts files"

if [ "$DEEP" -eq 1 ]; then
  UNOWNED=$(run_to 120 find / -xdev \( -nouser -o -nogroup \) 2>/dev/null | head -10)
  [ -n "$UNOWNED" ] && med "Files with no valid owner" "$(printf '%s\n' "$UNOWNED" | tr '\n' ' ')" "Assign owners or remove - often left by deleted accounts or intruders" || pass "Unowned files" "None found"
  SUIDN=$(run_to 120 find / -xdev -type f -perm -4000 2>/dev/null | wc -l)
  info "SUID binary inventory" "$SUIDN SUID binaries on the root filesystem" "Compare against a known-good baseline"
  WWD=$(run_to 120 find / -xdev -type d -perm -0002 ! -perm -1000 2>/dev/null | grep -v '^/proc' | head -10)
  [ -n "$WWD" ] && med "World-writable directories without sticky bit" "$(printf '%s\n' "$WWD" | tr '\n' ' ')" "chmod +t or remove world-write" || pass "World-writable directories" "All have sticky bit"
fi
fi

# =============================================================================
#  3. SSH
# =============================================================================
if ! skipped ssh; then
section "SSH Service"
SSHD_BIN=$(command -v sshd || ls /usr/sbin/sshd 2>/dev/null)
if [ -z "$SSHD_BIN" ]; then
  info "OpenSSH server" "sshd not installed"
else
  SSHD_T=""; [ "$IS_ROOT" -eq 1 ] && SSHD_T=$("$SSHD_BIN" -T 2>/dev/null)
  sshd_val() { # key default
    local v
    if [ -n "$SSHD_T" ]; then v=$(printf '%s\n' "$SSHD_T" | awk -v k="$1" 'tolower($1)==k{$1=""; sub(/^ /,""); print; exit}')
    else v=$(cat /etc/ssh/sshd_config.d/*.conf /etc/ssh/sshd_config 2>/dev/null | sed 's/#.*//' | awk -v k="$1" 'tolower($1)==k{$1=""; sub(/^ /,""); print; exit}'); fi
    printf '%s' "${v:-$2}"
  }
  [ -z "$SSHD_T" ] && info "SSH settings source" "sshd -T unavailable; parsing config files (defaults assumed)"
  SSHV=$( { ssh -V 2>&1 || "$SSHD_BIN" -V 2>&1; } | grep -o 'OpenSSH_[^ ,]*' | head -1 )
  [ -z "$SSHV" ] && SSHV=$( { dpkg-query -W -f='${Version}' openssh-server 2>/dev/null || rpm -q openssh-server 2>/dev/null; } )
  [ -z "$SSHV" ] && SSHV="unknown"
  info "OpenSSH version" "$SSHV"

  P=$(sshd_val port 22)
  [ "$P" = "22" ] && low "SSH listens on the default port" "Port 22" "Consider a non-default port (and update firewall/CSF first) - reduces log noise, not a substitute for hardening" || pass "SSH port" "$P"
  V=$(sshd_val permitrootlogin prohibit-password)
  case "$V" in
    yes) high "SSH root login with password enabled" "PermitRootLogin yes" "Set PermitRootLogin no (or prohibit-password) and use a sudo user";;
    prohibit-password|without-password) low "SSH root login allowed with keys" "PermitRootLogin $V" "Prefer PermitRootLogin no and log in as a sudo user";;
    forced-commands-only) info "SSH root login" "forced-commands-only";;
    *) pass "SSH root login" "PermitRootLogin $V";;
  esac
  V=$(sshd_val passwordauthentication yes)
  [ "$V" = "yes" ] && med "SSH password authentication enabled" "PasswordAuthentication yes" "Use key-based auth, or add fail2ban/CSF-lfd if passwords must stay" || pass "SSH password authentication" "disabled"
  V=$(sshd_val permitemptypasswords no)
  [ "$V" = "yes" ] && crit "SSH allows empty passwords" "PermitEmptyPasswords yes" "Set PermitEmptyPasswords no" || pass "SSH empty passwords" "not permitted"
  V=$(sshd_val maxauthtries 6)
  [ "$V" -gt 4 ] 2>/dev/null && low "SSH MaxAuthTries is high" "MaxAuthTries $V" "Set MaxAuthTries 3-4" || pass "SSH MaxAuthTries" "$V"
  V=$(sshd_val x11forwarding no)
  [ "$V" = "yes" ] && low "SSH X11 forwarding enabled" "X11Forwarding yes" "Disable unless required" || pass "SSH X11 forwarding" "$V"
  V=$(sshd_val logingracetime 120)
  case "$V" in *[!0-9]*) ;; *) [ "$V" -gt 60 ] && low "SSH LoginGraceTime is long" "${V}s" "Use 30-60 seconds";; esac
  V=$(sshd_val allowusers ""); W=$(sshd_val allowgroups "")
  [ -z "$V$W" ] && low "SSH access is not restricted by user/group" "No AllowUsers/AllowGroups" "Restrict SSH to the accounts that need it"
  if [ -n "$SSHD_T" ]; then
    WEAK=$(printf '%s\n' "$SSHD_T" | awk '/^ciphers /{print $2}' | tr ',' '\n' | grep -E '3des|arcfour|blowfish|cast128|-cbc$' | tr '\n' ' ')
    [ -n "$WEAK" ] && med "Weak SSH ciphers enabled" "$WEAK" "Remove CBC/3DES/RC4 ciphers via the Ciphers directive" || pass "SSH ciphers" "no weak ciphers"
    WEAKM=$(printf '%s\n' "$SSHD_T" | awk '/^macs /{print $2}' | tr ',' '\n' | grep -E 'md5|umac-64|hmac-sha1(-96)?$' | tr '\n' ' ')
    [ -n "$WEAKM" ] && low "Weak SSH MACs enabled" "$WEAKM" "Prefer *-etm@openssh.com SHA-2 MACs" || pass "SSH MACs" "no weak MACs"
  fi
fi

# failed logins
FAILS=""; SRC=""
if [ "$HAS_SYSTEMD" -eq 1 ] && have journalctl && [ "$IS_ROOT" -eq 1 ] && journalctl -u ssh -u sshd --since "-1h" --no-pager -q 2>/dev/null | head -1 | grep -q .; then
  FAILS=$(journalctl -u ssh -u sshd --since "-1h" --no-pager -q 2>/dev/null | grep -E "Failed password|Invalid user"); SRC="last hour (journal)"
else
  for f in /var/log/auth.log /var/log/secure; do
    if [ -r "$f" ]; then FAILS=$(tail -n 20000 "$f" | grep -E "sshd.*(Failed password|Invalid user)"); SRC="recent entries of $f"; break; fi
  done
fi
if [ -z "$SRC" ]; then info "Failed SSH logins" "No readable auth log/journal found"
else
  N=$(printf '%s\n' "$FAILS" | grep -c .)
  TOP=$(printf '%s\n' "$FAILS" | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' | sort | uniq -c | sort -rn | head -5 | awk '{printf "%s (%s) ", $2, $1}')
  if   [ "$N" -ge 500 ]; then high "Heavy SSH brute-force activity" "$N failed attempts in $SRC. Top sources: $TOP" "Enable fail2ban/lfd, restrict SSH by IP, disable password auth"
  elif [ "$N" -ge 50 ];  then med  "SSH brute-force activity" "$N failed attempts in $SRC. Top sources: $TOP" "Enable fail2ban/lfd; consider key-only auth"
  elif [ "$N" -gt 0 ];   then low  "Failed SSH logins" "$N in $SRC. Sources: $TOP" "Monitor; ensure brute-force protection is active"
  else pass "Failed SSH logins" "None in $SRC"; fi
fi
# recent successful root logins
if have last; then
  RL=$(last -n 200 -w 2>/dev/null | awk '$1=="root" && $0 !~ /still/ {print $3}' | grep -E '^[0-9]' | sort -u | head -5 | tr '\n' ' ')
  [ -n "$RL" ] && info "Recent root logins came from" "$RL" "Confirm these addresses are yours"
fi
fi

# =============================================================================
#  4. USERS & AUTHENTICATION
# =============================================================================
if ! skipped users; then
section "Users & Authentication"
UID0=$(awk -F: '$3==0 && $1!="root"{print $1}' /etc/passwd)
[ -n "$UID0" ] && crit "Extra accounts with UID 0 (root equivalent)" "$UID0" "Remove or change the UID of these accounts immediately" || pass "UID 0 accounts" "Only root"

if [ -r /etc/shadow ]; then
  EMPTYPW=$(awk -F: '$2==""{print $1}' /etc/shadow)
  [ -n "$EMPTYPW" ] && crit "Accounts with empty passwords" "$EMPTYPW" "Lock (passwd -l) or set a strong password" || pass "Empty passwords" "None"
else info "Empty password check" "/etc/shadow not readable (run as root)"; fi

SHELLUSERS=$(awk -F: '$7 ~ /(bash|zsh|ksh|sh|dash|fish)$/ && $1!="root" && $3>=1000 && $1!="nobody"{print $1}' /etc/passwd | tr '\n' ' ')
SYSSHELL=$(awk -F: '$7 ~ /(bash|zsh|ksh|sh|dash|fish)$/ && $3>0 && $3<1000 && $1!~/^(sync|shutdown|halt)$/{print $1}' /etc/passwd | tr '\n' ' ')
[ -n "$SHELLUSERS" ] && info "Users with interactive shell access" "$SHELLUSERS" "Keep shell access only for people who need it (use /sbin/nologin otherwise)" || pass "Interactive shell users" "None besides root"
[ -n "$SYSSHELL" ] && med "System accounts with a login shell" "$SYSSHELL" "Set the shell to /usr/sbin/nologin"

SUDOERS=$(getent group sudo wheel 2>/dev/null | cut -d: -f4 | tr ',' '\n' | sort -u | grep . | tr '\n' ' ')
[ -n "$SUDOERS" ] && info "Members of sudo/wheel" "$SUDOERS" "Verify each account is still needed" || pass "sudo/wheel members" "None"
NOPW=$(cat /etc/sudoers /etc/sudoers.d/* 2>/dev/null | grep -E '^[^#]*NOPASSWD' | head -5)
[ -n "$NOPW" ] && med "sudo rules without password" "$(printf '%s\n' "$NOPW" | tr '\n' ' ')" "Remove NOPASSWD unless strictly required (automation accounts)" || pass "sudo NOPASSWD" "No passwordless rules"

# authorized_keys audit
KEYRPT=""
while IFS=: read -r u _ uid _ _ home _; do
  [ "$uid" -lt 1000 ] && [ "$u" != "root" ] && continue
  af="$home/.ssh/authorized_keys"; [ -r "$af" ] || continue
  n=$(grep -Evc '^\s*(#|$)' "$af"); [ "$n" -gt 0 ] && KEYRPT="$KEYRPT $u:$n"
done < /etc/passwd
ROOTKEYS=0; [ -r /root/.ssh/authorized_keys ] && ROOTKEYS=$(grep -Evc '^\s*(#|$)' /root/.ssh/authorized_keys)
[ "$ROOTKEYS" -gt 0 ] && med "SSH keys authorised for root" "$ROOTKEYS key(s) in /root/.ssh/authorized_keys" "Verify every key is known and required" || pass "Root authorized_keys" "No keys"
[ -n "$KEYRPT" ] && info "Authorised SSH keys per user" "$KEYRPT" "Review periodically and remove stale keys"

# password policy
if [ -r /etc/login.defs ]; then
  MAXD=$(awk '$1=="PASS_MAX_DAYS"{print $2}' /etc/login.defs); MINL=$(awk '$1=="PASS_MIN_LEN"{print $2}' /etc/login.defs)
  { [ -z "$MAXD" ] || [ "$MAXD" -gt 365 ]; } 2>/dev/null && low "No password expiry policy" "PASS_MAX_DAYS=${MAXD:-unset}" "Set PASS_MAX_DAYS to 90-365 in /etc/login.defs" || pass "Password max age" "PASS_MAX_DAYS=$MAXD"
fi
if [ -d /etc/security ] && ! grep -rqsE 'pam_pwquality|pam_cracklib|pam_passwdqc' /etc/pam.d/; then
  low "No password-strength PAM module" "pam_pwquality/pam_cracklib not configured" "Install libpam-pwquality and enforce minlen/complexity"
fi

# MAC
if have getenforce; then
  M=$(getenforce 2>/dev/null); case "$M" in Enforcing) pass "SELinux" "Enforcing";; Permissive) low "SELinux is permissive" "Not enforcing" "setenforce 1 and set SELINUX=enforcing";; *) low "SELinux disabled" "$M" "Enable if the software stack supports it";; esac
elif [ -d /sys/kernel/security/apparmor ] || have aa-status; then
  pass "AppArmor" "$(aa-status --enabled >/dev/null 2>&1 && echo enabled || echo 'present')"
else low "No mandatory access control" "Neither SELinux nor AppArmor active" "Consider enabling one"; fi
fi

# =============================================================================
#  5. KERNEL, UPDATES, REBOOT
# =============================================================================
if ! skipped updates; then
section "Updates & Kernel"
[ "$REFRESH" -eq 1 ] && [ "$IS_ROOT" -eq 1 ] && { [ "$QUIET" -eq 0 ] && echo "  Refreshing package metadata..."
  case "$PKG" in apt) run_to 180 apt-get update -qq >"$WORK/refresh.log" 2>&1 ;; dnf|yum) run_to 180 "$PKG" -q makecache >"$WORK/refresh.log" 2>&1 ;; esac
  grep -Eiq '^(Err|E:)|error' "$WORK/refresh.log" 2>/dev/null && med "Package repository errors" "$(grep -Ei '^(Err|E:)|error' "$WORK/refresh.log" | head -3 | tr '\n' ' ')" "Fix repositories before relying on update status"; }

UPD_TOTAL=""; UPD_SEC=""; UPD_KERN=""
case "$PKG" in
  apt)
    SIM=$(run_to 120 apt-get -s dist-upgrade 2>/dev/null | grep '^Inst')
    UPD_TOTAL=$(printf '%s\n' "$SIM" | grep -c .); UPD_SEC=$(printf '%s\n' "$SIM" | grep -ci security); UPD_KERN=$(printf '%s\n' "$SIM" | grep -c '^Inst linux-image');;
  dnf|yum)
    run_to 180 "$PKG" -q check-update >"$WORK/upd.txt" 2>/dev/null; rc=$?
    if [ $rc -eq 100 ]; then
      UPD_TOTAL=$(awk 'NF>=3 && $1 ~ /\.[a-z0-9_]+$/' "$WORK/upd.txt" | wc -l)
      UPD_KERN=$(grep -c '^kernel' "$WORK/upd.txt")
      run_to 180 "$PKG" -q check-update --security >"$WORK/sec.txt" 2>/dev/null; [ $? -eq 100 ] && UPD_SEC=$(awk 'NF>=3 && $1 ~ /\.[a-z0-9_]+$/' "$WORK/sec.txt" | wc -l) || UPD_SEC=0
    elif [ $rc -eq 0 ]; then UPD_TOTAL=0; UPD_SEC=0; UPD_KERN=0; fi;;
esac
if [ -z "$UPD_TOTAL" ]; then info "Package updates" "Could not determine (package manager unavailable or check failed)"
else
  meta "Pending updates" "$UPD_TOTAL total, ${UPD_SEC:-0} security"
  if   [ "${UPD_SEC:-0}" -gt 0 ]; then high "Security updates available" "${UPD_SEC} security update(s) pending ($UPD_TOTAL total)" "Apply updates (apt upgrade / dnf update --security) in a maintenance window"
  elif [ "$UPD_TOTAL" -gt 0 ]; then low "Package updates available" "$UPD_TOTAL update(s) pending" "Apply during regular maintenance"
  else pass "Package updates" "System is up to date (based on $([ "$REFRESH" -eq 1 ] && echo refreshed || echo cached) package metadata)"; fi
  [ "${UPD_KERN:-0}" -gt 0 ] && med "Kernel update available" "$UPD_KERN kernel package(s) pending" "Update and reboot to load the new kernel"
fi

# newer kernel installed but not running / reboot required
LATEST=""
if [ "$FAMILY" = "debian" ]; then LATEST=$(ls -1 /boot/vmlinuz-* 2>/dev/null | sed 's|.*/vmlinuz-||' | sort -V | tail -1)
elif have rpm; then LATEST=$(rpm -q kernel --qf '%{VERSION}-%{RELEASE}.%{ARCH}\n' 2>/dev/null | grep -v 'not installed' | sort -V | tail -1); fi
if [ -n "$LATEST" ] && [ "$LATEST" != "$KERNEL" ] && [ "$(printf '%s\n%s\n' "$KERNEL" "$LATEST" | sort -V | tail -1)" = "$LATEST" ]; then
  if have kcarectl; then info "Newer kernel installed than running" "running $KERNEL, installed $LATEST (KernelCare detected)"
  else med "Reboot needed to load newer kernel" "running $KERNEL, installed $LATEST" "Schedule a reboot"; fi
else pass "Running kernel" "$KERNEL is the newest installed"; fi
[ -f /var/run/reboot-required ] && med "System reboot required" "$(tr '\n' ' ' < /var/run/reboot-required.pkgs 2>/dev/null | cut -c1-120)" "Reboot to finish applying updates"
if [ "$FAMILY" = "rhel" ] && have needs-restarting; then needs-restarting -r >/dev/null 2>&1 || med "System reboot required" "needs-restarting reports a reboot is needed" "Reboot to finish applying updates"; fi

# automatic updates
AU="unknown"
if [ "$FAMILY" = "debian" ]; then
  if dpkg -s unattended-upgrades >/dev/null 2>&1 && grep -qs 'Unattended-Upgrade "1"' /etc/apt/apt.conf.d/20auto-upgrades; then AU=yes; else AU=no; fi
elif [ "$FAMILY" = "rhel" ]; then
  if svc_enabled dnf-automatic.timer || svc_enabled dnf-automatic-install.timer || grep -qs 'apply_updates *= *yes' /etc/dnf/automatic.conf || [ -d /usr/local/cpanel ]; then AU=yes; else AU=no; fi
fi
case "$AU" in yes) pass "Automatic security updates" "Enabled";; no) low "Automatic security updates not enabled" "unattended-upgrades / dnf-automatic not active" "Enable automatic security updates (test on staging first for production panels)";; esac

# repos
if [ "$FAMILY" = "rhel" ] && [ "$OS_ID" = "centos" ]; then high "CentOS is EOL" "CentOS $OS_VER no longer receives updates" "Migrate to AlmaLinux/Rocky Linux/CloudLinux"; fi

# time sync
if have timedatectl && [ "$(timedatectl show -p NTPSynchronized --value 2>/dev/null)" = "yes" ]; then pass "Time synchronisation" "Clock is NTP-synchronised"
elif svc_active chronyd || svc_active chrony || svc_active ntpd || svc_active ntp || svc_active systemd-timesyncd; then pass "Time synchronisation" "time service running"
else low "Time synchronisation not confirmed" "No active NTP service detected" "Install/enable chrony or systemd-timesyncd (needed for logs & TLS)"; fi
fi

# =============================================================================
#  6. FIREWALL & NETWORK
# =============================================================================
if ! skipped firewall; then
section "Firewall & Brute-force Protection"
FW=""
if have ufw && ufw status 2>/dev/null | grep -qi '^Status: active'; then FW="$FW ufw"; fi
svc_active firewalld && FW="$FW firewalld"
if [ -x /usr/sbin/csf ] || have csf; then [ ! -f /etc/csf/csf.disable ] && FW="$FW csf"; fi
have apf && FW="$FW apf"
IPT=0; have iptables && IPT=$(iptables -S 2>/dev/null | grep -c '^-A'); [ "${IPT:-0}" -gt 3 ] && FW="$FW iptables($IPT rules)"
NFT=0; have nft && NFT=$(nft list ruleset 2>/dev/null | grep -c ' accept\| drop\| reject'); [ "${NFT:-0}" -gt 2 ] && FW="$FW nftables"
if [ -n "$FW" ]; then pass "Active firewall" "$FW"
elif [ "$IS_ROOT" -eq 0 ]; then info "Active firewall" "Cannot verify without root"
else high "No active host firewall detected" "ufw/firewalld/CSF/iptables/nftables show no rules" "Enable a firewall and allow only required inbound ports"; fi

# CSF details
if [ -x /usr/sbin/csf ] || [ -d /etc/csf ]; then
  if [ -f /etc/csf/csf.disable ]; then high "CSF is installed but disabled" "/etc/csf/csf.disable exists" "csf -e to enable CSF and lfd"
  else pass "CSF firewall" "Enabled"; fi
  if [ -r /etc/csf/csf.conf ]; then
    T=$(sed -n 's/^TESTING *= *"\{0,1\}\([01]\)"\{0,1\}.*/\1/p' /etc/csf/csf.conf | head -1)
    [ "$T" = "1" ] && high "CSF testing mode is ON" "TESTING=1 - rules are flushed every few minutes" "Set TESTING=\"0\" and restart CSF" || pass "CSF testing mode" "Off"
    TCPIN=$(sed -n 's/^TCP_IN *= *"\(.*\)".*/\1/p' /etc/csf/csf.conf | head -1)
    RISKY=$(echo "$TCPIN" | tr ',' '\n' | grep -xE '23|3306|5432|6379|27017|11211|9200|2375|5900|111|445|139' | tr '\n' ' ')
    [ -n "$RISKY" ] && med "CSF allows risky inbound ports" "$RISKY" "Remove database/admin ports from TCP_IN; use SSH tunnels or allow-listed IPs" 
    info "CSF TCP_IN ports" "$TCPIN" "Remove ports that are not needed"
  fi
  svc_active lfd && pass "LFD (login failure daemon)" "Running" || med "LFD is not running" "lfd service inactive" "systemctl enable --now lfd"
fi

# fail2ban
if have fail2ban-client; then
  if svc_active fail2ban; then
    J=$(fail2ban-client status 2>/dev/null | sed -n 's/.*Jail list:[ \t]*//p' | tr -d ',' )
    pass "Fail2Ban" "Running; jails: ${J:-none}"
    [ -z "$J" ] && low "Fail2Ban has no jails" "no active jails" "Enable at least the sshd jail"
  else med "Fail2Ban installed but not running" "service inactive" "systemctl enable --now fail2ban"; fi
elif [ ! -d /etc/csf ]; then low "No brute-force protection tool" "Neither Fail2Ban nor CSF/lfd found" "Install fail2ban (or CSF/lfd on hosting servers)"; fi
fi

if ! skipped network; then
section "Network Exposure"
if have ss; then
  LISTEN=$(ss -H -tuln 2>/dev/null || ss -tuln 2>/dev/null | tail -n +2)
  PUB=$(printf '%s\n' "$LISTEN" | awk '{a=$5; n=split(a,p,":"); port=p[n]; addr=substr(a,1,length(a)-length(port)-1)
        if (addr=="0.0.0.0"||addr=="*"||addr=="[::]"||addr=="::") print $1"/"port}' | sort -u | tr '\n' ' ')
  info "Ports listening on all interfaces" "${PUB:-none}" "Every open port should be intentional and firewalled"
  BAD=""
  for pp in 23/tcp:telnet 2375/tcp:docker-api 6379/tcp:redis 27017/tcp:mongodb 11211/tcp:memcached 9200/tcp:elasticsearch 5900/tcp:vnc 111/tcp:rpcbind 3306/tcp:mysql 5432/tcp:postgres 445/tcp:smb 139/tcp:netbios 69/udp:tftp 161/udp:snmp; do
    key=${pp%%:*}; nm=${pp##*:}; proto=${key##*/}; port=${key%%/*}
    printf '%s\n' "$PUB" | tr ' ' '\n' | grep -qx "$proto/$port" && BAD="$BAD $nm($port)"
  done
  [ -n "$BAD" ] && high "Sensitive services exposed on all interfaces" "$BAD" "Bind these to 127.0.0.1/private IPs or block them in the firewall" || pass "Sensitive services" "No databases/admin services listening publicly"
else info "Listening ports" "ss not available"; fi

# SYN backlog (replaces netstat use)
if have ss; then
  SYNR=$(ss -H -tn state syn-recv 2>/dev/null | grep -c .); SYNS=$(ss -H -tn state syn-sent 2>/dev/null | grep -c .)
  [ "${SYNR:-0}" -gt "$SYN_RECV_THRESHOLD" ] && high "Possible inbound SYN flood" "$SYNR half-open inbound connections" "Enable tcp_syncookies, rate-limit at the firewall/CDN" || pass "Inbound half-open connections" "${SYNR:-0}"
  [ "${SYNS:-0}" -gt "$SYN_SENT_THRESHOLD" ] && high "Excessive outbound SYN_SENT connections" "$SYNS - possible outbound scanning/DDoS from this host" "Check processes with ss -tnp state syn-sent" || pass "Outbound SYN_SENT connections" "${SYNS:-0}"
fi

# sysctl hardening
BADS=""
chk_sysctl() { local v; v=$(sysctl -n "$1" 2>/dev/null) || return; [ -z "$v" ] && return
  case " $2 " in *" $v "*) ;; *) BADS="$BADS $1=$v(want ${2// /|})" ;; esac; }
chk_sysctl net.ipv4.tcp_syncookies "1"; chk_sysctl net.ipv4.conf.all.accept_redirects "0"
chk_sysctl net.ipv4.conf.all.send_redirects "0"; chk_sysctl net.ipv4.conf.all.accept_source_route "0"
chk_sysctl net.ipv4.conf.all.rp_filter "1 2"; chk_sysctl net.ipv4.icmp_echo_ignore_broadcasts "1"
chk_sysctl kernel.randomize_va_space "2"; chk_sysctl fs.protected_hardlinks "1"; chk_sysctl fs.protected_symlinks "1"
chk_sysctl kernel.kptr_restrict "1 2"; chk_sysctl kernel.dmesg_restrict "1"
NB=$(echo $BADS | wc -w)
if   [ "$NB" -ge 5 ]; then med "Kernel/network hardening gaps" "$BADS" "Set these in /etc/sysctl.d/99-hardening.conf and run sysctl --system"
elif [ "$NB" -gt 0 ]; then low "Kernel/network hardening gaps" "$BADS" "Set these in /etc/sysctl.d/99-hardening.conf"
else pass "Kernel/network sysctl hardening" "All checked parameters are hardened"; fi
[ "$(sysctl -n net.ipv4.ip_forward 2>/dev/null)" = "1" ] && info "IP forwarding enabled" "net.ipv4.ip_forward=1" "Expected for routers/Docker/VPN hosts; otherwise disable"

# risky/legacy services
LEG=""
for s in telnet.socket telnetd rsh.socket rlogin.socket rexec.socket tftp.socket tftpd-hpa xinetd avahi-daemon cups rpcbind nfs-server smbd; do svc_active "$s" && LEG="$LEG ${s%.socket}"; done
[ -n "$LEG" ] && low "Unnecessary/legacy services running" "$LEG" "Disable services you do not use (systemctl disable --now)" || pass "Legacy services" "None of telnet/rsh/tftp/xinetd/avahi/cups/rpcbind/nfs/samba running"
if [ "$FAMILY" = "debian" ]; then SL="apache2 nginx bind9 postfix exim4 vsftpd mysql mariadb postgresql php-fpm dovecot pure-ftpd proftpd pdns lsws docker redis-server"; else SL="httpd nginx named postfix exim vsftpd mysqld mariadb postgresql php-fpm dovecot pure-ftpd proftpd pdns lsws docker redis"; fi
RUN=""; for s in $SL; do svc_active "$s" && RUN="$RUN $s"; done
info "Key services running" "${RUN:-none detected}"
fi

# =============================================================================
#  7. MALWARE & INTRUSION INDICATORS
# =============================================================================
if ! skipped malware; then
section "Malware & Intrusion Indicators"
CRONHITS=""
for cd in /var/spool/cron /var/spool/cron/crontabs /etc/cron.d /etc/cron.hourly /etc/cron.daily; do
  [ -d "$cd" ] || continue
  H=$(grep -rIHE '^[^#]*(/var/tmp/|/tmp/|/dev/shm/|base64 +-d|base64 +--decode|(curl|wget)[^|;]*\|[ ]*(ba)?sh)' "$cd" 2>/dev/null | cut -c1-160 | head -5)
  [ -n "$H" ] && CRONHITS="$CRONHITS$H"$'\n'
done
if [ -n "$CRONHITS" ]; then crit "Suspicious cron entries" "$(printf '%s' "$CRONHITS" | head -5)" "Inspect the cron files, remove malicious entries, and hunt for the dropper (often perl/PHP in /tmp, /var/tmp)"
else pass "Cron malware indicators" "No cron entries referencing /tmp, /dev/shm, base64 or curl|sh"; fi

# processes running from temp dirs / deleted binaries
PR_TMP=""; PR_MEMFD=""; PR_DEL=""
for p in /proc/[0-9]*; do e=$(readlink "$p/exe" 2>/dev/null) || continue; pid=${p#/proc/}
  case "$e" in
    /tmp/*|/var/tmp/*|/dev/shm/*) PR_TMP="$PR_TMP $pid:$e" ;;
    /memfd:*) PR_MEMFD="$PR_MEMFD $pid:${e%% (deleted)}" ;;
    *"(deleted)") PR_DEL="$PR_DEL $pid:${e%% (deleted)}" ;;
  esac
done
[ -n "$PR_TMP" ]   && high "Processes running from temp directories" "$(echo $PR_TMP | cut -c1-300)" "Investigate immediately (ls -l /proc/PID/exe, lsof -p PID) - classic malware/miner pattern" || pass "Processes in temp directories" "None executing from /tmp, /var/tmp or /dev/shm"
[ -n "$PR_MEMFD" ] && med  "Processes running from memory-only (memfd) binaries" "$(echo $PR_MEMFD | cut -c1-300)" "Usually benign (container runtimes, some agents) but also used by fileless malware - verify each one"
[ -n "$PR_DEL" ]   && low  "Processes using deleted/updated binaries" "$(echo $PR_DEL | cut -c1-300)" "Restart these services (needrestart / needs-restarting -s) so security updates take effect"
# scanners present
SC=""; have clamscan && SC="$SC clamav"; have maldet && SC="$SC maldet"; have rkhunter && SC="$SC rkhunter"; have chkrootkit && SC="$SC chkrootkit"; have imunify360-agent && SC="$SC imunify360"
if [ -n "$SC" ]; then pass "Malware/rootkit scanners installed" "$SC"
elif [ "$PANEL" != "None detected" ]; then med "No malware scanner installed" "clamav/maldet/rkhunter/imunify not found" "Install ClamAV + LMD (or Imunify) and schedule scans"
else low "No malware scanner installed" "clamav/rkhunter not found" "Install ClamAV or rkhunter for periodic scans"; fi
if have maldet; then
  { [ -e /etc/cron.daily/maldet ] || [ -e /etc/cron.d/maldet_pub ]; } && pass "LMD scheduled scans" "cron job present" || low "LMD has no scheduled scan" "No maldet cron job found" "Re-run the LMD installer or add a cron entry"
fi
if have auditctl; then
  if svc_active auditd; then pass "auditd" "Running"; else low "auditd installed but not running" "audit daemon inactive" "Enable auditd for tamper-evident logging"; fi
else low "auditd not installed" "No kernel audit logging" "Install auditd on sensitive servers"; fi

# rkhunter run
if have rkhunter; then
  DO=0; [ "$RUN_RKH" = "yes" ] && DO=1
  [ "$DO" -eq 0 ] && [ -z "$ASSUME" ] && ask_yes "Run an rkhunter scan now? (may take several minutes)" && DO=1
  [ "$ASSUME" = "yes" ] && DO=1
  if [ "$DO" -eq 1 ]; then
    [ "$QUIET" -eq 0 ] && echo "  Running rkhunter (warnings only)..."
    run_to 900 rkhunter --check --sk --rwo --nocolors >"$WORK/rkh.txt" 2>&1
    RW=$(grep -c 'Warning' "$WORK/rkh.txt")
    [ "$RW" -gt 0 ] && high "rkhunter reported warnings" "$RW warning(s): $(grep 'Warning' "$WORK/rkh.txt" | head -4 | tr '\n' ' ')" "Review /var/log/rkhunter.log - some warnings are false positives after package updates" || pass "rkhunter scan" "No warnings"
  else info "rkhunter scan" "Not run (use --rkhunter to include it)"; fi
fi
fi

# =============================================================================
#  8. WEB SERVERS
# =============================================================================
if ! skipped web; then
section "Web Servers"
APACHE_BIN=""; for b in apachectl httpd apache2ctl apache2; do have $b && APACHE_BIN=$b && break; done
if [ -n "$APACHE_BIN" ]; then
  ACONF=""; for d in /etc/apache2 /etc/httpd /usr/local/apache/conf /etc/apache2/conf; do [ -d "$d" ] && ACONF="$ACONF $d"; done
  # Options ... Indexes (ignoring comments and -Indexes)
  IDX=$(grep -rhIE '^[[:space:]]*Options[[:space:]]' $ACONF 2>/dev/null | sed 's/#.*//' | awk '{for(i=2;i<=NF;i++) if($i=="Indexes"||$i=="+Indexes"){print "x"; exit}}' | head -1)
  [ -n "$IDX" ] && med "Apache directory listing enabled" "An 'Options Indexes' directive is active in the Apache configuration" "Use 'Options -Indexes' globally and per-vhost" || pass "Apache directory listing" "No enabling 'Indexes' option found"
  ST=$(grep -rhIiE '^[[:space:]]*ServerTokens[[:space:]]' $ACONF 2>/dev/null | tail -1 | awk '{print $2}')
  case "${ST,,}" in prod|productonly|minor|minimal) pass "Apache ServerTokens" "$ST";; *) low "Apache reveals version details" "ServerTokens ${ST:-Full (default)}" "Set ServerTokens Prod and ServerSignature Off";; esac
  MODS=$($APACHE_BIN -M 2>/dev/null)
  if echo "$MODS" | grep -qiE 'security2_module|security3'; then pass "Apache ModSecurity (WAF)" "Loaded"
  else med "ModSecurity (WAF) not loaded in Apache" "security2_module missing" "Enable ModSecurity with the OWASP Core Rule Set"; fi
  echo "$MODS" | grep -q 'status_module' && grep -rhIE '^[[:space:]]*<Location[[:space:]]+/server-(status|info)' $ACONF 2>/dev/null | grep -q . && low "Apache server-status/info exposed" "" "Restrict /server-status to localhost"
else info "Apache" "Not installed"; fi

if have nginx; then
  NCONF=$(nginx -T 2>/dev/null); [ -z "$NCONF" ] && NCONF=$(cat /etc/nginx/nginx.conf /etc/nginx/conf.d/*.conf /etc/nginx/sites-enabled/* 2>/dev/null)
  printf '%s\n' "$NCONF" | sed 's/#.*//' | grep -Eq '^[[:space:]]*autoindex[[:space:]]+on[[:space:]]*;' && med "Nginx directory listing enabled" "autoindex on;" "Remove autoindex on (or set off)" || pass "Nginx directory listing" "autoindex not enabled"
  printf '%s\n' "$NCONF" | sed 's/#.*//' | grep -Eq 'server_tokens[[:space:]]+off' || low "Nginx reveals its version" "server_tokens not set to off" "Add server_tokens off; in the http block"
  { nginx -V 2>&1 | grep -qi modsecurity || printf '%s\n' "$NCONF" | grep -qi 'modsecurity'; } && pass "Nginx ModSecurity" "Enabled" || low "Nginx has no WAF module" "ModSecurity not detected" "Consider ModSecurity v3 or a CDN/WAF"
else info "Nginx" "Not installed"; fi

# LiteSpeed
VH=/usr/local/lsws/conf/vhosts
if [ -d "$VH" ]; then
  LSBAD=""; LSN=0
  for f in "$VH"/*/vhconf.conf; do [ -f "$f" ] || continue; d=$(basename "$(dirname "$f")"); [ "$d" = "Example" ] && continue; LSN=$((LSN+1))
    v=$(awk '/autoIndex/{print $2; exit}' "$f"); [ "${v:-1}" != "0" ] && LSBAD="$LSBAD $d"; done
  [ -n "$LSBAD" ] && med "LiteSpeed directory listing (autoIndex) not disabled" "$(echo $LSBAD | cut -c1-300)" "Set autoIndex 0 in each vhost" || pass "LiteSpeed directory listing" "Disabled for $LSN vhost(s)"
  if [ -d /usr/local/cpanel ]; then svc_active lsws && pass "LiteSpeed service" "running" || med "LiteSpeed installed but not running" "lsws inactive" "systemctl start lsws"; fi
fi
fi

# =============================================================================
#  9. PHP
# =============================================================================
if ! skipped php; then
section "PHP Configuration"
shopt -s nullglob
INIS=( /etc/php.ini /etc/php/*/apache2/php.ini /etc/php/*/fpm/php.ini /etc/php/*/cli/php.ini /etc/opt/remi/php*/php.ini
       /opt/cpanel/ea-php*/root/etc/php.ini /opt/alt/php*/etc/php.ini /usr/local/php*/lib/php.ini /opt/plesk/php/*/etc/php.ini )
shopt -u nullglob
if [ ${#INIS[@]} -eq 0 ]; then info "PHP" "No php.ini files found"; else
  L_DF=""; L_FOPEN=""; L_INC=""; L_EXP=""; L_ERR=""; L_EOL=""
  for ini in "${INIS[@]}"; do
    [ -f "$ini" ] || continue
    lbl=$(echo "$ini" | sed -E 's#/root/etc/php.ini##; s#/etc/php.ini##; s#/lib/php.ini##; s#/php.ini##; s#.*/(ea-php[0-9]+|php[0-9.]+|alt|[0-9.]+/(apache2|fpm|cli))$#\1#; s#^/etc$#system#')
    [ -z "$lbl" ] && lbl="$ini"
    [ -z "$(ini_val "$ini" disable_functions)" ] && L_DF="$L_DF $lbl"
    [ "$(ini_val "$ini" allow_url_fopen | tr 'A-Z' 'a-z')" != "off" ] && [ "$(ini_val "$ini" allow_url_fopen)" != "0" ] && L_FOPEN="$L_FOPEN $lbl"
    case "$(ini_val "$ini" allow_url_include | tr 'A-Z' 'a-z')" in on|1|true|yes) L_INC="$L_INC $lbl";; esac
    case "$(ini_val "$ini" expose_php | tr 'A-Z' 'a-z')" in off|0) ;; *) L_EXP="$L_EXP $lbl";; esac
    case "$(ini_val "$ini" display_errors | tr 'A-Z' 'a-z')" in on|1|true|stdout) L_ERR="$L_ERR $lbl";; esac
    # version from path
    v=$(echo "$ini" | grep -Eo 'php[-]?[0-9]{2}|ea-php[0-9]{2}|/php/[0-9]\.[0-9]|php[0-9]\.[0-9]|/opt/alt/php[0-9]{2}' | grep -Eo '[0-9]\.[0-9]|[0-9]{2}' | head -1)
    case "$v" in ??) v="${v:0:1}.${v:1:1}" ;; esac
    [ -n "$v" ] && [ "$(printf '%s\n%s\n' "$v" "$PHP_MIN_SUPPORTED" | sort -V | head -1)" != "$PHP_MIN_SUPPORTED" ] && L_EOL="$L_EOL $lbl($v)"
  done
  N=${#INIS[@]}
  [ -n "$L_DF" ]    && med  "PHP disable_functions not set" "$(echo $L_DF | cut -c1-300)" "Disable exec,passthru,shell_exec,system,proc_open,popen unless needed" || pass "PHP disable_functions" "Set in all $N php.ini file(s)"
  [ -n "$L_INC" ]   && high "PHP allow_url_include is On" "$(echo $L_INC | cut -c1-300)" "Set allow_url_include = Off" || pass "PHP allow_url_include" "Off everywhere"
  [ -n "$L_FOPEN" ] && low  "PHP allow_url_fopen is On" "$(echo $L_FOPEN | cut -c1-300)" "Set allow_url_fopen = Off where applications allow" || pass "PHP allow_url_fopen" "Off everywhere"
  [ -n "$L_EXP" ]   && low  "PHP expose_php is On" "$(echo $L_EXP | cut -c1-300)" "Set expose_php = Off" || pass "PHP expose_php" "Off everywhere"
  [ -n "$L_ERR" ]   && low  "PHP display_errors is On" "$(echo $L_ERR | cut -c1-300)" "Set display_errors = Off in production and log errors instead"
  [ -n "$L_EOL" ]   && high "End-of-life PHP versions installed" "$(echo $L_EOL | cut -c1-300) (minimum supported: $PHP_MIN_SUPPORTED)" "Upgrade sites to a supported PHP branch and remove old versions"
fi
fi

# =============================================================================
# 10. CLOUDLINUX
# =============================================================================
if [ "$IS_CLOUDLINUX" -eq 1 ] && ! skipped cloudlinux; then
section "CloudLinux"
if have cagefsctl; then
  DIS=$(cagefsctl --list-disabled 2>/dev/null | tr '\n' ' ')
  [ -z "${DIS// /}" ] && pass "CageFS" "Enabled for all users" || med "CageFS disabled for some users" "$DIS" "Enable CageFS for all users: cagefsctl --enable-all"
else med "CageFS not installed" "cagefsctl missing" "Install CageFS for user isolation"; fi
if have dbctl; then
  dbctl list 2>&1 | grep -qE "Can't connect to socket|governor is not started" && med "MySQL Governor problem" "dbctl cannot reach the governor" "Check the db_governor service" || pass "MySQL Governor" "Responding"
else low "MySQL Governor not installed" "dbctl missing" "Install governor-mysql to throttle abusive DB users"; fi
fi

# =============================================================================
# 11. cPanel / WHM
# =============================================================================
if [ -d /usr/local/cpanel ] && ! skipped cpanel; then
section "cPanel / WHM"
[ -f /var/cpanel/disable_whm_terminal_ui ] && pass "WHM Terminal" "Disabled" || low "WHM Terminal is enabled" "/var/cpanel/disable_whm_terminal_ui absent" "Disable WHM Terminal if not needed"
if [ -x /usr/local/cpanel/scripts/restartsrv_cphulkd ]; then
  /usr/local/cpanel/scripts/restartsrv_cphulkd --status 2>&1 | grep -q "is running" && pass "cPHulk brute-force protection" "Running" || med "cPHulk is not running" "cphulkd inactive" "Enable cPHulk in WHM > Security Center"
fi
[ -f /usr/local/cpanel/version ] && meta "cPanel version" "$(cat /usr/local/cpanel/version)"
# manual checklist (from the original script, de-duplicated)
checklist "cPanel/WHM" "WHM > Security Center > Run cPanel Security Advisor and apply its recommendations"
checklist "cPanel/WHM" "WHM > Security Center > Enable mod_userdir Protection"
checklist "cPanel/WHM" "WHM > Security Center > Enable SMTP Restrictions"
checklist "cPanel/WHM" "WHM > Security Center > Disable Compiler Access"
checklist "cPanel/WHM" "WHM > Security Center > Configure Security Policies"
checklist "cPanel/WHM" "WHM > Security Center > Host Access Control: restrict WHM and SSH port access"
checklist "cPanel/WHM" "WHM > Security Center > Enable OWASP ModSecurity Rule Set"
checklist "cPanel/WHM" "WHM > Security Center > Enable Shell Fork Bomb Protection"
checklist "cPanel/WHM" "WHM > Service Configuration > Apache Configuration > Global Configuration: enable Symlink Protection and tune Keep-Alive"
checklist "cPanel/WHM" "WHM > Exim Configuration Manager: enable Dictionary attack protection"
checklist "cPanel/WHM" "WHM > Exim Configuration Manager: Reject remote mail sent to the server's hostname"
checklist "cPanel/WHM" "WHM > Exim Configuration Manager: Reference /etc/mailips for custom IP on outgoing SMTP"
checklist "cPanel/WHM" "WHM > Exim Configuration Manager: enable System Filter File"
checklist "cPanel/WHM" "WHM > Exim Configuration Manager: Set SMTP Sender headers"
checklist "cPanel/WHM" "WHM > Exim Configuration Manager: enable Custom RBLs"
checklist "cPanel/WHM" "WHM > Exim Configuration Manager: Scan outgoing messages for malware"
checklist "cPanel/WHM" "WHM > FTP Server Configuration: disable Anonymous Logins and Anonymous Uploads"
checklist "cPanel/WHM" "WHM > FTP Server Configuration: disable Logins with Root Password"
checklist "cPanel/WHM" "WHM > SSL/TLS > Manage AutoSSL: enable AutoSSL for all users"
checklist "cPanel/WHM" "WHM > System Health: enable Background Process Killer"
checklist "cPanel/WHM" "WHM > Plugins > ConfigServer Security & Firewall: run Check Server Security and fix findings"
checklist "cPanel/WHM" "WHM > Tweak Settings: enable DKIM and SPF for new accounts"
checklist "cPanel/WHM" "WHM > Tweak Settings: set Max hourly emails per domain"
checklist "cPanel/WHM" "WHM > Tweak Settings: set default/catch-all forwarder destination to Fail"
checklist "cPanel/WHM" "WHM > Tweak Settings: enable Track email origin via X-Source headers"
checklist "cPanel/WHM" "WHM > Tweak Settings: Restrict outgoing SMTP to root, exim and mailman"
checklist "cPanel/WHM" "WHM > Tweak Settings: Prevent 'nobody' from sending mail"
checklist "cPanel/WHM" "WHM > Tweak Settings: enable Apache SpamAssassin"
checklist "cPanel/WHM" "WHM > Tweak Settings: enable Blank referrer safety check and Referrer safety check"

# CSI (remote script) - explicit opt-in only
DO=0; [ "$RUN_CSI" = "yes" ] && DO=1
if [ "$DO" -eq 0 ] && [ -z "$ASSUME" ]; then
  echo "  NOTE: cPanel CSI is downloaded from GitHub and executed as root. Review it first if unsure."
  ask_yes "Download and run cPanel CSI (CpanelInc/tech-CSI) now?" && DO=1
fi
if [ "$DO" -eq 1 ] && have curl && [ -x /usr/local/cpanel/3rdparty/bin/perl ]; then
  if curl -fsSL --max-time 60 https://raw.githubusercontent.com/CpanelInc/tech-CSI/master/csi.pl -o "$WORK/csi.pl"; then
    SUM=$(sha256sum "$WORK/csi.pl" | awk '{print $1}')
    [ "$QUIET" -eq 0 ] && echo "  CSI downloaded, sha256 $SUM"
    /usr/local/cpanel/3rdparty/bin/perl "$WORK/csi.pl" 2>&1 | tee "$WORK/csi.out" | tail -n 40
    info "cPanel CSI executed" "sha256 $SUM; see terminal output" "Review CSI output and act on any findings"
  else med "cPanel CSI download failed" "could not fetch csi.pl" "Run CSI manually"; fi
fi
fi

# =============================================================================
# 12. MAIL
# =============================================================================
if ! skipped mail; then
section "Mail"
QC=""; QN=""
if have exim; then QC=$(exim -bpc 2>/dev/null); QN=Exim
elif have postqueue; then QC=$(postqueue -p 2>/dev/null | grep -Ec '^[0-9A-F]{6,}[*!]?[[:space:]]'); QN=Postfix
elif have mailq; then QC=$(mailq 2>/dev/null | grep -Ec '^[0-9A-Za-z]{6,}[*!]?[[:space:]]'); QN=mailq; fi
if [ -z "$QC" ]; then info "Mail queue" "No local MTA found"
elif [ "$QC" -ge "$MAILQ_CRIT" ]; then high "Mail queue very large" "$QC messages ($QN)" "Look for compromised accounts/spam scripts (exim -bpr | grep '<' , check X-PHP-Script headers)"
elif [ "$QC" -ge "$MAILQ_WARN" ]; then med "Mail queue is large" "$QC messages ($QN)" "Check for delivery problems or outbound spam"
else pass "Mail queue" "$QC message(s) ($QN)"; fi
fi

# =============================================================================
# 13. DNS / RDNS
# =============================================================================
if ! skipped dns; then
section "DNS"
for ip in $(get_ips); do
  is_private_ip "$ip" && continue
  PTR=""; if have dig; then PTR=$(dig +short +time=3 +tries=1 -x "$ip" 2>/dev/null | head -1); elif have host; then PTR=$(host -W 3 "$ip" 2>/dev/null | awk '/pointer/{print $5}' | head -1); else info "PTR lookup" "dig/host not installed"; break; fi
  if [ -n "$PTR" ]; then pass "PTR record for $ip" "$PTR"
  elif svc_active exim || svc_active exim4 || svc_active postfix; then med "No PTR record for $ip" "Missing reverse DNS on a mail-sending host" "Ask your provider to set rDNS = server hostname"
  else low "No PTR record for $ip" "Missing reverse DNS" "Set rDNS with your provider"; fi
done
NC_FILE=""; for f in /etc/named.conf /etc/bind/named.conf.options /etc/bind/named.conf; do [ -f "$f" ] && NC_FILE="$f" && break; done
if [ -n "$NC_FILE" ] && { svc_active named || svc_active bind9; }; then
  if sed 's#//.*##; s/#.*//' "$NC_FILE" /etc/bind/named.conf.options 2>/dev/null | grep -Eq 'recursion[[:space:]]+no[[:space:]]*;|allow-recursion[[:space:]]*\{[^}]*(127\.0\.0\.1|localhost|localnets)'; then pass "DNS recursion" "Disabled or restricted"
  else med "DNS recursion appears open" "named allows recursion for any client" "Set recursion no; (or allow-recursion { trusted; }) to avoid being an open resolver (DDoS amplification)"; fi
fi
fi

# =============================================================================
# 14. TLS CERTIFICATES
# =============================================================================
if ! skipped tls && have openssl; then
section "TLS Certificates"
shopt -s nullglob
CERTS=( /etc/letsencrypt/live/*/cert.pem /var/cpanel/ssl/installed/certs/*.crt /etc/pki/tls/certs/localhost.crt /etc/ssl/certs/ssl-cert-snakeoil.pem /etc/nginx/ssl/*.crt /etc/apache2/ssl/*.crt /etc/httpd/ssl/*.crt )
shopt -u nullglob
EXP=""; SOON=""; NOK=0; NC=0
for c in "${CERTS[@]:0:300}"; do
  [ -r "$c" ] || continue; NC=$((NC+1))
  if ! openssl x509 -in "$c" -noout -checkend 0 >/dev/null 2>&1; then EXP="$EXP $(basename "$(dirname "$c")")/$(basename "$c")"
  elif ! openssl x509 -in "$c" -noout -checkend $((21*86400)) >/dev/null 2>&1; then SOON="$SOON $(basename "$(dirname "$c")")/$(basename "$c")"
  else NOK=$((NOK+1)); fi
done
if [ "$NC" -eq 0 ]; then info "TLS certificates" "No certificates in common locations"
else
  [ -n "$EXP" ]  && high "Expired TLS certificates" "$(echo $EXP | cut -c1-300)" "Renew immediately (AutoSSL / certbot renew)"
  [ -n "$SOON" ] && med  "TLS certificates expire within 21 days" "$(echo $SOON | cut -c1-300)" "Check that auto-renewal is working"
  [ -z "$EXP$SOON" ] && pass "TLS certificates" "$NC certificate(s) checked, none expiring within 21 days"
fi
fi

# =============================================================================
#  SUMMARY, HISTORY COMPARISON
# =============================================================================
END_EPOCH=$(date +%s); DURATION=$(( END_EPOCH - START_EPOCH ))

read -r N_CRIT N_HIGH N_MED N_LOW N_INFO N_PASS SCORE GRADE < <(awk -F'\t' '
  {c[$1]++}
  END { s=100-15*c["CRITICAL"]-8*c["HIGH"]-4*c["MEDIUM"]-1*c["LOW"]; if (s<0) s=0
        g=(s>=90)?"A":(s>=80)?"B":(s>=70)?"C":(s>=60)?"D":"F"
        printf "%d %d %d %d %d %d %d %s\n", c["CRITICAL"],c["HIGH"],c["MEDIUM"],c["LOW"],c["INFO"],c["PASS"],s,g }' "$FINDINGS")

# scan history: compare with the previous run on this host
if [ -z "$STATE_DIR" ]; then
  if [ "$IS_ROOT" -eq 1 ] && mkdir -p /var/lib/security-audit 2>/dev/null; then STATE_DIR=/var/lib/security-audit; else STATE_DIR="$HOME/.security-audit"; fi
fi
mkdir -p "$STATE_DIR" 2>/dev/null; chmod 700 "$STATE_DIR" 2>/dev/null
CUR="$WORK/current_issues.tsv"; PREV="$STATE_DIR/last_issues.tsv"
awk -F'\t' '$1=="CRITICAL"||$1=="HIGH"||$1=="MEDIUM"||$1=="LOW"{print $3"\t"$1}' "$FINDINGS" | sort -u > "$CUR"
if [ "$COMPARE" -eq 1 ] && [ -f "$PREV" ]; then
  PREV_DATE=$(date -r "$PREV" '+%Y-%m-%d %H:%M' 2>/dev/null)
  while IFS=$'\t' read -r t s; do
    printf 'NEW\tChanges\t%s\t%s\t\n' "$t" "New since $PREV_DATE (severity $s)" >> "$FINDINGS"
  done < <(awk -F'\t' 'NR==FNR{p[$1]=1; next} !($1 in p)' "$PREV" "$CUR")
  while IFS=$'\t' read -r t s; do
    printf 'RESOLVED\tChanges\t%s\t%s\t\n' "$t" "Resolved since $PREV_DATE (was $s)" >> "$FINDINGS"
  done < <(awk -F'\t' 'NR==FNR{c[$1]=1; next} !($1 in c)' "$CUR" "$PREV")
  meta "Compared with scan of" "$PREV_DATE"
fi
cp "$CUR" "$PREV" 2>/dev/null

meta "Scan finished" "$(date '+%Y-%m-%d %H:%M:%S %Z')"; meta "Scan duration" "${DURATION}s"
meta "Script version" "$VERSION"; meta "Run as" "$([ $IS_ROOT -eq 1 ] && echo root || id -un)"
meta "_score" "$SCORE"; meta "_grade" "$GRADE"; meta "_crit" "$N_CRIT"; meta "_high" "$N_HIGH"
meta "_med" "$N_MED"; meta "_low" "$N_LOW"; meta "_info" "$N_INFO"; meta "_pass" "$N_PASS"

# =============================================================================
#  REPORT WRITERS  (awk programs are written to the temp dir at run time)
# =============================================================================
cat > "$WORK/pdf.awk" <<'AWKEOF'
# Minimal dependency-free PDF writer: A4, Helvetica, wrapped text, coloured badges, page numbers.
function clean(s,  i,n,c,o){ o=""; n=length(s); for(i=1;i<=n;i++){ c=substr(s,i,1); o=o ((c in ORD)?c:"?") } return o }
function esc(s,  i,n,c,o){ o=""; n=length(s); for(i=1;i<=n;i++){ c=substr(s,i,1); if(c=="\\"||c=="("||c==")") o=o "\\" c; else o=o c } return o }
function strw(s,bold,size,  i,n,w){ w=0; n=length(s); for(i=1;i<=n;i++) w+=WID[ORD[substr(s,i,1)]]; return w*size/1000*(bold?1.09:1) }
function wrap(s,bold,size,maxw,  n,words,i,line,lw,sp,word,w,k){
  WN=0; line=""; lw=0; sp=strw(" ",bold,size); n=split(s,words," ")
  for(i=1;i<=n;i++){ word=words[i]; w=strw(word,bold,size)
    while(w>maxw){ if(line!=""){WL[++WN]=line; line=""; lw=0}
      k=length(word); while(k>1 && strw(substr(word,1,k),bold,size)>maxw) k--
      WL[++WN]=substr(word,1,k); word=substr(word,k+1); w=strw(word,bold,size) }
    if(word=="") continue
    if(line==""){line=word; lw=w} else if(lw+sp+w<=maxw){line=line " " word; lw+=sp+w} else {WL[++WN]=line; line=word; lw=w} }
  if(line!="") WL[++WN]=line; if(WN==0) WL[++WN]=""
}
function txt(font,size,x,yy,s,r,g,b){ PG=PG sprintf("%.3f %.3f %.3f rg BT /%s %.1f Tf %.2f %.2f Td (%s) Tj ET\n",r,g,b,font,size,x,yy,esc(s)) }
function rect(x,yy,w,h,r,g,b){ PG=PG sprintf("%.3f %.3f %.3f rg %.2f %.2f %.2f %.2f re f\n",r,g,b,x,yy,w,h) }
function box(x,yy,w,h,gr){ PG=PG sprintf("%.2f G 0.8 w %.2f %.2f %.2f %.2f re S\n",gr,x,yy,w,h) }
function hline(x1,x2,yy,gr){ PG=PG sprintf("%.2f G 0.5 w %.2f %.2f m %.2f %.2f l S\n",gr,x1,yy,x2,yy) }
function scol(s){ CR=0.5;CG=0.5;CB=0.55
  if(s=="CRITICAL"){CR=0.62;CG=0.05;CB=0.15} else if(s=="HIGH"){CR=0.86;CG=0.24;CB=0.10}
  else if(s=="MEDIUM"){CR=0.92;CG=0.55;CB=0.05} else if(s=="LOW"){CR=0.20;CG=0.47;CB=0.78}
  else if(s=="PASS"){CR=0.13;CG=0.58;CB=0.30} else if(s=="NEW"){CR=0.86;CG=0.24;CB=0.10} else if(s=="RESOLVED"){CR=0.13;CG=0.58;CB=0.30} }
function newpage(){ if(NP>0) PAGES[NP]=PG; NP++; PG=""; Y=H-M; if(NP>1){ rect(0,H-8,W,8,0.09,0.15,0.27); Y=H-M-8 } }
function ensure(h){ if(Y-h<M+24) newpage() }
function heading(t){ ensure(46); Y-=10; txt("F2",14,M,Y-12,t,0.09,0.15,0.27); Y-=18; hline(M,W-M,Y,0.75); Y-=12 }
function badge(x,yy,label,  w){ scol(label); w=54; rect(x,yy-2,w,12,CR,CG,CB); txt("F2",7,x+(w-strw(label,1,7))/2,yy+1.5,label,1,1,1) }
function finding(i,  tn,dn,rn,k,h,tw,j){
  tw=CW-64
  wrap(TTL[i],1,9.5,tw); tn=WN; for(k=1;k<=tn;k++) TL[k]=WL[k]
  wrap(DET[i],0,8.5,tw); dn=WN; if(dn>10){dn=10; WL[10]=WL[10] " ..."} for(k=1;k<=dn;k++) DL[k]=WL[k]
  rn=0; if(REC[i]!=""){ wrap("Fix: " REC[i],0,8.5,tw); rn=WN; if(rn>5){rn=5} for(k=1;k<=rn;k++) RL[k]=WL[k] }
  h=tn*12+dn*11+rn*11+10; ensure(h)
  badge(M,Y-9,SEV[i])
  for(k=1;k<=tn;k++){ txt("F2",9.5,M+64,Y-9,TL[k],0.1,0.1,0.12); Y-=12 }
  for(k=1;k<=dn;k++){ if(DL[k]!=""){ txt("F1",8.5,M+64,Y-8,DL[k],0.30,0.30,0.33) } Y-=11 }
  for(k=1;k<=rn;k++){ txt("F3",8.5,M+64,Y-8,RL[k],0.10,0.38,0.55); Y-=11 }
  Y-=8
}
function compact(i,  n,k,tw,line){
  tw=CW-64; line=TTL[i]; if(DET[i]!="") line=line ": " DET[i]
  wrap(line,0,8,tw); n=WN; if(n>3){n=3; WL[3]=WL[3] " ..."}
  ensure(n*10+4); badge(M,Y-8,SEV[i])
  for(k=1;k<=n;k++){ txt("F1",8,M+64,Y-7,WL[k],0.22,0.22,0.25); Y-=10 }
  Y-=3
}
BEGIN{
  FS="\t"; W=595; H=842; M=42; CW=W-2*M
  for(i=32;i<=126;i++) ORD[sprintf("%c",i)]=i
  split("278 278 355 556 556 889 667 191 333 333 389 584 278 333 278 278 556 556 556 556 556 556 556 556 556 556 278 278 584 584 584 556 1015 667 667 722 722 667 611 778 722 278 500 667 556 833 722 778 667 778 722 667 611 722 667 944 667 667 611 278 278 278 469 556 333 556 556 500 556 556 278 556 556 222 222 500 222 833 556 556 556 556 333 500 278 556 500 722 500 500 500 334 260 334 584",w," ")
  for(i=1;i<=95;i++) WID[31+i]=w[i]
  while((getline line < META)>0){ split(line,kv,"\t"); if(kv[1]!=""){ MK[++NM]=kv[1]; MV[kv[1]]=clean(kv[2]) } }
  close(META); NF_=0
}
{ n=++NF_; SEV[n]=$1; CATG[n]=clean($2); TTL[n]=clean($3); DET[n]=clean($4); REC[n]=clean($5) }
END{
  HOST=MV["Hostname"]; SC=MV["_score"]+0; GR=MV["_grade"]
  newpage()
  rect(0,H-92,W,92,0.09,0.15,0.27)
  txt("F2",22,M,H-46,"Server Security Audit Report",1,1,1)
  txt("F1",10.5,M,H-66,HOST "  |  " MV["Primary IP"] "  |  " MV["Scan finished"],0.80,0.86,0.95)
  txt("F1",8.5,M,H-80,"Generated by security_audit.sh v" MV["Script version"] " - scan took " MV["Scan duration"],0.60,0.70,0.85)
  Y=H-92-20
  # score card
  if(SC>=90){CR=0.13;CG=0.58;CB=0.30} else if(SC>=70){CR=0.92;CG=0.55;CB=0.05} else {CR=0.75;CG=0.12;CB=0.12}
  rect(M,Y-100,140,100,CR,CG,CB)
  txt("F2",46,M+ (140-strw(SC "",1,46))/2,Y-56,SC "",1,1,1)
  txt("F2",10,M+ (140-strw("SECURITY SCORE / 100",1,10))/2,Y-74,"SECURITY SCORE / 100",1,1,1)
  txt("F2",13,M+ (140-strw("Grade " GR,1,13))/2,Y-92,"Grade " GR,1,1,1)
  # severity bars
  split("CRITICAL HIGH MEDIUM LOW INFO PASS",SL," "); split("_crit _high _med _low _info _pass",SK," ")
  mx=1; for(i=1;i<=6;i++){ c[i]=MV[SK[i]]+0; if(c[i]>mx) mx=c[i] }
  bx=M+165; by=Y-14
  for(i=1;i<=6;i++){ scol(SL[i]); txt("F2",8.5,bx,by-2,SL[i],0.2,0.2,0.2)
    rect(bx+62,by-4,(c[i]/mx)*200+ (c[i]>0?2:0),12,CR,CG,CB); txt("F2",9,bx+62+(c[i]/mx)*200+8,by-2,c[i] "",0.2,0.2,0.2); by-=16 }
  Y=Y-100-22
  # overview
  heading("System overview")
  split("Hostname|Primary IP|OS|Kernel|Uptime|Control panel|CloudLinux|CPU|Memory|Disks|Pending updates|Run as|Compared with scan of",OV,"|")
  half=CW/2
  for(i=1;i<=13;i++){ k=OV[i]; if(!(k in MV)) continue
    wrap(MV[k],0,8.5,CW-110); ensure(WN*11+3); txt("F2",8.5,M,Y-8,k,0.25,0.25,0.3)
    for(j=1;j<=WN;j++){ txt("F1",8.5,M+110,Y-8,WL[j],0.1,0.1,0.1); Y-=11 } Y-=3 }
  if("All server IPs" in MV){ wrap(MV["All server IPs"],0,8.5,CW-110); txt("F2",8.5,M,Y-8,"All server IPs",0.25,0.25,0.3); for(j=1;j<=WN;j++){txt("F1",8.5,M+110,Y-8,WL[j],0.1,0.1,0.1); Y-=11} Y-=3 }
  # top priorities
  heading("Top priorities")
  tp=0
  for(s=1;s<=3&&tp<8;s++) for(i=1;i<=NF_&&tp<8;i++) if(SEV[i]==SL[s]){ tp++; finding(i) }
  if(tp==0){ txt("F1",10,M,Y-10,"No critical, high or medium findings. Nice work.",0.13,0.58,0.30); Y-=20 }
  # all issues
  heading("Findings requiring attention")
  any=0
  for(s=1;s<=4;s++){ cnt=0; for(i=1;i<=NF_;i++) if(SEV[i]==SL[s]) cnt++
    if(cnt==0) continue; any=1; ensure(40); scol(SL[s]); txt("F2",11,M,Y-10,SL[s] " (" cnt ")",CR,CG,CB); Y-=20
    for(i=1;i<=NF_;i++) if(SEV[i]==SL[s]) finding(i) }
  if(!any){ txt("F1",10,M,Y-10,"None.",0.3,0.3,0.3); Y-=20 }
  # changes
  nch=0; for(i=1;i<=NF_;i++) if(SEV[i]=="NEW"||SEV[i]=="RESOLVED") nch++
  if(nch>0){ heading("Changes since previous scan")
    for(i=1;i<=NF_;i++) if(SEV[i]=="NEW") compact(i)
    for(i=1;i<=NF_;i++) if(SEV[i]=="RESOLVED") compact(i) }
  # passed / info by category
  heading("Passed checks and informational notes")
  ncat=0; for(i=1;i<=NF_;i++) if(SEV[i]=="PASS"||SEV[i]=="INFO"){ if(!(CATG[i] in SEEN)){SEEN[CATG[i]]=1; CL[++ncat]=CATG[i]} }
  for(q=1;q<=ncat;q++){ ensure(30); txt("F2",10,M,Y-10,CL[q],0.09,0.15,0.27); Y-=16
    for(i=1;i<=NF_;i++) if((SEV[i]=="PASS"||SEV[i]=="INFO")&&CATG[i]==CL[q]) compact(i); Y-=4 }
  # checklist appendix
  nck=0; for(i=1;i<=NF_;i++) if(SEV[i]=="CHECKLIST") nck++
  if(nck>0){ heading("Appendix: manual hardening checklist")
    for(i=1;i<=NF_;i++) if(SEV[i]=="CHECKLIST"){ wrap(TTL[i],0,8.5,CW-24); ensure(WN*11+4); box(M,Y-9,8,8,0.4)
      for(j=1;j<=WN;j++){ txt("F1",8.5,M+16,Y-8,WL[j],0.1,0.1,0.1); Y-=11 } Y-=3 } }
  PAGES[NP]=PG
  # footers
  for(p=1;p<=NP;p++){ PAGES[p]=PAGES[p] sprintf("0.8 G 0.5 w %d 34 m %d 34 l S\n",M,W-M)
    f="Server Security Audit  |  " HOST "  |  " MV["Scan finished"]; PAGES[p]=PAGES[p] sprintf("0.45 0.45 0.5 rg BT /F1 7.5 Tf %d 22 Td (%s) Tj ET\n",M,esc(f))
    pn="Page " p " of " NP; PAGES[p]=PAGES[p] sprintf("0.45 0.45 0.5 rg BT /F1 7.5 Tf %.2f 22 Td (%s) Tj ET\n",W-M-strw(pn,0,7.5),pn) }
  # ---- write PDF ----
  OFF=0; emit("%PDF-1.4\n")
  obj(1,"<< /Type /Catalog /Pages 2 0 R >>")
  kids=""; for(p=1;p<=NP;p++) kids=kids (7+2*(p-1)) " 0 R "
  obj(2,"<< /Type /Pages /Kids [ " kids "] /Count " NP " >>")
  obj(3,"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>")
  obj(4,"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>")
  obj(5,"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Oblique /Encoding /WinAnsiEncoding >>")
  obj(6,"<< /Title (Server Security Audit - " esc(HOST) ") /Creator (security_audit.sh) /Producer (security_audit.sh) >>")
  for(p=1;p<=NP;p++){ pn=7+2*(p-1)
    obj(pn,"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 3 0 R /F2 4 0 R /F3 5 0 R >> >> /Contents " (pn+1) " 0 R >>")
    obj(pn+1,"<< /Length " length(PAGES[p]) " >>\nstream\n" PAGES[p] "endstream") }
  nobj=6+2*NP; xr=OFF
  emit("xref\n0 " (nobj+1) "\n0000000000 65535 f \n")
  for(n=1;n<=nobj;n++) emit(sprintf("%010d 00000 n \n",OFFS[n]))
  emit("trailer\n<< /Size " (nobj+1) " /Root 1 0 R /Info 6 0 R >>\nstartxref\n" xr "\n%%EOF\n")
  close(OUT)
}
function emit(s){ printf "%s",s > OUT; OFF+=length(s) }
function obj(n,body){ OFFS[n]=OFF; emit(n " 0 obj\n" body "\nendobj\n") }
AWKEOF

cat > "$WORK/html.awk" <<'AWKEOF'
function h(s){ gsub(/&/,"\\&amp;",s); gsub(/</,"\\&lt;",s); gsub(/>/,"\\&gt;",s); gsub(/"/,"\\&quot;",s); return s }
BEGIN{ FS="\t"
  while((getline line < META)>0){ split(line,kv,"\t"); MV[kv[1]]=kv[2]; MK[++NM]=kv[1] } close(META)
  print "<!doctype html><html><head><meta charset=\"utf-8\"><title>Security Audit - " h(MV["Hostname"]) "</title><style>"
  print "body{font:14px/1.5 -apple-system,Segoe UI,Roboto,sans-serif;margin:0;background:#f4f6f9;color:#1b2430}header{background:#172640;color:#fff;padding:24px 40px}"
  print "main{max-width:1000px;margin:24px auto;padding:0 20px}h2{border-bottom:2px solid #cfd6e0;padding-bottom:6px;margin-top:36px}"
  print ".score{display:inline-block;padding:14px 26px;border-radius:10px;color:#fff;font-size:34px;font-weight:700;margin-right:20px}"
  print ".card{background:#fff;border-radius:8px;padding:12px 16px;margin:8px 0;box-shadow:0 1px 2px #0002}.b{display:inline-block;min-width:70px;text-align:center;color:#fff;border-radius:4px;font-size:11px;font-weight:700;padding:2px 6px;margin-right:8px}"
  print ".CRITICAL{background:#9e0d26}.HIGH{background:#dc3d1a}.MEDIUM{background:#eb8c0d}.LOW{background:#3378c7}.INFO{background:#80808c}.PASS{background:#219450}.NEW{background:#dc3d1a}.RESOLVED{background:#219450}"
  print ".fix{color:#1a6190;font-style:italic;margin-top:4px}.d{color:#4a5260;margin-top:2px}table{border-collapse:collapse}td{padding:2px 14px 2px 0;vertical-align:top}</style></head><body>"
  print "<header><h1 style=\"margin:0\">Server Security Audit Report</h1><div>" h(MV["Hostname"]) " | " h(MV["Primary IP"]) " | " h(MV["Scan finished"]) "</div></header><main>"
  sc=MV["_score"]+0; col=(sc>=90)?"#219450":(sc>=70)?"#eb8c0d":"#bf1f1f"
  print "<p><span class=\"score\" style=\"background:" col "\">" sc "/100 &middot; " MV["_grade"] "</span>"
  print "Critical <b>" MV["_crit"] "</b> &middot; High <b>" MV["_high"] "</b> &middot; Medium <b>" MV["_med"] "</b> &middot; Low <b>" MV["_low"] "</b> &middot; Info " MV["_info"] " &middot; Passed " MV["_pass"] "</p>"
  print "<h2>System overview</h2><table>"; for(i=1;i<=NM;i++) if(MK[i]!~/^_/) print "<tr><td><b>" h(MK[i]) "</b></td><td>" h(MV[MK[i]]) "</td></tr>"; print "</table>"
}
{ n=++N; S[n]=$1; C[n]=$2; T[n]=$3; D[n]=$4; R[n]=$5 }
function card(i){ print "<div class=\"card\"><span class=\"b " S[i] "\">" S[i] "</span><b>" h(T[i]) "</b>"; if(D[i]!="") print "<div class=\"d\">" h(D[i]) "</div>"; if(R[i]!="" && S[i]!="PASS" && S[i]!="INFO") print "<div class=\"fix\">Fix: " h(R[i]) "</div>"; print "</div>" }
END{ split("CRITICAL HIGH MEDIUM LOW",L," ")
  print "<h2>Findings requiring attention</h2>"; a=0
  for(s=1;s<=4;s++) for(i=1;i<=N;i++) if(S[i]==L[s]){a=1; card(i)}
  if(!a) print "<p>No issues found.</p>"
  for(i=1;i<=N;i++) if(S[i]=="NEW"||S[i]=="RESOLVED"){ if(!ch++) print "<h2>Changes since previous scan</h2>"; card(i) }
  print "<h2>Passed checks and notes</h2>"; for(i=1;i<=N;i++) if(S[i]=="PASS"||S[i]=="INFO") card(i)
  for(i=1;i<=N;i++) if(S[i]=="CHECKLIST"){ if(!ck++) print "<h2>Manual hardening checklist</h2><ul style=\"list-style:none\">"; print "<li>&#9744; " h(T[i]) "</li>" } if(ck) print "</ul>"
  print "</main></body></html>" }
AWKEOF

cat > "$WORK/json.awk" <<'AWKEOF'
function j(s){ gsub(/\\/,"\\\\",s); gsub(/"/,"\\\"",s); gsub(/[\001-\037]/," ",s); return "\"" s "\"" }
BEGIN{ FS="\t"; print "{"
  while((getline line < META)>0){ split(line,kv,"\t"); if(kv[1]!~/^_/){ m=m (m?",\n":"") "    " j(kv[1]) ": " j(kv[2]) } else V[kv[1]]=kv[2] } close(META)
  print "  \"summary\": {\"score\": " V["_score"] ", \"grade\": " j(V["_grade"]) ", \"critical\": " V["_crit"] ", \"high\": " V["_high"] ", \"medium\": " V["_med"] ", \"low\": " V["_low"] ", \"info\": " V["_info"] ", \"pass\": " V["_pass"] "},"
  print "  \"system\": {\n" m "\n  },"; print "  \"findings\": [" }
{ printf "%s    {\"severity\": %s, \"category\": %s, \"title\": %s, \"detail\": %s, \"recommendation\": %s}", (NR>1?",\n":""), j($1), j($2), j($3), j($4), j($5) }
END{ print "\n  ]\n}" }
AWKEOF

cat > "$WORK/txt.awk" <<'AWKEOF'
BEGIN{ FS="\t"
  while((getline line < META)>0){ split(line,kv,"\t"); MV[kv[1]]=kv[2]; MK[++NM]=kv[1] } close(META)
  print "SERVER SECURITY AUDIT REPORT"; print "============================"
  for(i=1;i<=NM;i++) if(MK[i]!~/^_/) printf "%-22s %s\n", MK[i] ":", MV[MK[i]]
  printf "\nSECURITY SCORE: %s/100 (Grade %s)\n", MV["_score"], MV["_grade"]
  printf "Critical: %s  High: %s  Medium: %s  Low: %s  Info: %s  Passed: %s\n", MV["_crit"],MV["_high"],MV["_med"],MV["_low"],MV["_info"],MV["_pass"] }
{ n=++N; S[n]=$1; C[n]=$2; T[n]=$3; D[n]=$4; R[n]=$5 }
function show(i){ printf "\n[%s] %s\n", S[i], T[i]; if(D[i]!="") printf "    %s\n", D[i]; if(R[i]!=""&&S[i]!="PASS"&&S[i]!="INFO") printf "    Fix: %s\n", R[i] }
END{ split("CRITICAL HIGH MEDIUM LOW",L," ")
  print "\n\nFINDINGS REQUIRING ATTENTION\n----------------------------"
  for(s=1;s<=4;s++) for(i=1;i<=N;i++) if(S[i]==L[s]) show(i)
  for(i=1;i<=N;i++) if(S[i]=="NEW"||S[i]=="RESOLVED"){ if(!ch++) print "\n\nCHANGES SINCE PREVIOUS SCAN\n---------------------------"; show(i) }
  print "\n\nPASSED CHECKS AND NOTES\n-----------------------"
  for(i=1;i<=N;i++) if(S[i]=="PASS"||S[i]=="INFO") show(i)
  for(i=1;i<=N;i++) if(S[i]=="CHECKLIST"){ if(!ck++) print "\n\nMANUAL HARDENING CHECKLIST\n--------------------------"; print "[ ] " T[i] } }
AWKEOF

# =============================================================================
#  GENERATE OUTPUT FILES
# =============================================================================
BASE="$OUTDIR/security_audit_${HOSTN}_${STAMP}"; GENERATED=""
for f in $(echo "$FORMATS" | tr ',' ' '); do
  out="$BASE.$f"
  case "$f" in
    pdf)  awk -v META="$META" -v OUT="$out" -f "$WORK/pdf.awk" "$FINDINGS" ;;
    html) awk -v META="$META" -f "$WORK/html.awk" "$FINDINGS" > "$out" ;;
    json) awk -v META="$META" -f "$WORK/json.awk" "$FINDINGS" > "$out" ;;
    txt)  awk -v META="$META" -f "$WORK/txt.awk"  "$FINDINGS" > "$out" ;;
  esac
  if [ -s "$out" ]; then chmod 600 "$out" 2>/dev/null; GENERATED="$GENERATED $out"; else echo "Failed to write $out" >&2; fi
done

# =============================================================================
#  CONSOLE SUMMARY
# =============================================================================
printf '\n%s================ AUDIT SUMMARY ================%s\n' "$C_BLD" "$C_NC"
printf '  Score : %s%s/100  (Grade %s)%s\n' "$C_BLD" "$SCORE" "$GRADE" "$C_NC"
printf '  %sCritical %s%s | %sHigh %s%s | %sMedium %s%s | %sLow %s%s | Info %s | Passed %s\n' \
  "$C_RED" "$N_CRIT" "$C_NC" "$C_ORG" "$N_HIGH" "$C_NC" "$C_YEL" "$N_MED" "$C_NC" "$C_BLU" "$N_LOW" "$C_NC" "$N_INFO" "$N_PASS"
if [ "$N_CRIT$N_HIGH" != "00" ]; then
  printf '\n  Most urgent:\n'
  awk -F'\t' '$1=="CRITICAL"||$1=="HIGH"{printf "   - [%s] %s\n", $1, $3}' "$FINDINGS" | head -10
fi
printf '\n  Scan time: %ss\n' "$DURATION"
for g in $GENERATED; do printf '  Report   : %s\n' "$g"; done
printf '\n'

[ "$N_CRIT" -gt 0 ] && exit 2
[ "$N_HIGH" -gt 0 ] && exit 1
exit 0

#!/usr/bin/env bash
# ==========================================================================
#  Combined Server Security + Load Audit  (READ-ONLY)
#  Targets: cPanel/WHM, CloudLinux, EL/Debian-family hosts
#
#  * Detects each service first (installed? running? port listening?) and
#    only runs deep checks for services that are actually present.
#  * Every data source is collected ONCE (ps, ss, unit list, auth log,
#    httpd -M, config greps ...) and re-used by all checks - no duplicates.
#  * Does NOT restart/stop/enable anything, kill, block, edit configs,
#    write temp files, create DB objects or enable logging.
#  * The ONLY thing written is the final HTML report (default: Apache
#    default document root, random file name).
#
#  Usage:   sudo bash security_audit.sh [-o OUTPUT_DIR] [-i PUBLIC_IP]
#  Env:     AUTH_TAIL EXIM_LOG_TAIL SLOW_LINES MAX_2FA_USERS CMD_TIMEOUT
# ==========================================================================

export LC_ALL=C
umask 022
shopt -u patsub_replacement 2>/dev/null   # bash 5.2: keep a literal & in ${var//x/&y;} replacements
START_EPOCH=$(date +%s)

AUTH_TAIL="${AUTH_TAIL:-200000}"
EXIM_LOG_TAIL="${EXIM_LOG_TAIL:-200000}"
SLOW_LINES="${SLOW_LINES:-20000}"
MAX_2FA_USERS="${MAX_2FA_USERS:-1000}"
CMD_TIMEOUT="${CMD_TIMEOUT:-20}"
OUT_DIR="${OUT_DIR:-}"
SYN_RECV_WARN="${SYN_RECV_WARN:-500}"; SYN_RECV_CRIT="${SYN_RECV_CRIT:-1000}"   # inbound  half-open
SYN_SENT_WARN="${SYN_SENT_WARN:-200}"; SYN_SENT_CRIT="${SYN_SENT_CRIT:-500}"    # outbound half-open

PUBLIC_IP="${PUBLIC_IP:-}"
while getopts "o:i:h" opt; do
  case $opt in
    o) OUT_DIR=$OPTARG ;;
    i) PUBLIC_IP=$OPTARG ;;
    h|*) sed -n '2,19p' "$0"; exit 0 ;;
  esac
done

# ---- lower our own priority (affects only this process) -------------------
renice -n 19 -p $$ >/dev/null 2>&1
command -v ionice >/dev/null 2>&1 && ionice -c3 -p $$ >/dev/null 2>&1

# ==========================================================================
#  Helpers
# ==========================================================================
have() { command -v "$1" >/dev/null 2>&1; }
HAVE_TO=0; have timeout && HAVE_TO=1
t()  { if [ $HAVE_TO -eq 1 ]; then timeout "$CMD_TIMEOUT" "$@" 2>/dev/null; else "$@" 2>/dev/null; fi; }
t2() { if [ $HAVE_TO -eq 1 ]; then timeout "$CMD_TIMEOUT" "$@" 2>&1;       else "$@" 2>&1;       fi; }
say() { printf '[+] %s\n' "$*" >&2; }

hesc() { local s=$1; s=${s//&/&amp;}; s=${s//</&lt;}; s=${s//>/&gt;}; s=${s//\"/&quot;}; printf '%s' "$s"; }
first_line() { printf '%s\n' "$1" | head -n1; }
lower() { printf '%s' "$1" | tr 'A-Z' 'a-z'; }

declare -A SEV_COUNT=([FAIL]=0 [WARN]=0 [PASS]=0 [INFO]=0 [SKIP]=0)
declare -A SEV_RANK=([SKIP]=0 [INFO]=1 [PASS]=2 [WARN]=3 [FAIL]=4)
FINDINGS=""; SECTIONS=""; NAV=""
SEC_ID=""; SEC_TITLE=""; SEC_BUF=""; SEC_WORST=0
declare -A SEC_C=([FAIL]=0 [WARN]=0 [PASS]=0 [INFO]=0 [SKIP]=0)

sec_open() { SEC_ID=$1; SEC_TITLE=$2; SEC_BUF=""; SEC_WORST=0; SEC_BADGE=""; SEC_C=([FAIL]=0 [WARN]=0 [PASS]=0 [INFO]=0 [SKIP]=0); say "$2"; }
sec_close() {
  local cls=SKIP o="" lbl
  case $SEC_WORST in 4) cls=FAIL;; 3) cls=WARN;; 2) cls=PASS;; 1) cls=INFO;; esac
  [ "$SEC_WORST" -ge 3 ] && o=" open"
  lbl=$cls; [ -n "${SEC_BADGE:-}" ] && { cls=INFO; lbl=$SEC_BADGE; }
  SECTIONS+="<section id=\"$SEC_ID\" data-title=\"$(hesc "$SEC_TITLE")\" data-f=\"${SEC_C[FAIL]}\" data-w=\"${SEC_C[WARN]}\" data-p=\"${SEC_C[PASS]}\" data-i=\"${SEC_C[INFO]}\" data-s=\"${SEC_C[SKIP]}\"><details$o><summary><span class=\"b $cls\">$lbl</span> <span class=\"st\">$(hesc "$SEC_TITLE")</span><button type=\"button\" class=\"rm\" title=\"Remove this section from the report\" onclick=\"rmSec('$SEC_ID',event)\">&#10005; Remove</button></summary><div class=\"sbody\">$SEC_BUF</div></details></section>"$'\n'
  NAV+="<label class=\"ni\" data-id=\"$SEC_ID\"><input type=\"checkbox\" checked onchange=\"tog('$SEC_ID',this.checked)\"><a href=\"#$SEC_ID\"><i class=\"dot $cls\"></i>$(hesc "$SEC_TITLE")</a></label>"
}
# chk SEVERITY label [detail]
chk() {
  local sev=$1 label=$2 detail=${3:-} flat
  SEV_COUNT[$sev]=$(( SEV_COUNT[$sev] + 1 )); SEC_C[$sev]=$(( SEC_C[$sev] + 1 ))
  [ "${SEV_RANK[$sev]}" -gt "$SEC_WORST" ] && SEC_WORST=${SEV_RANK[$sev]}
  if [ "${SEV_RANK[$sev]}" -ge 3 ]; then
    flat=${detail//$'\n'/ | }; flat=${flat//$'\t'/ }
    FINDINGS+="${SEV_RANK[$sev]}"$'\t'"$sev"$'\t'"$SEC_TITLE"$'\t'"$label"$'\t'"${flat:0:300}"$'\n'
  fi
  SEC_BUF+="<div class=\"chk\"><span class=\"b $sev\">$sev</span><div><b>$(hesc "$label")</b>"
  [ -n "$detail" ] && SEC_BUF+="<span class=\"d\">$(hesc "$detail")</span>"
  SEC_BUF+="</div></div>"$'\n'
}
note() { SEC_BUF+="<p class=\"note\">$(hesc "$1")</p>"$'\n'; }
raw() { # title text
  local txt=$2; [ -z "$txt" ] && txt="(no output)"
  SEC_BUF+="<details class=\"raw\"><summary>$(hesc "$1")</summary><pre>$(hesc "$txt")</pre></details>"$'\n'
}
tbl() { # "h1<TAB>h2" "rows (tab separated)"
  [ -z "$2" ] && return 0
  SEC_BUF+="$(printf '%s\n%s\n' "$1" "$2" | awk -F'\t' '
    function e(s){gsub(/&/,"\\&amp;",s);gsub(/</,"\\&lt;",s);gsub(/>/,"\\&gt;",s);return s}
    NR==1{printf "<div class=\"tw\"><table><thead><tr>";for(i=1;i<=NF;i++)printf "<th>%s</th>",e($i);print "</tr></thead><tbody>";next}
    {printf "<tr>";for(i=1;i<=NF;i++){c=e($i);if(c ~ /^(PASS|WARN|FAIL|INFO|SKIP|UP|DOWN|DEGRADED|ABSENT)$/)c="<span class=\"b " c "\">" c "</span>";printf "<td>%s</td>",c}print "</tr>"}
    END{print "</tbody></table></div>"}')"$'\n'
}

# ==========================================================================
#  One-time data collection (shared by all checks)
# ==========================================================================
IS_ROOT=0; [ "$(id -u)" -eq 0 ] && IS_ROOT=1
HOST=$(hostname -f 2>/dev/null || hostname 2>/dev/null || echo unknown)
NOW_HUMAN=$(date '+%Y-%m-%d %H:%M:%S %Z')
TS=$(date +%Y%m%d_%H%M%S)
CORES=$(nproc 2>/dev/null || echo 1)
OS_PRETTY=$( . /etc/os-release 2>/dev/null; echo "${PRETTY_NAME:-unknown}")
KERNEL=$(uname -r)

say "Collecting shared data (processes, sockets, units, logs)"
PS_ALL=$(ps -eo pid,ppid,user:20,pcpu,pmem,etime,comm,args --sort=-pcpu 2>/dev/null)
PROC_NAMES=$'\n'$(printf '%s\n' "$PS_ALL" | awk 'NR>1{print $7}' | sort -u)$'\n'
proc_running() { [[ $PROC_NAMES == *$'\n'"$1"$'\n'* ]]; }

HAVE_SYSTEMD=0; have systemctl && [ -d /run/systemd/system ] && HAVE_SYSTEMD=1
UNIT_FILES=""
[ $HAVE_SYSTEMD -eq 1 ] && UNIT_FILES=$(t systemctl list-unit-files --type=service --no-legend --no-pager)

SS_LISTEN=""; SS_TAN=""
if have ss; then
  SS_LISTEN=$(t ss -lntup | awk 'NR>1')
  SS_TAN=$(t ss -tan | awk 'NR>1')
fi
declare -A PORT_SCOPE PORT_PROC
PORT_ROWS=$(printf '%s\n' "$SS_LISTEN" | awk '
  NF>=5 { proto=$1; loc=$5; port=loc; sub(/^.*:/,"",port); addr=loc; sub(/:[0-9]+$/,"",addr)
    gsub(/[\[\]]/,"",addr); sub(/%.*$/,"",addr)
    scope="bound"; if(addr=="*"||addr=="0.0.0.0"||addr==""||addr=="::") scope="public"
    else if(addr ~ /^127\./||addr=="::1") scope="local"
    p="-"; if(match($0,/\(\("[^"]+"/)) p=substr($0,RSTART+3,RLENGTH-4)
    print proto "\t" port "\t" scope "\t" addr "\t" p }')
while IFS=$'\t' read -r _pr _po _sc _ad _pp; do
  [ -z "$_po" ] && continue
  case $_pr in tcp*) _k="tcp:$_po";; udp*) _k="udp:$_po";; *) continue;; esac
  if [ "${PORT_SCOPE[$_k]:-}" != "public" ]; then PORT_SCOPE[$_k]=$_sc; fi
  PORT_PROC[$_k]=$_pp
done <<<"$PORT_ROWS"
port_scope() { echo "${PORT_SCOPE[tcp:$1]:-}"; }

# ==========================================================================
#  Service detection (condition-based availability)
# ==========================================================================
declare -A SV_LABEL SV_INST SV_STATE SV_PORTS SV_CRIT SV_DETAIL
SV_ORDER=()
# svc_detect key label unit_regex "bins/paths" "procs" "ports(any-of)" crit
svc_detect() {
  local key=$1 label=$2 ure=$3 bins=$4 procs=$5 ports=$6 crit=$7
  local inst=0 active=0 units="" u b p lst="" state detail=""
  if [ -n "$ure" ] && [ -n "$UNIT_FILES" ]; then
    units=$(printf '%s\n' "$UNIT_FILES" | grep -oE "^($ure)\.service" | sed 's/\.service$//')
    [ -n "$units" ] && inst=1
    for u in $units; do systemctl is-active --quiet "$u" 2>/dev/null && { active=1; detail+="$u "; }; done
  fi
  for b in $bins; do { [ -e "$b" ] || have "$b"; } && inst=1; done
  for p in $procs; do proc_running "$p" && { active=1; inst=1; }; done
  for p in $ports; do [ -n "${PORT_SCOPE[tcp:$p]:-}" ] && lst+="$p/${PORT_SCOPE[tcp:$p]} "; done
  if   [ $inst -eq 0 ];   then state=ABSENT
  elif [ $active -eq 1 ]; then
    if [ -n "$ports" ] && [ -z "$lst" ]; then state=DEGRADED; else state=UP; fi
  else state=DOWN; fi
  SV_ORDER+=("$key"); SV_LABEL[$key]=$label; SV_INST[$key]=$inst; SV_STATE[$key]=$state
  SV_PORTS[$key]=${lst:-"-"}; SV_CRIT[$key]=$crit; SV_DETAIL[$key]=${detail:-"-"}
}
svc_inst() { [ "${SV_INST[$1]:-0}" = 1 ]; }
svc_up()   { [[ "${SV_STATE[$1]:-}" == UP || "${SV_STATE[$1]:-}" == DEGRADED ]]; }

# SSH ports from effective config (falls back to 22)
SSHD_T=""
have sshd && SSHD_T=$(t sshd -T)
SSH_PORTS=$(printf '%s\n' "$SSHD_T" | awk '$1=="port"{print $2}' | tr '\n' ' ')
SSH_PORTS=${SSH_PORTS:-22}

svc_detect cpanel   "cPanel / WHM"        "cpanel|cpsrvd"                        "/usr/local/cpanel/cpanel"  "cpsrvd"             "2087 2083" 1
svc_detect ssh      "OpenSSH"             "sshd|ssh"                             "sshd"                      "sshd"               "$SSH_PORTS" 1
svc_detect apache   "Apache httpd"        "httpd|apache2"                        "httpd apache2"             "httpd apache2"      "80 443 81 444 8080 8443" 0
svc_detect nginx    "Nginx"               "nginx"                                "nginx"                     "nginx"              "80 443" 0
svc_detect lsws     "LiteSpeed"           "lsws|lshttpd|litespeed"               "/usr/local/lsws/bin/lshttpd" "litespeed lshttpd openlitespeed" "80 443 7080" 0
svc_detect phpfpm   "PHP-FPM"             "(ea-php[0-9]+-)?php[0-9.]*-?fpm"      "php-fpm"                   "php-fpm"            "" 0
svc_detect mysql    "MySQL / MariaDB"     "mysqld|mysql|mariadb"                 "mysqld mariadbd"           "mysqld mariadbd"    "3306" 1
svc_detect exim     "Exim (SMTP)"         "exim|exim4"                           "exim exim4"                "exim exim4"         "25 465 587" 1
svc_detect dovecot  "Dovecot (IMAP/POP3)" "dovecot"                              "dovecot doveconf"          "dovecot"            "143 993 110 995" 1
svc_detect ftp      "FTP server"          "pure-ftpd|proftpd|vsftpd"             "pure-ftpd proftpd vsftpd"  "pure-ftpd proftpd vsftpd" "21 990" 0
svc_detect dns      "DNS (BIND/PowerDNS)" "named|named-chroot|bind9|pdns"        "named pdns_server"         "named pdns_server"  "53" 1
svc_detect csf      "CSF / LFD firewall"  "csf|lfd"                              "csf /etc/csf/csf.conf"     "lfd"                "" 0
svc_detect fwd      "firewalld"           "firewalld"                            "firewall-cmd"              "firewalld"          "" 0
svc_detect i360     "Imunify360"          "imunify360"                           "imunify360-agent"          ""                   "" 0
svc_detect imav     "Imunify AV (antivirus)" "imunify-antivirus"                 "imunify-antivirus"         ""                   "" 0
svc_detect bitninja "BitNinja"            "bitninja"                             "bnconfig /etc/bitninja"    "BitNinja"           "" 0

CL_INST=0
{ [ -f /etc/cloudlinux-release ] || have cldetect || have lveps || have lveinfo; } && CL_INST=1
CP_INST=0; [ -d /usr/local/cpanel ] && CP_INST=1


# ---- public IP detection (used only to build the report link) -----------
is_private_ip() {
  case $1 in
    0.*|10.*|127.*|169.254.*|192.168.*|172.1[6-9].*|172.2[0-9].*|172.3[01].*|100.6[4-9].*|100.[7-9][0-9].*|100.1[01][0-9].*|100.12[0-7].*) return 0;;
  esac; return 1
}
get_public_ip() {
  local ip u main re='^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'
  [[ $PUBLIC_IP =~ $re ]] && { echo "$PUBLIC_IP"; return; }
  # 1) the server's MAIN IP: cPanel main shared IP, else the default-route source address
  main=$(cat /var/cpanel/mainip 2>/dev/null | tr -d ' \r\n')
  if ! [[ $main =~ $re ]]; then
    main=$(ip -4 route get 8.8.8.8 2>/dev/null | awk '{for(i=1;i<NF;i++)if($i=="src"){print $(i+1);exit}}')
  fi
  if ! [[ $main =~ $re ]]; then main=$(hostname -I 2>/dev/null | awk '{print $1}'); fi
  if [[ $main =~ $re ]] && ! is_private_ip "$main"; then echo "$main"; return; fi
  # 2) main IP is private (NAT): use cPanel's NAT mapping (/var/cpanel/cpnat: "local public")
  if [[ $main =~ $re ]] && [ -r /var/cpanel/cpnat ]; then
    ip=$(awk -v m="$main" '$1==m{print $2; exit}' /var/cpanel/cpnat 2>/dev/null)
    [[ $ip =~ $re ]] && { echo "$ip"; return; }
  fi
  # 3) NAT without mapping: ask an external echo service (4s timeout each)
  for u in https://api.ipify.org https://ifconfig.me/ip https://icanhazip.com https://checkip.amazonaws.com; do
    if have curl; then ip=$(curl -4 -fsS --max-time 4 "$u" 2>/dev/null | tr -d ' \r\n')
    elif have wget; then ip=$(wget -4 -qO- --timeout=4 "$u" 2>/dev/null | tr -d ' \r\n')
    else break; fi
    [[ $ip =~ $re ]] && ! is_private_ip "$ip" && { echo "$ip"; return; }
  done
  echo "$main"
}

# default document root for the report
if [ -z "$OUT_DIR" ]; then
  for d in /usr/local/apache/htdocs /var/www/html /usr/share/nginx/html /usr/local/lsws/DEFAULT/html; do
    [ -d "$d" ] && { OUT_DIR=$d; break; }
  done
  [ -z "$OUT_DIR" ] && OUT_DIR=$PWD
fi

# ==========================================================================
#  SECTION: Service availability matrix
# ==========================================================================
sec_open services "Service Availability"
[ $IS_ROOT -eq 0 ] && chk WARN "Not running as root" "Many checks need root (sshd -T, logs, firewall, DB). Results are partial - re-run with sudo."
[ $HAVE_SYSTEMD -eq 0 ] && chk INFO "systemd not detected" "Service state is derived from running processes only."
ROWS=""
for k in "${SV_ORDER[@]}"; do
  ROWS+="${SV_LABEL[$k]}"$'\t'"${SV_STATE[$k]}"$'\t'"${SV_DETAIL[$k]}"$'\t'"${SV_PORTS[$k]}"$'\n'
done
if [ $CL_INST -eq 1 ]; then ROWS+="CloudLinux"$'\t'"UP"$'\t'"n/a (OS feature)"$'\t'"-"$'\n'; else ROWS+="CloudLinux"$'\t'"ABSENT"$'\t'"-"$'\t'"-"$'\n'; fi
tbl $'Service\tState\tActive units\tListening (port/scope)' "$ROWS"
note "UP = installed, active and expected port listening. DEGRADED = active but no expected port listening. DOWN = installed but not active. ABSENT = not installed (its checks are skipped)."
for k in "${SV_ORDER[@]}"; do
  case ${SV_STATE[$k]} in
    DOWN)     [ "${SV_CRIT[$k]}" = 1 ] && chk WARN "${SV_LABEL[$k]} is installed but NOT running" || chk INFO "${SV_LABEL[$k]} is installed but not running" ;;
    DEGRADED) chk WARN "${SV_LABEL[$k]} running but expected port not listening" "Expected one of: see table" ;;
  esac
done
# at least one web server must be up
if svc_inst apache || svc_inst nginx || svc_inst lsws; then
  if svc_up apache || svc_up nginx || svc_up lsws; then chk PASS "At least one web server is available"
  else chk FAIL "Web server installed but none is running"; fi
else chk INFO "No web server detected"; fi
sec_close

# ==========================================================================
#  SECTION: System baseline
# ==========================================================================
sec_open baseline "System & OS Baseline"
chk INFO "OS / Kernel" "$OS_PRETTY - kernel $KERNEL"
have hostnamectl && raw "hostnamectl" "$(t hostnamectl)"
have lscpu && raw "CPU summary" "$(t lscpu | awk -F: '/Architecture|^CPU\(s\)|Model name|Thread|Core|Socket|NUMA node\(s\)/{gsub(/^[ \t]+/,"",$2);print $1": "$2}')"
if have uptime; then
  chk INFO "Uptime" "$(uptime -p 2>/dev/null) (booted $(uptime -s 2>/dev/null))"
fi
RES=$(grep -E '^[[:space:]]*nameserver[[:space:]]+' /etc/resolv.conf 2>/dev/null)
[ -n "$RES" ] && chk INFO "DNS resolvers" "$(echo "$RES" | awk '{print $2}' | tr '\n' ' ')" || chk SKIP "/etc/resolv.conf has no nameservers"
# /tmp hardening
if [ ! -d /tmp ]; then chk FAIL "/tmp does not exist"
elif have findmnt; then
  TMPT=$(findmnt -no TARGET /tmp 2>/dev/null); TMPO=$(findmnt -no OPTIONS /tmp 2>/dev/null)
  if [ "$TMPT" != "/tmp" ]; then chk WARN "/tmp is not a dedicated mount" "Inherited from '$TMPT' - cannot enforce noexec/nosuid/nodev."
  else
    for o in noexec nosuid nodev; do
      if printf '%s' "$TMPO" | tr ',' '\n' | grep -qx "$o"; then chk PASS "/tmp mounted $o"; else chk WARN "/tmp missing '$o'" "Options: $TMPO"; fi
    done
  fi
  chk INFO "/tmp permissions" "$(stat -c '%A %a %U:%G' /tmp)"
else chk SKIP "/tmp mount options" "findmnt not available"; fi
sec_close

# ==========================================================================
#  SECTION: Load & resources
# ==========================================================================
sec_open load "Load, Memory & Storage"
read -r L1 L5 L15 _ < /proc/loadavg 2>/dev/null
if [ -n "${L1:-}" ]; then
  RATIO=$(awk -v l="$L1" -v c="$CORES" 'BEGIN{printf "%.2f", l/c}')
  SEVL=PASS; awk -v r="$RATIO" 'BEGIN{exit !(r>=2)}' && SEVL=FAIL || { awk -v r="$RATIO" 'BEGIN{exit !(r>=1)}' && SEVL=WARN; }
  chk $SEVL "Load average" "1m=$L1 5m=$L5 15m=$L15 on $CORES core(s) -> $RATIO per core"
fi
if [ -r /proc/meminfo ]; then
  MEMLINE=$(awk '/^MemTotal/{t=$2}/^MemAvailable/{a=$2}/^SwapTotal/{st=$2}/^SwapFree/{sf=$2}END{printf "%d %d %d %d", t/1024,a/1024,st/1024,sf/1024}' /proc/meminfo)
  read -r MT MA ST SF <<<"$MEMLINE"
  if [ "${MT:-0}" -gt 0 ]; then
    MP=$(( MA * 100 / MT )); SEVM=PASS; [ $MP -lt 20 ] && SEVM=WARN; [ $MP -lt 10 ] && SEVM=FAIL
    chk $SEVM "Memory available" "${MA}MB of ${MT}MB (${MP}%)"
    if [ "${ST:-0}" -gt 0 ]; then
      SU=$(( (ST-SF) * 100 / ST )); [ $SU -ge 50 ] && chk WARN "Swap usage high" "${SU}% of ${ST}MB used" || chk PASS "Swap usage" "${SU}% of ${ST}MB used"
    else chk INFO "No swap configured"; fi
  fi
fi
# disk + inodes
DF=$(t df -PTh -x tmpfs -x devtmpfs -x squashfs -x overlay | awk 'NR>1{print $7"\t"$2"\t"$3"\t"$4"\t"$6}')
DFI=$(t df -PTi -x tmpfs -x devtmpfs -x squashfs -x overlay | awk 'NR>1{print $7"\t"$6}')
DROWS=""
while IFS=$'\t' read -r mp fs sz used pct; do
  [ -z "$mp" ] && continue
  ip=$(printf '%s\n' "$DFI" | awk -F'\t' -v m="$mp" '$1==m{print $2; exit}')
  s=PASS; n=${pct%\%}; i=${ip%\%}
  { [ "${n:-0}" -ge 85 ] 2>/dev/null || [ "${i:-0}" -ge 85 ] 2>/dev/null; } && s=WARN
  { [ "${n:-0}" -ge 95 ] 2>/dev/null || [ "${i:-0}" -ge 95 ] 2>/dev/null; } && s=FAIL
  DROWS+="$s"$'\t'"$mp"$'\t'"$fs"$'\t'"$sz"$'\t'"$used"$'\t'"$pct"$'\t'"${ip:--}"$'\n'
  [ $s != PASS ] && chk $s "Disk/inode pressure on $mp" "space ${pct}, inodes ${ip:--}"
done <<<"$DF"
tbl $'Status\tMount\tType\tSize\tUsed\tUse%\tInode%' "$DROWS"
# top processes (from shared ps snapshot)
raw "Top 15 processes by CPU" "$(printf '%s\n' "$PS_ALL" | awk 'NR==1{print;next}{print}' | cut -c1-200 | head -n 16)"
raw "Top 15 processes by memory" "$( { printf '%s\n' "$PS_ALL" | head -n1; printf '%s\n' "$PS_ALL" | awk 'NR>1' | sort -k5,5nr | head -n 15; } | cut -c1-200)"
UTBL=$(printf '%s\n' "$PS_ALL" | awk 'NR>1{c[$3]+=$4;m[$3]+=$5;n[$3]++}END{for(u in c)printf "%s\t%.1f\t%.1f\t%d\n",u,c[u],m[u],n[u]}' | sort -t$'\t' -k2,2nr | head -n 5)
tbl $'Top 5 users\tCPU %\tMEM %\tProcesses' "$UTBL"
if have iostat; then raw "Disk I/O (iostat -x 1 2)" "$(t iostat -x 1 2)"; else chk INFO "iostat unavailable" "sysstat not installed (informational)"; fi
# CloudLinux (only if present)
if [ $CL_INST -eq 1 ]; then
  CLV=$(cat /etc/cloudlinux-release 2>/dev/null)
  chk INFO "CloudLinux detected" "${CLV:-version unknown}"
  have lveps   && { raw "LVE top CPU (1s sample)" "$(t lveps -d -c 1 -s cpu | head -n 11)"; raw "LVE top physical memory" "$(t lveps -d -c 1 -s mem | head -n 11)"; }
  if have lveinfo; then
    LF=$(t lveinfo --period=1h --order-by=any_faults --display-username --limit=10)
    raw "LVE top faulting accounts (last 1h)" "$LF"
    printf '%s\n' "$LF" | awk 'NR>2 && $0 ~ /[0-9]/' | grep -q . && chk INFO "LVE faults recorded in last hour" "See faulting accounts list"
  fi
else chk SKIP "CloudLinux not detected" "LVE checks skipped"; fi
sec_close

# ==========================================================================
#  SECTION: Accounts, sudo, keys, cron
# ==========================================================================
sec_open accounts "Accounts, Privileges & Cron"
UID0=$(awk -F: '$3==0{print $1}' /etc/passwd 2>/dev/null)
if [ "$UID0" = "root" ]; then chk PASS "Only root has UID 0"; else chk FAIL "Additional UID 0 accounts" "$UID0"; fi
SUDOERS=$(grep -RhsE '^[[:space:]]*[a-zA-Z0-9_.-]+[[:space:]]+ALL[[:space:]]*=' /etc/sudoers /etc/sudoers.d/ 2>/dev/null | awk '{print $1}' | grep -v '^%' | sort -u | grep -vx root)
WHEEL=$( { getent group wheel; getent group sudo; } 2>/dev/null | awk -F: '{print $4}' | tr ',' '\n' | sed '/^$/d' | sort -u)
chk INFO "Sudo users (sudoers)" "${SUDOERS:-none}"
chk INFO "Wheel/sudo group members" "${WHEEL:-none}"
# Shell-enabled accounts (UID >= 1000 with a login shell)
CPU_LIST=""; [ -d /var/cpanel/users ] && CPU_LIST=$(ls /var/cpanel/users 2>/dev/null)
SHELLU=$(awk -F: -v cp="$CPU_LIST" 'BEGIN{n=split(cp,a,"\n");for(i=1;i<=n;i++)C[a[i]]=1}
  $3>=1000 && $3<65534 && $7!="" && $7 !~ /(nologin|false|noshell)$/ {t=($7 ~ /jailshell/)?"Jailed shell":"FULL shell"; print $1"\t"$7"\t"t"\t"(C[$1]?"cPanel account":"system/other")"\t"$6}' /etc/passwd 2>/dev/null | sort -t$'\t' -k3,3r -k1,1)
SHN=$(printf '%s' "$SHELLU" | grep -c .); SHF=$(printf '%s\n' "$SHELLU" | awk -F'\t' '$3=="FULL shell"' | grep -c .)
if   [ "$SHN" -eq 0 ]; then chk PASS "No accounts have shell access enabled"
elif [ "$SHF" -gt 0 ]; then chk WARN "Shell access enabled for $SHN user(s), $SHF with an unrestricted shell" "Users with full shell: $(printf '%s\n' "$SHELLU" | awk -F'\t' '$3=="FULL shell"{print $1}' | head -n 15 | tr '\n' ' ')"
else chk INFO "Shell access enabled for $SHN user(s) - all jailed" "Confirm each user needs shell access"; fi
tbl $'Shell-enabled user\tShell\tType\tAccount type\tHome' "$SHELLU"
# SSH authorized keys
RK=0; [ -f /root/.ssh/authorized_keys ] && RK=$(grep -cE '^[[:space:]]*[^#[:space:]]' /root/.ssh/authorized_keys 2>/dev/null)
[ "$RK" -gt 0 ] && chk INFO "root authorized_keys" "$RK key(s) present - confirm each is authorized" || chk PASS "No root authorized_keys"
UK=$(find /home* -maxdepth 3 -type f -path '*/.ssh/authorized_keys' 2>/dev/null)
UKN=$(printf '%s' "$UK" | grep -c .)
[ "$UKN" -gt 0 ] && { chk INFO "User accounts with authorized_keys" "$UKN account(s)"; raw "authorized_keys files" "$UK"; } || chk PASS "No user authorized_keys under /home*"
# cron (read files directly - no crontab calls, no temp files)
CRON_ALL=""
for f in /etc/crontab /etc/cron.d/* /var/spool/cron/* /var/spool/cron/crontabs/*; do
  [ -f "$f" ] && CRON_ALL+=$(sed "s|^|[$f] |" "$f" 2>/dev/null)$'\n'
done
CRON_ACT=$(printf '%s\n' "$CRON_ALL" | grep -vE '^\[[^]]*\][[:space:]]*(#|$)' | grep -v '^$')
CN=$(printf '%s' "$CRON_ACT" | grep -c .)
chk INFO "Active cron entries" "$CN"
SUSP='(/tmp/|/var/tmp/|/dev/shm/|(^|[[:space:]|;&(])(curl|wget|nc|netcat)[[:space:]]|(ba)?sh[[:space:]]+-c|base64[[:space:]]+(-d|--decode)|python[0-9.]*[[:space:]]+-c|perl[[:space:]]+-e|php[[:space:]]+-r|eval[[:space:]]*\(|chattr[[:space:]]+\+i|chmod[[:space:]]+(-[A-Za-z]+[[:space:]]+)?(0?777|[ao]\+w))'
SM=$(printf '%s\n' "$CRON_ACT" | grep -Ei "$SUSP" | sort -u | head -n 50)
[ -n "$SM" ] && { chk WARN "Cron entries matching suspicious patterns" "$(printf '%s\n' "$SM" | wc -l) line(s) - review manually"; raw "Suspicious cron lines" "$SM"; } || chk PASS "No suspicious cron patterns"
CPW=$(find /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly -type f -perm /022 -ls 2>/dev/null)
[ -n "$CPW" ] && { chk WARN "Cron files writable by group/others"; raw "Writable cron files" "$CPW"; } || chk PASS "Cron files not group/other-writable"
raw "All active cron entries" "$CRON_ACT"
sec_close

# ==========================================================================
#  SECTION: SSH
# ==========================================================================
sec_open ssh "SSH Configuration"
if ! svc_inst ssh; then chk SKIP "OpenSSH not installed"
else
  [ -f /etc/ssh/sshd_config ] && chk PASS "sshd_config present" || chk WARN "/etc/ssh/sshd_config not found"
  chk INFO "Service state" "${SV_STATE[ssh]} (listening: ${SV_PORTS[ssh]})"
  if [ -z "$SSHD_T" ]; then
    chk WARN "Effective config unavailable" "sshd -T returned nothing (needs root). Showing raw file settings."
    SSHD_T=$(grep -vE '^[[:space:]]*(#|$)' /etc/ssh/sshd_config 2>/dev/null | awk '{k=tolower($1);$1="";sub(/^ /,"");print k" "$0}')
  fi
  sv() { printf '%s\n' "$SSHD_T" | awk -v k="$1" '$1==k{$1="";sub(/^ /,"");print;exit}'; }
  v=$(sv permitrootlogin)
  case $v in no|forced-commands-only) chk PASS "PermitRootLogin" "$v";; prohibit-password|without-password) chk INFO "PermitRootLogin" "$v (key-only root login)";; yes) chk FAIL "PermitRootLogin yes" "Root can log in with password";; "") chk SKIP "PermitRootLogin not determinable";; *) chk WARN "PermitRootLogin" "$v";; esac
  v=$(sv passwordauthentication); [ "$v" = no ] && chk PASS "PasswordAuthentication no" || chk WARN "PasswordAuthentication ${v:-default(yes)}" "Prefer key-based auth + fail2ban/CSF"
  v=$(sv permitemptypasswords);   [ "$v" = yes ] && chk FAIL "PermitEmptyPasswords yes" || chk PASS "PermitEmptyPasswords" "${v:-no}"
  v=$(sv pubkeyauthentication);   [ "$v" = no ] && chk WARN "PubkeyAuthentication disabled" || chk PASS "PubkeyAuthentication" "${v:-yes}"
  v=$(sv maxauthtries);           { [ -n "$v" ] && [ "$v" -le 4 ] 2>/dev/null; } && chk PASS "MaxAuthTries" "$v" || chk WARN "MaxAuthTries ${v:-6}" "Recommended <= 4"
  v=$(sv logingracetime);         chk INFO "LoginGraceTime" "${v:-default}"
  for p in $SSH_PORTS; do [ "$p" = 22 ] && { chk INFO "SSH on default port 22" "Consider restricting by firewall/allowlist"; break; }; done
  v=$(sv x11forwarding);          [ "$v" = yes ] && chk WARN "X11Forwarding yes" || chk PASS "X11Forwarding" "${v:-no}"
  v=$(sv allowtcpforwarding);     [ "$v" = no ] && chk PASS "AllowTcpForwarding no" || chk INFO "AllowTcpForwarding" "${v:-yes}"
  v="$(sv allowusers)$(sv allowgroups)"; [ -n "$v" ] && chk PASS "AllowUsers/AllowGroups restriction set" || chk INFO "No AllowUsers/AllowGroups restriction"
  v=$(sv ciphers); printf '%s' "$v" | grep -qiE '3des|arcfour|blowfish|(^|,)aes[0-9]+-cbc' && chk WARN "Weak SSH ciphers enabled" "$v" || chk PASS "SSH ciphers"
  v=$(sv macs);    printf '%s' "$v" | grep -qiE 'md5|umac-64' && chk WARN "Weak SSH MACs enabled" "$v" || chk PASS "SSH MACs"
  v=$(sv kexalgorithms); printf '%s' "$v" | grep -qiE 'diffie-hellman-group1-sha1|diffie-hellman-group14-sha1|group-exchange-sha1' && chk WARN "Weak SSH KEX enabled" "$v" || chk PASS "SSH key exchange"
  raw "Effective sshd settings" "$(printf '%s\n' "$SSHD_T" | grep -E '^(port|permitrootlogin|passwordauthentication|pubkeyauthentication|permitemptypasswords|maxauthtries|logingracetime|allowusers|allowgroups|denyusers|denygroups|clientaliveinterval|clientalivecountmax|allowtcpforwarding|x11forwarding|permittunnel|gatewayports|ciphers|macs|kexalgorithms) ')"
fi
sec_close

# ==========================================================================
#  SECTION: Authentication logs (single pass)
# ==========================================================================
sec_open authlog "Authentication Logs"
AUTH_SRC=""; AUTH_DATA=""
if   [ -f /var/log/secure ];   then AUTH_SRC=/var/log/secure;   AUTH_DATA=$(tail -n "$AUTH_TAIL" /var/log/secure 2>/dev/null)
elif [ -f /var/log/auth.log ]; then AUTH_SRC=/var/log/auth.log; AUTH_DATA=$(tail -n "$AUTH_TAIL" /var/log/auth.log 2>/dev/null)
elif have journalctl && [ $HAVE_SYSTEMD -eq 1 ]; then AUTH_SRC="journalctl (sshd)"; AUTH_DATA=$(t journalctl _COMM=sshd --no-pager -n "$AUTH_TAIL" -o cat)
fi
if [ -z "$AUTH_DATA" ]; then chk SKIP "No authentication log available" "Checked /var/log/secure, /var/log/auth.log, journald"
else
  AR=$(printf '%s\n' "$AUTH_DATA" | awk '
    /Failed password|authentication failure|Failed publickey|Invalid user/ {f++; if(match($0,/[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/)) ip[substr($0,RSTART,RLENGTH)]++}
    /Accepted (password|publickey|keyboard-interactive)/ {s++; if(match($0,/ for [^ ]+/)) u[substr($0,RSTART+5,RLENGTH-5)]++}
    /(Accepted|Failed) [a-z-]+ for root|Invalid user root/ {r++}
    END{print "F\t" f+0; print "S\t" s+0; print "R\t" r+0; for(i in ip)print "IP\t" ip[i] "\t" i; for(x in u)print "U\t" u[x] "\t" x}')
  FC=$(awk -F'\t' '$1=="F"{print $2}' <<<"$AR"); SC=$(awk -F'\t' '$1=="S"{print $2}' <<<"$AR"); RC=$(awk -F'\t' '$1=="R"{print $2}' <<<"$AR")
  chk INFO "Source" "$AUTH_SRC (last $AUTH_TAIL lines analysed)"
  if   [ "$FC" -gt 100 ]; then chk WARN "High failed-authentication count" "$FC failed attempts"
  elif [ "$FC" -gt 0 ];   then chk INFO "Failed authentication attempts" "$FC (review)"
  else chk PASS "No failed authentication attempts"; fi
  chk INFO "Successful SSH logins" "$SC"
  chk INFO "Root SSH login activity" "$RC attempts/logins"
  tbl $'Failures\tSource IP' "$(awk -F'\t' '$1=="IP"{print $2"\t"$3}' <<<"$AR" | sort -t$'\t' -k1,1nr | head -n 20)"
  tbl $'Logins\tUser' "$(awk -F'\t' '$1=="U"{print $2"\t"$3}' <<<"$AR" | sort -t$'\t' -k1,1nr | head -n 15)"
  raw "Last 20 failed attempts" "$(printf '%s\n' "$AUTH_DATA" | grep -iE 'Failed password|authentication failure|Invalid user' | tail -n 20)"
fi
sec_close

# ==========================================================================
#  SECTION: Firewall & network exposure
# ==========================================================================
sec_open firewall "Firewall & Network Exposure"
FW_ANY=0
if svc_inst csf; then
  FW_ANY=1
  if svc_up csf; then chk PASS "CSF/LFD active" "${SV_DETAIL[csf]}"; else chk WARN "CSF installed but LFD/CSF not active"; fi
  if [ -f /etc/csf/csf.conf ]; then
    CSFC=$(grep -E '^(TESTING|LF_DAEMON|TCP_IN|TCP_OUT|UDP_IN|UDP_OUT|SYNFLOOD|CONNLIMIT|PORTFLOOD)[[:space:]]*=' /etc/csf/csf.conf 2>/dev/null)
    raw "CSF configuration" "$CSFC"
    printf '%s\n' "$CSFC" | grep -qE '^TESTING[[:space:]]*=[[:space:]]*"1"' && chk FAIL "CSF is in TESTING mode" "Rules are flushed periodically; set TESTING = 0"
    TIN=$(printf '%s\n' "$CSFC" | sed -nE 's/^TCP_IN[[:space:]]*=[[:space:]]*"([^"]*)".*/\1/p' | tr ',' ' ')
    BADP=""; for p in 23 3306 5432 6379 11211 27017; do [[ " $TIN " == *" $p "* ]] && BADP+="$p "; done
    [ -n "$BADP" ] && chk WARN "Sensitive ports allowed inbound in CSF" "TCP_IN includes: $BADP" || chk PASS "No database/cache ports open in CSF TCP_IN"
  fi
  have csf && raw "csf -l (first 100 lines)" "$(t csf -l | head -n 100)"
fi
if svc_inst fwd; then
  FW_ANY=1
  svc_up fwd && chk PASS "firewalld active" || chk INFO "firewalld installed but inactive"
  if svc_up fwd; then
    raw "firewalld zones & rules" "$(t firewall-cmd --get-active-zones; t firewall-cmd --list-all-zones)"
  fi
fi
if [ $FW_ANY -eq 0 ] || ! svc_up csf && ! svc_up fwd; then
  # generic fallback: only inspect raw netfilter when no managed firewall is active
  if have iptables; then
    IPT=$(t iptables -S); IPN=$(printf '%s\n' "$IPT" | grep -c '^-A')
    raw "iptables -S" "$IPT"; raw "ip6tables -S" "$(have ip6tables && t ip6tables -S)"
    if [ "$IPN" -eq 0 ] && printf '%s\n' "$IPT" | grep -q -- '-P INPUT ACCEPT'; then chk FAIL "No firewall rules and INPUT policy ACCEPT"
    elif [ "$IPN" -gt 0 ]; then chk INFO "Unmanaged iptables rules present" "$IPN rule(s)"; fi
  elif have nft; then
    NFT=$(t nft list ruleset); raw "nft ruleset" "$NFT"; [ -z "$NFT" ] && chk WARN "No nftables ruleset" || chk INFO "nftables ruleset present"
  else chk WARN "No firewall tooling detected"; fi
fi
# Listening ports (single table) + exposure analysis
if [ -n "$PORT_ROWS" ]; then
  RISKY="23:telnet 111:rpcbind 445:smb 3306:mysql 5432:postgres 6379:redis 11211:memcached 27017:mongodb 9200:elasticsearch 5900:vnc 2049:nfs"
  for e in $RISKY; do p=${e%%:*}; n=${e##*:}
    [ "${PORT_SCOPE[tcp:$p]:-}" = public ] && chk WARN "$n (tcp/$p) listening on all interfaces" "Bind to 127.0.0.1 or firewall it"
  done
  [ "${PORT_SCOPE[udp:53]:-}" = public ] && ! svc_inst dns && chk INFO "udp/53 listening but no known DNS service" "${PORT_PROC[udp:53]:-}"
  PT=$(printf '%s\n' "$PORT_ROWS" | sort -t$'\t' -k2,2n | awk -F'\t' '{print $1"\t"$2"\t"$4"\t"$3"\t"$5}')
  tbl $'Proto\tPort\tAddress\tScope\tProcess' "$PT"
else chk SKIP "Listening ports" "ss unavailable or no permission"; fi
have ip && raw "Interfaces" "$(t ip -br addr)"
FWD4=$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null); FWD6=$(cat /proc/sys/net/ipv6/conf/all/forwarding 2>/dev/null)
[ "$FWD4" = 1 ] && chk INFO "IPv4 forwarding enabled" "Expected only for routers/VPN/containers" || chk PASS "IPv4 forwarding disabled"
[ "$FWD6" = 1 ] && chk INFO "IPv6 forwarding enabled"
[ $HAVE_SYSTEMD -eq 1 ] && raw "Running systemd services" "$(t systemctl --type=service --state=running --no-pager --no-legend | awk '{print $1}')"
sec_close

# ==========================================================================
#  SECTION: Traffic / DDoS indicators (from shared ss snapshot)
# ==========================================================================
sec_open traffic "Connection Load & DDoS Indicators"
if [ -z "$SS_TAN" ]; then chk SKIP "ss unavailable" "Connection analysis skipped"
else
  tbl $'Count\tTCP state' "$(printf '%s\n' "$SS_TAN" | awk '{c[$1]++}END{for(s in c)print c[s]"\t"s}' | sort -t$'\t' -k1,1nr)"
  for P in 80 443; do
    CNT=$(printf '%s\n' "$SS_TAN" | awk -v p=":$P" '$1!="LISTEN" && substr($4,length($4)-length(p)+1)==p{n++}END{print n+0}')
    chk INFO "Established-class connections on port $P" "$CNT"
    TOP=$(printf '%s\n' "$SS_TAN" | awk -v p=":$P" '$1!="LISTEN" && substr($4,length($4)-length(p)+1)==p{ip=$5;sub(/:[0-9]+$/,"",ip);gsub(/[\[\]]/,"",ip);c[ip]++}END{for(i in c)print c[i]"\t"i}' | sort -t$'\t' -k1,1nr | head -n 20)
    tbl "Conns"$'\t'"Top source IPs on :$P" "$TOP"
    TOPN=$(printf '%s\n' "$TOP" | head -n1 | cut -f1)
    [ "${TOPN:-0}" -ge 200 ] && chk WARN "Single IP has $TOPN connections on :$P" "$(printf '%s\n' "$TOP" | head -n1 | cut -f2)"
  done
  # Inbound: half-open connections arriving at this server
  SYN=$(printf '%s\n' "$SS_TAN" | awk '$1=="SYN-RECV"{n++}END{print n+0}')
  MSG_IN="Potential SYN_RECV DDoS attack detected! Please check network connections"
  if   [ "$SYN" -ge "$SYN_RECV_CRIT" ]; then chk FAIL "Inbound DDoS check (SYN_RECV): $SYN" "$MSG_IN"
  elif [ "$SYN" -ge "$SYN_RECV_WARN" ]; then chk WARN "Inbound DDoS check (SYN_RECV): $SYN" "$MSG_IN"
  elif [ "$SYN" -ge 100 ]; then chk INFO "Inbound DDoS check (SYN_RECV): $SYN" "Elevated - monitor connection rate and source distribution (warn at $SYN_RECV_WARN)"
  else chk PASS "Inbound DDoS check (SYN_RECV)" "$SYN half-open inbound connection(s) - normal"; fi
  if [ "$SYN" -ge 100 ]; then
    tbl $'Count\tSYN-RECV source IP' "$(printf '%s\n' "$SS_TAN" | awk '$1=="SYN-RECV"{ip=$5;sub(/:[0-9]+$/,"",ip);c[ip]++}END{for(i in c)print c[i]"\t"i}' | sort -t$'\t' -k1,1nr | head -n 15)"
    tbl $'Count\tSYN-RECV by dest port' "$(printf '%s\n' "$SS_TAN" | awk '$1=="SYN-RECV"{p=$4;sub(/^.*:/,"",p);c[p]++}END{for(i in c)print c[i]"\t"i}' | sort -t$'\t' -k1,1nr | head -n 10)"
  fi
  # Outbound: half-open connections this server is initiating (compromised-host / outbound flood indicator)
  SYNS=$(printf '%s\n' "$SS_TAN" | awk '$1=="SYN-SENT"{n++}END{print n+0}')
  MSG_OUT="Potential SYN_SENT DDoS attack detected! Please check network connections"
  if   [ "$SYNS" -ge "$SYN_SENT_CRIT" ]; then chk FAIL "Outbound DDoS check (SYN_SENT): $SYNS" "$MSG_OUT"
  elif [ "$SYNS" -ge "$SYN_SENT_WARN" ]; then chk WARN "Outbound DDoS check (SYN_SENT): $SYNS" "$MSG_OUT"
  elif [ "$SYNS" -ge 100 ]; then chk INFO "Outbound DDoS check (SYN_SENT): $SYNS" "Elevated - monitor (warn at $SYN_SENT_WARN)"
  else chk PASS "Outbound DDoS check (SYN_SENT)" "$SYNS outbound half-open connection(s) - normal"; fi
  if [ "$SYNS" -ge 100 ]; then
    tbl $'Count\tSYN-SENT destination IP' "$(printf '%s\n' "$SS_TAN" | awk '$1=="SYN-SENT"{ip=$5;sub(/:[0-9]+$/,"",ip);c[ip]++}END{for(i in c)print c[i]"\t"i}' | sort -t$'\t' -k1,1nr | head -n 15)"
    tbl $'Count\tSYN-SENT destination port' "$(printf '%s\n' "$SS_TAN" | awk '$1=="SYN-SENT"{p=$5;sub(/^.*:/,"",p);c[p]++}END{for(i in c)print c[i]"\t"i}' | sort -t$'\t' -k1,1nr | head -n 10)"
    # process attribution - only queried when the threshold is reached
    tbl $'Count\tProcess opening the connections' "$(t ss -tanp state syn-sent | awk 'NR>1{p="-"; if(match($0,/\(\("[^"]+"/))p=substr($0,RSTART+3,RLENGTH-4); c[p]++}END{for(i in c)print c[i]"\t"i}' | sort -t$'\t' -k1,1nr | head -n 10)"
  fi
fi
sec_close

# ==========================================================================
#  SECTION: Host protection (Imunify / BitNinja)
# ==========================================================================
sec_open protect "Malware / Intrusion Protection (Imunify, BitNinja)"
imunify_report() { # key unit cli label
  local key=$1 unit=$2 cli=$3 label=$4 u st rows="" prim
  prim=$(systemctl is-active "$unit" 2>/dev/null)
  if [ "$prim" = active ]; then chk PASS "$label service ($unit) is active"
  else chk WARN "$label service ($unit) is ${prim:-not running}" "Check: systemctl status $unit"; fi
  have systemctl && raw "systemctl status $unit" "$(t systemctl status "$unit" --no-pager -l | head -n 15)"
  # companion units of the same product
  for u in $(printf '%s\n' "$UNIT_FILES" | grep -oE "^imunify[a-z0-9-]*\.service" | sed 's/\.service$//' | sort -u); do
    [ "$u" = "$unit" ] && continue
    case $key in i360) [[ $u == imunify360* ]] || continue;; imav) [[ $u == imunify360* ]] && continue;; esac
    st=$(systemctl is-active "$u" 2>/dev/null); rows+="$u"$'\t'"${st:-unknown}"$'\n'
  done
  [ -n "$rows" ] && tbl $'Companion service\tState' "$rows"
  if have "$cli"; then
    chk INFO "$label version" "$(t $cli version | head -n 3 | tr '\n' ' ')"
    if [ "$key" = imav ]; then raw "$cli show-license" "$(t $cli show-license | head -n 20)"
    else raw "$cli rstatus (registration/license)" "$(t $cli rstatus | head -n 20)"; fi
  else chk INFO "$cli command not found" "Version/licence not shown"; fi
}
if svc_inst i360 || svc_inst imav; then
  svc_inst i360 && imunify_report i360 imunify360 imunify360-agent "Imunify360"
  svc_inst imav && imunify_report imav imunify-antivirus imunify-antivirus "Imunify AV"
  svc_inst imav && ! svc_inst i360 && chk INFO "Imunify AV edition installed" "Malware scanning only - no Imunify360 firewall/WAF/proactive defense"
  for lg in /var/log/imunify360/imunify360.log /var/log/imunify360/console.log /var/log/imunify360/error.log; do
    [ -f "$lg" ] && raw "Recent log: $lg (20 lines)" "$(tail -n 20 "$lg" 2>/dev/null | cut -c1-250)"
  done
else chk SKIP "Imunify360 / Imunify AV not installed"; fi
if svc_inst bitninja; then
  svc_up bitninja && chk PASS "BitNinja running" || chk WARN "BitNinja installed but not running"
  have bnconfig && raw "BitNinja version" "$(t bnconfig --version)"
  [ -d /var/log/bitninja ] && raw "Recent BitNinja logs" "$(find /var/log/bitninja -type f -printf '%TY-%Tm-%Td %TH:%TM %p\n' 2>/dev/null | sort -r | head -n 5)"
else chk SKIP "BitNinja not installed"; fi
! svc_inst i360 && ! svc_inst imav && ! svc_inst bitninja && chk INFO "No host-level malware/intrusion agent detected" "Rely on CSF/LFD + ModSecurity"
sec_close

# ==========================================================================
#  SECTION: Web servers (+ ModSecurity)
# ==========================================================================
sec_open web "Web Server & ModSecurity"
if ! svc_inst apache && ! svc_inst nginx && ! svc_inst lsws; then chk SKIP "No web server installed"
else
  if svc_inst apache; then
    HB=""; for b in httpd apache2; do have $b && { HB=$b; break; }; done
    [ -n "$HB" ] && chk INFO "Apache version" "$(t $HB -v | head -n1)"
    if [ -n "$HB" ]; then
      HT=$(t2 $HB -t); printf '%s' "$HT" | grep -q 'Syntax OK' && chk PASS "Apache configuration syntax" "Syntax OK" || chk FAIL "Apache configuration test failed" "$HT"
      MODS=$(t $HB -M)
    fi
    ADIRS=(); for d in /etc/apache2/conf /etc/apache2/conf.d /etc/apache2/conf.modules.d /etc/httpd/conf /etc/httpd/conf.d /usr/local/apache/conf; do [ -d "$d" ] && ADIRS+=("$d"); done
    if [ ${#ADIRS[@]} -gt 0 ]; then
      ACFG=$(grep -RIsniE --include='*.conf' --exclude-dir=modsec_vendor_configs --exclude-dir=userdata --exclude-dir=modsec \
        '^[[:space:]]*(Options[[:space:]]|ServerTokens|ServerSignature|TraceEnable|AllowOverride|Header[[:space:]].*(X-Frame-Options|X-Content-Type-Options|Content-Security-Policy|Strict-Transport-Security|Referrer-Policy))' "${ADIRS[@]}")
      IDX=$(printf '%s\n' "$ACFG" | grep -iE 'Options.*[[:space:]+]Indexes' | head -n 10)
      [ -n "$IDX" ] && { chk WARN "Directory listing (Indexes) enabled in global config" "$IDX"; } || chk PASS "No global 'Options Indexes'"
      v=$(printf '%s\n' "$ACFG" | grep -i 'ServerTokens' | tail -n1 | awk '{print tolower($NF)}')
      case $v in prod|productonly) chk PASS "ServerTokens" "$v";; *) chk WARN "ServerTokens ${v:-not set (default Full)}" "Set ServerTokens Prod";; esac
      v=$(printf '%s\n' "$ACFG" | grep -i 'ServerSignature' | tail -n1 | awk '{print tolower($NF)}')
      [ "$v" = off ] && chk PASS "ServerSignature Off" || chk WARN "ServerSignature ${v:-not set}" "Set ServerSignature Off"
      v=$(printf '%s\n' "$ACFG" | grep -i 'TraceEnable' | tail -n1 | awk '{print tolower($NF)}')
      [ "$v" = off ] && chk PASS "TraceEnable Off" || chk WARN "TraceEnable ${v:-not set (default On)}" "Set TraceEnable Off"
      MISSH=""; for h in X-Frame-Options X-Content-Type-Options Content-Security-Policy Strict-Transport-Security Referrer-Policy; do
        printf '%s\n' "$ACFG" | grep -qi "$h" || MISSH+="$h "; done
      [ -n "$MISSH" ] && chk INFO "Security headers not set in global Apache config" "$MISSH (may be set per-site/app)" || chk PASS "Security headers configured globally"
      raw "Apache config findings (global)" "$(printf '%s\n' "$ACFG" | cut -c1-220 | head -n 80)"
    fi
    if [ -n "${MODS:-}" ]; then
      chk INFO "Key Apache modules" "$(printf '%s\n' "$MODS" | grep -Ei 'security|rewrite|ssl|headers|proxy_fcgi|expires|autoindex|status|info' | awk '{print $1}' | tr '\n' ' ')"
      printf '%s\n' "$MODS" | grep -qE 'status_module|info_module' && chk INFO "mod_status/mod_info loaded" "Ensure /server-status and /server-info are restricted"
      # ModSecurity
      if printf '%s\n' "$MODS" | grep -q security2_module; then
        chk PASS "ModSecurity module loaded"
        ENG=$(grep -RhsiE --include='*.conf' '^[[:space:]]*SecRuleEngine' /etc/apache2/conf.d /etc/apache2/conf /etc/httpd/conf.d /usr/local/apache/conf 2>/dev/null | tail -n1 | awk '{print tolower($2)}')
        case $ENG in on) chk PASS "SecRuleEngine On";; detectiononly) chk WARN "SecRuleEngine DetectionOnly" "Rules log but do not block";; off) chk FAIL "SecRuleEngine Off";; *) chk INFO "SecRuleEngine not found in global conf";; esac
        VD=/etc/apache2/conf.d/modsec_vendor_configs
        if [ -d $VD ]; then
          VL=$(find $VD -maxdepth 1 -mindepth 1 -type d -printf '%f\n' 2>/dev/null)
          chk INFO "ModSecurity vendor rule sets" "${VL:-none}"
          printf '%s\n' "$VL" | grep -qi imunify && chk PASS "Imunify360 WAF rules present"
          printf '%s\n' "$VL" | grep -qi owasp && chk PASS "OWASP CRS present" || { grep -RqsE 'OWASP_CRS' /etc/apache2/conf.d 2>/dev/null && chk PASS "OWASP CRS referenced in config"; }
        else chk INFO "No modsec_vendor_configs directory"; fi
        MAL=/usr/local/apache/logs/modsec_audit.log
        [ -f $MAL ] && { chk INFO "ModSecurity audit log" "$(du -h $MAL | awk '{print $1}')"; raw "ModSecurity audit log (last 20 lines)" "$(tail -n 20 $MAL 2>/dev/null | cut -c1-250)"; }
      else chk WARN "ModSecurity (security2_module) not loaded" "No WAF at web-server level"; fi
    fi
    raw "Apache top processes by CPU" "$(printf '%s\n' "$PS_ALL" | awk '$7=="httpd"||$7=="apache2"' | cut -c1-180 | head -n 25)"
  else chk SKIP "Apache not installed"; fi

  if svc_inst nginx; then
    chk INFO "Nginx version" "$(t2 nginx -v)"
    NT=$(t2 nginx -t); printf '%s' "$NT" | grep -q 'successful' && chk PASS "Nginx configuration test" || chk FAIL "Nginx configuration test failed" "$NT"
    NCFG=$(grep -RIsniE --include='*.conf' '^[[:space:]]*(server_tokens|autoindex|add_header.*(X-Frame-Options|X-Content-Type-Options|Content-Security-Policy|Strict-Transport-Security|Referrer-Policy))' /etc/nginx /usr/local/nginx/conf 2>/dev/null | head -n 60)
    printf '%s\n' "$NCFG" | grep -qiE 'server_tokens[[:space:]]+off' && chk PASS "server_tokens off" || chk WARN "nginx server_tokens not disabled"
    printf '%s\n' "$NCFG" | grep -qiE 'autoindex[[:space:]]+on' && chk WARN "nginx autoindex on" || chk PASS "nginx autoindex not enabled"
    raw "Nginx config findings" "$NCFG"
  fi
  if svc_inst lsws; then
    LSV=$(cat /usr/local/lsws/VERSION 2>/dev/null)
    chk INFO "LiteSpeed" "version ${LSV:-unknown}; state ${SV_STATE[lsws]}"
    [ -f /usr/local/lsws/conf/httpd_config.xml ] && chk INFO "LiteSpeed main config present" || chk INFO "LiteSpeed main config not found at default path"
    raw "LiteSpeed processes" "$(printf '%s\n' "$PS_ALL" | awk '$7 ~ /litespeed|lshttpd/' | cut -c1-180 | head -n 25)"
  fi
  LSPHP=$(printf '%s\n' "$PS_ALL" | awk '$7 ~ /lsphp/' | cut -c1-180 | head -n 15)
  [ -n "$LSPHP" ] && raw "Top 15 LSPHP workers (per-account)" "$LSPHP"
fi
sec_close

# ==========================================================================
#  SECTION: PHP & PHP-FPM
# ==========================================================================
sec_open php "PHP & PHP-FPM"
declare -A EOLD=([8.2]=2026-12-31 [8.3]=2027-12-31 [8.4]=2028-12-31 [8.5]=2029-12-31)
PHPBINS=(); PHPINIS=(); PHPLBL=(); PHPPHPD=(); PHPFPMD=()
for d in /opt/cpanel/ea-php*; do [ -x "$d/root/usr/bin/php" ] && { PHPBINS+=("$d/root/usr/bin/php"); PHPINIS+=("$d/root/etc/php.ini"); PHPLBL+=("$(basename $d)"); PHPPHPD+=("$d/root/etc/php.d"); PHPFPMD+=("$d/root/etc/php-fpm.d"); }; done
# Alt-PHP (CloudLinux PHP Selector) - only inspected when present (normally CloudLinux hosts)
ALT_DIRS=$(ls -d /opt/alt/php[0-9]* 2>/dev/null)
if [ -n "$ALT_DIRS" ]; then
  [ $CL_INST -eq 1 ] && chk INFO "Alt-PHP detected (CloudLinux)" "$(printf '%s\n' "$ALT_DIRS" | xargs -n1 basename | tr '\n' ' ')" \
                     || chk INFO "Alt-PHP directories found but CloudLinux not detected" "Checking anyway"
  for d in $ALT_DIRS; do [ -x "$d/usr/bin/php" ] && { PHPBINS+=("$d/usr/bin/php"); PHPINIS+=("$(ls $d/etc/php.ini $d/usr/etc/php.ini 2>/dev/null | head -n1)"); PHPLBL+=("alt-$(basename $d)"); PHPPHPD+=("$d/etc/php.d"); PHPFPMD+=("$d/etc/php-fpm.d"); }; done
elif [ $CL_INST -eq 1 ]; then chk INFO "CloudLinux present but no Alt-PHP installed"
else chk SKIP "Alt-PHP not present" "Not a CloudLinux/PHP-Selector host - Alt-PHP checks skipped"; fi
if [ ${#PHPBINS[@]} -eq 0 ] && have php; then PHPBINS+=("$(command -v php)"); PHPINIS+=("$(php --ini 2>/dev/null | awk -F': *' '/Loaded Configuration/{print $2}')"); PHPLBL+=("system-php"); PHPPHPD+=("/etc/php.d"); PHPFPMD+=("/etc/php-fpm.d"); fi
# Function baselines for disable_functions verification
DF_CRIT="exec passthru shell_exec system proc_open popen pcntl_exec"
DF_HARD="dl symlink link posix_kill posix_setuid proc_terminate proc_get_status show_source"
DFROWS=""; DFLISTS=""
if [ ${#PHPBINS[@]} -eq 0 ] && ! svc_inst phpfpm; then chk SKIP "PHP not installed"
else
  TODAY=$(date +%s); VROWS=""; IROWS=""
  for i in "${!PHPBINS[@]}"; do
    bin=${PHPBINS[$i]}; ini=${PHPINIS[$i]}; lbl=${PHPLBL[$i]}
    pv=$(t "$bin" -n -v | head -n1 | awk '{print $2}'); mm=$(echo "$pv" | awk -F. '{print $1"."$2}')
    if [ -n "${EOLD[$mm]:-}" ]; then
      ee=$(date -d "${EOLD[$mm]}" +%s 2>/dev/null); days=$(( (ee - TODAY) / 86400 ))
      if [ $days -lt 0 ]; then st=FAIL; msg="EOL since ${EOLD[$mm]}"
      elif [ $days -lt 180 ]; then st=WARN; msg="security support ends ${EOLD[$mm]} ($days days)"
      else st=PASS; msg="supported until ${EOLD[$mm]}"; fi
    elif awk -v v="$mm" 'BEGIN{exit !(v+0<8.2)}'; then st=FAIL; msg="End of life"
    else st=INFO; msg="not in lifecycle table"; fi
    [ "$st" != PASS ] && [ "$st" != INFO ] && chk $st "$lbl PHP $pv" "$msg"
    VROWS+="$st"$'\t'"$lbl"$'\t'"${pv:-?}"$'\t'"$msg"$'\n'
    if [ -f "$ini" ]; then
      L=$(awk -F'=' '
        function trim(s){gsub(/^[ \t"]+|[ \t"]+$/,"",s);return s}
        /^[ \t]*;/ || !/=/ {next}
        {k=tolower(trim($1)); v=trim(substr($0,index($0,"=")+1)); sub(/[ \t]*;.*$/,"",v); val[k]=v}
        END{n=split("disable_functions allow_url_include allow_url_fopen display_errors expose_php enable_dl open_basedir memory_limit max_execution_time upload_max_filesize post_max_size",K," ")
            for(j=1;j<=n;j++){x=val[K[j]]; if(x=="")x="-"; printf "%s%s",(j>1?"\t":""),x}; print ""}' "$ini")
      IFS=$'\t' read -r df aui auf de ep edl ob ml me um pm <<<"$L"
      IROWS+="$lbl"$'\t'"$( [ "$df" = "-" ] && echo NONE || echo "$(echo "$df" | tr ',' '\n' | wc -l) funcs")"$'\t'"$aui"$'\t'"$auf"$'\t'"$de"$'\t'"$ep"$'\t'"$ml"$'\t'"$me"$'\t'"$um"$'\t'"$pm"$'\n'
      shopt -s nocasematch
      [[ $aui == on || $aui == 1 || $aui == true ]] && chk FAIL "$lbl allow_url_include enabled"
      [[ $ep  == on || $ep  == 1 || $ep  == true ]] && chk WARN "$lbl expose_php enabled"
      [[ $de  == on || $de  == 1 || $de  == true ]] && chk WARN "$lbl display_errors enabled" "Leaks paths/errors to visitors"
      [[ $edl == on || $edl == 1 ]] && chk WARN "$lbl enable_dl enabled"
      shopt -u nocasematch
    fi
    # ---- disable_functions: effective value (php.ini + php.d/*.ini as loaded by this build) ----
    EFF=$(t "$bin" -r 'echo ini_get("disable_functions");' | tr -d ' \r')
    [ -z "$EFF" ] && [ -f "$ini" ] && EFF=$(awk -F= '/^[ \t]*disable_functions[ \t]*=/{v=$2; sub(/[ \t]*;.*$/,"",v); gsub(/[ \t"]/,"",v); r=v} END{print r}' "$ini")
    DFLIST=$(printf '%s' "$EFF" | tr ',' '\n' | sed '/^$/d' | sort -u)
    DFN=$(printf '%s' "$DFLIST" | grep -c .)
    DFSRC=$( { [ -f "$ini" ] && grep -nHiE '^[[:space:]]*disable_functions[[:space:]]*=' "$ini"; grep -nHiE '^[[:space:]]*disable_functions[[:space:]]*=' "${PHPPHPD[$i]}"/*.ini 2>/dev/null; } | cut -c1-160)
    MISS_C=""; for f in $DF_CRIT; do printf '%s\n' "$DFLIST" | grep -qx "$f" || MISS_C+="$f "; done
    MISS_H=""; for f in $DF_HARD; do printf '%s\n' "$DFLIST" | grep -qx "$f" || MISS_H+="$f "; done
    if [ "$DFN" -eq 0 ]; then chk FAIL "$lbl disable_functions is EMPTY" "No functions disabled - exec/system/shell_exec/passthru available to scripts"; dst=FAIL
    elif [ -n "$MISS_C" ]; then chk WARN "$lbl: command-execution functions NOT disabled" "$MISS_C"; dst=WARN
    else chk PASS "$lbl: all command-execution functions disabled" "$DFN function(s) disabled"; dst=PASS; fi
    [ -n "$MISS_H" ] && [ "$DFN" -gt 0 ] && chk INFO "$lbl: hardening functions not disabled" "$MISS_H"
    DFROWS+="$dst"$'\t'"$lbl"$'\t'"$DFN"$'\t'"${MISS_C:--}"$'\t'"${MISS_H:--}"$'\n'
    DFLISTS+="### $lbl ($DFN disabled)"$'\n'"$(printf '%s' "$DFLIST" | tr '\n' ' ' | fold -s -w 110)"$'\n'"Defined in:"$'\n'"${DFSRC:-  (not set in php.ini / php.d)}"$'\n\n'
  done
  tbl $'Status\tPHP build\tVersion\tSupport' "$VROWS"
  tbl $'Build\tdisable_functions\turl_include\turl_fopen\tdisplay_errors\texpose_php\tmemory\texec time\tupload\tpost' "$IROWS"
  # ---- disable_functions summary + full lists ----
  tbl $'Status\tPHP build\t# disabled\tCommand-exec functions NOT disabled\tHardening functions NOT disabled' "$DFROWS"
  raw "Disabled functions - full list per PHP build (effective value + where defined)" "$DFLISTS"
  note "Baseline checked - command execution: $DF_CRIT. Hardening: $DF_HARD."
  # ---- verify disable_functions in PHP-FPM pool settings ----
  FPM_ANY=0
  for i in "${!PHPBINS[@]}"; do
    fd=${PHPFPMD[$i]}; lbl=${PHPLBL[$i]}
    ls "$fd"/*.conf >/dev/null 2>&1 || continue
    FPM_ANY=1
    NP=$(ls "$fd"/*.conf 2>/dev/null | wc -l)
    GL=$(t "${PHPBINS[$i]}" -r 'echo ini_get("disable_functions");' | tr -d ' \r')
    OV=$(grep -HsiE '^[[:space:]]*php(_admin)?_value\[disable_functions\]' "$fd"/*.conf | awk -v crit="$DF_CRIT" -v glb="$GL" '
      BEGIN{nc=split(crit,C," "); ng=split(glb,G,",")}
      { f=$0; sub(/:.*/,"",f); n=split(f,a,"/"); pool=a[n]; sub(/\.conf$/,"",pool)
        kind=(tolower($0) ~ /php_admin_value/)?"admin":"user"
        v=$0; sub(/^[^=]*=[ \t]*/,"",v); gsub(/[ \t"]/,"",v)
        delete M; m=split(v,P,","); for(j=1;j<=m;j++) if(P[j]!="") M[P[j]]=1
        mc=""; for(j=1;j<=nc;j++) if(!(C[j] in M)) mc=mc C[j] " "
        mg=0; for(j=1;j<=ng;j++) if(G[j]!="" && !(G[j] in M)) mg++
        print pool "\t" kind "\t" length(M) "\t" (mc==""?"-":mc) "\t" mg }')
    NO=$(printf '%s\n' "$OV" | cut -f1 | sed '/^$/d' | sort -u | wc -l)
    if [ "$NO" -eq 0 ]; then
      chk PASS "$lbl FPM: $NP pool(s) inherit disable_functions from php.ini" "No pool-level override - the global value above applies"
    else
      WEAK=$(printf '%s\n' "$OV" | awk -F'\t' '$4!="-"')
      NW=$(printf '%s\n' "$WEAK" | cut -f1 | sed '/^$/d' | sort -u | wc -l)
      chk INFO "$lbl FPM: $NO of $NP pool(s) override disable_functions" "$(printf '%s\n' "$OV" | awk -F'\t' '{k[$2]++}END{for(x in k)printf "%s=%d ",x,k[x]}')"
      if [ "$NW" -gt 0 ]; then
        chk WARN "$lbl FPM: $NW pool(s) override with a list missing command-exec functions" "Pools: $(printf '%s\n' "$WEAK" | cut -f1 | head -n 10 | tr '\n' ' ')"
        tbl $'Pool\tDirective\t# disabled\tMissing command-exec funcs\tGlobal funcs missing' "$(printf '%s\n' "$WEAK" | sed 's/\tadmin\t/\tphp_admin_value\t/;s/\tuser\t/\tphp_value (ignored by PHP)\t/' | head -n 25)"
      else chk PASS "$lbl FPM: all pool overrides keep command-exec functions disabled"; fi
      printf '%s\n' "$OV" | awk -F'\t' '$2=="user"' | grep -q . && chk INFO "$lbl FPM: pool(s) use php_value[disable_functions]" "disable_functions is PHP_INI_SYSTEM; only php_admin_value[] is honoured"
    fi
  done
  # cPanel-managed FPM defaults / per-domain overrides (YAML)
  if [ -d /var/cpanel/ApachePHPFPM ] || [ -d /var/cpanel/userdata ]; then
    YD=$(grep -siE 'disable_functions' /var/cpanel/ApachePHPFPM/system_pool_defaults.yaml 2>/dev/null | cut -c1-300)
    if [ -n "$YD" ]; then
      YM=""; for f in $DF_CRIT; do printf '%s' "$YD" | grep -qw "$f" || YM+="$f "; done
      [ -n "$YM" ] && chk WARN "cPanel FPM system pool defaults: command-exec functions missing" "$YM" || chk PASS "cPanel FPM system pool defaults disable all command-exec functions"
      raw "cPanel FPM system_pool_defaults.yaml (disable_functions)" "$YD"
    fi
    YF=$(grep -lsiE 'disable_functions' /var/cpanel/userdata/*/*.php-fpm.yaml 2>/dev/null)
    if [ -n "$YF" ]; then
      YW=""; while IFS= read -r f; do
        miss=""; txt=$(grep -siE 'disable_functions' "$f"); for fn in $DF_CRIT; do printf '%s' "$txt" | grep -qw "$fn" || miss+="$fn "; done
        [ -n "$miss" ] && YW+="$f"$'\t'"$miss"$'\n'
      done <<<"$YF"
      chk INFO "Per-domain FPM YAML files with disable_functions override" "$(printf '%s\n' "$YF" | grep -c .) file(s)"
      [ -n "$YW" ] && { chk WARN "Per-domain FPM overrides missing command-exec functions" "$(printf '%s' "$YW" | grep -c .) file(s)"; tbl $'YAML file\tMissing functions' "$(printf '%s' "$YW" | head -n 25)"; }
    fi
  fi
  [ $FPM_ANY -eq 0 ] && ! [ -d /var/cpanel/ApachePHPFPM ] && chk SKIP "No PHP-FPM pool configuration found" "Handler uses the global php.ini value shown above"
  # PHP-FPM
  if svc_inst phpfpm; then
    chk INFO "PHP-FPM state" "${SV_STATE[phpfpm]} ${SV_DETAIL[phpfpm]}"
    FPN=$(printf '%s\n' "$PS_ALL" | awk '$7=="php-fpm" && $0 ~ /master/{n++}END{print n+0}')
    chk INFO "PHP-FPM master processes" "$FPN"
    for d in /opt/cpanel/ea-php*; do
      u="$(basename $d)-php-fpm"
      if [ -d "$d/root/etc/php-fpm.d" ] && [ -x "$d/root/usr/sbin/php-fpm" ] && systemctl is-active --quiet "$u" 2>/dev/null; then
        POOLS=$(ls "$d/root/etc/php-fpm.d"/*.conf 2>/dev/null | wc -l)
        PMS=$(grep -hsE '^[[:space:]]*pm[[:space:]]*=' "$d/root/etc/php-fpm.d"/*.conf | awk -F= '{gsub(/[ \t]/,"",$2);c[$2]++}END{for(k in c)printf "%s=%d ",k,c[k]}')
        PMAX=$(grep -hsE '^[[:space:]]*pm\.max_children' "$d/root/etc/php-fpm.d"/*.conf | awk -F= '{gsub(/[ \t]/,"",$2);if($2+0>m)m=$2+0}END{print m+0}')
        chk INFO "$(basename $d) FPM pools" "$POOLS pool(s); pm: ${PMS:-n/a}; highest pm.max_children=$PMAX"
        grep -hsEq 'listen\.mode[[:space:]]*=[[:space:]]*0?666' "$d/root/etc/php-fpm.d"/*.conf && chk WARN "$(basename $d) FPM socket mode 0666" "World-accessible FPM sockets"
        FT=$(t2 "$d/root/usr/sbin/php-fpm" -t); printf '%s' "$FT" | grep -qi 'test is successful' && chk PASS "$(basename $d) php-fpm -t" "configuration OK" || chk WARN "$(basename $d) php-fpm -t" "$(echo "$FT" | tail -n 3)"
      fi
    done
    [ -d /var/cpanel/userdata ] && chk INFO "Per-domain PHP-FPM YAML overrides" "$(find /var/cpanel/userdata -maxdepth 2 -type f -name '*.php-fpm.yaml' 2>/dev/null | wc -l) file(s)"
    # pool saturation events
    FOUND=0; FLOG=0; EVT=""
    for f in /opt/cpanel/ea-php*/root/usr/var/log/php-fpm/error.log /opt/cpanel/ea-php*/root/usr/var/log/php-fpm/www-error.log /var/log/php-fpm/error.log /var/log/php-fpm/www-error.log; do
      [ -f "$f" ] || continue; FLOG=1
      m=$(tail -n 5000 "$f" 2>/dev/null | grep -Ei 'max_children|seems busy|would exceed' | tail -n 20)
      [ -n "$m" ] && { FOUND=1; EVT+="== $f"$'\n'"$m"$'\n'; }
    done
    if   [ $FLOG -eq 0 ]; then chk SKIP "PHP-FPM error log not found" "pool saturation check not possible"
    elif [ $FOUND -eq 1 ]; then chk WARN "PHP-FPM pool saturation events (pm.max_children)" "See events below"; raw "PHP-FPM limit events" "$EVT"
    else chk PASS "No PHP-FPM max_children events in recent logs"; fi
  else chk SKIP "PHP-FPM not installed"; fi
  [ -x /usr/local/cpanel/bin/rebuild_phpconf ] && raw "PHP handler per version (rebuild_phpconf --current)" "$(t /usr/local/cpanel/bin/rebuild_phpconf --current)"
fi
sec_close

# ==========================================================================
#  SECTION: Database
# ==========================================================================
sec_open db "MySQL / MariaDB"
if ! svc_inst mysql; then chk SKIP "MySQL/MariaDB not installed"
else
  DBC=""; for b in mariadb mysql; do have $b && { DBC=$b; break; }; done
  case "$(port_scope 3306)" in public) chk WARN "Database listening on all interfaces (3306)" "Restrict with bind-address=127.0.0.1 or firewall";; local) chk PASS "Database bound to localhost only";; "") chk INFO "Database not listening on TCP 3306 (socket only or other port)";; esac
  if ! svc_up mysql; then chk WARN "Database service not running" "Live checks skipped"
  elif [ -z "$DBC" ]; then chk SKIP "No mysql/mariadb client" "Live checks skipped"
  elif [ -z "$(t $DBC -Nse 'SELECT 1')" ]; then chk WARN "Cannot authenticate to database" "Needs root socket auth or ~/.my.cnf; live checks skipped"
  else
    q() { t $DBC -Nse "$1"; }
    chk INFO "Server version" "$(q 'SELECT VERSION()')"
    BA=$(q "SHOW VARIABLES LIKE 'bind_address'" | awk '{print $2}'); chk INFO "bind_address / port" "${BA:-n/a} / $(q "SHOW VARIABLES LIKE 'port'" | awk '{print $2}')"
    AN=$(q "SELECT COUNT(*) FROM mysql.user WHERE User=''"); [ "$AN" = 0 ] && chk PASS "No anonymous DB users" || chk WARN "Anonymous DB users: ${AN:-unknown}"
    RR=$(q "SELECT COUNT(*) FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost','127.0.0.1','::1')"); [ "${RR:-0}" -gt 0 ] && chk WARN "Remote-capable root DB account(s)" "$RR"
    MC=$(q "SHOW VARIABLES LIKE 'max_connections'" | awk '{print $2}'); MU=$(q "SHOW GLOBAL STATUS LIKE 'Max_used_connections'" | awk '{print $2}')
    if [ -n "$MC" ] && [ -n "$MU" ]; then PC=$(( MU * 100 / MC )); [ $PC -ge 85 ] && chk WARN "Connection headroom low" "Max used $MU of $MC ($PC%)" || chk PASS "Connection headroom" "Max used $MU of $MC ($PC%)"; fi
    raw "Active queries (non-sleep, top 20)" "$(q "SELECT id,user,LEFT(host,30),db,command,time,state,LEFT(info,150) FROM information_schema.processlist WHERE command<>'Sleep' ORDER BY time DESC LIMIT 20")"
    SL=$(q "SHOW VARIABLES LIKE 'slow_query_log'" | awk '{print $2}'); SF=$(q "SHOW VARIABLES LIKE 'slow_query_log_file'" | awk '{print $2}')
    DS=""; for b in mariadb-dumpslow mysqldumpslow; do have $b && { DS=$b; break; }; done
    if [ "$SL" != ON ] && [ "$SL" != 1 ]; then chk INFO "Slow query log disabled" "Not enabled by this script (read-only). Enable manually if analysis is wanted."
    elif [ ! -r "${SF:-/nonexistent}" ]; then chk INFO "Slow query log file not readable" "${SF:-unknown}"
    elif [ -z "$DS" ]; then chk INFO "dumpslow tool not installed"
    else
      SLD=$(tail -n "$SLOW_LINES" "$SF" 2>/dev/null)
      chk INFO "Slow query log" "$SF (last $SLOW_LINES lines analysed)"
      for m in "t:query time" "l:lock time" "r:rows sent" "c:count"; do
        raw "Top 10 slow patterns by ${m#*:}" "$(t $DS -s "${m%%:*}" -t 10 <(printf '%s\n' "$SLD") | cut -c1-250)"
      done
      raw "Latest 10 slow entries" "$(printf '%s\n' "$SLD" | awk '/^# User@Host:/{if(e!="")E[++n]=e; e=""} {e=e $0 "\n"} END{if(e!="")E[++n]=e; s=n-9; if(s<1)s=1; for(i=s;i<=n;i++)printf "%s",E[i]}' | cut -c1-250)"
    fi
  fi
fi
sec_close

# ==========================================================================
#  SECTION: Mail (Exim + Dovecot)
# ==========================================================================
sec_open mail "Mail Services (Exim, Dovecot)"
if ! svc_inst exim && ! svc_inst dovecot; then chk SKIP "No mail services installed"
else
  if svc_inst exim; then
    EX=exim; have exim || EX=exim4
    chk INFO "Exim version" "$(t $EX -bV | head -n1)"
    QC=$(t $EX -bpc)
    if [[ $QC =~ ^[0-9]+$ ]]; then
      if   [ "$QC" -ge 10000 ]; then chk FAIL "Exim queue $QC" "Possible spam outbreak"
      elif [ "$QC" -ge 500 ];   then chk WARN "Exim queue $QC" "Elevated - check senders"
      elif [ "$QC" -ge 100 ];   then chk INFO "Exim queue $QC" "Above normal"
      else chk PASS "Exim queue" "$QC message(s)"; fi
      if [ "$QC" -ge 100 ] && [ "$QC" -lt 10000 ]; then
        tbl $'Queued\tSender (from queue)' "$(t $EX -bp | awk '/^ *[0-9]+[smhdw] +[0-9.]+[KM]? +[0-9A-Za-z]+-[0-9A-Za-z]+-[0-9A-Za-z]+ /{s=$4;gsub(/[<>]/,"",s);c[s]++}END{for(x in c)print c[x]"\t"x}' | sort -t$'\t' -k1,1nr | head -n 15)"
      fi
    else chk SKIP "Exim queue count unavailable"; fi
    EL=""; for f in /var/log/exim_mainlog /var/log/exim4/mainlog; do [ -f $f ] && { EL=$f; break; }; done
    if [ -n "$EL" ]; then
      tbl $'Messages\tTop senders (recent log)' "$(tail -n "$EXIM_LOG_TAIL" $EL 2>/dev/null | awk '{for(i=1;i<NF;i++)if($i=="<="){c[$(i+1)]++;break}}END{for(s in c)print c[s]"\t"s}' | sort -t$'\t' -k1,1nr | head -n 10)"
    else chk SKIP "Exim main log not found"; fi
    # relay / auth from effective config file (no mail is sent, no SMTP simulation)
    CF=$(t $EX -bP configure_file | sed 's/^[^=]*=[[:space:]]*//')
    if [ -r "${CF:-/nonexistent}" ]; then
      if grep -qiE 'relay not permitted' "$CF"; then chk PASS "Open-relay protection present" "ACL contains 'relay not permitted' deny rule"
      else chk WARN "Could not confirm relay protection in Exim config" "$CF - review acl_check_rcpt"; fi
      AUTHN=$(awk '/^begin authenticators/{a=1;next} /^begin /{a=0} a && /^[A-Za-z0-9_]+:[[:space:]]*$/{gsub(/:/,"");print}' "$CF" | tr '\n' ' ')
      [ -n "$AUTHN" ] && chk PASS "SMTP authenticators configured" "$AUTHN" || chk WARN "No SMTP authenticators found"
    else chk SKIP "Exim config file not readable" "Relay/auth checks skipped"; fi
    for p in 465 587; do s=$(port_scope $p); [ -n "$s" ] && chk PASS "Submission port $p listening" "$s" || chk INFO "Submission port $p not listening"; done
  fi
  if svc_inst dovecot; then
    if have doveconf; then
      DV=$(t doveconf -a)
      dv() { printf '%s\n' "$DV" | awk -F' *= *' -v k="$1" '$1==k{print $2;exit}'; }
      s=$(dv ssl); case $s in required) chk PASS "Dovecot ssl" "required";; yes) chk PASS "Dovecot ssl" "yes (optional)";; no) chk FAIL "Dovecot TLS disabled";; *) chk INFO "Dovecot ssl" "${s:-unknown}";; esac
      m=$(dv ssl_min_protocol); case $m in TLSv1|TLSv1.1|SSLv3|"") [ -z "$m" ] && chk INFO "Dovecot ssl_min_protocol not reported" || chk WARN "Dovecot allows legacy TLS" "$m";; *) chk PASS "Dovecot minimum TLS" "$m";; esac
      d=$(dv disable_plaintext_auth); a=$(dv auth_allow_cleartext)
      { [ "$d" = no ] || [ "$a" = yes ]; } && chk WARN "Dovecot allows cleartext auth without TLS" "disable_plaintext_auth=${d:-?} auth_allow_cleartext=${a:-?}" || chk PASS "Dovecot cleartext auth restricted"
      raw "Dovecot ssl_cipher_list" "$(dv ssl_cipher_list)"
    else chk SKIP "doveconf not found" "TLS checks skipped"; fi
  fi
  MP=""; for e in 25:SMTP 465:SMTPS 587:Submission 110:POP3 995:POP3S 143:IMAP 993:IMAPS; do p=${e%%:*}; s=$(port_scope $p); MP+="$p"$'\t'"${e##*:}"$'\t'"${s:-not listening}"$'\n'; done
  tbl $'Port\tProtocol\tListening' "$MP"
fi
sec_close

# ==========================================================================
#  SECTION: FTP
# ==========================================================================
sec_open ftp "FTP Service"
if ! svc_inst ftp; then chk SKIP "No FTP server installed"
else
  svc_up ftp && chk INFO "FTP service running" "${SV_DETAIL[ftp]}" || chk INFO "FTP installed but not running"
  if have pure-ftpd || [ -f /etc/pure-ftpd.conf ] || [ -f /etc/pure-ftpd/pure-ftpd.conf ]; then
    PC=""; for f in /etc/pure-ftpd.conf /etc/pure-ftpd/pure-ftpd.conf; do [ -f $f ] && { PC=$f; break; }; done
    if [ -n "$PC" ]; then
      v=$(grep -Ei '^[[:space:]]*NoAnonymous[[:space:]]' $PC | tail -n1 | awk '{print tolower($2)}')
      case $v in yes) chk PASS "Pure-FTPd anonymous access disabled";; no) chk WARN "Pure-FTPd anonymous access ENABLED";; *) chk INFO "Pure-FTPd anonymous setting not determinable";; esac
      v=$(grep -Ei '^[[:space:]]*TLS[[:space:]]' $PC | tail -n1 | awk '{print tolower($2)}')
      case $v in 2) chk PASS "Pure-FTPd TLS required";; 1|yes|on) chk INFO "Pure-FTPd TLS enabled but not enforced";; 0|no|off) chk WARN "Pure-FTPd TLS disabled";; *) chk INFO "Pure-FTPd TLS setting not determinable";; esac
    else chk SKIP "Pure-FTPd config not found"; fi
  elif have proftpd || [ -f /etc/proftpd.conf ]; then
    grep -ERiqs '^[[:space:]]*<Anonymous[[:space:]]' /etc/proftpd.conf /etc/proftpd/ && chk WARN "ProFTPD <Anonymous> block present" || chk PASS "No ProFTPD anonymous config"
    TL=$(grep -ERihs '^[[:space:]]*(TLSEngine|TLSRequired|TLSProtocol)' /etc/proftpd.conf /etc/proftpd/ | head -n 10)
    printf '%s\n' "$TL" | grep -qi 'TLSEngine[[:space:]]*on' && chk PASS "ProFTPD TLS enabled" || chk WARN "ProFTPD TLS not enabled"
    raw "ProFTPD TLS settings" "$TL"
  elif [ -f /etc/vsftpd/vsftpd.conf ] || [ -f /etc/vsftpd.conf ]; then
    VC=/etc/vsftpd/vsftpd.conf; [ -f $VC ] || VC=/etc/vsftpd.conf
    grep -qiE '^anonymous_enable=YES' $VC && chk WARN "vsftpd anonymous enabled" || chk PASS "vsftpd anonymous disabled"
    grep -qiE '^ssl_enable=YES' $VC && chk PASS "vsftpd TLS enabled" || chk WARN "vsftpd TLS disabled"
  fi
  for p in 21 990; do s=$(port_scope $p); [ -n "$s" ] && chk INFO "FTP port $p listening" "$s"; done
fi
sec_close

# ==========================================================================
#  SECTION: DNS
# ==========================================================================
sec_open dns "DNS Server"
if ! svc_inst dns; then chk SKIP "No DNS server installed"
else
  chk INFO "DNS service" "${SV_STATE[dns]} ${SV_DETAIL[dns]}"
  if have named-checkconf || [ -f /etc/named.conf ]; then
    NC=""; have named-checkconf && NC=$(t named-checkconf -p)
    [ -z "$NC" ] && NC=$(cat /etc/named.conf 2>/dev/null)
    REC=$(printf '%s\n' "$NC" | grep -E '^[[:space:]]*(recursion|allow-recursion)[[:space:]]' | sed 's/^[[:space:]]*//' | sort | uniq -c)
    if   printf '%s\n' "$REC" | grep -qE 'recursion[[:space:]]+no;'; then chk PASS "DNS recursion disabled"
    elif printf '%s\n' "$REC" | grep -qE 'allow-recursion[[:space:]]*\{[[:space:]]*any;'; then chk FAIL "Open DNS resolver" "allow-recursion { any; }"
    elif [ -n "$REC" ]; then chk INFO "DNS recursion restricted/configured" "$REC"
    else chk INFO "No explicit recursion setting" "BIND default restricts recursion to localnets/localhost"; fi
    ZT=$(printf '%s\n' "$NC" | grep -E '^[[:space:]]*allow-transfer[[:space:]]' | sed 's/^[[:space:]]*//' | sort | uniq -c | sort -nr | head -n 10)
    if   printf '%s\n' "$ZT" | grep -qE '\{[[:space:]]*any;'; then chk FAIL "Zone transfers allowed to any host" "$ZT"
    elif [ -n "$ZT" ]; then chk INFO "Zone transfer restrictions configured" "$ZT"
    else chk WARN "No allow-transfer restriction found" "BIND default allows transfers; restrict to secondaries"; fi
  else chk INFO "BIND config tools not found" "Likely PowerDNS - BIND recursion/AXFR checks not applicable"; fi
fi
sec_close

# ==========================================================================
#  SECTION: cPanel / WHM
# ==========================================================================
sec_open cpanel "cPanel / WHM"
if [ $CP_INST -eq 0 ]; then chk SKIP "cPanel not installed"
else
  CPV=$(cat /usr/local/cpanel/version 2>/dev/null); [ -z "$CPV" ] && CPV=$(t /usr/local/cpanel/cpanel -V)
  chk INFO "cPanel version" "${CPV:-unknown}"
  if [ -f /etc/cpupdate.conf ]; then
    CU=$(grep -E '^(CPANEL|UPDATES|RPMUP|SARULESUP|STAGING_DIR)=' /etc/cpupdate.conf 2>/dev/null)
    raw "/etc/cpupdate.conf (key settings)" "$CU"
    u=$(printf '%s\n' "$CU" | sed -n 's/^UPDATES=//p'); case $u in daily) chk PASS "cPanel automatic updates" "daily";; manual|never) chk WARN "cPanel automatic updates are '$u'";; *) chk INFO "cPanel UPDATES policy" "${u:-unset}";; esac
    c=$(printf '%s\n' "$CU" | sed -n 's/^CPANEL=//p'); chk INFO "cPanel release tier" "${c:-unset}"
  else chk SKIP "/etc/cpupdate.conf not found"; fi
  UL=/usr/local/cpanel/logs/update_log
  if [ -f $UL ]; then
    AGE=$(( ($(date +%s) - $(stat -c %Y $UL)) / 86400 ))
    [ $AGE -gt 8 ] && chk WARN "cPanel update log is $AGE days old" "$(stat -c %y $UL)" || chk PASS "cPanel last update activity" "$AGE day(s) ago ($(stat -c %y $UL | cut -d. -f1))"
    raw "update_log (last 30 lines)" "$(tail -n 30 $UL)"
  fi
  printf '%s\n' "$PS_ALL" | awk '$0 ~ /cpanelup|upcp/ && $0 !~ /awk/' | grep -q . && chk INFO "cPanel update currently running"
  # ---- WHM Terminal ----
  if [ -e /var/cpanel/disable_whm_terminal_ui ]; then chk PASS "WHM Terminal is disabled" "/var/cpanel/disable_whm_terminal_ui exists"
  else chk WARN "WHM Terminal is ENABLED" "Root shell is reachable from the WHM web UI. To disable: touch /var/cpanel/disable_whm_terminal_ui (not done by this script)"; fi
  # ---- 2FA (WHM API v1) ----
  if ! have whmapi1; then chk SKIP "whmapi1 not found" "2FA checks skipped"
  else
    POL=$(t2 whmapi1 twofactorauth_policy_status)
    if printf '%s' "$POL" | grep -qiE 'is_enabled:[[:space:]]*1|enabled:[[:space:]]*1'; then chk PASS "WHM two-factor policy enabled"
    elif printf '%s' "$POL" | grep -qiE 'is_enabled:[[:space:]]*0|enabled:[[:space:]]*0'; then chk WARN "WHM two-factor policy is disabled"
    else chk INFO "WHM 2FA policy status not available via API on this version"; fi
    tf() { t whmapi1 twofactorauth_get_user_configs user="$1" | grep -qiE 'is_enabled:[[:space:]]*1'; }
    tf root && chk PASS "root account 2FA enabled" || chk FAIL "root account has NO 2FA" "Enable two-factor for root in WHM"
    ACCTS=$(t whmapi1 listaccts want=user | awk '/^[[:space:]]*-?[[:space:]]*user:/{print $NF}')
    TOT=$(printf '%s\n' "$ACCTS" | grep -c .); LIM=$ACCTS
    [ "$TOT" -gt "$MAX_2FA_USERS" ] && { LIM=$(printf '%s\n' "$ACCTS" | head -n "$MAX_2FA_USERS"); chk INFO "2FA check capped" "$MAX_2FA_USERS of $TOT accounts (set MAX_2FA_USERS to change)"; }
    EN=0; RW=""
    while IFS= read -r u; do
      [ -z "$u" ] && continue
      if tf "$u"; then EN=$((EN+1)); RW+="$u"$'\t'"ENABLED"$'\n'; else RW+="$u"$'\t'"NOT ENABLED"$'\n'; fi
    done <<<"$LIM"
    if [ "$TOT" -gt 0 ]; then
      [ "$EN" -eq 0 ] && chk WARN "No cPanel account has 2FA" "0 of $TOT" || chk INFO "cPanel accounts with 2FA" "$EN of $TOT"
      tbl $'cPanel user\t2FA status' "$(printf '%s' "$RW" | sort -t$'\t' -k2,2 -k1,1)"
    else chk SKIP "No cPanel accounts returned by listaccts"; fi
  fi
fi
sec_close

# ==========================================================================
#  SECTION: Manual verification checklist (cPanel/WHM only)
# ==========================================================================
if [ $CP_INST -eq 1 ]; then
  sec_open manual "Manual Verification Checklist (cPanel/WHM)"
  SEC_BADGE="MANUAL"
  CK_N=0; CK_HTML=""
  ck_group() { CK_HTML+="<h3 class=\"ckg\">$(hesc "$1")</h3>"; }
  ck_item()  { CK_N=$((CK_N+1)); CK_HTML+="<label class=\"ck\"><input type=\"checkbox\" data-k=\"c$CK_N\"><span>$(hesc "$1")</span></label>"; }
  ck_group "WHM >> Security Center"
  ck_item "Run cPanel Security Advisor and enable all recommendations"
  ck_item "Enable mod_userdir Protection"
  ck_item "Enable SMTP Restrictions"
  ck_item "Disable Compiler Access"
  ck_item "Configure Security Policies"
  ck_item "Host Access Control to restrict WHM & SSH Port Access"
  ck_item "Enable OWASP ModSecurity Rule Set"
  ck_item "Enable Shell Fork Bomb Protection"
  ck_group "WHM >> Service Configuration >> Apache Configuration >> Global Configuration"
  ck_item "Enable Symlink Protection & Keep-Alive settings"
  ck_group "WHM >> Service Configuration >> Exim Configuration Manager"
  ck_item "Enable Dictionary attack protection"
  ck_item "Enable Reject remote mail sent to the server's hostname"
  ck_item "Enable Reference /etc/mailips for custom IP on outgoing SMTP connections"
  ck_item "Enable System Filter File"
  ck_item "Enable Set SMTP Sender: headers"
  ck_item "Enable Custom RBLs"
  ck_item "Scan outgoing messages for malware"
  ck_group "WHM >> Service Configuration >> FTP Server Configuration"
  ck_item "Disable Allow Anonymous Logins & Allow Anonymous Uploads"
  ck_item "Disable Allow Logins with Root Password"
  ck_group "WHM >> SSL/TLS >> Manage AutoSSL"
  ck_item "Enable AutoSSL for all users"
  ck_group "WHM >> System Health"
  ck_item "Enable Background Process Killer"
  ck_group "WHM >> Plugins >> ConfigServer Security & Firewall"
  ck_item "Perform Check Server Security and do the needful changes"
  ck_group "WHM >> Server Configuration >> Tweak Settings"
  ck_item "Enable DKIM & SPF on domains for newly created accounts"
  ck_item "Set Max hourly emails per domain"
  ck_item "Set Initial default/catch-all forwarder destination to Fail"
  ck_item "Enable Track email origin via X-Source email headers"
  ck_item "Enable Restrict outgoing SMTP to root, exim, and mailman"
  ck_item "Enable Prevent \"nobody\" from sending mail"
  ck_item "Enable Apache SpamAssassin spam filter"
  ck_item "Enable Blank referrer safety check & Referrer safety check"
  SEC_BUF+="<p class=\"note\">These settings cannot be verified safely from the shell. Review each in WHM and tick it off - ticks are remembered in this browser and are included when you print / save as PDF.</p>"
  SEC_BUF+="<div class=\"ckbar\"><b id=\"ckprog\">0 of $CK_N verified</b><span><button type=\"button\" onclick=\"ckAll(true)\">Tick all</button> <button type=\"button\" onclick=\"ckAll(false)\">Clear</button></span></div><div id=\"cklist\" data-total=\"$CK_N\">$CK_HTML</div>"
  sec_close
fi

# ==========================================================================
#  Assemble HTML
# ==========================================================================
say "Building report"
ELAPSED=$(( $(date +%s) - START_EPOCH ))
TOKEN=$(LC_ALL=C tr -dc 'a-z0-9' </dev/urandom 2>/dev/null | head -c 12)
SAFE_HOST=$(printf '%s' "$HOST" | tr -c 'A-Za-z0-9.-' '_')
FNAME="security_audit_${SAFE_HOST}_${TS}_${TOKEN}.html"
OUT="$OUT_DIR/$FNAME"

FSORT=$(printf '%s' "$FINDINGS" | sort -s -t$'\t' -k1,1nr | cut -f2-)
SEC_BUF=""
FROWS=$(printf '%s\n' "$FSORT" | awk -F'\t' 'NF>=3{print $1"\t"$2"\t"$3"\t"$4}')
OVERVIEW=""
if [ -n "$FROWS" ]; then
  SEC_BUF=""; tbl $'Severity\tSection\tFinding\tDetail' "$FROWS"; OVERVIEW=$SEC_BUF
else OVERVIEW='<p class="note">No warnings or failures were found.</p>'; fi

SCORE_TOTAL=$(( SEV_COUNT[PASS] + SEV_COUNT[WARN] + SEV_COUNT[FAIL] ))
[ $SCORE_TOTAL -eq 0 ] && SCORE_TOTAL=1
SCORE=$(( SEV_COUNT[PASS] * 100 / SCORE_TOTAL ))

IP=$(get_public_ip)
IP_NOTE=""; is_private_ip "$IP" && IP_NOTE=" (private - public IP could not be detected; use -i PUBLIC_IP)"
URL_SCHEME=http; [ -z "$(port_scope 80)" ] && [ -n "$(port_scope 443)" ] && URL_SCHEME=https
case $OUT_DIR in /usr/local/apache/htdocs|/var/www/html|/usr/share/nginx/html|/usr/local/lsws/DEFAULT/html) REPORT_URL="$URL_SCHEME://$IP/$FNAME";; *) REPORT_URL="";; esac
{
cat <<HTML
<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow,noarchive">
<title>Security Audit - $(hesc "$HOST")</title>
<style>
:root{--bg:#f4f6f9;--card:#fff;--ink:#1b2430;--mute:#637083;--line:#e3e8ef;--pre:#0f172a;--preink:#e2e8f0;
--pass:#15803d;--passbg:#dcfce7;--warn:#b45309;--warnbg:#fef3c7;--fail:#b91c1c;--failbg:#fee2e2;--info:#1d4ed8;--infobg:#dbeafe;--skip:#64748b;--skipbg:#e2e8f0;--accent:#1e3a8a}
@media(prefers-color-scheme:dark){:root{--bg:#0e131b;--card:#161d28;--ink:#e6ebf2;--mute:#97a3b6;--line:#263041;--pre:#0a0e15;--preink:#d5dde8;
--pass:#4ade80;--passbg:#12301d;--warn:#fbbf24;--warnbg:#3a2a0a;--fail:#f87171;--failbg:#3d1414;--info:#7cb2ff;--infobg:#15284a;--skip:#9aa7ba;--skipbg:#222c3b;--accent:#7cb2ff}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
.layout{display:grid;grid-template-columns:260px 1fr;gap:20px;max-width:1500px;margin:0 auto;padding:20px}
nav{position:sticky;top:16px;align-self:start;max-height:calc(100vh - 32px);overflow:auto;background:var(--card);border:1px solid var(--line);border-radius:12px;padding:10px}
nav a{display:flex;gap:8px;align-items:center;padding:6px 8px;border-radius:6px;color:var(--ink);text-decoration:none;font-size:13px}
nav a:hover{background:var(--bg)}
.dot{width:9px;height:9px;border-radius:50%;flex:none;display:inline-block}
.dot.PASS{background:var(--pass)}.dot.WARN{background:var(--warn)}.dot.FAIL{background:var(--fail)}.dot.INFO{background:var(--info)}.dot.SKIP{background:var(--skip)}
header{background:linear-gradient(135deg,#0f172a,#1e3a8a);color:#fff;border-radius:14px;padding:24px;margin-bottom:16px}
header h1{margin:0 0 6px;font-size:24px}header p{margin:2px 0;color:#cbd5f5}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(110px,1fr));gap:10px;margin:14px 0 0}
.card{background:rgba(255,255,255,.12);border-radius:10px;padding:10px 12px}.card b{display:block;font-size:24px}.card span{font-size:12px;color:#cbd5f5}
section,.panel{background:var(--card);border:1px solid var(--line);border-radius:12px;margin-bottom:12px;overflow:hidden}
.panel{padding:14px 16px}.panel h2{margin:0 0 10px;font-size:16px}
section>details>summary{cursor:pointer;padding:12px 16px;font-weight:600;font-size:15px;list-style:none;display:flex;gap:10px;align-items:center}
section>details>summary::-webkit-details-marker{display:none}
.sbody{padding:4px 16px 16px;border-top:1px solid var(--line)}
.chk{display:flex;gap:10px;padding:7px 0;border-bottom:1px dashed var(--line);align-items:flex-start}.chk:last-child{border:0}
.d{display:block;color:var(--mute);font-size:12.5px;white-space:pre-wrap;word-break:break-word}
.b{display:inline-block;min-width:58px;text-align:center;font-size:11px;font-weight:700;padding:2px 7px;border-radius:999px;flex:none}
.b.PASS,.b.UP{background:var(--passbg);color:var(--pass)}.b.WARN,.b.DEGRADED{background:var(--warnbg);color:var(--warn)}
.b.FAIL,.b.DOWN{background:var(--failbg);color:var(--fail)}.b.INFO{background:var(--infobg);color:var(--info)}.b.SKIP,.b.ABSENT{background:var(--skipbg);color:var(--skip)}
.tw{overflow-x:auto;margin:10px 0}table{border-collapse:collapse;width:100%;font-size:13px}
th,td{text-align:left;padding:6px 10px;border-bottom:1px solid var(--line);vertical-align:top;word-break:break-word}th{background:var(--bg);font-weight:600;white-space:nowrap}
.note{color:var(--mute);font-size:12.5px;margin:8px 0}
details.raw{margin:8px 0}details.raw>summary{cursor:pointer;color:var(--accent);font-size:13px}
pre{background:var(--pre);color:var(--preink);padding:12px;border-radius:8px;overflow:auto;max-height:420px;font:12px/1.5 ui-monospace,Menlo,Consolas,monospace;white-space:pre-wrap;word-break:break-word}
.ni{display:flex;align-items:center;gap:6px;padding:0 6px}.ni input{flex:none;cursor:pointer}.ni a{flex:1}.ni.off a{opacity:.45;text-decoration:line-through}
nav .nh{font-size:11px;text-transform:uppercase;letter-spacing:.05em;color:var(--mute);padding:6px 8px}
.rm{margin-left:auto;background:transparent;color:var(--mute);border:1px solid var(--line);border-radius:6px;padding:2px 8px;font-size:12px;cursor:pointer}.rm:hover{color:var(--fail);border-color:var(--fail)}
.hidden{display:none!important}
.ckg{margin:14px 0 4px;font-size:13px;color:var(--accent)}.ck{display:flex;gap:10px;align-items:flex-start;padding:5px 0;cursor:pointer}.ck input{margin-top:3px;width:16px;height:16px;flex:none}
.ck:has(input:checked) span{color:var(--mute);text-decoration:line-through}
.ckbar{display:flex;justify-content:space-between;align-items:center;gap:8px;flex-wrap:wrap;margin:8px 0}.ckbar button{background:var(--card);color:var(--ink);border:1px solid var(--line);border-radius:6px;padding:3px 10px;cursor:pointer}
.tools{display:flex;gap:8px;margin-bottom:12px;flex-wrap:wrap}.tools button.primary{background:var(--accent);color:#fff;border-color:var(--accent)}
.tools button{background:var(--card);color:var(--ink);border:1px solid var(--line);border-radius:8px;padding:6px 12px;cursor:pointer}
footer{color:var(--mute);font-size:12px;text-align:center;padding:16px}
@media(max-width:900px){.layout{grid-template-columns:1fr;padding:12px}nav{position:static;max-height:none}}
@page{size:A4;margin:12mm}
@media print{
:root{--bg:#fff;--card:#fff;--ink:#111;--mute:#444;--line:#cfd6df;--pre:#f3f5f8;--preink:#111;--pass:#15803d;--passbg:#dcfce7;--warn:#b45309;--warnbg:#fef3c7;--fail:#b91c1c;--failbg:#fee2e2;--info:#1d4ed8;--infobg:#dbeafe;--skip:#64748b;--skipbg:#e2e8f0;--accent:#1e3a8a}
*{-webkit-print-color-adjust:exact;print-color-adjust:exact}
nav,.tools,.rm{display:none!important}.layout{display:block;padding:0;max-width:none}
section,.panel{break-inside:auto;border-color:var(--line)}section>details>summary{break-after:avoid}.chk,tr{break-inside:avoid}
pre{max-height:none!important;overflow:visible;border:1px solid var(--line)}header{break-inside:avoid}}
</style></head><body><div class="layout">
<nav><div class="nh">Sections - untick to remove</div><label class="ni"><span style="width:13px"></span><a href="#overview"><i class="dot INFO"></i>Overview</a></label>$NAV</nav>
<main>
<header id="overview"><h1>Server Security &amp; Load Audit</h1>
<p><b>Host:</b> $(hesc "$HOST") ${IP:+($IP)} &nbsp; <b>OS:</b> $(hesc "$OS_PRETTY") &nbsp; <b>Kernel:</b> $(hesc "$KERNEL")</p>
<p><b>Generated:</b> $NOW_HUMAN &nbsp; <b>Runtime:</b> ${ELAPSED}s &nbsp; <b>Run as:</b> $( [ $IS_ROOT -eq 1 ] && echo root || echo "non-root (partial)")</p>
<div class="cards">
<div class="card"><b id="c-FAIL">${SEV_COUNT[FAIL]}</b><span>Critical</span></div>
<div class="card"><b id="c-WARN">${SEV_COUNT[WARN]}</b><span>Warnings</span></div>
<div class="card"><b id="c-PASS">${SEV_COUNT[PASS]}</b><span>Passed</span></div>
<div class="card"><b id="c-INFO">${SEV_COUNT[INFO]}</b><span>Info</span></div>
<div class="card"><b id="c-SKIP">${SEV_COUNT[SKIP]}</b><span>Skipped (n/a)</span></div>
<div class="card"><b id="c-RATE">${SCORE}%</b><span>Pass rate</span></div></div></header>
<div class="tools"><button class="primary" onclick="window.print()">&#128424; Print / Save as PDF</button>
<button onclick="document.querySelectorAll('section details').forEach(d=>d.open=true)">Expand all</button>
<button onclick="document.querySelectorAll('section details').forEach(d=>d.open=false)">Collapse all</button>
<button onclick="restoreAll()">Restore all sections</button>
<button onclick="setAll(false)">Remove all</button></div>
<div class="panel" id="findings"><h2>Findings requiring attention</h2>$OVERVIEW</div>
$SECTIONS
<footer>Read-only audit - no services, configs, rules or data were modified. The only file written is this report.<br>
This report contains sensitive information. Delete it after use: <code>rm -f $(hesc "$OUT")</code></footer>
</main></div>
<script>
function tog(id,on){var s=document.getElementById(id);if(s)s.classList.toggle('hidden',!on);
 var n=document.querySelector('.ni[data-id="'+id+'"]');if(n){n.classList.toggle('off',!on);n.querySelector('input').checked=on;}recalc();}
function rmSec(id,e){e.preventDefault();e.stopPropagation();tog(id,false);}
function setAll(on){document.querySelectorAll('section[data-title]').forEach(s=>tog(s.id,on));}
function restoreAll(){setAll(true);}
function recalc(){var c={f:0,w:0,p:0,i:0,s:0},hid={};
 document.querySelectorAll('section[data-title]').forEach(function(s){
  if(s.classList.contains('hidden')){hid[s.dataset.title]=1;return;}
  for(var k in c)c[k]+=parseInt(s.dataset[k]||0,10);});
 var m={FAIL:'f',WARN:'w',PASS:'p',INFO:'i',SKIP:'s'};
 for(var k in m){var e=document.getElementById('c-'+k);if(e)e.textContent=c[m[k]];}
 var t=c.p+c.w+c.f,r=document.getElementById('c-RATE');if(r)r.textContent=(t?Math.round(c.p*100/t):0)+'%';
 document.querySelectorAll('#findings tbody tr').forEach(function(tr){var td=tr.children[1];tr.classList.toggle('hidden',!!(td&&hid[td.textContent.trim()]));});}
var CKK='audit-ck:'+location.pathname;
function ckSave(){var o={};document.querySelectorAll('#cklist input').forEach(i=>{if(i.checked)o[i.dataset.k]=1});try{localStorage.setItem(CKK,JSON.stringify(o));}catch(e){}}
function ckProg(){var l=document.getElementById('cklist');if(!l)return;var n=l.querySelectorAll('input:checked').length;document.getElementById('ckprog').textContent=n+' of '+l.dataset.total+' verified';}
function ckAll(v){document.querySelectorAll('#cklist input').forEach(i=>i.checked=v);ckSave();ckProg();}
(function(){var l=document.getElementById('cklist');if(!l)return;var o={};try{o=JSON.parse(localStorage.getItem(CKK)||'{}');}catch(e){}
 l.querySelectorAll('input').forEach(i=>{i.checked=!!o[i.dataset.k];i.addEventListener('change',function(){ckSave();ckProg();});});ckProg();})();
window.addEventListener('beforeprint',function(){document.querySelectorAll('section details').forEach(d=>d.open=true);});
</script>
</body></html>
HTML
} > "$OUT" 2>/dev/null

if [ ! -s "$OUT" ]; then echo "ERROR: could not write report to $OUT_DIR" >&2; exit 1; fi

echo >&2
echo "============================================================" >&2
echo " AUDIT COMPLETE in ${ELAPSED}s   FAIL=${SEV_COUNT[FAIL]} WARN=${SEV_COUNT[WARN]} PASS=${SEV_COUNT[PASS]} INFO=${SEV_COUNT[INFO]} SKIP=${SEV_COUNT[SKIP]}" >&2
echo " Report : $OUT" >&2
if [ -n "$REPORT_URL" ]; then echo " Link   : $REPORT_URL$IP_NOTE" >&2; echo " (random file name - delete after viewing: rm -f $OUT)" >&2
else echo " Link   : not in a known web root - copy the file to your document root to view it in a browser" >&2; fi
echo "============================================================" >&2
exit 0

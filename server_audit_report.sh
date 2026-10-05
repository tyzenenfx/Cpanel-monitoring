#!/bin/bash
# =============================================================================
#  server_audit_report.sh
#  Combined cPanel / CloudLinux SECURITY AUDIT + LOAD & RESOURCE REPORT
#  READ-ONLY
# =============================================================================
#
#  OUTPUT  (default directory: /var/log/server_audit_reports/, mode 600)
#    <host>_audit_<YYYYmmdd_HHMMSS>.html   Styled report with findings summary
#    <host>_audit_<YYYYmmdd_HHMMSS>.docx   Word report (built with python3).
#                                          If python3 is not found, a
#                                          Word-compatible .doc is written.
#
#  USAGE
#    chmod +x server_audit_report.sh
#    sudo ./server_audit_report.sh
#
#  OPTIONAL ENVIRONMENT VARIABLES
#    REPORT_DIR=/path        Output directory
#    SLOW_QUERY_COUNT=200    Latest slow-query entries analysed
#    MAX_LINES=150           Max lines kept from any single long listing
#    EXIM_LOG_LINES=100000   exim_mainlog lines scanned for top senders
#    CMD_TIMEOUT=60          Timeout (seconds) for slow external tools
#    PUBLISH_WEB=1           ALSO copy the HTML into the Apache docroot.
#                            OFF by default: the report contains sensitive
#                            security data and would be publicly readable.
#
#  READ-ONLY: does not restart/stop services, kill processes, block IPs,
#  change firewall, database, PHP, mail, DNS, FTP or CloudLinux settings,
#  touch the mail queue, or install packages.
#  The open-relay check uses "exim -bh" - a simulated SMTP session in which
#  no message is accepted, queued or delivered.
#  Files written: the two report files + a private temp directory inside
#  REPORT_DIR that is removed on exit (+ docroot copy only if PUBLISH_WEB=1).
# =============================================================================

SCRIPT_VERSION="1.0"

###############################################################################
# CONFIGURATION
###############################################################################

REPORT_DIR="${REPORT_DIR:-/var/log/server_audit_reports}"
SLOW_QUERY_COUNT="${SLOW_QUERY_COUNT:-200}"
MAX_LINES="${MAX_LINES:-150}"
EXIM_LOG_LINES="${EXIM_LOG_LINES:-100000}"
CMD_TIMEOUT="${CMD_TIMEOUT:-60}"
PUBLISH_WEB="${PUBLISH_WEB:-0}"
WEB_DOCROOT="${WEB_DOCROOT:-/usr/local/apache/htdocs}"

export LC_ALL=C
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/cpanel/bin:$PATH"
umask 077

###############################################################################
# GENERIC HELPERS
###############################################################################

have()        { command -v "$1" >/dev/null 2>&1; }
tmo()         { if have timeout; then timeout "$CMD_TIMEOUT" "$@"; else "$@"; fi; }
unit_exists() { [ -n "$UNITS" ] && grep -qx "$1.service" <<<"$UNITS"; }
unit_match()  { [ -n "$UNITS" ] && grep -E "$1" <<<"$UNITS" | sed 's/\.service$//'; }
svc_state()   { local s=""; have systemctl && s=$(systemctl is-active  "$1" 2>/dev/null); echo "${s:-unknown}"; }
svc_enabled() { local s=""; have systemctl && s=$(systemctl is-enabled "$1" 2>/dev/null); echo "${s:-unknown}"; }

# Is anything listening on this port (TCP or UDP)?
port_listening() {
    awk -v p="$1" '{n = split($0, a, ":"); if (a[n] == p) f = 1} END {exit !f}' <<<"$LISTEN_LOCAL"
}

# Status line + record PASS/WARN/FAIL for the summary
status() {
    local lvl="$1"; shift
    printf '[%s] %s\n' "$lvl" "$*"
    case "$lvl" in
        PASS|WARN|FAIL)
            printf '%s\t%s\t%s\t%s\n' "$lvl" "$CUR_NO" "$CUR_TITLE" "$*" >> "$FINDINGS" ;;
    esac
}
skip() { status SKIP "$*"; }
sub()  { printf '\n--- %s ---\n' "$*"; }
kv()   { printf '%-32s: %s\n' "$1" "${2:-n/a}"; }
cap()  { awk -v max="${1:-$MAX_LINES}" 'NR <= max {print} END {if (NR > max) printf "... [%d more lines truncated]\n", NR - max}'; }
num_ge() { awk -v a="$1" -v b="$2" 'BEGIN {exit !(a + 0 >= b + 0)}'; }

pkgver() {
    if have rpm; then rpm -q "$1" 2>/dev/null | grep -v 'not installed'
    elif have dpkg-query; then dpkg-query -W -f='${Package} ${Version}\n' "$1" 2>/dev/null
    fi
}

# Remove ANSI colour codes / control characters from captured output
sanitize() {
    sed -i -e 's/\x1b\[[0-9;?]*[A-Za-z]//g' "$1" 2>/dev/null
    tr -d '\000-\010\013-\037' < "$1" > "$1.tmp" && mv -f "$1.tmp" "$1"
}

###############################################################################
# PHP LIFECYCLE (security-support end dates)
###############################################################################

php_eol() {
    case "$1" in
        4.*|5.*|7.*|8.0) echo "past" ;;
        8.1) echo "2025-12-31" ;;
        8.2) echo "2026-12-31" ;;
        8.3) echo "2027-12-31" ;;
        8.4) echo "2028-12-31" ;;
        8.5) echo "2029-12-31" ;;
        *)   echo "unknown" ;;
    esac
}

# eol_check <major.minor> <subject text> <level to use when EOL>
eol_check() {
    local ver="$1" what="$2" lvl="$3" ok="PASS" eol
    [ "$lvl" = "INFO" ] && ok="INFO"
    eol=$(php_eol "$ver")
    case "$eol" in
        past)    status "$lvl" "$what is end-of-life" ;;
        unknown) status INFO "$what: lifecycle unknown - verify" ;;
        *)
            if [[ "$eol" < "$TODAY" ]]; then
                status "$lvl" "$what is end-of-life (since $eol)"
            elif [[ "$eol" < "$SOON" ]]; then
                status WARN "$what reaches end-of-life on $eol"
            else
                status "$ok" "$what supported until $eol"
            fi ;;
    esac
}

###############################################################################
# 1. SERVER & OS BASELINE
###############################################################################

sec_baseline() {
    sub "Host"
    if have hostnamectl; then hostnamectl 2>/dev/null; else skip "hostnamectl not available"; fi
    kv "FQDN" "$HOST_FQDN"
    kv "Primary IP" "$PRIMARY_IP"
    kv "OS" "$OS_NAME"
    kv "Kernel" "$(uname -r)"

    sub "CPU"
    if have lscpu; then
        lscpu | awk -F: '/^(Architecture|CPU\(s\)|Model name|Thread\(s\) per core|Core\(s\) per socket|Socket\(s\)|NUMA node\(s\))/ {
            gsub(/^[ \t]+|[ \t]+$/, "", $2); printf "%-32s: %s\n", $1, $2 }'
    else
        skip "lscpu not available"
    fi

    sub "Uptime"
    if have uptime; then
        kv "Uptime" "$(uptime -p 2>/dev/null)"
        kv "Boot time" "$(uptime -s 2>/dev/null)"
    else
        skip "uptime not available"
    fi

    sub "DNS resolvers (/etc/resolv.conf)"
    if [ -f /etc/resolv.conf ]; then
        grep -E '^[[:space:]]*nameserver[[:space:]]+' /etc/resolv.conf || status WARN "No nameserver entries in /etc/resolv.conf"
    else
        skip "/etc/resolv.conf not found"
    fi
}

###############################################################################
# 2. SYSTEM LOAD & MEMORY
###############################################################################

sec_load() {
    local l1 l5 l15 rest ratio mt ma pct

    sub "Load average"
    if [ -r /proc/loadavg ]; then
        read -r l1 l5 l15 rest < /proc/loadavg
        kv "Load average (1 / 5 / 15 min)" "$l1 / $l5 / $l15"
        kv "CPU cores" "$CPU_CORES"
        if [[ "$CPU_CORES" =~ ^[0-9]+$ ]] && [ "$CPU_CORES" -gt 0 ]; then
            ratio=$(awk -v l="$l5" -v c="$CPU_CORES" 'BEGIN {printf "%.2f", l / c}')
            if   num_ge "$ratio" 2; then status FAIL "5-min load is ${ratio}x the CPU core count"
            elif num_ge "$ratio" 1; then status WARN "5-min load is ${ratio}x the CPU core count"
            else                         status PASS "5-min load is ${ratio}x the CPU core count"
            fi
        fi
    else
        skip "/proc/loadavg not readable"
    fi

    sub "Memory"
    if have free; then free -h; else skip "free not available"; fi
    if [ -r /proc/meminfo ]; then
        mt=$(awk '/^MemTotal:/ {print $2}' /proc/meminfo)
        ma=$(awk '/^MemAvailable:/ {print $2}' /proc/meminfo)
        if [ -n "$mt" ] && [ -n "$ma" ] && [ "$mt" -gt 0 ]; then
            pct=$(( ma * 100 / mt ))
            if   [ "$pct" -lt 10 ]; then status FAIL "Only ${pct}% of memory available"
            elif [ "$pct" -lt 20 ]; then status WARN "Only ${pct}% of memory available"
            else                         status PASS "${pct}% of memory available"
            fi
        fi
    fi

    sub "Top 15 processes by CPU"
    ps -eo pid,ppid,user:16,%cpu,%mem,etime,args --sort=-%cpu 2>/dev/null | head -n 16 | cut -c1-200

    sub "Top 15 processes by memory"
    ps -eo pid,ppid,user:16,%cpu,%mem,etime,args --sort=-%mem 2>/dev/null | head -n 16 | cut -c1-200

    sub "Top 10 users by CPU (sum of all their processes)"
    printf '%-24s %8s %8s %8s\n' "USER" "CPU%" "MEM%" "PROCS"
    ps -eo user:32,%cpu,%mem --no-headers 2>/dev/null | awk '
        {cpu[$1] += $2; mem[$1] += $3; n[$1]++}
        END {for (u in cpu) printf "%-24s %8.1f %8.1f %8d\n", u, cpu[u], mem[u], n[u]}' |
        sort -k2,2nr | head -n 10
}

###############################################################################
# 3. STORAGE, DISK I/O & /tmp
###############################################################################

sec_storage() {
    local issues=0 pct mnt opts o perms

    sub "Disk space"
    df -hTP -x tmpfs -x devtmpfs -x squashfs 2>/dev/null || df -hP
    while read -r pct mnt; do
        [[ "$pct" =~ ^[0-9]+$ ]] || continue
        if   [ "$pct" -ge 90 ]; then status FAIL "Filesystem $mnt is ${pct}% full"; issues=1
        elif [ "$pct" -ge 80 ]; then status WARN "Filesystem $mnt is ${pct}% full"; issues=1
        fi
    done < <(df -PT -x tmpfs -x devtmpfs -x squashfs 2>/dev/null | awk 'NR > 1 {gsub("%", "", $6); print $6, $7}')
    [ "$issues" -eq 0 ] && status PASS "All filesystems below 80% space usage"

    sub "Inode usage"
    issues=0
    df -ihP -x tmpfs -x devtmpfs -x squashfs 2>/dev/null || df -ih
    while read -r pct mnt; do
        [[ "$pct" =~ ^[0-9]+$ ]] || continue
        if   [ "$pct" -ge 90 ]; then status FAIL "Filesystem $mnt inodes ${pct}% used"; issues=1
        elif [ "$pct" -ge 80 ]; then status WARN "Filesystem $mnt inodes ${pct}% used"; issues=1
        fi
    done < <(df -iPT -x tmpfs -x devtmpfs -x squashfs 2>/dev/null | awk 'NR > 1 {gsub("%", "", $6); print $6, $7}')
    [ "$issues" -eq 0 ] && status PASS "All filesystems below 80% inode usage"

    sub "Disk I/O (iostat, 1-second sample)"
    if have iostat; then
        iostat -dx 1 2 2>/dev/null | awk '/^Device/ {n++} n == 2' | cap 40
    else
        skip "iostat not available (sysstat package not installed)"
    fi

    sub "/tmp mount security"
    if [ ! -d /tmp ]; then
        status FAIL "/tmp does not exist"
        return
    fi
    if have findmnt && findmnt -n /tmp >/dev/null 2>&1; then
        findmnt /tmp
        opts=$(findmnt -no OPTIONS /tmp 2>/dev/null)
        for o in noexec nosuid nodev; do
            if tr ',' '\n' <<<"$opts" | grep -qx "$o"; then
                status PASS "/tmp mounted with $o"
            else
                status WARN "/tmp not mounted with $o"
            fi
        done
    elif have findmnt; then
        status WARN "/tmp is not a separate mount (noexec/nosuid/nodev cannot apply)"
    else
        skip "findmnt not available - /tmp mount options not checked"
    fi
    stat -c '%A %a %U:%G %n' /tmp
    perms=$(stat -c '%a' /tmp 2>/dev/null)
    if [ "$perms" = "1777" ]; then status PASS "/tmp permissions are 1777"
    else status WARN "/tmp permissions are $perms (expected 1777)"
    fi
}

###############################################################################
# 4. PRIVILEGED ACCOUNTS
###############################################################################

sec_users() {
    local uid0 g m

    sub "UID 0 accounts"
    uid0=$(awk -F: '$3 == 0 {print $1}' /etc/passwd 2>/dev/null)
    printf '%s\n' "${uid0:-(none found)}"
    if   [ "$uid0" = "root" ]; then status PASS "Only root has UID 0"
    elif [ -z "$uid0" ];       then status WARN "Unable to read UID 0 accounts"
    else status FAIL "Additional UID 0 accounts: $(paste -sd, <<<"$uid0")"
    fi

    sub "sudoers entries granting ALL"
    if [ -r /etc/sudoers ]; then
        grep -hsE '^[[:space:]]*[%A-Za-z0-9_.-]+[[:space:]]+ALL[[:space:]]*=' /etc/sudoers /etc/sudoers.d/* 2>/dev/null |
            sed 's/^[[:space:]]*//' | sort -u
    else
        skip "/etc/sudoers not present or not readable"
    fi

    sub "wheel / sudo group members"
    for g in wheel sudo admin; do
        if getent group "$g" >/dev/null 2>&1; then
            m=$(getent group "$g" | awk -F: '{print $4}')
            kv "$g" "${m:-(no members)}"
        fi
    done
    status INFO "Verify every sudo/wheel user is authorised and still required"
}

###############################################################################
# 5. SSH SECURITY
###############################################################################

sec_ssh() {
    local svc="" cfg v p keys d

    if ! have sshd && [ ! -f /etc/ssh/sshd_config ]; then
        skip "OpenSSH server not installed"
        return
    fi

    sub "Service"
    if unit_exists sshd; then svc=sshd; elif unit_exists ssh; then svc=ssh; fi
    if [ -n "$svc" ]; then
        kv "Unit" "$svc.service"
        kv "Active" "$(svc_state "$svc")"
        kv "Enabled" "$(svc_enabled "$svc")"
    else
        status INFO "No sshd/ssh systemd unit found"
    fi
    if [ -f /etc/ssh/sshd_config ]; then status PASS "/etc/ssh/sshd_config present"
    else status WARN "/etc/ssh/sshd_config not found"
    fi

    sub "Effective configuration (sshd -T)"
    if ! have sshd; then
        skip "sshd binary not found - effective configuration not evaluated"
    else
        cfg=$(sshd -T 2>/dev/null)
        if [ -z "$cfg" ]; then
            status WARN "sshd -T returned no output - configuration test:"
            sshd -t 2>&1 | cap 20
        else
            grep -E '^(port|listenaddress|permitrootlogin|passwordauthentication|kbdinteractiveauthentication|challengeresponseauthentication|pubkeyauthentication|permitemptypasswords|maxauthtries|logingracetime|allowusers|allowgroups|denyusers|denygroups|clientaliveinterval|clientalivecountmax|allowtcpforwarding|x11forwarding|permittunnel|gatewayports|ciphers|macs|kexalgorithms) ' <<<"$cfg" | cut -c1-200
            echo

            v=$(awk '$1 == "permitrootlogin" {print $2}' <<<"$cfg")
            case "$v" in
                no) status PASS "Root login disabled" ;;
                prohibit-password|without-password|forced-commands-only) status PASS "Root login restricted to keys ($v)" ;;
                yes) status WARN "Root login with password permitted (PermitRootLogin yes)" ;;
            esac

            v=$(awk '$1 == "passwordauthentication" {print $2}' <<<"$cfg")
            [ "$v" = "yes" ] && status WARN "Password authentication enabled (key-only recommended)"
            [ "$v" = "no" ]  && status PASS "Password authentication disabled"

            v=$(awk '$1 == "permitemptypasswords" {print $2}' <<<"$cfg")
            [ "$v" = "yes" ] && status FAIL "Empty passwords permitted (PermitEmptyPasswords yes)"
            [ "$v" = "no" ]  && status PASS "Empty passwords not permitted"

            v=$(awk '$1 == "maxauthtries" {print $2}' <<<"$cfg")
            if [[ "$v" =~ ^[0-9]+$ ]] && [ "$v" -gt 4 ]; then
                status WARN "MaxAuthTries is $v (recommend 3-4)"
            fi

            v=$(awk '$1 == "x11forwarding" {print $2}' <<<"$cfg")
            [ "$v" = "yes" ] && status WARN "X11Forwarding enabled"

            for p in $(awk '$1 == "port" {print $2}' <<<"$cfg"); do
                [ "$p" = "22" ] && status INFO "SSH is on the default port 22"
                if [ -n "$LISTEN_LOCAL" ]; then
                    if port_listening "$p"; then status PASS "sshd listening on port $p"
                    else status WARN "sshd configured for port $p but nothing is listening"
                    fi
                fi
            done
        fi
    fi

    sub "Authorized SSH keys"
    if [ -f /root/.ssh/authorized_keys ]; then
        keys=$(grep -cvE '^[[:space:]]*(#|$)' /root/.ssh/authorized_keys 2>/dev/null)
        status INFO "root has ${keys:-0} authorized key(s) - verify each is still required"
        awk '!/^[[:space:]]*(#|$)/ {print "  " $1 "  " $NF}' /root/.ssh/authorized_keys | cap 30
    else
        status INFO "No /root/.ssh/authorized_keys file"
    fi
    echo
    echo "User authorized_keys files:"
    for d in /home /home[0-9]*; do
        [ -d "$d" ] && find "$d" -maxdepth 3 -type f -name authorized_keys 2>/dev/null
    done | cap 50
}

###############################################################################
# 6. AUTHENTICATION LOGS
###############################################################################

sec_auth() {
    local log="" src="" failed success rootn
    local pf='Failed password|authentication failure|Failed publickey|Invalid user'
    local pok='Accepted (password|publickey|keyboard-interactive)'

    if   [ -f /var/log/secure ];   then log=/var/log/secure
    elif [ -f /var/log/auth.log ]; then log=/var/log/auth.log
    elif have journalctl; then
        log="$WORK/auth_journal.log"
        tmo journalctl -q --no-pager --since "-7 days" _COMM=sshd > "$log" 2>/dev/null
        [ -s "$log" ] || log=""
        src="systemd journal (last 7 days)"
    fi
    if [ -z "$log" ]; then
        skip "No authentication log found (/var/log/secure, /var/log/auth.log, journal)"
        return
    fi

    kv "Source" "${src:-$log (since last rotation)}"
    failed=$(grep -Eic "$pf" "$log" 2>/dev/null)
    success=$(grep -Eic "$pok" "$log" 2>/dev/null)
    rootn=$(grep -Eic 'Accepted [^ ]+ for root |Failed [^ ]+ for root |Invalid user root' "$log" 2>/dev/null)
    kv "Failed authentication attempts" "${failed:-0}"
    kv "Successful SSH logins" "${success:-0}"
    kv "Root SSH login attempts" "${rootn:-0}"

    sub "Top 20 source IPs of failed attempts"
    grep -Ei "$pf" "$log" 2>/dev/null | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' | sort | uniq -c | sort -nr | head -n 20

    sub "Successful SSH logins by user and source"
    grep -Ei "$pok" "$log" 2>/dev/null |
        sed -nE 's/.*Accepted [^ ]+ for ([^ ]+) from ([^ ]+).*/\1 from \2/p' |
        sort | uniq -c | sort -nr | head -n 20

    sub "Last 15 failed attempts"
    grep -Ei "$pf" "$log" 2>/dev/null | tail -n 15 | cut -c1-200

    echo
    if   [ "${failed:-0}" -gt 1000 ]; then status WARN "High number of failed authentication attempts (${failed}) - confirm brute-force blocking (cPHulk/LFD) is active"
    elif [ "${failed:-0}" -gt 0 ];    then status INFO "${failed} failed authentication attempts recorded"
    else                                   status PASS "No failed authentication attempts recorded"
    fi
    if grep -qE 'Accepted password for root ' "$log" 2>/dev/null; then
        status WARN "root has logged in over SSH with a password"
    fi
}

###############################################################################
# 7. FIREWALL & NETWORK CONFIGURATION
###############################################################################

sec_firewall() {
    local fw=0 csf=0 fwd=0 v st z r4 r6

    sub "CSF / LFD"
    if have csf || [ -f /etc/csf/csf.conf ]; then
        csf=1
        have csf && kv "CSF version" "$(tmo csf -v 2>/dev/null | head -n1)"
        if [ -f /etc/csf/csf.conf ]; then
            grep -E '^(TESTING|RESTRICT_SYSLOG|LF_DAEMON|LF_SSHD|LF_FTPD|LF_SMTPAUTH|LF_POP3D|LF_IMAPD|LF_CPANEL|CT_LIMIT|SYNFLOOD|PORTFLOOD|TCP_IN|TCP_OUT|UDP_IN|UDP_OUT|TCP6_IN|UDP6_IN)[[:space:]]*=' /etc/csf/csf.conf
            v=$(sed -nE 's/^TESTING[[:space:]]*=[[:space:]]*"?([0-9])"?.*/\1/p' /etc/csf/csf.conf | tail -n1)
            [ "$v" = "1" ] && status FAIL "CSF is in TESTING mode (rules are flushed periodically)"
            [ "$v" = "0" ] && status PASS "CSF is not in testing mode"
        fi
        if unit_exists lfd; then
            st=$(svc_state lfd); kv "lfd service" "$st"
            if [ "$st" = "active" ]; then status PASS "LFD (login failure daemon) running"
            else status WARN "LFD service is $st"
            fi
        fi
    else
        status INFO "CSF not installed"
    fi

    sub "firewalld"
    if have firewall-cmd; then
        st=$(svc_state firewalld)
        kv "Active" "$st"; kv "Enabled" "$(svc_enabled firewalld)"
        if [ "$st" = "active" ]; then
            fwd=1; fw=1
            status PASS "firewalld running"
            for z in $(firewall-cmd --get-active-zones 2>/dev/null | grep -v '^[[:space:]]'); do
                firewall-cmd --zone="$z" --list-all 2>/dev/null
            done | cap
        else
            status INFO "firewalld installed but not running"
        fi
    else
        status INFO "firewalld not installed"
    fi
    [ "$csf" -eq 1 ] && [ "$fwd" -eq 1 ] && status WARN "Both CSF and firewalld are active - they conflict"

    sub "Packet-filter rules"
    if have iptables; then
        r4=$(iptables -S 2>/dev/null | grep -c '^-A')
        kv "IPv4 rules (iptables)" "$r4"
        [ "${r4:-0}" -gt 0 ] && fw=1
        if have ip6tables; then
            r6=$(ip6tables -S 2>/dev/null | grep -c '^-A')
            kv "IPv6 rules (ip6tables)" "$r6"
        fi
        # Full listing only when neither CSF nor firewalld already describes the rules
        if [ "$csf" -eq 0 ] && [ "$fwd" -eq 0 ] && [ "${r4:-0}" -gt 0 ]; then
            echo; iptables -L -n -v --line-numbers 2>/dev/null | cap
        fi
    elif have nft; then
        r4=$(nft list ruleset 2>/dev/null | grep -cE '(accept|drop|reject)')
        kv "nftables rules" "$r4"
        [ "${r4:-0}" -gt 0 ] && fw=1
    else
        skip "Neither iptables nor nft available"
    fi
    if [ "$fw" -eq 1 ]; then status PASS "Host firewall rules are active"
    else status FAIL "No active host firewall detected (CSF / firewalld / iptables / nftables)"
    fi

    sub "Network interfaces"
    if have ip; then ip -br addr 2>/dev/null; else skip "ip command not available"; fi

    sub "IP forwarding"
    if have sysctl; then
        v=$(sysctl -n net.ipv4.ip_forward 2>/dev/null)
        kv "net.ipv4.ip_forward" "$v"
        kv "net.ipv6.conf.all.forwarding" "$(sysctl -n net.ipv6.conf.all.forwarding 2>/dev/null)"
        [ "$v" = "1" ] && status WARN "IPv4 forwarding enabled (only needed for routers/VPN/containers)"
        [ "$v" = "0" ] && status PASS "IPv4 forwarding disabled"
    else
        skip "sysctl not available"
    fi
}

###############################################################################
# 8. LISTENING PORTS & SERVICES  (single, de-duplicated port listing)
###############################################################################

sec_ports() {
    local risky p s

    if [ -z "$SS_LISTEN" ]; then
        if have netstat; then netstat -lntup 2>/dev/null | cap 200
        else skip "Neither ss nor netstat available"
        fi
        return
    fi

    printf '%-6s %-40s %-6s %-14s %-8s %s\n' "PROTO" "LOCAL ADDRESS" "PORT" "SERVICE" "SCOPE" "PROCESS"
    awk '
    BEGIN {
        n = split("21:FTP 22:SSH 25:SMTP 53:DNS 80:HTTP 110:POP3 111:RPCbind 123:NTP 143:IMAP 161:SNMP 443:HTTPS 465:SMTPS 587:Submission 783:SpamAssassin 953:rndc 990:FTPS 993:IMAPS 995:POP3S 2049:NFS 2077:WebDisk 2078:WebDisk-SSL 2079:CalDAV 2080:CalDAV-SSL 2082:cPanel 2083:cPanel-SSL 2086:WHM 2087:WHM-SSL 2095:Webmail 2096:Webmail-SSL 3306:MySQL 3310:ClamAV 5432:PostgreSQL 6379:Redis 7080:LSWS-Admin 8080:HTTP-alt 8443:HTTPS-alt 9200:Elasticsearch 11211:Memcached 27017:MongoDB", a, " ")
        for (i = 1; i <= n; i++) { split(a[i], b, ":"); svc[b[1]] = b[2] }
    }
    NR > 1 {
        local_addr = $5
        port = local_addr; sub(/.*:/, "", port)
        addr = local_addr; sub(/:[^:]*$/, "", addr)
        if (addr ~ /^(127\.|\[::1\]|::1)/ || addr ~ /%lo$/) scope = "local"
        else if (addr ~ /^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)/) scope = "private"
        else scope = "public"
        proc = "-"
        if (match($0, /\(\("[^"]+"/)) proc = substr($0, RSTART + 3, RLENGTH - 4)
        s = (port in svc) ? svc[port] : "-"
        printf "%-6s %-40s %-6s %-14s %-8s %s\n", $1, local_addr, port, s, scope, proc
    }' <<<"$SS_LISTEN" | sort -k1,1 -k3,3n -u | cap 200

    echo
    kv "Total listening sockets" "$(awk 'NR > 1' <<<"$SS_LISTEN" | wc -l)"

    # Database / cache services that should not be reachable from the internet
    risky=$(awk 'NR > 1 {
        la = $5; p = la; sub(/.*:/, "", p); a = la; sub(/:[^:]*$/, "", a)
        if (a ~ /^(127\.|\[::1\]|::1)/ || a ~ /%lo$/) next
        if (p ~ /^(3306|5432|6379|11211|27017|9200)$/) print p
    }' <<<"$SS_LISTEN" | sort -u)
    for p in $risky; do
        case "$p" in
            3306) s="MySQL/MariaDB" ;; 5432) s="PostgreSQL" ;; 6379) s="Redis" ;;
            11211) s="Memcached" ;; 27017) s="MongoDB" ;; 9200) s="Elasticsearch" ;;
        esac
        status WARN "$s (port $p) listens on a non-loopback address - make sure the firewall restricts it"
    done
    [ -z "$risky" ] && status PASS "No database/cache ports listening on public interfaces"
}

###############################################################################
# 9. NETWORK CONNECTIONS / SYN-FLOOD INDICATORS
###############################################################################

sec_conn() {
    local tan syn p

    if ! have ss; then
        skip "ss not available - connection analysis skipped"
        return
    fi
    tan=$(ss -tan 2>/dev/null)

    sub "TCP connection states"
    awk 'NR > 1 {c[$1]++} END {for (s in c) printf "%8d %s\n", c[s], s}' <<<"$tan" | sort -nr

    for p in 80 443; do
        sub "Port $p - top 20 remote IPs"
        kv "Connections on port $p" "$(awk -v p="$p" 'NR > 1 && $4 ~ (":" p "$")' <<<"$tan" | wc -l)"
        awk -v p="$p" 'NR > 1 && $4 ~ (":" p "$") {
            ip = $5; sub(/:[0-9]+$/, "", ip); gsub(/\[|\]/, "", ip); sub(/^::ffff:/, "", ip)
            c[ip]++
        } END {for (i in c) printf "%8d %s\n", c[i], i}' <<<"$tan" | sort -nr | head -n 20
    done

    sub "SYN-RECV (possible SYN flood)"
    syn=$(awk 'NR > 1 && $1 == "SYN-RECV"' <<<"$tan" | wc -l)
    kv "SYN-RECV connections" "$syn"
    if   [ "$syn" -ge 1000 ]; then status FAIL "$syn SYN-RECV connections - possible SYN flood"
    elif [ "$syn" -ge 500 ];  then status WARN "$syn SYN-RECV connections - investigate SYN flood / traffic surge"
    elif [ "$syn" -ge 100 ];  then status WARN "$syn SYN-RECV connections - monitor source IP distribution"
    else                           status PASS "SYN-RECV level normal ($syn)"
    fi
    if [ "$syn" -gt 0 ]; then
        echo; echo "Top 10 SYN-RECV source IPs:"
        awk 'NR > 1 && $1 == "SYN-RECV" {ip = $5; sub(/:[0-9]+$/, "", ip); gsub(/\[|\]/, "", ip); sub(/^::ffff:/, "", ip); c[ip]++}
             END {for (i in c) printf "%8d %s\n", c[i], i}' <<<"$tan" | sort -nr | head -n 10
        echo; echo "SYN-RECV by destination port:"
        awk 'NR > 1 && $1 == "SYN-RECV" {p = $4; sub(/.*:/, "", p); c[p]++}
             END {for (i in c) printf "%8d port %s\n", c[i], i}' <<<"$tan" | sort -nr | head -n 10
    fi

    sub "Web connection states (80/443)"
    awk 'NR > 1 && ($4 ~ /:80$/ || $4 ~ /:443$/) {c[$1]++} END {for (s in c) printf "%8d %s\n", c[s], s}' <<<"$tan" | sort -nr
}

###############################################################################
# 10. SECURITY SOFTWARE: IMUNIFY360 / BITNINJA / MODSECURITY
###############################################################################

sec_secsoft() {
    local prot=0 st u v vend log d

    sub "Imunify360"
    if have imunify360-agent || unit_exists imunify360; then
        prot=1
        have imunify360-agent && kv "Version" "$(tmo imunify360-agent version 2>/dev/null | head -n1)"
        for u in $(unit_match '^imunify'); do kv "$u" "$(svc_state "$u")"; done
        st=$(svc_state imunify360)
        if [ "$st" = "active" ]; then status PASS "Imunify360 agent running"
        else status FAIL "Imunify360 installed but agent is $st"
        fi
        if have imunify360-agent; then
            echo "License / registration:"
            tmo imunify360-agent rstatus 2>&1 | sed 's/^/  /' | cap 10
        fi
        if [ -d /etc/apache2/conf.d/modsec_vendor_configs/imunify360-full-apache ] ||
           [ -d /etc/apache2/conf.d/modsec_vendor_configs/imunify360-full-litespeed ]; then
            status PASS "Imunify360 WAF ruleset installed"
        fi
        if [ -f /var/log/imunify360/console.log ]; then
            echo; echo "Recent Imunify360 log entries:"
            tail -n 15 /var/log/imunify360/console.log | cut -c1-200
        fi
    elif have imunify-antivirus || unit_exists imunify-antivirus; then
        prot=1
        status INFO "ImunifyAV (malware scanner only) installed - $(svc_state imunify-antivirus)"
        kv "Version" "$(tmo imunify-antivirus version 2>/dev/null | head -n1)"
    else
        status INFO "Imunify360 not installed"
    fi

    sub "BitNinja"
    if have bitninjacli || unit_exists bitninja || [ -d /etc/bitninja ]; then
        prot=1
        kv "Package" "$(pkgver bitninja)"
        st=$(svc_state bitninja)
        kv "Service" "$st"
        if [ "$st" = "active" ]; then status PASS "BitNinja running"
        else status FAIL "BitNinja installed but service is $st"
        fi
        if [ -d /var/log/bitninja ]; then
            echo "Most recently updated logs:"
            find /var/log/bitninja -type f -printf '  %TY-%Tm-%Td %TH:%TM  %p\n' 2>/dev/null | sort -r | head -n 5
        fi
    else
        status INFO "BitNinja not installed"
    fi

    if have maldet || unit_exists clamd || unit_exists clamd@scan; then
        prot=1
        status INFO "Other malware scanning detected (maldet/ClamAV)"
    fi
    [ "$prot" -eq 0 ] && status WARN "No server-level malware/intrusion protection detected (Imunify360, BitNinja or equivalent)"

    sub "ModSecurity (WAF)"
    if [ -z "$APACHE_CTL" ] && [ ! -x /usr/local/lsws/bin/lshttpd ]; then
        skip "No Apache/LiteSpeed installed - ModSecurity not applicable"
        return
    fi
    if [ -n "$APACHE_CTL" ]; then
        if $APACHE_CTL -M 2>/dev/null | grep -qi 'security2_module'; then
            status PASS "Apache ModSecurity module (security2) loaded"
        else
            status WARN "Apache ModSecurity module not loaded"
        fi
    fi
    v=$(grep -rhiE '^[[:space:]]*SecRuleEngine[[:space:]]' $APACHE_CONF_DIR /usr/local/lsws/conf 2>/dev/null | awk '{print tolower($2)}' | sort | uniq -c)
    if [ -n "$v" ]; then
        echo "SecRuleEngine settings found:"; echo "$v" | sed 's/^/  /'
        if   grep -qw 'on' <<<"$v";            then status PASS "ModSecurity rule engine On"
        elif grep -qw 'detectiononly' <<<"$v"; then status WARN "ModSecurity in DetectionOnly mode (not blocking)"
        else                                        status FAIL "ModSecurity rule engine Off"
        fi
    else
        status INFO "No SecRuleEngine directive found"
    fi
    for d in /etc/apache2/conf.d/modsec_vendor_configs /usr/local/apache/conf/modsec_vendor_configs; do
        if [ -d "$d" ]; then
            vend=$(find "$d" -mindepth 1 -maxdepth 1 -type d -printf '%f\n' 2>/dev/null | sort)
            echo; echo "Vendor rule sets ($d):"; echo "${vend:-  (none)}" | sed 's/^/  /'
            grep -qi 'owasp' <<<"$vend" && status INFO "OWASP CRS vendor rules present"
            break
        fi
    done
    for log in /etc/apache2/logs/modsec_audit.log /usr/local/apache/logs/modsec_audit.log /var/log/apache2/modsec_audit.log /var/log/httpd/modsec_audit.log; do
        if [ -f "$log" ]; then
            echo; kv "Audit log" "$log ($(du -h "$log" 2>/dev/null | awk '{print $1}'))"
            echo "Top 10 triggered rule IDs (last 50,000 lines):"
            tail -n 50000 "$log" 2>/dev/null | grep -oE '\[id "[0-9]+"\]' | sort | uniq -c | sort -nr | head -n 10
            break
        fi
    done
}

###############################################################################
# 11. cPANEL & WHM
###############################################################################

sec_cpanel() {
    local st upd tier rpmup lastlog age pol res users en total root_en u notlist

    if [ ! -x /usr/local/cpanel/cpanel ]; then
        skip "cPanel/WHM not installed"
        return
    fi

    sub "Version & service"
    kv "cPanel & WHM version" "$(/usr/local/cpanel/cpanel -V 2>/dev/null)"
    st=$(svc_state cpanel)
    kv "cpanel service" "$st"
    if [ "$st" = "active" ]; then status PASS "cPanel service running"
    else status WARN "cPanel service is $st"
    fi

    sub "Update policy (/etc/cpupdate.conf)"
    if [ -f /etc/cpupdate.conf ]; then
        grep -E '^(CPANEL|RPMUP|SARULESUP|UPDATES|STAGING_DIR)=' /etc/cpupdate.conf
        upd=$(sed -n 's/^UPDATES=//p' /etc/cpupdate.conf | tail -n1)
        tier=$(sed -n 's/^CPANEL=//p' /etc/cpupdate.conf | tail -n1)
        rpmup=$(sed -n 's/^RPMUP=//p' /etc/cpupdate.conf | tail -n1)
        case "$upd" in
            daily)        status PASS "Automatic cPanel updates: daily" ;;
            manual|never) status WARN "Automatic cPanel updates set to '$upd'" ;;
            *)            status INFO "UPDATES=${upd:-unset}" ;;
        esac
        case "$tier" in
            [0-9]*) status WARN "cPanel pinned to version $tier (no automatic tier updates)" ;;
            *)      status INFO "Release tier: ${tier:-default}" ;;
        esac
        case "$rpmup" in
            daily)        status PASS "Automatic OS package (RPM) updates: daily" ;;
            manual|never) status WARN "Automatic OS package (RPM) updates set to '$rpmup'" ;;
        esac
    else
        status WARN "/etc/cpupdate.conf not found"
    fi

    sub "Last update run (upcp)"
    lastlog=$(ls -1t /var/cpanel/updatelogs/update.*.log 2>/dev/null | head -n1)
    if [ -n "$lastlog" ]; then
        age=$(( ( $(date +%s) - $(stat -c %Y "$lastlog") ) / 86400 ))
        kv "Latest log" "$lastlog"
        kv "Age (days)" "$age"
        if [ "$age" -gt 14 ]; then status WARN "Last cPanel update ran $age days ago"
        else status PASS "cPanel update ran $age day(s) ago"
        fi
        echo; tail -n 8 "$lastlog" | cut -c1-200
    else
        status INFO "No update logs found in /var/cpanel/updatelogs"
    fi
    pgrep -f 'scripts/upcp' >/dev/null 2>&1 && status INFO "A cPanel update (upcp) is running right now"

    sub "Two-factor authentication (2FA)"
    if ! have whmapi1; then
        skip "whmapi1 not available"
        return
    fi
    pol=$(tmo whmapi1 twofactorauth_policy_status 2>/dev/null | awk '/is_enabled:/ {print $2; exit}')
    kv "2FA security policy enabled" "${pol:-unknown}"
    if   [ "$pol" = "1" ]; then status PASS "WHM 2FA security policy enabled"
    elif [ "$pol" = "0" ]; then status WARN "WHM 2FA security policy disabled"
    else                        status WARN "Unable to read the WHM 2FA policy"
    fi

    # One bulk call; the parser accepts either a per-user map or a list layout.
    # Secrets are never printed.
    res=$(tmo whmapi1 twofactorauth_get_user_configs 2>/dev/null)
    en=$(awk '
        /^[[:space:]]*user:[[:space:]]*[^[:space:]]+/ {u = $2}
        /^    [^[:space:]][^:]*:[[:space:]]*$/       {u = $1; sub(/:$/, "", u)}
        /is_enabled:[[:space:]]*1/                   {print u}' <<<"$res" | sort -u)
    users=$(tmo whmapi1 listaccts want=user 2>/dev/null | awk '/^[[:space:]]*user:/ {print $2}' | sort -u)
    total=$(grep -c . <<<"$users")
    root_en=0; grep -qx root <<<"$en" && root_en=1

    kv "cPanel accounts" "$total"
    kv "Accounts with 2FA enabled" "$(comm -12 <(echo "$users") <(echo "$en") | grep -c .)"
    if [ "$root_en" -eq 1 ]; then status PASS "root has 2FA configured"
    else status WARN "root does not have 2FA configured"
    fi
    notlist=$(comm -23 <(echo "$users") <(echo "$en") | grep .)
    if [ -n "$notlist" ]; then
        echo; echo "Accounts WITHOUT 2FA:"
        echo "$notlist" | sed 's/^/  /' | cap 100
    fi
}

###############################################################################
# 12. WEB SERVERS: APACHE / NGINX / LITESPEED / LSPHP
###############################################################################

sec_web() {
    local found=0 st out rc v idx

    sub "Detected web servers"
    if [ -n "$APACHE_CTL" ]; then found=1; kv "Apache" "$($APACHE_CTL -v 2>/dev/null | head -n1 | sed 's/^Server version: //')"; fi
    if have nginx; then found=1; kv "Nginx" "$(nginx -v 2>&1 | head -n1)"; fi
    if [ -x /usr/local/lsws/bin/lshttpd ]; then found=1; kv "LiteSpeed" "$(/usr/local/lsws/bin/lshttpd -v 2>&1 | head -n1)"; fi
    if [ "$found" -eq 0 ]; then
        skip "No web server (Apache / Nginx / LiteSpeed) detected"
        return
    fi
    kv "Running" "$( { pgrep -x httpd >/dev/null || pgrep -x apache2 >/dev/null; } && printf 'Apache ')$(pgrep -x nginx >/dev/null && printf 'Nginx ')$(pgrep -f 'lshttpd|litespeed' >/dev/null && printf 'LiteSpeed')"

    # ---------------- Apache ----------------
    if [ -n "$APACHE_CTL" ]; then
        sub "Apache"
        if   unit_exists httpd;   then st=$(svc_state httpd)
        elif unit_exists apache2; then st=$(svc_state apache2)
        else st="unknown"; fi
        kv "Service" "$st"
        echo "Key modules:"
        $APACHE_CTL -M 2>/dev/null | grep -Ei 'security2|rewrite|ssl|headers|proxy_fcgi|expires|autoindex|status|mpm_|ruid2|suexec|lsapi|fcgid' | sed 's/^/  /'
        out=$(tmo $APACHE_CTL -t 2>&1); rc=$?
        echo "Configuration test:"; echo "$out" | sed 's/^/  /' | cap 15
        if [ "$rc" -eq 0 ]; then status PASS "Apache configuration syntax OK"
        else status FAIL "Apache configuration test failed"
        fi

        if [ -n "$APACHE_CONF_DIR" ]; then
            echo; echo "Security directives in $APACHE_CONF_DIR:"
            grep -rhiE '^[[:space:]]*(ServerTokens|ServerSignature|TraceEnable|FileETag)[[:space:]]' "$APACHE_CONF_DIR" 2>/dev/null |
                sed 's/^[[:space:]]*//' | sort | uniq -c | sed 's/^/  /'

            v=$(grep -rhiE '^[[:space:]]*ServerTokens[[:space:]]' "$APACHE_CONF_DIR" 2>/dev/null | awk '{print tolower($2)}' | tail -n1)
            case "$v" in
                prod|productonly) status PASS "ServerTokens ProductOnly" ;;
                "")               status WARN "ServerTokens not set (default Full - version disclosed)" ;;
                *)                status WARN "ServerTokens is '$v' (recommend ProductOnly)" ;;
            esac
            v=$(grep -rhiE '^[[:space:]]*ServerSignature[[:space:]]' "$APACHE_CONF_DIR" 2>/dev/null | awk '{print tolower($2)}' | tail -n1)
            if [ "$v" = "off" ]; then status PASS "ServerSignature Off"
            else status WARN "ServerSignature is '${v:-unset}' (recommend Off)"
            fi
            v=$(grep -rhiE '^[[:space:]]*TraceEnable[[:space:]]' "$APACHE_CONF_DIR" 2>/dev/null | awk '{print tolower($2)}' | tail -n1)
            if [ "$v" = "off" ]; then status PASS "TraceEnable Off"
            else status WARN "TraceEnable is '${v:-unset (default On)}' (recommend Off)"
            fi

            sub "Apache directory listing (Options Indexes)"
            idx=$(grep -rniE '^[[:space:]]*Options[[:space:]]' "$APACHE_CONF_DIR" 2>/dev/null | grep -iE '([[:space:]]|\+)Indexes([[:space:]]|$)')
            if [ -n "$idx" ]; then
                echo "$idx" | cut -c1-200 | cap 15
                status WARN "Directory listing (Indexes) enabled in $(grep -c . <<<"$idx") place(s)"
            else
                status PASS "Directory listing not enabled in server configuration"
            fi

            sub "Apache security headers (global configuration)"
            v=$(grep -rhiE 'Header[[:space:]]+(always[[:space:]]+)?(set|append|add|merge)[[:space:]]+"?(X-Frame-Options|X-Content-Type-Options|Content-Security-Policy|Strict-Transport-Security|Referrer-Policy|Permissions-Policy)' "$APACHE_CONF_DIR" 2>/dev/null)
            if [ -n "$v" ]; then echo "$v" | sed 's/^[[:space:]]*/  /' | sort | uniq -c | cap 20
            else status INFO "No global security headers configured (may be set per site in .htaccess)"
            fi

            sub "AllowOverride settings"
            grep -rhiE '^[[:space:]]*AllowOverride' "$APACHE_CONF_DIR" 2>/dev/null | sed 's/^[[:space:]]*//' | sort | uniq -c | cap 15
        fi

        if pgrep -x httpd >/dev/null 2>&1 || pgrep -x apache2 >/dev/null 2>&1; then
            sub "Top 15 Apache processes by CPU"
            ps -C httpd,apache2 -o pid,user:16,%cpu,%mem,etime,args --sort=-%cpu 2>/dev/null | head -n 16 | cut -c1-200
        fi
    fi

    # ---------------- Nginx ----------------
    if have nginx; then
        sub "Nginx"
        kv "Service" "$(svc_state nginx)"
        out=$(tmo nginx -t 2>&1); rc=$?
        echo "Configuration test:"; echo "$out" | sed 's/^/  /' | cap 10
        if [ "$rc" -eq 0 ]; then status PASS "Nginx configuration syntax OK"
        else status FAIL "Nginx configuration test failed"
        fi
        if [ -d /etc/nginx ]; then
            v=$(grep -rhiE '^[[:space:]]*server_tokens[[:space:]]' /etc/nginx 2>/dev/null | awk '{print tolower($2)}' | tr -d ';' | sort -u)
            if [ "$v" = "off" ]; then status PASS "Nginx server_tokens off"
            else status WARN "Nginx server_tokens is '${v:-unset (default on)}' (recommend off)"
            fi
            v=$(grep -rniE '^[[:space:]]*autoindex[[:space:]]+on' /etc/nginx 2>/dev/null)
            if [ -n "$v" ]; then echo "$v" | cap 10; status WARN "Nginx autoindex (directory listing) enabled"
            else status PASS "Nginx autoindex not enabled"
            fi
            echo "Security headers:"
            grep -rhiE 'add_header[[:space:]]+"?(X-Frame-Options|X-Content-Type-Options|Content-Security-Policy|Strict-Transport-Security|Referrer-Policy)' /etc/nginx 2>/dev/null |
                sed 's/^[[:space:]]*/  /' | sort | uniq -c | cap 20
        fi
    fi

    # ---------------- LiteSpeed ----------------
    if [ -x /usr/local/lsws/bin/lshttpd ] || unit_exists lsws; then
        sub "LiteSpeed"
        st=$(svc_state lsws)
        kv "Service (lsws)" "$st"
        if [ -f /usr/local/lsws/conf/httpd_config.xml ]; then kv "Main config" "/usr/local/lsws/conf/httpd_config.xml"
        elif [ -f /usr/local/lsws/conf/httpd_config.conf ]; then kv "Main config" "/usr/local/lsws/conf/httpd_config.conf"
        else status WARN "LiteSpeed main configuration not found"
        fi
        if [ "$st" = "active" ]; then
            echo; echo "Top 15 LiteSpeed processes by CPU:"
            ps -eo pid,user:16,%cpu,%mem,etime,args --sort=-%cpu 2>/dev/null | grep -Ei '[l]shttpd|[l]itespeed' | head -n 15 | cut -c1-200
        fi
    fi

    # ---------------- LSPHP workers (LiteSpeed or mod_lsapi) ----------------
    if pgrep -f lsphp >/dev/null 2>&1; then
        sub "Top 15 LSPHP workers (per-account PHP)"
        ps -eo pid,user:16,%cpu,%mem,etime,args --sort=-%cpu 2>/dev/null | grep -i '[l]sphp' | head -n 15 | cut -c1-200
    fi
}

###############################################################################
# 13. PHP & PHP-FPM
###############################################################################

ini_val() {  # ini_val <file> <key>  -> lower-case value of last occurrence
    awk -F= -v k="$2" 'tolower($1) ~ "^[[:space:]]*" k "[[:space:]]*$" {v = $2}
        END {gsub(/[[:space:]";]/, "", v); print tolower(v)}' "$1" 2>/dev/null
}

sec_php() {
    local bin dir label full ver df any=0 empty_df="" lvl_inst n v nn ini lvl units u logs hits

    lvl_inst=WARN; have whmapi1 && lvl_inst=INFO   # with whmapi1, EOL is judged on versions IN USE

    sub "EA-PHP versions (cPanel MultiPHP)"
    for bin in /opt/cpanel/ea-php*/root/usr/bin/php; do
        [ -x "$bin" ] || continue
        any=1
        dir=${bin%/root/usr/bin/php}; label=${dir##*/}
        full=$(tmo "$bin" -r 'echo PHP_VERSION;' 2>/dev/null)
        ver=$(tmo "$bin" -r 'echo PHP_MAJOR_VERSION.".".PHP_MINOR_VERSION;' 2>/dev/null)
        df=$(tmo "$bin" -r 'echo ini_get("disable_functions");' 2>/dev/null)
        kv "$label" "${full:-unknown}"
        printf '  disable_functions: %s\n' "${df:-(none)}" | cut -c1-220
        eol_check "$ver" "$label (PHP $ver) installed" "$lvl_inst"
        [ -z "$df" ] && empty_df="$empty_df $label"
    done
    [ "$any" -eq 0 ] && skip "No EA-PHP installations found"
    [ -n "$empty_df" ] && status WARN "disable_functions is empty for:$empty_df"
    echo
    echo "Reference: PHP <=8.0 EOL; 8.1 EOL 2025-12-31; 8.2 until 2026-12-31; 8.3 until 2027-12-31; 8.4 until 2028-12-31; 8.5 until 2029-12-31"

    sub "Domains per PHP version"
    if have whmapi1; then
        tmo whmapi1 php_get_vhost_versions 2>/dev/null | awk '/^[[:space:]]+version:/ {print $2}' |
            sort | uniq -c | sort -nr > "$WORK/php_inuse.txt"
        if [ -s "$WORK/php_inuse.txt" ]; then
            cat "$WORK/php_inuse.txt"; echo
            while read -r n v; do
                case "$v" in
                    ea-php[0-9][0-9])
                        nn=${v#ea-php}
                        eol_check "${nn:0:1}.${nn:1}" "$v (used by $n domain(s))" WARN ;;
                esac
            done < "$WORK/php_inuse.txt"
        else
            status INFO "No per-domain PHP version data returned"
        fi
    else
        skip "whmapi1 not available - per-domain PHP versions not checked"
    fi

    sub "CloudLinux alt-php versions"
    any=0
    for bin in /opt/alt/php[0-9]*/usr/bin/php; do
        [ -x "$bin" ] || continue
        any=1
        dir=${bin%/usr/bin/php}; label=${dir##*/}
        ver=$(tmo "$bin" -r 'echo PHP_MAJOR_VERSION.".".PHP_MINOR_VERSION;' 2>/dev/null)
        eol_check "$ver" "$label (PHP $ver)" INFO
    done
    [ "$any" -eq 0 ] && skip "No alt-php installations found"

    sub "Risky php.ini settings"
    any=0
    for ini in /opt/cpanel/ea-php*/root/etc/php.ini /opt/alt/php*/etc/php.ini; do
        [ -f "$ini" ] || continue
        any=1
        lvl=WARN; [[ "$ini" == /opt/alt/* ]] && lvl=INFO
        echo "FILE: $ini"
        grep -Ei '^[[:space:]]*(allow_url_include|allow_url_fopen|display_errors|display_startup_errors|expose_php|enable_dl|cgi\.fix_pathinfo|file_uploads|open_basedir|session\.cookie_secure|session\.cookie_httponly|session\.cookie_samesite|max_execution_time|max_input_time|memory_limit|upload_max_filesize|post_max_size)[[:space:]]*=' "$ini" 2>/dev/null |
            sed 's/^[[:space:]]*/  /'
        case "$(ini_val "$ini" allow_url_include)" in on|1) status "$( [ "$lvl" = WARN ] && echo FAIL || echo INFO )" "$ini: allow_url_include enabled" ;; esac
        case "$(ini_val "$ini" display_errors)"    in on|1) status "$lvl" "$ini: display_errors enabled" ;; esac
        case "$(ini_val "$ini" expose_php)"        in on|1) status "$lvl" "$ini: expose_php enabled (version disclosed)" ;; esac
        case "$(ini_val "$ini" enable_dl)"         in on|1) status "$lvl" "$ini: enable_dl enabled" ;; esac
    done
    [ "$any" -eq 0 ] && skip "No php.ini files found"

    sub "PHP-FPM services"
    units=$(unit_match 'php.*fpm')
    if [ -z "$units" ]; then
        skip "No PHP-FPM services found"
    else
        for u in $units; do kv "$u" "$(svc_state "$u")"; done
    fi

    if ls -d /opt/cpanel/ea-php*/root/etc/php-fpm.d >/dev/null 2>&1; then
        sub "PHP-FPM pool settings"
        kv "Pool config files" "$(find /opt/cpanel/ea-php*/root/etc/php-fpm.d -type f -name '*.conf' 2>/dev/null | wc -l)"
        grep -rHiE '^[[:space:]]*(pm[[:space:]]*=|pm\.max_children|pm\.max_requests|pm\.process_idle_timeout|request_terminate_timeout|security\.limit_extensions)' \
            /opt/cpanel/ea-php*/root/etc/php-fpm.d/ 2>/dev/null | cut -c1-200 | cap 80
    fi

    if [ -d /var/cpanel/userdata ]; then
        sub "cPanel per-domain PHP-FPM overrides"
        kv "Domains with PHP-FPM YAML" "$(find /var/cpanel/userdata -type f -name '*.php-fpm.yaml' 2>/dev/null | wc -l)"
        echo "disable_functions overrides:"
        grep -rHi 'disable_functions' /var/cpanel/userdata 2>/dev/null | cut -c1-200 | cap 30
    fi

    if [ -x /usr/local/cpanel/bin/rebuild_phpconf ]; then
        sub "PHP handlers (rebuild_phpconf --current, read-only)"
        tmo /usr/local/cpanel/bin/rebuild_phpconf --current 2>/dev/null | cap 40
    fi

    sub "PHP-FPM pool saturation (pm.max_children) events"
    logs=$(ls /opt/cpanel/ea-php*/root/usr/var/log/php-fpm/error.log /var/log/php-fpm/error.log /var/log/php*-fpm.log 2>/dev/null)
    if [ -z "$logs" ]; then
        skip "No PHP-FPM error logs found"
    else
        echo "Logs checked:"; echo "$logs" | sed 's/^/  /'
        # shellcheck disable=SC2086
        hits=$(grep -hE 'max_children|seems busy' $logs 2>/dev/null)
        if [ -z "$hits" ]; then
            status PASS "No pm.max_children / busy-pool events in PHP-FPM logs"
        else
            status WARN "$(grep -c . <<<"$hits") PHP-FPM pool saturation event(s) logged"
            echo; echo "Events per pool (account):"
            grep -oE '\[pool [^]]+\]' <<<"$hits" | sort | uniq -c | sort -nr | head -n 15
            echo; echo "Latest 10 events:"
            tail -n 10 <<<"$hits" | cut -c1-200
        fi
    fi
}

###############################################################################
# 14. MYSQL / MARIADB
###############################################################################

db_q() { tmo "$DB_CLI" -Nse "$1" 2>/dev/null; }

slow_extract() {  # slow_extract <max entries>  (stdin: tail of slow log)
    awk -v max="$1" '
        /^# Time:/      {pend = $0 "\n"; next}
        /^# User@Host:/ {if (e != "") buf[++n] = e; e = pend $0 "\n"; pend = ""; next}
                        {if (e != "") e = e $0 "\n"}
        END {
            if (e != "") buf[++n] = e
            s = n - max + 1; if (s < 1) s = 1
            for (i = s; i <= n; i++) printf "%s", buf[i]
        }'
}

sec_db() {
    local dump="" bind skipnet port anon wild conns maxc maxused pct slow_on slowf lqt datadir k label

    DB_CLI=""
    if   have mariadb; then DB_CLI=mariadb
    elif have mysql;   then DB_CLI=mysql
    fi
    if [ -z "$DB_CLI" ]; then
        skip "MySQL/MariaDB client not installed"
        return
    fi

    sub "Version"
    $DB_CLI --version 2>/dev/null
    if ! tmo "$DB_CLI" -Nse 'SELECT 1' >/dev/null 2>&1; then
        status WARN "Cannot connect to MySQL/MariaDB as root (server down or /root/.my.cnf missing) - remaining database checks skipped"
        return
    fi
    kv "Server version" "$(db_q 'SELECT VERSION()')"
    kv "Uptime (seconds)" "$(db_q "SHOW GLOBAL STATUS LIKE 'Uptime'" | awk '{print $2}')"

    sub "Network exposure"
    bind=$(db_q "SHOW VARIABLES LIKE 'bind_address'" | awk '{print $2}')
    skipnet=$(db_q "SHOW VARIABLES LIKE 'skip_networking'" | awk '{print $2}')
    port=$(db_q "SHOW VARIABLES LIKE 'port'" | awk '{print $2}')
    kv "bind_address" "${bind:-(not set = all interfaces)}"
    kv "port" "$port"
    kv "skip_networking" "$skipnet"
    if [ "$skipnet" = "ON" ]; then
        status PASS "TCP networking disabled (socket only)"
    elif [ -z "$bind" ] || [[ "$bind" =~ ^(\*|0\.0\.0\.0|::)$ ]]; then
        status WARN "MySQL/MariaDB accepts connections on all interfaces - restrict with the firewall or bind to 127.0.0.1 if remote access is not needed"
    else
        status PASS "MySQL/MariaDB bound to $bind"
    fi

    sub "Accounts"
    anon=$(db_q "SELECT COUNT(*) FROM mysql.user WHERE User=''")
    kv "Anonymous users" "${anon:-unknown}"
    if   [ "$anon" = "0" ]; then status PASS "No anonymous MySQL users"
    elif [ -n "$anon" ];    then status FAIL "$anon anonymous MySQL user(s) present"
    else                         status WARN "Unable to check anonymous users"
    fi
    wild=$(db_q "SELECT CONCAT(User,'@',Host) FROM mysql.user WHERE Host='%'")
    if [ -n "$wild" ]; then
        echo "Users allowed from any host ('%'):"; echo "$wild" | sed 's/^/  /' | cap 30
        status WARN "$(grep -c . <<<"$wild") MySQL user(s) can connect from any host"
    else
        status PASS "No MySQL users allowed from any host ('%')"
    fi

    sub "Connections"
    conns=$(db_q "SHOW GLOBAL STATUS LIKE 'Threads_connected'" | awk '{print $2}')
    maxused=$(db_q "SHOW GLOBAL STATUS LIKE 'Max_used_connections'" | awk '{print $2}')
    maxc=$(db_q "SHOW VARIABLES LIKE 'max_connections'" | awk '{print $2}')
    kv "Threads connected" "$conns"
    kv "Max used connections" "$maxused"
    kv "max_connections" "$maxc"
    if [[ "$conns" =~ ^[0-9]+$ ]] && [[ "$maxc" =~ ^[0-9]+$ ]] && [ "$maxc" -gt 0 ]; then
        pct=$(( conns * 100 / maxc ))
        if [ "$pct" -ge 80 ]; then status WARN "Connections at ${pct}% of max_connections"
        else status PASS "Connections at ${pct}% of max_connections"
        fi
    fi

    sub "Active queries (excluding Sleep), longest first"
    tmo "$DB_CLI" -t -e "SELECT ID, USER, HOST, DB, COMMAND, TIME, STATE, LEFT(REPLACE(INFO, '\n', ' '), 120) AS QUERY FROM information_schema.PROCESSLIST WHERE COMMAND <> 'Sleep' ORDER BY TIME DESC LIMIT 20" 2>&1 | cut -c1-250

    sub "Slow query log"
    slow_on=$(db_q "SHOW VARIABLES LIKE 'slow_query_log'" | awk '{print $2}')
    slowf=$(db_q "SHOW VARIABLES LIKE 'slow_query_log_file'" | awk '{print $2}')
    lqt=$(db_q "SHOW VARIABLES LIKE 'long_query_time'" | awk '{print $2}')
    datadir=$(db_q "SHOW VARIABLES LIKE 'datadir'" | awk '{print $2}')
    [ -n "$slowf" ] && [ "${slowf#/}" = "$slowf" ] && slowf="${datadir%/}/$slowf"
    kv "slow_query_log" "${slow_on:-unknown}"
    kv "slow_query_log_file" "${slowf:-unknown}"
    kv "long_query_time (s)" "$lqt"
    [ "$slow_on" != "ON" ] && status INFO "Slow query logging is disabled (existing log, if any, is still analysed)"

    if [ -z "$slowf" ] || [ ! -s "$slowf" ]; then
        skip "Slow query log not found or empty"
        return
    fi
    kv "Log size" "$(du -h "$slowf" 2>/dev/null | awk '{print $1}')"
    if   have mariadb-dumpslow; then dump=mariadb-dumpslow
    elif have mysqldumpslow;    then dump=mysqldumpslow
    fi
    tail -n $(( SLOW_QUERY_COUNT * 50 )) "$slowf" 2>/dev/null | slow_extract "$SLOW_QUERY_COUNT" > "$WORK/slow.log"
    if [ ! -s "$WORK/slow.log" ]; then
        status INFO "No complete slow-query entries found"
        return
    fi
    kv "Entries analysed" "$(grep -c '^# User@Host:' "$WORK/slow.log")"
    if [ -n "$dump" ]; then
        for k in t l r c; do
            case "$k" in t) label="query time" ;; l) label="lock time" ;; r) label="rows sent" ;; c) label="count" ;; esac
            sub "Top 10 slow query patterns by $label"
            tmo "$dump" -s "$k" -t 10 "$WORK/slow.log" 2>/dev/null | cut -c1-250 | cap 80
        done
    else
        skip "mariadb-dumpslow / mysqldumpslow not found - pattern analysis skipped"
    fi
    sub "Latest 5 slow queries"
    slow_extract 5 < "$WORK/slow.log" | cut -c1-300 | cap 80
}

###############################################################################
# 15. CLOUDLINUX LVE
###############################################################################

sec_cloudlinux() {
    local ver=""
    if [ -f /etc/cloudlinux-release ]; then
        ver=$(cat /etc/cloudlinux-release 2>/dev/null)
    elif have cldetect; then
        ver=$(cldetect --detect-edition 2>/dev/null)
    fi
    if [ -z "$ver" ] && ! have lveps && ! have lveinfo; then
        status INFO "CloudLinux not detected - LVE checks skipped"
        return
    fi
    kv "CloudLinux" "${ver:-detected (LVE tools present)}"

    sub "Top 10 LVE users by current CPU (1-second sample)"
    if have lveps; then tmo lveps -d -c 1 -s cpu 2>&1 | head -n 11
    else skip "lveps not found"
    fi

    sub "Top 10 LVE users by current physical memory"
    if have lveps; then tmo lveps -d -c 1 -s mem 2>&1 | head -n 11
    else skip "lveps not found"
    fi

    sub "Top 10 accounts by LVE faults (last 1 hour)"
    if have lveinfo; then
        tmo lveinfo --period=1h --order-by=any_faults --display-username --limit=10 2>&1 | cap 30
    else
        skip "lveinfo not found"
    fi
}

###############################################################################
# 16. EMAIL: EXIM / DOVECOT
###############################################################################

sec_mail() {
    local st q frozen mainlog resp rcpt auth p ssl minp clear dv

    sub "Exim"
    if ! have exim; then
        status INFO "Exim not installed - Exim checks skipped"
    else
        kv "Version" "$(exim -bV 2>/dev/null | head -n1)"
        if unit_exists exim; then
            st=$(svc_state exim); kv "Service" "$st"
            if [ "$st" = "active" ]; then status PASS "Exim running"
            else status WARN "Exim service is $st"
            fi
        fi

        sub "Mail queue"
        q=$(tmo exim -bpc 2>/dev/null)
        if [[ "$q" =~ ^[0-9]+$ ]]; then
            kv "Queued messages" "$q"
            if   [ "$q" -gt 10000 ]; then status FAIL "Mail queue has $q messages - check for a spam outbreak"
            elif [ "$q" -gt 1000 ];  then status WARN "Mail queue has $q messages"
            elif [ "$q" -gt 100 ];   then status WARN "Mail queue elevated ($q messages)"
            else                          status PASS "Mail queue normal ($q messages)"
            fi
            if [ "$q" -gt 100 ]; then
                tmo exim -bp 2>/dev/null > "$WORK/exim_queue.txt"
                frozen=$(grep -c 'frozen' "$WORK/exim_queue.txt")
                kv "Frozen messages" "$frozen"
                echo; echo "Top 15 senders in the queue:"
                awk '/^[[:space:]]*[0-9]+[mhd][[:space:]]+/ {c[$4]++} END {for (s in c) printf "%8d %s\n", c[s], s}' "$WORK/exim_queue.txt" |
                    sort -nr | head -n 15
            fi
        else
            status WARN "Unable to read the Exim queue"
        fi

        sub "Top senders (exim_mainlog, last $EXIM_LOG_LINES lines)"
        mainlog=""
        for p in /var/log/exim_mainlog /var/log/exim4/mainlog; do [ -r "$p" ] && { mainlog=$p; break; }; done
        if [ -n "$mainlog" ]; then
            tail -n "$EXIM_LOG_LINES" "$mainlog" > "$WORK/exim_tail.log" 2>/dev/null
            kv "Log" "$mainlog"
            echo "By envelope sender:"
            grep ' <= ' "$WORK/exim_tail.log" | awk -F' <= ' '{split($2, a, " "); print a[1]}' | sort | uniq -c | sort -nr | head -n 10
            echo; echo "By authenticated SMTP user:"
            grep -oE 'A=dovecot_(login|plain):[^ ]+' "$WORK/exim_tail.log" | cut -d: -f2 | sort | uniq -c | sort -nr | head -n 10
            echo; echo "By script directory (mail sent by PHP/CGI scripts):"
            grep -oE 'cwd=/home[0-9]*/[^ ]+' "$WORK/exim_tail.log" | sort | uniq -c | sort -nr | head -n 10
        else
            skip "Exim main log not found"
        fi

        sub "Open relay test (simulated session - nothing is sent)"
        resp=$(printf 'EHLO relay-test.example.com\r\nMAIL FROM:<audit@example.com>\r\nRCPT TO:<audit@example.net>\r\nQUIT\r\n' |
               tmo exim -bh 192.0.2.10 2>/dev/null | tr -d '\r' | grep -E '^[0-9]{3}[ -]')
        rcpt=$(grep -E '^[0-9]{3} ' <<<"$resp" | sed -n '4p')
        echo "$resp" | cut -c1-160 | cap 25
        echo
        case "$rcpt" in
            2*)    status FAIL "OPEN RELAY: unauthenticated relay to an external domain was accepted ($(cut -c1-80 <<<"$rcpt"))" ;;
            4*|5*) status PASS "Unauthenticated relay to an external domain refused ($(cut -c1-80 <<<"$rcpt"))" ;;
            *)     status WARN "Open relay test inconclusive - review the Exim RCPT ACL manually" ;;
        esac

        sub "SMTP authentication"
        auth=$(exim -bP authenticator_list 2>/dev/null)
        [ -z "$auth" ] && auth=$(exim -bP authenticators 2>/dev/null | sed -nE 's/^([A-Za-z0-9_-]+)( authenticator)?:.*$/\1/p')
        if [ -n "$auth" ]; then status PASS "SMTP AUTH configured: $(paste -sd, <<<"$auth")"
        else status WARN "No SMTP authenticators detected"
        fi
        for p in 25 465 587; do
            if port_listening "$p"; then kv "Port $p" "listening"; else kv "Port $p" "not listening"; fi
        done
    fi

    sub "Dovecot (IMAP / POP3)"
    if ! have doveconf && ! unit_exists dovecot; then
        status INFO "Dovecot not installed"
        return
    fi
    st=$(svc_state dovecot); kv "Service" "$st"
    if [ "$st" = "active" ]; then status PASS "Dovecot running"
    else status WARN "Dovecot service is $st"
    fi
    if have doveconf; then
        ssl=$(doveconf -h ssl 2>/dev/null)
        minp=$(doveconf -h ssl_min_protocol 2>/dev/null)
        clear=$(doveconf -h auth_allow_cleartext 2>/dev/null)            # Dovecot 2.4
        if [ -z "$clear" ]; then                                          # Dovecot 2.3
            dv=$(doveconf -h disable_plaintext_auth 2>/dev/null)
            case "$dv" in yes) clear=no ;; no) clear=yes ;; esac
        fi
        kv "ssl" "$ssl"; kv "ssl_min_protocol" "$minp"; kv "Cleartext auth on non-TLS" "$clear"
        case "$ssl" in
            no)           status FAIL "Dovecot SSL/TLS disabled" ;;
            yes|required) status PASS "Dovecot SSL/TLS enabled ($ssl)" ;;
            *)            status WARN "Dovecot SSL/TLS setting unclear (${ssl:-unset})" ;;
        esac
        case "$minp" in
            SSLv3|TLSv1|TLSv1.1) status WARN "Dovecot allows legacy protocol (ssl_min_protocol=$minp)" ;;
            TLSv1.2|TLSv1.3)     status PASS "Dovecot minimum protocol $minp" ;;
        esac
        [ "$clear" = "yes" ] && status WARN "Dovecot allows cleartext authentication on unencrypted connections"
        [ "$clear" = "no" ]  && status PASS "Dovecot refuses cleartext authentication without TLS"
        echo "ssl_cipher_list: $(doveconf -h ssl_cipher_list 2>/dev/null | cut -c1-180)"
    else
        skip "doveconf not available - TLS settings not evaluated"
    fi
    for p in 110 143 993 995; do
        if port_listening "$p"; then kv "Port $p" "listening"; else kv "Port $p" "not listening"; fi
    done
}

###############################################################################
# 17. FTP
###############################################################################

sec_ftp() {
    local svc="" st conf="" v f p

    if   have pure-ftpd || unit_exists pure-ftpd; then svc=pure-ftpd
    elif have proftpd   || unit_exists proftpd;   then svc=proftpd
    else
        status INFO "No FTP server (Pure-FTPd / ProFTPD) detected"
        return
    fi
    st=$(svc_state "$svc")
    kv "FTP server" "$svc"
    kv "Service" "$st"
    [ "$st" != "active" ] && status INFO "$svc installed but not running"
    for p in 21 990; do
        if port_listening "$p"; then kv "Port $p" "listening"; else kv "Port $p" "not listening"; fi
    done

    if [ "$svc" = "pure-ftpd" ]; then
        for f in /etc/pure-ftpd.conf /etc/pure-ftpd/pure-ftpd.conf; do [ -f "$f" ] && { conf=$f; break; }; done
        if [ -z "$conf" ]; then
            status WARN "Pure-FTPd configuration file not found"
            return
        fi
        kv "Config" "$conf"
        v=$(awk 'tolower($1) == "noanonymous" {v = tolower($2)} END {print v}' "$conf")
        case "$v" in
            yes) status PASS "Anonymous FTP disabled" ;;
            no)  status FAIL "Anonymous FTP enabled" ;;
            *)   status WARN "Anonymous FTP setting not found (NoAnonymous)" ;;
        esac
        v=$(awk 'toupper($1) == "TLS" {v = $2} END {print v}' "$conf")
        case "$v" in
            0)   status WARN "FTP TLS disabled - credentials sent in cleartext" ;;
            1)   status PASS "FTP TLS available (plain FTP still allowed)" ;;
            2|3) status PASS "FTP TLS required" ;;
            *)   status WARN "FTP TLS setting not found" ;;
        esac
    else
        if grep -rqiE '^[[:space:]]*<Anonymous' /etc/proftpd.conf /etc/proftpd/ 2>/dev/null; then
            status FAIL "ProFTPD anonymous configuration present"
        else
            status PASS "No ProFTPD anonymous configuration"
        fi
        v=$(grep -rhiE '^[[:space:]]*(TLSEngine|TLSRequired|TLSProtocol)[[:space:]]' /etc/proftpd.conf /etc/proftpd/ 2>/dev/null | sort -u)
        [ -n "$v" ] && echo "$v" | sed 's/^/  /'
        if   grep -qiE 'TLSRequired[[:space:]]+on' <<<"$v"; then status PASS "ProFTPD TLS required"
        elif grep -qiE 'TLSEngine[[:space:]]+on' <<<"$v";   then status PASS "ProFTPD TLS enabled (not required)"
        else status WARN "ProFTPD TLS not enabled - credentials sent in cleartext"
        fi
    fi
}

###############################################################################
# 18. DNS: BIND / POWERDNS
###############################################################################

sec_dns() {
    local cfg flat rec arec xfer v st

    if have named-checkconf && { unit_exists named || unit_exists bind9 || [ -f /etc/named.conf ]; }; then
        if unit_exists named; then st=$(svc_state named); else st=$(svc_state bind9); fi
        kv "BIND service" "$st"
        cfg=$(tmo named-checkconf -p 2>/dev/null)
        if [ -z "$cfg" ]; then
            status WARN "named-checkconf -p returned nothing - configuration test:"
            tmo named-checkconf 2>&1 | cap 10
            return
        fi
        flat=$(tr '\n\t' '  ' <<<"$cfg" | tr -s ' ')

        sub "Recursion"
        rec=$(grep -oE '(^|[ {;])recursion (yes|no);' <<<"$flat" | sed 's/^[ {;]*//' | sort | uniq -c)
        arec=$(grep -oE 'allow-recursion \{[^}]*\}' <<<"$flat" | sort | uniq -c)
        echo "${rec:-  recursion: not set}"; echo "${arec:-  allow-recursion: not set}"
        if   grep -q 'recursion no;' <<<"$rec" && ! grep -q 'recursion yes;' <<<"$rec"; then status PASS "DNS recursion disabled"
        elif grep -qE 'allow-recursion \{ ?"?any"?;' <<<"$arec"; then status FAIL "Open resolver: recursion allowed for any client"
        elif [ -n "$arec" ]; then status PASS "Recursion restricted by allow-recursion"
        else status WARN "Recursion not explicitly restricted (BIND default: localhost; localnets) - verify"
        fi

        sub "Zone transfers"
        xfer=$(grep -oE 'allow-transfer \{[^}]*\}' <<<"$flat" | sort | uniq -c)
        echo "${xfer:-  allow-transfer: not set}" | cap 20
        if   grep -qE 'allow-transfer \{ ?"?any"?;' <<<"$xfer"; then status FAIL "Zone transfers allowed to any host"
        elif [ -n "$xfer" ] && ! grep -vqE 'allow-transfer \{ ?"?none"?; ?\}' <<<"$xfer"; then status PASS "Zone transfers disabled"
        elif [ -n "$xfer" ]; then status PASS "Zone transfers restricted to specific hosts - verify they are your secondaries"
        else status WARN "No allow-transfer restriction found - verify zone transfers are restricted"
        fi
    elif unit_exists pdns || have pdns_server; then
        kv "PowerDNS service" "$(svc_state pdns)"
        status INFO "PowerDNS authoritative server (no recursion)"
        if [ -f /etc/pdns/pdns.conf ]; then
            v=$(grep -E '^[[:space:]]*(disable-axfr|allow-axfr-ips)[[:space:]]*=' /etc/pdns/pdns.conf)
            [ -n "$v" ] && echo "$v"
            if   grep -qE 'disable-axfr[[:space:]]*=[[:space:]]*yes' <<<"$v"; then status PASS "PowerDNS AXFR disabled"
            elif grep -q 'allow-axfr-ips' <<<"$v"; then status PASS "PowerDNS AXFR limited by allow-axfr-ips - verify the list"
            else status PASS "PowerDNS AXFR limited to default 127.0.0.0/8,::1"
            fi
        fi
    else
        status INFO "No local DNS server (BIND / PowerDNS) detected"
        return
    fi
    if port_listening 53; then kv "Port 53" "listening"; else kv "Port 53" "not listening"; fi
}

###############################################################################
# 19. CRON JOBS
###############################################################################

sec_cron() {
    local all="$WORK/cron_all.txt" act="$WORK/cron_active.txt" f susp perm re

    : > "$all"
    for f in /etc/crontab /etc/cron.d/* /var/spool/cron/* /var/spool/cron/crontabs/*; do
        [ -f "$f" ] && [ -r "$f" ] || continue
        awk -v f="$f" '{print f ": " $0}' "$f" >> "$all"
    done
    grep -vE '^[^:]+: [[:space:]]*(#|$)' "$all" | grep -vE '^[^:]+: [[:space:]]*[A-Za-z_]+[[:space:]]*=' > "$act"
    kv "Active cron entries" "$(grep -c . "$act")"

    sub "Active cron entries (system + all users)"
    cut -c1-220 "$act" | cap

    sub "Potentially suspicious entries"
    re='(/tmp/|/var/tmp/|/dev/shm/|(curl|wget)[[:space:]]|[[:space:]](nc|ncat|netcat)[[:space:]]|(bash|sh)[[:space:]]+-c|base64[[:space:]]+(-d|--decode)|python[0-9.]*[[:space:]]+-c|perl[[:space:]]+-e|php[[:space:]]+-r|eval[[:space:]]*\(|chattr[[:space:]]+\+i|chmod[[:space:]]+(-[a-zA-Z]+[[:space:]]+)*0?[0-7]{2}[2367]([[:space:]]|;|$))'
    susp=$(grep -E "$re" "$act")
    if [ -n "$susp" ]; then
        echo "$susp" | cut -c1-220 | cap 60
        status WARN "$(grep -c . <<<"$susp") cron entr(y/ies) match suspicious patterns - review (wp-cron jobs using curl/wget are usually legitimate)"
    else
        status PASS "No cron entries match known suspicious patterns"
    fi

    sub "Cron files writable by group/others"
    perm=$(find /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly -type f -perm /022 2>/dev/null)
    if [ -n "$perm" ]; then
        echo "$perm" | xargs ls -l 2>/dev/null | cap 30
        status WARN "Cron files writable by group/others detected"
    else
        status PASS "No group/other-writable cron files"
    fi
}

###############################################################################
# RENDERING: HTML
###############################################################################

html_esc() { sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g' -e 's/"/\&quot;/g'; }

color_lines() {
    html_esc | sed -E \
        -e 's#^\[PASS\](.*)$#<span class="pass">[PASS]\1</span>#' \
        -e 's#^\[WARN\](.*)$#<span class="warn">[WARN]\1</span>#' \
        -e 's#^\[FAIL\](.*)$#<span class="fail">[FAIL]\1</span>#' \
        -e 's#^\[INFO\](.*)$#<span class="info">[INFO]\1</span>#' \
        -e 's#^\[SKIP\](.*)$#<span class="skip">[SKIP]\1</span>#' \
        -e 's#^--- (.*) ---$#<span class="sh">\1</span>#'
}

render_html() {
    local out="$1" np nw nf num title
    np=$(grep -c '^PASS' "$FINDINGS"); nw=$(grep -c '^WARN' "$FINDINGS"); nf=$(grep -c '^FAIL' "$FINDINGS")
    {
    cat <<EOF
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Server Audit - $(html_esc <<<"$HOST_FQDN")</title>
<style>
*{box-sizing:border-box}
body{margin:0;background:#f1f5f9;color:#1e293b;font:14px/1.5 Arial,Helvetica,sans-serif}
.wrap{max-width:1400px;margin:auto;padding:24px}
header{background:linear-gradient(135deg,#0f172a,#1e3a8a);color:#fff;padding:26px 28px;border-radius:12px;margin-bottom:20px}
header h1{margin:0 0 14px;font-size:26px}
.meta{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:4px 24px;color:#dbeafe}
.meta b{color:#fff}
.cards{display:grid;grid-template-columns:repeat(3,1fr);gap:14px;margin-bottom:20px}
.card{background:#fff;border-radius:10px;padding:16px 20px;box-shadow:0 2px 8px rgba(0,0,0,.06);border-top:5px solid}
.card .n{font-size:32px;font-weight:bold}
.card.f{border-color:#dc2626}.card.f .n{color:#b91c1c}
.card.w{border-color:#f59e0b}.card.w .n{color:#b45309}
.card.p{border-color:#16a34a}.card.p .n{color:#15803d}
.box{background:#fff;border-radius:10px;margin-bottom:20px;box-shadow:0 2px 8px rgba(0,0,0,.06);overflow:hidden}
.box h2{margin:0;background:#e2e8f0;padding:12px 18px;font-size:17px;color:#0f172a}
.box .in{padding:16px 18px}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{text-align:left;padding:7px 10px;border-bottom:1px solid #e2e8f0;vertical-align:top}
th{background:#f8fafc}
.b{display:inline-block;padding:1px 8px;border-radius:10px;font-size:11px;font-weight:bold;color:#fff}
.b.fail{background:#dc2626}.b.warn{background:#d97706}
a{color:#1d4ed8;text-decoration:none}
.toc{columns:2;margin:0;padding-left:22px}
.toc li{margin:2px 0}
.cnt{font-size:11px;margin-left:6px}
pre{margin:0;background:#0f172a;color:#e2e8f0;padding:14px;border-radius:7px;overflow-x:auto;white-space:pre-wrap;word-wrap:break-word;font:12px/1.5 Consolas,Monaco,monospace}
pre .pass{color:#4ade80;font-weight:bold}
pre .warn{color:#fbbf24;font-weight:bold}
pre .fail{color:#f87171;font-weight:bold}
pre .info{color:#93c5fd}
pre .skip{color:#94a3b8}
pre .sh{color:#7dd3fc;font-weight:bold}
footer{text-align:center;color:#64748b;font-size:12px;padding:16px}
@media (max-width:700px){.wrap{padding:10px}.cards{grid-template-columns:1fr}.toc{columns:1}}
@media print{body{background:#fff}.box,.card{box-shadow:none;border:1px solid #cbd5e1}}
</style>
</head>
<body>
<div class="wrap">
<header>
<h1>Server Security &amp; Load Audit Report</h1>
<div class="meta">
EOF
    awk -F'\t' '{gsub(/&/,"\\&amp;");gsub(/</,"\\&lt;");gsub(/>/,"\\&gt;"); printf "<div><b>%s:</b> %s</div>\n", $1, $2}' "$WORK/meta.tsv"
    cat <<EOF
</div>
</header>
<div class="cards">
<div class="card f"><div class="n">$nf</div>Failed checks</div>
<div class="card w"><div class="n">$nw</div>Warnings</div>
<div class="card p"><div class="n">$np</div>Passed checks</div>
</div>
<div class="box"><h2>Findings requiring attention</h2><div class="in">
EOF
    if [ "$((nf + nw))" -gt 0 ]; then
        echo '<table><tr><th style="width:80px">Level</th><th style="width:28%">Section</th><th>Finding</th></tr>'
        for lvl in FAIL WARN; do
            awk -F'\t' -v l="$lvl" '
                function esc(s) {gsub(/&/,"\\&amp;",s); gsub(/</,"\\&lt;",s); gsub(/>/,"\\&gt;",s); return s}
                $1 == l {printf "<tr><td><span class=\"b %s\">%s</span></td><td><a href=\"#s%s\">%s</a></td><td>%s</td></tr>\n", tolower($1), $1, $2, esc($3), esc($4)}' "$FINDINGS"
        done
        echo '</table>'
    else
        echo '<p>No warnings or failures were recorded.</p>'
    fi
    echo '</div></div>'
    echo '<div class="box"><h2>Contents</h2><div class="in"><ol class="toc">'
    while IFS=$'\t' read -r num title; do
        printf '<li><a href="#s%s">%s</a>%s</li>\n' "$num" "$(html_esc <<<"$title")" \
            "$(awk -F'\t' -v n="$num" '$2 == n && $1 == "FAIL" {f++} $2 == n && $1 == "WARN" {w++}
                END {s = ""; if (f) s = s "<span class=\"cnt\" style=\"color:#b91c1c\">" f " fail</span>";
                     if (w) s = s "<span class=\"cnt\" style=\"color:#b45309\">" w " warn</span>"; printf "%s", s}' "$FINDINGS")"
    done < "$WORK/index.tsv"
    echo '</ol></div></div>'
    while IFS=$'\t' read -r num title; do
        printf '<div class="box" id="s%s"><h2>%d. %s</h2><div class="in"><pre>' "$num" "$((10#$num))" "$(html_esc <<<"$title")"
        color_lines < "$WORK/sec_$num.txt"
        echo '</pre></div></div>'
    done < "$WORK/index.tsv"
    cat <<EOF
<footer>Generated by server_audit_report.sh v$SCRIPT_VERSION on $(html_esc <<<"$HOST_FQDN") at $(html_esc <<<"$DATE_VALUE")<br>
Read-only audit - no configuration changes were made.</footer>
</div>
</body>
</html>
EOF
    } > "$out"
}

###############################################################################
# RENDERING: WORD (.docx via python3, no extra modules required)
###############################################################################

write_docx_builder() {
cat > "$WORK/mkdocx.py" <<'PY'
import os, re, sys, zipfile
from xml.sax.saxutils import escape

work, out = sys.argv[1], sys.argv[2]
CTRL = re.compile(u'[\x00-\x08\x0b\x0c\x0e-\x1f]')
TAG = re.compile(r'^\[(PASS|WARN|FAIL|INFO|SKIP)\]')
COL = {'PASS': '15803D', 'WARN': 'B45309', 'FAIL': 'B91C1C', 'INFO': '1D4ED8', 'SKIP': '64748B'}
W = 'xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"'

def rd(name):
    with open(os.path.join(work, name), 'rb') as f:
        return f.read().decode('utf-8', 'replace')

def X(s):
    return escape(CTRL.sub('', s))

def run(text, b=False, color=None, sz=None):
    p = ''
    if b: p += '<w:b/>'
    if color: p += '<w:color w:val="%s"/>' % color
    if sz: p += '<w:sz w:val="%d"/><w:szCs w:val="%d"/>' % (sz, sz)
    return '<w:r>%s<w:t xml:space="preserve">%s</w:t></w:r>' % ('<w:rPr>%s</w:rPr>' % p if p else '', X(text))

def para(runs='', style=None, extra=''):
    ppr = ('<w:pStyle w:val="%s"/>' % style if style else '') + extra
    return '<w:p>%s%s</w:p>' % ('<w:pPr>%s</w:pPr>' % ppr if ppr else '', runs)

BORD = ''.join('<w:%s w:val="single" w:sz="4" w:space="0" w:color="CBD5E1"/>' % e
               for e in ('top', 'left', 'bottom', 'right', 'insideH', 'insideV'))

def table(rows, widths, head=True):
    o = ['<w:tbl><w:tblPr><w:tblW w:w="%d" w:type="dxa"/><w:tblBorders>%s</w:tblBorders>'
         '<w:tblLayout w:type="fixed"/><w:tblCellMar><w:left w:w="80" w:type="dxa"/>'
         '<w:right w:w="80" w:type="dxa"/></w:tblCellMar></w:tblPr><w:tblGrid>' % (sum(widths), BORD)]
    o += ['<w:gridCol w:w="%d"/>' % w for w in widths]
    o.append('</w:tblGrid>')
    for i, row in enumerate(rows):
        hdr = head and i == 0
        o.append('<w:tr>' + ('<w:trPr><w:tblHeader/></w:trPr>' if hdr else ''))
        for j, cell in enumerate(row):
            text, color = cell if isinstance(cell, tuple) else (cell, None)
            shd = '<w:shd w:val="clear" w:color="auto" w:fill="E2E8F0"/>' if hdr else ''
            o.append('<w:tc><w:tcPr><w:tcW w:w="%d" w:type="dxa"/>%s</w:tcPr>%s</w:tc>' % (
                widths[j], shd,
                para(run(text, b=hdr or bool(color), color=color, sz=18), extra='<w:spacing w:after="0"/>')))
        o.append('</w:tr>')
    o.append('</w:tbl>')
    return ''.join(o)

meta = [l.split('\t', 1) for l in rd('meta.tsv').splitlines() if '\t' in l]
index = [l.split('\t', 1) for l in rd('index.tsv').splitlines() if '\t' in l]
finds = [l.split('\t', 3) for l in rd('findings.tsv').splitlines() if l.count('\t') >= 3]
host = dict(meta).get('Hostname', '')

body = [para(run('Server Security & Load Audit Report'), 'Title'),
        table([[k, v] for k, v in meta], [3200, 12000], head=False),
        para(run('Summary'), 'Heading1')]
cnt = dict((k, sum(1 for f in finds if f[0] == k)) for k in ('FAIL', 'WARN', 'PASS'))
body.append(table([['Result', 'Count'],
                   [('FAIL', COL['FAIL']), str(cnt['FAIL'])],
                   [('WARN', COL['WARN']), str(cnt['WARN'])],
                   [('PASS', COL['PASS']), str(cnt['PASS'])]], [3200, 2000]))
body.append(para(run('Findings requiring attention'), 'Heading2'))
issues = [f for f in finds if f[0] == 'FAIL'] + [f for f in finds if f[0] == 'WARN']
if issues:
    body.append(table([['Level', 'Section', 'Finding']] +
                      [[(f[0], COL[f[0]]), f[2], f[3]] for f in issues], [1100, 3800, 10300]))
else:
    body.append(para(run('No warnings or failures were recorded.')))

for num, title in index:
    body.append(para(run('%d. %s' % (int(num, 10), title)), 'Heading1'))
    for line in rd('sec_%s.txt' % num).splitlines():
        line = line.expandtabs(8)
        m = TAG.match(line)
        if m:
            body.append(para(run(line, b=True, color=COL[m.group(1)]), 'Code'))
        elif line.startswith('--- ') and line.endswith(' ---'):
            body.append(para(run(line[4:-4], b=True, color='1E3A8A'), 'CodeHead'))
        else:
            body.append(para(run(line) if line else '', 'Code'))
body.append(para(run('Read-only audit - no configuration changes were made.', color='64748B')))

document = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:document %s><w:body>%s'
            '<w:sectPr><w:footerReference w:type="default" r:id="rId2"/>'
            '<w:pgSz w:w="16838" w:h="11906" w:orient="landscape"/>'
            '<w:pgMar w:top="720" w:right="720" w:bottom="720" w:left="720" w:header="360" w:footer="360" w:gutter="0"/>'
            '</w:sectPr></w:body></w:document>') % (W, ''.join(body))

styles = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:styles %s>'
  '<w:docDefaults><w:rPrDefault><w:rPr><w:rFonts w:ascii="Calibri" w:hAnsi="Calibri" w:cs="Calibri"/>'
  '<w:sz w:val="20"/><w:szCs w:val="20"/></w:rPr></w:rPrDefault>'
  '<w:pPrDefault><w:pPr><w:spacing w:after="80"/></w:pPr></w:pPrDefault></w:docDefaults>'
  '<w:style w:type="paragraph" w:default="1" w:styleId="Normal"><w:name w:val="Normal"/></w:style>'
  '<w:style w:type="paragraph" w:styleId="Title"><w:name w:val="Title"/><w:basedOn w:val="Normal"/>'
  '<w:pPr><w:spacing w:after="160"/></w:pPr><w:rPr><w:b/><w:color w:val="0F172A"/><w:sz w:val="40"/><w:szCs w:val="40"/></w:rPr></w:style>'
  '<w:style w:type="paragraph" w:styleId="Heading1"><w:name w:val="heading 1"/><w:basedOn w:val="Normal"/><w:next w:val="Normal"/>'
  '<w:pPr><w:keepNext/><w:pBdr><w:bottom w:val="single" w:sz="8" w:space="2" w:color="1E3A8A"/></w:pBdr>'
  '<w:spacing w:before="320" w:after="120"/><w:outlineLvl w:val="0"/></w:pPr>'
  '<w:rPr><w:b/><w:color w:val="1E3A8A"/><w:sz w:val="28"/><w:szCs w:val="28"/></w:rPr></w:style>'
  '<w:style w:type="paragraph" w:styleId="Heading2"><w:name w:val="heading 2"/><w:basedOn w:val="Normal"/><w:next w:val="Normal"/>'
  '<w:pPr><w:keepNext/><w:spacing w:before="240" w:after="80"/><w:outlineLvl w:val="1"/></w:pPr>'
  '<w:rPr><w:b/><w:color w:val="0F172A"/><w:sz w:val="24"/><w:szCs w:val="24"/></w:rPr></w:style>'
  '<w:style w:type="paragraph" w:styleId="Code"><w:name w:val="Code"/><w:basedOn w:val="Normal"/>'
  '<w:pPr><w:shd w:val="clear" w:color="auto" w:fill="F8FAFC"/><w:spacing w:after="0" w:line="240" w:lineRule="auto"/></w:pPr>'
  '<w:rPr><w:rFonts w:ascii="Consolas" w:hAnsi="Consolas" w:cs="Consolas"/><w:sz w:val="15"/><w:szCs w:val="15"/></w:rPr></w:style>'
  '<w:style w:type="paragraph" w:styleId="CodeHead"><w:name w:val="Code Heading"/><w:basedOn w:val="Code"/><w:next w:val="Code"/>'
  '<w:pPr><w:keepNext/><w:spacing w:before="120" w:after="20"/></w:pPr><w:rPr><w:sz w:val="17"/><w:szCs w:val="17"/></w:rPr></w:style>'
  '</w:styles>') % W

footer = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:ftr %s><w:p><w:pPr><w:jc w:val="center"/></w:pPr>'
          '%s<w:r><w:fldChar w:fldCharType="begin"/></w:r><w:r><w:instrText xml:space="preserve"> PAGE </w:instrText></w:r>'
          '<w:r><w:fldChar w:fldCharType="separate"/></w:r><w:r><w:t>1</w:t></w:r><w:r><w:fldChar w:fldCharType="end"/></w:r>'
          '</w:p></w:ftr>') % (W, run('%s  |  Server Audit  |  Page ' % host, color='64748B', sz=16))

ctypes = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
  '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
  '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
  '<Default Extension="xml" ContentType="application/xml"/>'
  '<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
  '<Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/>'
  '<Override PartName="/word/footer1.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.footer+xml"/>'
  '</Types>')
rels = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
  '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
  '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>'
  '</Relationships>')
docrels = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
  '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
  '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>'
  '<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/footer" Target="footer1.xml"/>'
  '</Relationships>')

with zipfile.ZipFile(out, 'w', zipfile.ZIP_DEFLATED) as z:
    z.writestr('[Content_Types].xml', ctypes)
    z.writestr('_rels/.rels', rels)
    z.writestr('word/_rels/document.xml.rels', docrels)
    z.writestr('word/document.xml', document)
    z.writestr('word/styles.xml', styles)
    z.writestr('word/footer1.xml', footer)
PY
}

render_word() {
    local base="$1" py=""
    for p in python3 /usr/libexec/platform-python /usr/bin/python3; do
        if command -v "$p" >/dev/null 2>&1 || [ -x "$p" ]; then py=$p; break; fi
    done
    if [ -n "$py" ]; then
        write_docx_builder
        if "$py" "$WORK/mkdocx.py" "$WORK" "$base.docx" 2>"$WORK/mkdocx.err"; then
            WORD_REPORT="$base.docx"
            return
        fi
        echo "WARNING: .docx build failed ($(head -n1 "$WORK/mkdocx.err")) - writing .doc instead" >&2
    fi
    # Fallback: Word opens HTML saved with a .doc extension
    cp "$HTML_REPORT" "$base.doc"
    WORD_REPORT="$base.doc"
}

###############################################################################
# SECTION RUNNER
###############################################################################

SECTIONS=(
    "Server & OS Baseline|sec_baseline"
    "System Load & Memory|sec_load"
    "Storage, Disk I/O & /tmp|sec_storage"
    "Privileged Accounts|sec_users"
    "SSH Security|sec_ssh"
    "Authentication Logs|sec_auth"
    "Firewall & Network Configuration|sec_firewall"
    "Listening Ports & Services|sec_ports"
    "Network Connections / SYN-Flood Indicators|sec_conn"
    "Security Software (Imunify360 / BitNinja / ModSecurity)|sec_secsoft"
    "cPanel & WHM|sec_cpanel"
    "Web Servers (Apache / Nginx / LiteSpeed)|sec_web"
    "PHP & PHP-FPM|sec_php"
    "MySQL / MariaDB|sec_db"
    "CloudLinux LVE|sec_cloudlinux"
    "Email (Exim / Dovecot)|sec_mail"
    "FTP|sec_ftp"
    "DNS (BIND / PowerDNS)|sec_dns"
    "Cron Jobs|sec_cron"
)

run_section() {
    local title="$1" fn="$2" file
    SEC_NO=$((SEC_NO + 1))
    CUR_NO=$(printf '%03d' "$SEC_NO")
    CUR_TITLE="$title"
    file="$WORK/sec_$CUR_NO.txt"
    printf '%s\t%s\n' "$CUR_NO" "$title" >> "$WORK/index.tsv"
    printf '  [%2d/%d] %s\n' "$SEC_NO" "${#SECTIONS[@]}" "$title" >&2
    "$fn" > "$file" 2>&1 < /dev/null
    sanitize "$file"
    grep -q . "$file" || echo "(no output)" > "$file"
}

###############################################################################
# MAIN
###############################################################################

if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: This script must be run as root."
    echo "Usage: sudo $0"
    exit 1
fi

mkdir -p "$REPORT_DIR" 2>/dev/null && chmod 700 "$REPORT_DIR" 2>/dev/null
if [ ! -d "$REPORT_DIR" ] || [ ! -w "$REPORT_DIR" ]; then
    echo "ERROR: Unable to create/write report directory: $REPORT_DIR"
    exit 1
fi

WORK=$(mktemp -d "$REPORT_DIR/.work.XXXXXX") || { echo "ERROR: cannot create temp directory"; exit 1; }
trap 'rm -rf "$WORK"' EXIT
trap 'exit 130' INT TERM
FINDINGS="$WORK/findings.tsv"
: > "$FINDINGS"; : > "$WORK/index.tsv"

# ---- Discovery (cached once, reused by every section) ----
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
DATE_VALUE=$(date '+%Y-%m-%d %H:%M:%S (UTC%:z)')
TODAY=$(date +%F)
SOON=$(date -d '+90 days' +%F 2>/dev/null || date +%F)
HOST_FQDN=$(hostname -f 2>/dev/null || hostname)
HOST_SHORT=$(hostname -s 2>/dev/null | tr -c 'A-Za-z0-9._-\n' '_')
HOST_SHORT=${HOST_SHORT:-server}
CPU_CORES=$(nproc 2>/dev/null || grep -c ^processor /proc/cpuinfo 2>/dev/null || echo "unknown")
OS_NAME=$( [ -r /etc/os-release ] && . /etc/os-release && echo "$PRETTY_NAME" )
OS_NAME=${OS_NAME:-$(uname -s)}
PRIMARY_IP=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for (i = 1; i <= NF; i++) if ($i == "src") {print $(i + 1); exit}}')
[ -z "$PRIMARY_IP" ] && PRIMARY_IP=$(hostname -I 2>/dev/null | awk '{print $1}')

UNITS=""
have systemctl && UNITS=$(systemctl list-unit-files --type=service --no-legend 2>/dev/null | awk '{print $1}')

SS_LISTEN=""; LISTEN_LOCAL=""
if have ss; then
    SS_LISTEN=$(ss -lntup 2>/dev/null)
    LISTEN_LOCAL=$(awk 'NR > 1 {print $5}' <<<"$SS_LISTEN")
elif have netstat; then
    LISTEN_LOCAL=$(netstat -lntu 2>/dev/null | awk 'NR > 2 {print $4}')
fi

APACHE_CTL=""
if   have httpd;      then APACHE_CTL=httpd
elif have apache2ctl; then APACHE_CTL=apache2ctl
fi
APACHE_CONF_DIR=""
for d in /etc/apache2 /etc/httpd /usr/local/apache/conf; do
    [ -d "$d" ] && { APACHE_CONF_DIR=$d; break; }
done

CPANEL_VER=""
[ -x /usr/local/cpanel/cpanel ] && CPANEL_VER=$(/usr/local/cpanel/cpanel -V 2>/dev/null)

{
    printf 'Hostname\t%s\n' "$HOST_FQDN"
    printf 'Primary IP\t%s\n' "${PRIMARY_IP:-unknown}"
    printf 'Operating system\t%s\n' "$OS_NAME"
    printf 'Kernel\t%s\n' "$(uname -r)"
    printf 'CPU cores\t%s\n' "$CPU_CORES"
    [ -n "$CPANEL_VER" ] && printf 'cPanel & WHM\t%s\n' "$CPANEL_VER"
    [ -f /etc/cloudlinux-release ] && printf 'CloudLinux\t%s\n' "$(head -n1 /etc/cloudlinux-release)"
    printf 'Generated\t%s\n' "$DATE_VALUE"
    printf 'Report type\t%s\n' "Read-only security audit + load report (v$SCRIPT_VERSION)"
} > "$WORK/meta.tsv"

echo "============================================================"
echo " Server Security & Load Audit - $HOST_FQDN"
echo "============================================================"

SEC_NO=0
for s in "${SECTIONS[@]}"; do
    run_section "${s%%|*}" "${s##*|}"
done

BASE="$REPORT_DIR/${HOST_SHORT}_audit_${TIMESTAMP}"
HTML_REPORT="$BASE.html"
WORD_REPORT=""

echo "  Building HTML report..." >&2
render_html "$HTML_REPORT"
echo "  Building Word report..." >&2
render_word "$BASE"
chmod 600 "$HTML_REPORT" "$WORD_REPORT" 2>/dev/null

# ---- Optional: publish HTML in the Apache docroot (off by default) ----
REPORT_URL=""
if [ "$PUBLISH_WEB" = "1" ]; then
    if [ -d "$WEB_DOCROOT" ]; then
        TOKEN=$(head -c 12 /dev/urandom 2>/dev/null | od -An -tx1 | tr -d ' \n')
        WEB_FILE="$WEB_DOCROOT/audit_${TIMESTAMP}_${TOKEN:-$RANDOM}.html"
        if cp "$HTML_REPORT" "$WEB_FILE" 2>/dev/null; then
            chmod 644 "$WEB_FILE"
            PUB_IP=""
            have curl && PUB_IP=$(curl -4 -s --max-time 3 https://api.ipify.org 2>/dev/null)
            [[ "$PUB_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || PUB_IP=${PRIMARY_IP:-SERVER-IP}
            REPORT_URL="http://${PUB_IP}/$(basename "$WEB_FILE")"
        else
            echo "WARNING: unable to copy the HTML report to $WEB_DOCROOT" >&2
        fi
    else
        echo "WARNING: web docroot $WEB_DOCROOT does not exist - not published" >&2
    fi
fi

NF=$(grep -c '^FAIL' "$FINDINGS"); NW=$(grep -c '^WARN' "$FINDINGS"); NP=$(grep -c '^PASS' "$FINDINGS")

echo
echo "============================================================"
echo " REPORT COMPLETED"
echo "============================================================"
echo " Failed: $NF    Warnings: $NW    Passed: $NP"
echo
echo " HTML report : $HTML_REPORT"
echo " Word report : $WORD_REPORT"
if [ -n "$REPORT_URL" ]; then
    echo " Web copy    : $REPORT_URL"
    echo "               (publicly reachable - delete it once downloaded)"
fi
echo "============================================================"

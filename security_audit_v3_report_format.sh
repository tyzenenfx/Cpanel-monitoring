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
export PATH="$PATH:/usr/sbin:/sbin:/usr/local/sbin:/usr/local/bin"
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
declare -A SEC_CK=()
SEC_HTML=(); SEC_NAV=(); SEC_RANK=()

sec_open() { SEC_ID=$1; SEC_TITLE=$2; SEC_BUF=""; SEC_WORST=0; SEC_BADGE=""; SEC_CK=([FAIL]="" [WARN]="" [INFO]="" [PASS]="" [SKIP]=""); SEC_C=([FAIL]=0 [WARN]=0 [PASS]=0 [INFO]=0 [SKIP]=0); say "$2"; }
sevtxt() { case $1 in SKIP) echo SKIPPED;; *) echo "$1";; esac; }
sec_close() {
  local cls=SKIP o="" lbl r ck="" rank body sub chips="" f w p i sk sclass="" tb=""
  case $SEC_WORST in 4) cls=FAIL;; 3) cls=WARN;; 2) cls=PASS;; 1) cls=INFO;; esac
  [ "$SEC_WORST" -ge 1 ] && o=" open"
  rank=$SEC_WORST
  lbl=$(sevtxt $cls); [ -n "${SEC_BADGE:-}" ] && { cls=INFO; lbl=$SEC_BADGE; rank=1; o=" open"; }
  f=${SEC_C[FAIL]}; w=${SEC_C[WARN]}; p=${SEC_C[PASS]}; i=${SEC_C[INFO]}; sk=${SEC_C[SKIP]}
  [ "$SEC_WORST" -eq 0 ] && [ -z "${SEC_BADGE:-}" ] && sclass=" sk"
  [ "$f" -gt 0 ] && chips+="<span class=\"cn FAIL\" title=\"$f FAIL\">$f FAIL</span>"
  [ "$w" -gt 0 ] && chips+="<span class=\"cn WARN\" title=\"$w WARN\">$w WARN</span>"
  [ "$p" -gt 0 ] && chips+="<span class=\"cn PASS\" title=\"$p PASS\">$p PASS</span>"
  [ "$i" -gt 0 ] && chips+="<span class=\"cn INFO\" title=\"$i INFO\">$i INFO</span>"
  for r in FAIL WARN INFO PASS SKIP; do ck+="${SEC_CK[$r]}"; done      # most severe first
  [ -n "$ck" ] && tb="<table class=\"ct\"><thead><tr><th style=\"width:22%\">Check</th><th style=\"width:11%\">Status</th><th style=\"width:33%\">Current State</th><th>Recommendation</th></tr></thead><tbody>$ck</tbody></table>"
  body="$tb$SEC_BUF"
  SEC_HTML+=("<section id=\"$SEC_ID\" class=\"section sec $cls$sclass\" data-title=\"$(hesc "$SEC_TITLE")\" data-f=\"$f\" data-w=\"$w\" data-p=\"$p\" data-i=\"$i\" data-s=\"$sk\"><details$o><summary><h2><span class=\"sn\">@@N@@</span> $(hesc "$SEC_TITLE")</h2><span class=\"chips2\">$chips</span><button type=\"button\" class=\"rm\" title=\"Remove this section from the report\" aria-label=\"Remove section: $(hesc "$SEC_TITLE")\" onclick=\"rmSec('$SEC_ID',event)\">&#10005; Remove</button></summary><div class=\"sbody\">$body</div></details></section>")
  SEC_NAV+=("<label class=\"pi\" data-id=\"$SEC_ID\"><input type=\"checkbox\" checked onchange=\"tog('$SEC_ID',this.checked)\"><i class=\"dot $cls\"></i><span class=\"nt\">$(hesc "$SEC_TITLE")</span><span class=\"nchips\">$chips</span></label>")
  SEC_RANK+=("$rank")
}

# reco SEV label  -> recommendation text (shown in the Recommendation column)
reco() {
  local sev=$1 l=${2,,} K="" R="" I=""
  case $l in
    "not running as root"*) R="Re-run the audit as root (sudo) so that all checks can be completed.";;
    "systemd not detected"*) I="No action needed unless a service is missing from the table below.";;
    "no web server detected"*) I="Not applicable unless this host should serve web content.";;
    *"is installed but not running"*|*"service ("*") is "*) R="Start the service if it is required (systemctl status/restart), or remove it if it is unused.";;
    *"expected port not listening"*) R="Check the service configuration and bind address, and confirm the expected port is listening.";;
    "service state table"*|"at least one web server"*|"web server installed"*) K="Keep the web server running and monitored."; R="Start the web server and review its error log.";;
    "os / kernel"*) I="Keep the operating system supported and fully patched; update the kernel regularly.";;
    "uptime"*) I="Reboot during a maintenance window after kernel updates.";;
    "dns resolvers"*|*"has no nameservers"*) I="Use reliable resolvers and confirm they are reachable.";;
    "/tmp does not exist"*) R="Create /tmp with mode 1777.";;
    "/tmp permissions"*) I="/tmp should be mode 1777 (sticky bit).";;
    "/tmp"*) K="Keep /tmp mounted with noexec,nosuid,nodev."; R="Mount /tmp as a dedicated filesystem (cPanel securetmp) with noexec,nosuid,nodev.";;
    "load average"*) K="Monitor load trends."; R="Identify heavy processes/accounts (see Top processes) and limit resources or add capacity.";;
    "memory available"*) K="Monitor memory use."; R="Review memory-heavy processes, tune PHP-FPM/MySQL or add RAM.";;
    "swap usage"*) K="Monitor swap use."; R="Investigate memory pressure; sustained swapping degrades performance.";;
    "no swap"*) I="Consider adding swap as a safety buffer if memory is tight.";;
    "disk/inode"*) R="Free space or inodes (logs, old backups, unused accounts) or expand storage before it fills.";;
    "iostat"*) I="Install sysstat if disk I/O statistics are required.";;
    "cloudlinux"*|"lve"*) I="Review faulting accounts and adjust LVE limits if required.";;
    "only root has uid 0"*) K="Keep root as the only UID 0 account.";;
    "additional uid 0"*) R="Investigate and remove any non-root UID 0 account immediately.";;
    "sudo users"*|"wheel/sudo"*) I="Review privileged group membership and remove users who do not require it.";;
    "no accounts have shell"*) K="Keep shell access disabled for accounts that do not need it.";;
    "shell access enabled"*) R="Disable shell access (or use a jailed shell) for accounts that do not need SSH/terminal access."; I="Confirm each user needs shell access.";;
    *"authorized_keys"*) K="Keep root and account SSH keys under review."; I="Confirm each key is authorized and remove unknown or unused keys.";;
    "active cron"*) I="Review scheduled jobs periodically.";;
    "cron entries matching"*) R="Review the listed cron entries and remove anything not recognised.";;
    "no suspicious cron"*) K="Keep reviewing cron jobs periodically.";;
    "cron files writable"*) R="Remove group/other write permission from the listed cron files (chmod go-w).";;
    "cron files not"*) K="Keep cron files restricted to root.";;
    "sshd_config present"*) K="Keep the SSH configuration under change control.";;
    "/etc/ssh/sshd_config not found"*) R="Verify the SSH server configuration path.";;
    "effective config unavailable"*) R="Run the audit as root so that sshd -T can report the effective configuration.";;
    "permitrootlogin"*) K="Keep direct root SSH login disabled."; R="Disable direct root login (PermitRootLogin no) after confirming an administrative account with sudo access."; I="Prefer PermitRootLogin no once an alternate admin account exists.";;
    "passwordauthentication"*) K="Keep password-based SSH logins disabled."; R="After confirming key access works for all administrators, set PasswordAuthentication no.";;
    "permitemptypasswords"*) K="Keep empty passwords disallowed."; R="Set PermitEmptyPasswords no.";;
    "pubkeyauthentication"*) K="Keep SSH public-key authentication enabled."; R="Enable PubkeyAuthentication yes.";;
    "maxauthtries"*) K="Keep MaxAuthTries at 4 or lower."; R="Set MaxAuthTries to 3-4.";;
    "logingracetime"*) I="Consider LoginGraceTime 30-60 seconds.";;
    "ssh on default port"*) I="Consider a non-default SSH port and restrict access by firewall allow-list.";;
    "x11forwarding source"*) I="sshd -T was unavailable; run as root for the effective value.";;
    "x11forwarding"*) K="Keep X11Forwarding disabled."; R="Set X11Forwarding no in /etc/ssh/sshd_config (and sshd_config.d drop-ins), then reload sshd."; I="Set X11Forwarding no explicitly; distribution drop-ins can override the OpenSSH default.";;
    "allowtcpforwarding"*) K="Keep TCP forwarding disabled."; I="Set AllowTcpForwarding no if tunnelling is not required.";;
    "allowusers"*|"no allowusers"*) K="Keep SSH logins restricted to approved users/groups."; I="Restrict SSH logins with AllowUsers or AllowGroups.";;
    "weak ssh"*) R="Remove legacy ciphers/MACs/key-exchange algorithms from sshd_config.";;
    "ssh ciphers"*|"ssh macs"*|"ssh key exchange"*) K="Keep only modern SSH algorithms enabled.";;
    "high failed-authentication"*|"failed authentication"*) R="Review the source IPs and make sure CSF/LFD or cPHulk blocks repeated failures."; I="Review failed attempts for patterns.";;
    "no failed authentication"*) K="Keep brute-force protection active.";;
    "successful ssh logins"*|"root ssh login activity"*|"source"*) I="Confirm all logins are expected.";;
    "no authentication log"*) I="Enable authentication logging (rsyslog/journald).";;
    "csf is in testing"*) R="Set TESTING = 0 in /etc/csf/csf.conf and restart CSF.";;
    "csf/lfd active"*|"csf installed"*) K="Keep CSF/LFD enabled and updated."; R="Start and enable CSF and LFD (csf -e; systemctl enable --now lfd).";;
    *"sensitive ports allowed"*) R="Remove database/cache ports from TCP_IN in CSF.";;
    "no database/cache ports"*) K="Keep database/cache ports closed to the Internet.";;
    "firewalld"*) K="Keep the firewall enabled."; I="Enable firewalld or another host firewall if none is active.";;
    "no firewall rules"*|"no firewall tooling"*|"no nftables"*) R="Enable a host firewall (CSF, firewalld or nftables) with a default-deny inbound policy.";;
    "unmanaged iptables"*|"nftables ruleset present"*) I="Confirm the rules are managed by an approved tool.";;
    *"listening on all interfaces"*) R="Bind the service to 127.0.0.1 or restrict the port with the firewall.";;
    "udp/53 listening"*) I="Confirm the DNS listener is expected.";;
    "ipv4 forwarding"*|"ipv6 forwarding"*) K="Keep IP forwarding disabled."; I="Keep forwarding disabled unless the host is a router, VPN or container host.";;
    "inbound ddos"*) K="Keep SYN cookies and CSF SYNFLOOD protection enabled."; R="Inspect sources (ss -tan state syn-recv), enable SYN cookies/rate limits in CSF and engage the network team if the attack is sustained."; I="Monitor connection rate and source distribution.";;
    "outbound ddos"*) K="Keep outbound SMTP/firewall restrictions enabled."; R="Look for compromised accounts or scripts making outbound connections (ss -tanp state syn-sent) and review SMTP restrictions."; I="Monitor outbound connection attempts.";;
    "established-class"*) I="Compare with normal traffic baselines.";;
    "single ip has"*) R="Review the top source IPs and block abusive addresses in CSF.";;
    *"imunify"*) K="Keep Imunify running, licensed and updated."; R="Check the service (systemctl status), licence and logs, then restart it."; I="Imunify AV provides scanning only; consider Imunify360 for firewall/WAF.";;
    *"bitninja"*) K="Keep BitNinja running and updated."; R="Start the BitNinja service and check its licence.";;
    "no host-level malware"*) I="Rely on CSF/LFD and ModSecurity, or install Imunify360/BitNinja.";;
    "apache version"*) I="Keep Apache updated to a supported release.";;
    "apache configuration"*) K="Run apachectl -t before every Apache change."; R="Fix the Apache configuration errors before the next restart.";;
    *"directory listing"*|*"options indexes"*) K="Keep directory listing disabled."; R="Remove Options Indexes from the global Apache configuration.";;
    "servertokens"*) K="Keep Apache version disclosure restricted."; R="Set ServerTokens Prod.";;
    "serversignature"*) K="Keep ServerSignature disabled."; R="Set ServerSignature Off.";;
    "traceenable"*) K="Keep HTTP TRACE disabled."; R="Set TraceEnable Off.";;
    "security headers"*|"no global"*) K="Keep security headers configured."; I="Add X-Frame-Options, X-Content-Type-Options and HSTS where applicable (may be set per site).";;
    "key apache modules"*) I="Review loaded modules and disable unused ones.";;
    "mod_status"*) I="Restrict /server-status and /server-info to localhost.";;
    "modsecurity module"*|"modsecurity ("*) K="Keep ModSecurity enabled and maintain an updated ruleset."; R="Install and enable ModSecurity with a maintained rule set.";;
    "secruleengine"*) K="Keep SecRuleEngine On."; R="Set SecRuleEngine On so that rules block attacks, not only log them.";;
    "modsecurity vendor"*|"modsecurity audit"*|"no modsec_vendor"*) I="Keep vendor rule sets updated.";;
    *"owasp"*|*"waf rules"*) K="Keep the rule set updated."; I="Enable the OWASP ModSecurity rule set.";;
    "nginx"*|"server_tokens"*|*"autoindex"*) K="Keep Nginx hardened and updated."; R="Review the Nginx configuration (nginx -t, server_tokens off, autoindex off).";;
    "litespeed"*) I="Keep LiteSpeed updated.";;
    "alt-php"*|"cloudlinux present"*) I="Review installed Alt-PHP versions and remove unsupported ones.";;
    *" php "[0-9]*) R="Upgrade to a supported PHP version and retire end-of-life versions.";;
    *"allow_url_include"*) R="Set allow_url_include = Off.";;
    *"expose_php"*) R="Set expose_php = Off.";;
    *"display_errors"*) R="Set display_errors = Off in production.";;
    *"enable_dl"*) R="Set enable_dl = Off.";;
    *"disable_functions is empty"*) R="Disable command-execution functions: exec, system, shell_exec, passthru, popen, proc_open.";;
    *"command-execution functions not disabled"*|*"command-exec functions not disabled"*|*"missing command-exec"*|*"override with a list missing"*|*"system pool defaults"*) R="Add the missing command-execution functions to disable_functions (php.ini and FPM pool/YAML overrides).";;
    *"all command-execution functions disabled"*|*"inherit disable_functions"*|*"keep command-exec"*|*"pool defaults disable"*) K="Review the disabled-function list periodically.";;
    *"hardening functions not disabled"*) I="Consider also disabling the listed functions if applications do not need them.";;
    *"override disable_functions"*|*"php_value[disable_functions]"*|*"per-domain fpm yaml"*) I="Confirm pool-level overrides are intentional and not weaker than the global list.";;
    *"fpm socket mode"*) R="Set listen.mode to 0660 (not 0666) in the pool configuration.";;
    *"php-fpm -t"*) K="Keep validating FPM configuration before reloads."; R="Fix the php-fpm configuration errors.";;
    *"pool saturation"*|*"max_children"*) K="Keep monitoring FPM pool usage."; R="Raise pm.max_children if memory allows, or optimise slow scripts.";;
    "php-fpm"*|*" fpm pools"*) I="Review pool configuration and keep PHP-FPM versions supported.";;
    *"no php-fpm pool"*) I="Handler uses the global php.ini values.";;
    "database listening"*|"database bound"*) K="Keep the database bound to localhost."; R="Set bind-address=127.0.0.1 or restrict port 3306 with the firewall.";;
    "database service"*|"cannot authenticate"*|"no mysql/mariadb client"*) R="Start the database service or provide root socket/credentials so live checks can run.";;
    "no anonymous db"*|"anonymous db"*) K="Keep anonymous database users removed."; R="Remove anonymous MySQL users.";;
    "remote-capable root"*) R="Restrict root to localhost.";;
    "connection headroom"*) K="Monitor max_used_connections."; R="Increase max_connections or optimise application connection use.";;
    "slow query"*|"dumpslow"*) I="Enable the slow query log temporarily when tuning is needed.";;
    "server version"*|"bind_address"*) I="Keep MySQL/MariaDB on a supported release.";;
    "exim queue"*) K="Keep monitoring the mail queue."; R="Inspect the queue (exim -bp), find spamming accounts/scripts and clear frozen messages."; I="Check senders if the queue keeps growing.";;
    "exim version"*) I="Keep Exim updated.";;
    "open-relay"*|"could not confirm relay"*) K="Keep relay protection enabled."; R="Review acl_check_rcpt to confirm the server is not an open relay.";;
    "smtp authenticators"*|"no smtp authenticators"*) K="Keep SMTP authentication enabled."; R="Configure SMTP authenticators for submission.";;
    "submission port"*) K="Keep submission ports (465/587) available for authenticated mail."; I="Confirm the submission port is expected to be closed.";;
    "dovecot"*) K="Keep Dovecot TLS enforced with modern protocols."; R="Require TLS and set ssl_min_protocol = TLSv1.2; disable cleartext authentication without TLS.";;
    "pure-ftpd anonymous"*|"proftpd <anonymous>"*|"vsftpd anonymous"*|"no proftpd anonymous"*) K="Keep anonymous FTP disabled."; R="Disable anonymous FTP access.";;
    "pure-ftpd tls"*|"proftpd tls"*|"vsftpd tls"*) K="Keep FTP TLS required."; R="Enable and require TLS for FTP."; I="Require TLS (TLSCipherSuite/ssl_enable) instead of optional.";;
    "ftp service"*|"ftp installed"*|"ftp port"*) I="Prefer SFTP and disable FTP if it is not required.";;
    "dns recursion"*) K="Keep recursion disabled for external clients."; R="Restrict recursion to local/trusted networks.";;
    "open dns resolver"*) R="Restrict allow-recursion to trusted networks.";;
    "zone transfers"*|"no allow-transfer"*|"zone transfer"*) K="Keep zone transfers restricted to secondaries."; R="Restrict allow-transfer to secondary DNS servers.";;
    "dns service"*|"no explicit recursion"*|"bind config tools"*|"dns recursion restricted"*) I="Confirm recursion/transfers are restricted for your DNS software.";;
    "cpanel version"*|"cpanel release tier"*) I="Keep cPanel & WHM on a supported release tier.";;
    "cpanel automatic updates"*) K="Keep automatic cPanel updates enabled."; R="Set UPDATES=daily in /etc/cpupdate.conf.";;
    "cpanel update log"*|"cpanel last update"*) K="Keep updates running regularly."; R="Run /scripts/upcp and investigate why updates are not running.";;
    "cpanel update currently"*) I="Wait for the update to finish before maintenance.";;
    "whm terminal"*) K="Keep WHM Terminal disabled unless browser-based root access is required."; R="Disable WHM Terminal if not required (touch /var/cpanel/disable_whm_terminal_ui).";;
    "whm two-factor"*|"whm 2fa"*|"root account"*|"no cpanel account has 2fa"*|"cpanel accounts with 2fa"*|"2fa check capped"*) K="Keep two-factor authentication enabled."; R="Enable two-factor authentication in WHM >> Security Center >> Two-Factor Authentication."; I="Encourage 2FA for all accounts.";;
    "whmapi1"*) I="Run on a cPanel server with whmapi1 available to include 2FA checks.";;
    "cpanel not installed"*|*"not installed"*|*"not detected"*|*"not present"*) I="Not applicable on this server.";;
  esac
  case $sev in
    PASS) printf '%s' "${K:-No action required. Keep the current configuration.}";;
    INFO) printf '%s' "${I:-${K:-${R:-Informational. Confirm this is expected.}}}";;
    SKIP) printf '%s' "Not applicable or could not be checked on this server - see Current State.";;
    WARN) printf '%s' "${R:-Review this item and remediate if it is not intentional.}";;
    FAIL) printf '%s' "${R:-Remediate promptly.}";;
  esac
}

# chk SEVERITY label [detail] [meter-percent] [meter-caption] [recommendation]
chk() {
  local sev=$1 label=$2 detail=${3:-} pct=${4:-} cap=${5:-} rec=${6:-} flat cls
  SEV_COUNT[$sev]=$(( SEV_COUNT[$sev] + 1 )); SEC_C[$sev]=$(( SEC_C[$sev] + 1 ))
  [ "${SEV_RANK[$sev]}" -gt "$SEC_WORST" ] && SEC_WORST=${SEV_RANK[$sev]}
  [ -z "$rec" ] && rec=$(reco "$sev" "$label")
  case $sev in PASS) cls=pass;; WARN) cls=warn;; FAIL) cls=fail;; INFO) cls=info;; *) cls=skip;; esac
  SEC_CK[$sev]+="<tr class=\"r-$sev\"><td><strong>$(hesc "$label")</strong></td><td><span class=\"status status-$cls\">$(sevtxt $sev)</span></td><td class=\"current-state\">$(hesc "$detail")"
  if [ -n "$pct" ]; then
    [ "$pct" -gt 100 ] && pct=100
    SEC_CK[$sev]+="<div class=\"meter $sev\" role=\"img\" aria-label=\"$(hesc "$cap") $pct%\"><i style=\"width:$pct%\"></i></div><span class=\"mv\">$(hesc "$cap")</span>"
  fi
  SEC_CK[$sev]+="</td><td>$(hesc "$rec")</td></tr>"$'\n'
}
note() { SEC_BUF+="<p class=\"note\">$(hesc "$1")</p>"$'\n'; }
raw() { # title text
  local txt=$2; [ -z "$txt" ] && txt="(no output)"
  SEC_BUF+="<details class=\"raw\"><summary>$(hesc "$1")</summary><div class=\"term\"><div class=\"termbar\"><span class=\"tt\">$(hesc "$1")</span><button type=\"button\" class=\"copy\" aria-label=\"Copy output: $(hesc "$1")\">Copy</button></div><pre>$(hesc "$txt")</pre></div></details>"$'\n'
}
tbl() { # "h1<TAB>h2" "rows (tab separated)"
  [ -z "$2" ] && return 0
  SEC_BUF+="$(printf '%s\n%s\n' "$1" "$2" | awk -F'\t' '
    function e(s){gsub(/&/,"\\&amp;",s);gsub(/</,"\\&lt;",s);gsub(/>/,"\\&gt;",s);return s}
    function sc(c){ if(c=="PASS"||c=="UP")return "pass"; if(c=="WARN"||c=="DEGRADED"||c=="DOWN")return "warn"; if(c=="FAIL")return "fail"; if(c=="INFO")return "info"; return "skip"}
    NR==1{printf "<div class=\"tw\" tabindex=\"0\"><table class=\"dt\"><thead><tr>";for(i=1;i<=NF;i++){H[i]=$i;nc=NF;printf "<th scope=\"col\"%s>%s</th>",(H[i] ~ /%/?" class=\"num\"":""),e($i)}print "</tr></thead><tbody>";next}
    {printf "<tr>";for(i=1;i<=NF;i++){raw_=$i;c=e(raw_)
       if(c ~ /^(PASS|WARN|FAIL|INFO|SKIP|UP|DOWN|DEGRADED|ABSENT)$/){t=(c=="SKIP"?"SKIPPED":c);printf "<td><span class=\"status status-%s\">%s</span></td>",sc(c),t;continue}
       if(H[i] ~ /%/ && raw_ ~ /^[0-9]+(\.[0-9]+)?%?$/){v=raw_;sub(/%$/,"",v);v=v+0;w=(v>100?100:v)
          if(H[i] ~ /(Use|Inode)%/){m=(v>=95?"FAIL":(v>=85?"WARN":"PASS"))}else{m="N"}
          printf "<td class=\"num\"><div class=\"mt\"><b>%s</b><div class=\"meter %s\" role=\"img\" aria-label=\"%s\"><i style=\"width:%d%%\"></i></div></div></td>",c,m,c,w;continue}
       n=(raw_ ~ /^[0-9][0-9.,]*[%KMGTkmgt]?$/)?" class=\"num\"":""
       printf "<td%s>%s</td>",n,c}print "</tr>"}
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
SSHD_T=""; SSHD_SRC=effective
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
# Imunify products are identified by THEIR OWN systemd service; a shared CLI binary alone does not count
I360_BINS="imunify360-agent"; IMAV_BINS="imunify-antivirus"
[ $HAVE_SYSTEMD -eq 1 ] && { I360_BINS=""; IMAV_BINS=""; }
svc_detect i360     "Imunify360"          "imunify360"                           "$I360_BINS"                ""                   "" 0
svc_detect imav     "Imunify AV (antivirus)" "imunify-antivirus"                 "$IMAV_BINS"                ""                   "" 0
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
  LP=$(awk -v r="$RATIO" 'BEGIN{p=r*100;if(p>100)p=100;printf "%d",p}')
  chk $SEVL "Load average" "1m=$L1 5m=$L5 15m=$L15 on $CORES core(s) -> $RATIO per core" "$LP" "load per core $RATIO (bar full = 1.00 per core)"
fi
if [ -r /proc/meminfo ]; then
  MEMLINE=$(awk '/^MemTotal/{t=$2}/^MemAvailable/{a=$2}/^SwapTotal/{st=$2}/^SwapFree/{sf=$2}END{printf "%d %d %d %d", t/1024,a/1024,st/1024,sf/1024}' /proc/meminfo)
  read -r MT MA ST SF <<<"$MEMLINE"
  if [ "${MT:-0}" -gt 0 ]; then
    MP=$(( MA * 100 / MT )); SEVM=PASS; [ $MP -lt 20 ] && SEVM=WARN; [ $MP -lt 10 ] && SEVM=FAIL
    chk $SEVM "Memory available" "${MA}MB of ${MT}MB (${MP}%)" "$((100-MP))" "memory used $((100-MP))%"
    if [ "${ST:-0}" -gt 0 ]; then
      SU=$(( (ST-SF) * 100 / ST )); [ $SU -ge 50 ] && chk WARN "Swap usage high" "${SU}% of ${ST}MB used" "$SU" "swap used ${SU}%" || chk PASS "Swap usage" "${SU}% of ${ST}MB used" "$SU" "swap used ${SU}%"
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
    SSHD_SRC=file
    # file fallback: sshd_config + Include files (e.g. sshd_config.d/*.conf), global section only (stop at Match), first value wins
    SSHD_T=$( { for f in $(ls /etc/ssh/sshd_config.d/*.conf 2>/dev/null) /etc/ssh/sshd_config; do [ -r "$f" ] && cat "$f"; echo; done; } 2>/dev/null |
      awk 'tolower($1)=="match"{exit} /^[[:space:]]*(#|$)/{next} {k=tolower($1);$1="";sub(/^[[:space:]]+/,"");sub(/[[:space:]]+#.*$/,""); if(!(k in s)){s[k]=1;print k" "tolower($0)}}')
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
  v=$(sv x11forwarding | tr 'A-Z' 'a-z')
  case $v in
    yes) chk WARN "X11Forwarding yes" "Disable unless X11 apps are required (set X11Forwarding no in sshd_config / sshd_config.d)";;
    no)  chk PASS "X11Forwarding" "no";;
    "")  chk INFO "X11Forwarding not set" "OpenSSH default is no; verify with: sshd -T | grep -i x11forwarding";;
    *)   chk INFO "X11Forwarding" "$v";;
  esac
  [ "$SSHD_SRC" = file ] && chk INFO "X11Forwarding source" "Read from config files (sshd -T unavailable); Match-block overrides are not evaluated"
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
    if [ "$key" = imav ]; then
      LIC=$(t2 $cli show-license | head -n 20)
      printf '%s' "$LIC" | grep -qiE 'usage:|invalid choice|unrecognized|error' && LIC=$(t2 $cli rstatus | head -n 20)
      raw "$cli licence / registration status" "$LIC"
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

ORDER=$(for i in "${!SEC_RANK[@]}"; do [ "$i" -eq 0 ] && continue; printf '%s %s\n' "${SEC_RANK[$i]}" "$i"; done | sort -k1,1nr -k2,2n | awk '{print $2}')
SECTIONS=""; NAV=""; SN=0
for i in 0 $ORDER; do SN=$((SN+1)); SECTIONS+="${SEC_HTML[$i]/@@N@@/$SN.}"$'\n'; NAV+="${SEC_NAV[$i]}"; done

SCORE_TOTAL=$(( SEV_COUNT[PASS] + SEV_COUNT[WARN] + SEV_COUNT[FAIL] ))
[ $SCORE_TOTAL -eq 0 ] && SCORE_TOTAL=1
RUN_USER=$(id -un 2>/dev/null); [ $IS_ROOT -eq 1 ] || RUN_USER="$RUN_USER (non-root, partial results)"

IP=$(get_public_ip)
IP_NOTE=""; is_private_ip "$IP" && IP_NOTE=" (private - public IP could not be detected; use -i PUBLIC_IP)"
URL_SCHEME=http; [ -z "$(port_scope 80)" ] && [ -n "$(port_scope 443)" ] && URL_SCHEME=https
case $OUT_DIR in /usr/local/apache/htdocs|/var/www/html|/usr/share/nginx/html|/usr/local/lsws/DEFAULT/html) REPORT_URL="$URL_SCHEME://$IP/$FNAME";; *) REPORT_URL="";; esac
cpbtn() { printf '<button type="button" class="copy" data-copy="%s" aria-label="Copy %s">Copy</button>' "$(hesc "$1")" "$2"; }

{
cat <<HTML
<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow,noarchive">
<title>Security Audit - $(hesc "$HOST")</title>
<style>@page{margin:14mm 12mm;@top-left{content:"Server Security Audit - $SAFE_HOST";font-size:9pt;color:#666}@bottom-right{content:"Page " counter(page) " of " counter(pages);font-size:9pt;color:#666}}</style>
<style>
HTML
cat <<'CSS'
*{box-sizing:border-box}
body{font-family:Arial,Helvetica,sans-serif;background:#f4f6f8;margin:0;padding:0;color:#222;font-size:14px;line-height:1.45}
:focus-visible{outline:3px solid #2563eb;outline-offset:2px}
button{font:inherit}
.header{background:#1f2937;color:#fff;padding:25px}
.header h1{margin:0 0 8px 0}
.header .hm{display:flex;flex-wrap:wrap;gap:6px 28px;margin-top:6px;font-size:13.5px}
.header .hm div{min-width:0;overflow-wrap:anywhere}
.header .hm span{color:#cbd5e1}
.header .copy{margin-left:6px;background:#374151;color:#fff;border-color:#4b5563}
.container{padding:25px;max-width:1600px;margin:0 auto}
.summary{display:flex;flex-wrap:wrap;gap:15px;margin-bottom:25px}
.card{background:#fff;border-radius:8px;padding:18px;min-width:150px;box-shadow:0 2px 6px rgba(0,0,0,.08)}
.card h3{margin:0 0 8px 0}
.card div{font-size:26px;font-weight:700}
.pass-card{border-left:5px solid #16a34a}.warn-card{border-left:5px solid #f59e0b}.fail-card{border-left:5px solid #dc2626}.info-card{border-left:5px solid #2563eb}.skip-card{border-left:5px solid #9ca3af}
.tools{display:flex;gap:8px;flex-wrap:wrap;margin:0 0 20px;align-items:flex-start}
.tools button,.ckbar button,.copy,.rm{cursor:pointer;border:1px solid #cbd5e1;background:#fff;border-radius:6px;padding:7px 13px;min-height:34px;font-size:13px;font-weight:600;color:#1f2937}
.tools button:hover,.ckbar button:hover,.copy:hover{background:#eef2f7}
.tools button.primary{background:#1f2937;border-color:#1f2937;color:#fff}
.picker{background:#fff;border:1px solid #cbd5e1;border-radius:6px}
.picker>summary{cursor:pointer;padding:7px 13px;font-size:13px;font-weight:600;min-height:34px;list-style:none}
.picker>summary::-webkit-details-marker{display:none}
.picker>summary::after{content:" \25BE"}
.pgrid{padding:6px 10px 10px;display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:2px 16px;max-height:340px;overflow:auto;border-top:1px solid #e5e7eb}
.pi{display:flex;align-items:center;gap:8px;padding:5px 4px;font-size:13px;cursor:pointer;border-radius:4px}
.pi:hover{background:#f3f4f6}.pi.off .nt{text-decoration:line-through;opacity:.55}
.pi input{flex:none}
.nt{flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.dot{width:9px;height:9px;border-radius:50%;flex:none;background:#9ca3af}
.dot.FAIL{background:#dc2626}.dot.WARN{background:#f59e0b}.dot.PASS{background:#16a34a}.dot.INFO{background:#2563eb}
.nchips,.chips2{display:flex;gap:4px;flex:none}
.cn{font-size:10.5px;font-weight:700;padding:1px 7px;border-radius:99px;white-space:nowrap}
.cn.FAIL{background:#fee2e2;color:#991b1b}.cn.WARN{background:#fef3c7;color:#92400e}.cn.PASS{background:#dcfce7;color:#166534}.cn.INFO{background:#dbeafe;color:#1e40af}
.section{background:#fff;margin-bottom:25px;border-radius:8px;box-shadow:0 2px 6px rgba(0,0,0,.08);overflow:hidden}
.section.hidden,.hidden{display:none}
.section>details>summary{list-style:none;cursor:pointer;display:flex;align-items:center;gap:12px;background:#374151;color:#fff;padding:0 18px 0 0}
.section>details>summary::-webkit-details-marker{display:none}
.section h2{flex:1;min-width:0;margin:0;padding:14px 18px;font-size:20px;display:flex;gap:8px}
.section h2::before{content:"\25B8";font-size:16px;line-height:1.9;transition:transform .15s}
.section>details[open]>summary h2::before{transform:rotate(90deg)}
.section .sn{white-space:nowrap}
.section.FAIL>details>summary{border-left:6px solid #dc2626}.section.WARN>details>summary{border-left:6px solid #f59e0b}.section.PASS>details>summary{border-left:6px solid #16a34a}.section.INFO>details>summary{border-left:6px solid #2563eb}.section.SKIP>details>summary{border-left:6px solid #9ca3af}
.section.sk>details>summary{background:#6b7280}
.rm{background:transparent;color:#fff;border-color:#9ca3af;padding:4px 10px;min-height:30px;font-weight:500}
.rm:hover{background:#4b5563}
.sbody{overflow-x:auto}
table{width:100%;border-collapse:collapse}
th{background:#f3f4f6;text-align:left;padding:12px;border-bottom:1px solid #ddd}
td{padding:12px;border-bottom:1px solid #eee;vertical-align:top}
.ct td:first-child{overflow-wrap:anywhere}
th.num,td.num{text-align:right;font-variant-numeric:tabular-nums}
.dt th{position:sticky;top:0}
.tw{overflow-x:auto;border-top:1px solid #eee}
.status{font-weight:700;padding:5px 10px;border-radius:5px;display:inline-block;white-space:nowrap;font-size:13px}
.status-pass{background:#dcfce7;color:#166534}.status-warn{background:#fef3c7;color:#92400e}.status-fail{background:#fee2e2;color:#991b1b}.status-info{background:#dbeafe;color:#1e40af}.status-skip{background:#e5e7eb;color:#374151}
tr.r-FAIL td:first-child{border-left:4px solid #dc2626}tr.r-WARN td:first-child{border-left:4px solid #f59e0b}
.current-state{white-space:pre-wrap;word-break:break-word;font-family:monospace;font-size:12px}
.meter{height:8px;background:#e5e7eb;border-radius:99px;overflow:hidden;margin-top:6px;min-width:90px}
.meter i{display:block;height:100%;background:#2563eb}
.meter.PASS i{background:#16a34a}.meter.WARN i{background:#f59e0b}.meter.FAIL i{background:#dc2626}
.mv{display:block;font-family:Arial,sans-serif;font-size:11.5px;color:#6b7280;margin-top:2px}
.mt b{font-weight:600}
.note{margin:0;padding:12px 18px;color:#4b5563;background:#f9fafb;border-bottom:1px solid #eee;font-size:13px}
details.raw{border-top:1px solid #eee}
details.raw>summary{cursor:pointer;padding:10px 18px;font-weight:600;font-size:13px;color:#1f2937}
.term{margin:0 18px 14px;border-radius:6px;overflow:hidden;border:1px solid #1f2937}
.termbar{display:flex;align-items:center;justify-content:space-between;background:#1f2937;color:#e5e7eb;padding:5px 10px;font:12px monospace}
.termbar .copy{min-height:26px;padding:2px 10px;font-size:12px}
.term pre{margin:0;background:#0f172a;color:#e2e8f0;padding:12px 14px;font:12px/1.5 monospace;overflow:auto;max-height:420px;white-space:pre}
.copy.ok{background:#dcfce7;color:#166534;border-color:#16a34a}
.ckbar{display:flex;justify-content:space-between;align-items:center;gap:10px;padding:12px 18px;border-bottom:1px solid #eee;flex-wrap:wrap}
.ckg{margin:0;padding:10px 18px 4px;font-size:13px;color:#374151;background:#f9fafb}
label.ck{display:flex;gap:10px;align-items:flex-start;padding:7px 18px;border-bottom:1px solid #f3f4f6;cursor:pointer}
label.ck input{margin-top:3px;width:16px;height:16px;flex:none}
label.ck:has(input:checked) span{color:#6b7280;text-decoration:line-through}
.footer{text-align:center;color:#666;padding:20px;font-size:12px}
.footer code{background:#e5e7eb;padding:2px 6px;border-radius:4px}
.printhdr{display:none}
@media screen and (max-width:900px){.container{padding:14px}.header{padding:16px}.ct thead{display:none}.ct,.ct tbody,.ct tr,.ct td{display:block;width:100%}.ct tr{border-bottom:2px solid #e5e7eb;padding:6px 0}.ct td{border:0;padding:4px 14px}.ct td:nth-child(4)::before{content:"Recommendation: ";font-weight:700}.ct td:nth-child(3):not(:empty)::before{content:"Current state: ";font-weight:700;font-family:Arial;font-size:12px}.section h2{font-size:17px}.chips2{display:none}}
@media print{
 body{background:#fff;font-size:11px}
 .tools,.rm,.copy,.picker,.ckbar button{display:none!important}
 .header{-webkit-print-color-adjust:exact;print-color-adjust:exact}
 .container{padding:10px 0;max-width:none}
 .section,.card{box-shadow:none;border:1px solid #ddd}
 .section{break-inside:auto;margin-bottom:14px}
 .section>details>summary,.status,.meter i,th,.cn,.dot{-webkit-print-color-adjust:exact;print-color-adjust:exact}
 .section>details>summary{break-after:avoid}
 tr{break-inside:avoid}
 .term pre{max-height:none;white-space:pre-wrap;word-break:break-word;background:#f8fafc;color:#111;border:0}
 .term{border-color:#cbd5e1}.termbar{background:#e5e7eb;color:#111}
 .current-state{font-size:10px}
 .summary{gap:8px;flex-wrap:nowrap;margin-bottom:14px}.card{min-width:0;flex:1;padding:8px 10px}.card div{font-size:20px}.card h3{font-size:11px;margin-bottom:2px}
 .header{padding:14px 18px}
 td,th{padding:6px 8px}
 .ct thead{display:table-header-group}
}
CSS
cat <<HTML
</style></head><body>

<div class="header">
<h1>Server Security &amp; Load Audit</h1>
<div>Server: <strong>$(hesc "$HOST")</strong> $(cpbtn "$HOST" hostname)</div>
<div>Generated: <strong>$NOW_HUMAN</strong></div>
<div class="hm">
<div><span>Server IP:</span> <strong>$(hesc "${IP:-unknown}")</strong> $( [ -n "$IP" ] && cpbtn "$IP" "IP address")</div>
<div><span>OS:</span> <strong>$(hesc "$OS_PRETTY")</strong></div>
<div><span>Kernel:</span> <strong>$(hesc "$KERNEL")</strong></div>
<div><span>Runtime:</span> <strong>${ELAPSED}s</strong></div>
<div><span>Executed as:</span> <strong>$(hesc "$RUN_USER")</strong></div>
$( [ -n "$REPORT_URL" ] && printf '<div><span>Report link:</span> <strong>%s</strong> %s</div>' "$(hesc "$REPORT_URL")" "$(cpbtn "$REPORT_URL" "report link")" )
</div>
</div>

<div class="container">

<div class="summary">
<div class="card pass-card"><h3>PASS</h3><div id="c-PASS">${SEV_COUNT[PASS]}</div></div>
<div class="card warn-card"><h3>WARNING</h3><div id="c-WARN">${SEV_COUNT[WARN]}</div></div>
<div class="card fail-card"><h3>FAIL</h3><div id="c-FAIL">${SEV_COUNT[FAIL]}</div></div>
<div class="card info-card"><h3>INFO</h3><div id="c-INFO">${SEV_COUNT[INFO]}</div></div>
<div class="card skip-card"><h3>SKIPPED</h3><div id="c-SKIP">${SEV_COUNT[SKIP]}</div></div>
</div>

<div class="tools" role="toolbar" aria-label="Report actions">
<button type="button" class="primary" onclick="window.print()">Print / Save as PDF</button>
<button type="button" onclick="expandAll()">Expand all</button>
<button type="button" onclick="collapseAll()">Collapse all</button>
<button type="button" onclick="restoreAll()">Restore all sections</button>
<button type="button" onclick="setAll(false)">Remove all</button>
<details class="picker"><summary>Choose sections to include</summary><div class="pgrid">$NAV</div></details>
</div>

$SECTIONS
</div>

<div class="footer">
Generated by Server Security &amp; Load Audit<br><br>
<strong>This report is READ-ONLY.</strong><br>
No server security settings, firewall rules, services, packages, or configuration files were modified by this audit.<br>
The only file written is this report, which contains sensitive information. Delete it after use: <code>rm -f $(hesc "$OUT")</code> $(cpbtn "rm -f $OUT" "delete command")
</div>
<script>
HTML
cat <<'JS'
(function () {
  var D = document, W = window;
  function qs(s, r) { return (r || D).querySelector(s); }
  function qa(s, r) { return Array.prototype.slice.call((r || D).querySelectorAll(s)); }

  /* sections: remove / restore */
  W.tog = function (id, on) {
    var s = D.getElementById(id); if (s) s.classList.toggle('hidden', !on);
    var n = qs('.pi[data-id="' + id + '"]');
    if (n) { n.classList.toggle('off', !on); qs('input', n).checked = on; }
    recalc();
  };
  W.rmSec = function (id, e) { e.preventDefault(); e.stopPropagation(); W.tog(id, false); };
  W.setAll = function (on) { qa('section[data-title]').forEach(function (s) { W.tog(s.id, on); }); };
  W.restoreAll = function () { W.setAll(true); };
  W.expandAll = function () { qa('section details').forEach(function (d) { d.open = true; }); };
  W.collapseAll = function () { qa('section details').forEach(function (d) { d.open = false; }); };

  /* live summary + section numbers */
  function recalc() {
    var c = { f: 0, w: 0, p: 0, i: 0, s: 0 }, n = 0;
    qa('section[data-title]').forEach(function (s) {
      if (s.classList.contains('hidden')) return;
      n++; var nm = qs('.sn', s); if (nm) nm.textContent = n + '.';
      for (var k in c) c[k] += parseInt(s.dataset[k] || 0, 10);
    });
    var map = { FAIL: 'f', WARN: 'w', PASS: 'p', INFO: 'i', SKIP: 's' };
    for (var k in map) { var e = D.getElementById('c-' + k); if (e) e.textContent = c[map[k]]; }
  }

  /* copy buttons (also works on plain http) */
  function fallbackCopy(txt) {
    var ta = D.createElement('textarea'); ta.value = txt; ta.setAttribute('readonly', '');
    ta.style.position = 'fixed'; ta.style.opacity = '0'; D.body.appendChild(ta); ta.select();
    var ok = false; try { ok = D.execCommand('copy'); } catch (e) {} D.body.removeChild(ta); return ok;
  }
  function flash(btn) {
    var o = btn.getAttribute('data-l') || btn.textContent; btn.setAttribute('data-l', o);
    btn.textContent = 'Copied'; btn.classList.add('ok');
    setTimeout(function () { btn.textContent = o; btn.classList.remove('ok'); }, 1500);
  }
  D.addEventListener('click', function (e) {
    var btn = e.target.closest ? e.target.closest('.copy') : null; if (!btn) return;
    e.preventDefault(); e.stopPropagation();
    var txt = btn.hasAttribute('data-copy') ? btn.getAttribute('data-copy') : (btn.closest('.term') ? qs('pre', btn.closest('.term')).textContent : '');
    if (W.navigator.clipboard && W.isSecureContext) {
      W.navigator.clipboard.writeText(txt).then(function () { flash(btn); }, function () { if (fallbackCopy(txt)) flash(btn); });
    } else if (fallbackCopy(txt)) flash(btn);
  });

  /* manual verification checklist */
  var CKK = 'audit-ck:' + location.pathname;
  function ckSave() { var o = {}; qa('#cklist input').forEach(function (i) { if (i.checked) o[i.dataset.k] = 1; }); try { localStorage.setItem(CKK, JSON.stringify(o)); } catch (e) {} }
  function ckProg() { var l = D.getElementById('cklist'); if (!l) return; D.getElementById('ckprog').textContent = qa('input:checked', l).length + ' of ' + l.dataset.total + ' verified'; }
  W.ckAll = function (v) { qa('#cklist input').forEach(function (i) { i.checked = v; }); ckSave(); ckProg(); };
  (function () {
    var l = D.getElementById('cklist'); if (!l) return; var o = {};
    try { o = JSON.parse(localStorage.getItem(CKK) || '{}'); } catch (e) {}
    qa('input', l).forEach(function (i) { i.checked = !!o[i.dataset.k]; i.addEventListener('change', function () { ckSave(); ckProg(); }); });
    ckProg();
  })();

  W.addEventListener('beforeprint', function () { qa('section details').forEach(function (d) { d.open = true; }); });
  recalc();
})();
JS
cat <<HTML
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


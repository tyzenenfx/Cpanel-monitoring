#!/bin/bash
# ==========================================================
# cPanel / CloudLinux Server Load & Resource Usage Report
# READ-ONLY MONITORING SCRIPT
#
# Generates:
#   1. Plain-text .log report
#   2. Human-readable .html report
#
# Checks:
#   - System load average
#   - CPU/memory usage
#   - Top CPU processes
#   - Top memory processes
#   - Top 5 cPanel users by CPU/memory
#
# DATABASE:
#   - MariaDB/MySQL live processlist
#   - MariaDB/MySQL slow query log analysis
#   - mariadb-dumpslow / mysqldumpslow
#
# WEB:
#   - Apache process usage
#   - LiteSpeed process usage
#   - LSPHP per-account PHP workers
#
# CLOUDLINUX:
#   - CloudLinux detected / not detected
#   - Top 10 LVE users by current CPU
#   - Top 10 LVE users by current physical memory
#   - Users with LVE faults
#   - Top faulting accounts
#
# EXIM:
#   - Total queued messages
#   - Top 10 senders
#
# NETWORK:
#   - TCP connection state summary
#   - Top source IPs on port 80
#   - Top source IPs on port 443
#   - SYN-RECV count
#   - Top SYN-RECV source IPs
#   - SYN-RECV by destination port
#
# STORAGE:
#   - Disk I/O
#   - Disk space
#   - Inode usage
#
# READ-ONLY:
#
#   Does NOT:
#     - restart services
#     - stop services
#     - kill processes
#     - block IPs
#     - modify firewall rules
#     - modify databases
#     - modify MariaDB/MySQL configuration
#     - enable/disable slow query logging
#     - delete Exim mail
#     - freeze/thaw Exim mail
#     - force Exim delivery
#     - retry Exim delivery
#     - modify CloudLinux limits
#     - enable/disable CloudLinux features
#     - install packages
#
# The script DOES create:
#   /var/log/server_load_reports/
#   timestamped .log report
#   timestamped .html report
#
# Temporary files:
#   /tmp/mysql_slow_analysis.*
#   /tmp/html_section.*
#
# These temporary files are removed after use.
#
# Usage:
#
#   chmod +x server_load_report.sh
#   sudo ./server_load_report.sh
#
# Optional:
#
#   SLOW_QUERY_COUNT=500 sudo ./server_load_report.sh
#
# ==========================================================


###############################################################################
# CONFIGURATION
###############################################################################

REPORT_DIR="/var/log/server_load_reports"

SLOW_QUERY_COUNT="${SLOW_QUERY_COUNT:-200}"

TIMESTAMP="$(date +%Y%m%d_%H%M%S)"

REPORT="$REPORT_DIR/load_report_${TIMESTAMP}.log"
HTML_REPORT="$REPORT_DIR/load_report_${TIMESTAMP}.html"


###############################################################################
# ROOT CHECK
###############################################################################

if [ "$(id -u)" -ne 0 ]; then

    echo "ERROR: This script must be run as root."
    echo
    echo "Usage:"
    echo "  sudo $0"

    exit 1

fi


###############################################################################
# REPORT DIRECTORY
###############################################################################

mkdir -p "$REPORT_DIR" 2>/dev/null

if [ ! -d "$REPORT_DIR" ]; then

    echo "ERROR: Unable to create report directory:"
    echo "$REPORT_DIR"

    exit 1

fi


###############################################################################
# REPORT FILES
###############################################################################

: > "$REPORT"
: > "$HTML_REPORT"

if [ ! -f "$REPORT" ] || [ ! -f "$HTML_REPORT" ]; then

    echo "ERROR: Unable to create report files."

    exit 1

fi


###############################################################################
# BASIC INFORMATION
###############################################################################

HOSTNAME_VALUE="$(hostname)"
DATE_VALUE="$(date)"

CPU_CORES="$(nproc 2>/dev/null || echo "Unavailable")"


###############################################################################
# HTML ESCAPE
###############################################################################

html_escape() {

    sed \
        -e 's/&/\&amp;/g' \
        -e 's/</\&lt;/g' \
        -e 's/>/\&gt;/g' \
        -e 's/"/\&quot;/g' \
        -e "s/'/\&#39;/g"

}


###############################################################################
# HTML HEADER
###############################################################################

cat > "$HTML_REPORT" <<EOF
<!DOCTYPE html>
<html lang="en">

<head>

<meta charset="UTF-8">

<meta name="viewport"
      content="width=device-width, initial-scale=1.0">

<title>Server Load Report - ${HOSTNAME_VALUE}</title>

<style>

* {
    box-sizing: border-box;
}

body {
    margin: 0;
    padding: 0;
    background: #f1f5f9;
    color: #1e293b;
    font-family: Arial, Helvetica, sans-serif;
    font-size: 14px;
}

.container {
    max-width: 1500px;
    margin: auto;
    padding: 25px;
}

.header {
    background: linear-gradient(
        135deg,
        #0f172a,
        #1e3a8a
    );

    color: white;

    padding: 28px;

    border-radius: 12px;

    margin-bottom: 20px;

    box-shadow:
        0 4px 15px rgba(0,0,0,.15);
}

.header h1 {
    margin: 0 0 12px 0;
    font-size: 28px;
}

.header p {
    margin: 5px 0;
    color: #dbeafe;
}

.section {
    background: white;

    border-radius: 10px;

    margin-bottom: 20px;

    box-shadow:
        0 2px 8px rgba(0,0,0,.08);

    overflow: hidden;
}

.section-header {
    background: #e2e8f0;

    padding: 14px 18px;

    font-size: 17px;

    font-weight: bold;

    color: #0f172a;
}

.section-body {
    padding: 18px;
}

pre {
    background: #0f172a;

    color: #e2e8f0;

    padding: 15px;

    border-radius: 7px;

    overflow-x: auto;

    white-space: pre-wrap;

    word-wrap: break-word;

    font-family:
        Consolas,
        Monaco,
        monospace;

    font-size: 12px;

    line-height: 1.5;
}

.warning {
    background: #fff7ed;

    border-left:
        5px solid #f97316;

    padding: 12px;

    margin-bottom: 15px;

    border-radius: 5px;
}

.critical {
    background: #fef2f2;

    border-left:
        5px solid #dc2626;

    padding: 12px;

    margin-bottom: 15px;

    border-radius: 5px;
}

.normal {
    background: #f0fdf4;

    border-left:
        5px solid #16a34a;

    padding: 12px;

    margin-bottom: 15px;

    border-radius: 5px;
}

.footer {
    text-align: center;

    color: #64748b;

    padding: 20px;

    font-size: 12px;
}

@media (max-width: 700px) {

    .container {
        padding: 10px;
    }

    .header h1 {
        font-size: 21px;
    }

    .section-body {
        padding: 10px;
    }

    pre {
        font-size: 11px;
    }

}

</style>

</head>

<body>

<div class="container">

<div class="header">

<h1>
Server Load & Resource Usage Report
</h1>

<p>
<strong>Hostname:</strong>
${HOSTNAME_VALUE}
</p>

<p>
<strong>Generated:</strong>
${DATE_VALUE}
</p>

<p>
<strong>CPU Cores:</strong>
${CPU_CORES}
</p>

<p>
<strong>Text Report:</strong>
${REPORT}
</p>

</div>

EOF


###############################################################################
# HTML SECTION VARIABLES
###############################################################################

HTML_CURRENT_SECTION=""
CURRENT_SECTION_TITLE=""


###############################################################################
# LOG FUNCTION
###############################################################################

log() {

    local message="$1"

    echo "$message" | tee -a "$REPORT"

    if [ -n "$HTML_CURRENT_SECTION" ]; then

        printf '%s\n' "$message" >> "$HTML_CURRENT_SECTION"

    fi

}


###############################################################################
# SECTION FUNCTION
###############################################################################

section() {

    local title="$1"

    echo >> "$REPORT"

    echo "###############################################################################" \
        >> "$REPORT"

    echo "# $title" >> "$REPORT"

    echo "###############################################################################" \
        >> "$REPORT"


    HTML_CURRENT_SECTION="$(mktemp /tmp/html_section.XXXXXX)"

    CURRENT_SECTION_TITLE="$title"

}


###############################################################################
# RUN FUNCTION
###############################################################################

run() {

    local command="$1"
    local output

    output=$(eval "$command" 2>&1)

    if [ -z "$output" ]; then

        output="(no output)"

    fi

    echo "$output" | tee -a "$REPORT"

    if [ -n "$HTML_CURRENT_SECTION" ]; then

        printf '%s\n' "$output" >> "$HTML_CURRENT_SECTION"

    fi

}


###############################################################################
# FINISH HTML SECTION
###############################################################################

finish_section() {

    if [ -n "$HTML_CURRENT_SECTION" ] &&
       [ -f "$HTML_CURRENT_SECTION" ]; then

        local content

        content="$(cat "$HTML_CURRENT_SECTION")"

        {

            echo '<div class="section">'

            echo '<div class="section-header">'

            printf '%s\n' "$CURRENT_SECTION_TITLE" | html_escape

            echo '</div>'

            echo '<div class="section-body">'

            echo '<pre>'

            printf '%s\n' "$content" | html_escape

            echo '</pre>'

            echo '</div>'

            echo '</div>'

        } >> "$HTML_REPORT"


        rm -f "$HTML_CURRENT_SECTION"

        HTML_CURRENT_SECTION=""

    fi

}


###############################################################################
# HEADER / BASIC INFORMATION
###############################################################################

section "SERVER LOAD REPORT"

log "SERVER LOAD REPORT"
log "============================================================"
log "Generated : $DATE_VALUE"
log "Hostname  : $HOSTNAME_VALUE"
log "CPU Cores : $CPU_CORES"
log "Text      : $REPORT"
log "HTML      : $HTML_REPORT"
log "============================================================"

finish_section


###############################################################################
# SYSTEM LOAD
###############################################################################

section "SYSTEM LOAD"

run "uptime"

log "CPU cores: $CPU_CORES"

if [ -r /proc/loadavg ]; then

    log "Load average: $(cat /proc/loadavg)"

fi

finish_section


###############################################################################
# MEMORY
###############################################################################

section "MEMORY USAGE"

if command -v free &> /dev/null; then

    run "free -h"

else

    log "free command not available."

fi

finish_section


###############################################################################
# TOP PROCESSES BY CPU
###############################################################################

section "TOP 15 PROCESSES BY CPU"

run "ps -eo pid,ppid,user,%cpu,%mem,etime,cmd --sort=-%cpu | head -n 16"

finish_section


###############################################################################
# TOP PROCESSES BY MEMORY
###############################################################################

section "TOP 15 PROCESSES BY MEMORY"

run "ps -eo pid,ppid,user,%cpu,%mem,etime,cmd --sort=-%mem | head -n 16"

finish_section


###############################################################################
# TOP 5 USERS
###############################################################################

section "TOP 5 USERS BY RESOURCE USAGE (cPanel accounts)"

run "ps -eo user,%cpu,%mem --no-headers | awk '{
    cpu[\$1] += \$2
    mem[\$1] += \$3
    count[\$1]++
}
END {
    printf \"%-20s %-10s %-10s %-10s\n\", \"USER\", \"CPU%\", \"MEM%\", \"PROC_COUNT\"
    for (u in cpu)
        printf \"%-20s %-10.1f %-10.1f %-10d\n\", u, cpu[u], mem[u], count[u]
}' | (read -r header; echo \"\$header\"; sort -k2 -nr | head -n 5)"

finish_section


###############################################################################
# CLOUDLINUX DETECTION
###############################################################################

section "CLOUDLINUX STATUS"


###############################################################################
# Detection variables
###############################################################################

CLOUDLINUX_DETECTED="NO"
CLOUDLINUX_VERSION=""
CLOUDLINUX_TOOL=""


###############################################################################
# Detect CloudLinux from release files
###############################################################################

if [ -f /etc/cloudlinux-release ]; then

    CLOUDLINUX_DETECTED="YES"

    CLOUDLINUX_VERSION="$(cat /etc/cloudlinux-release 2>/dev/null)"

fi


###############################################################################
# Detect CloudLinux using cldetect
###############################################################################

if command -v cldetect &> /dev/null; then

    CLOUDLINUX_DETECTED="YES"

    CLOUDLINUX_TOOL="$(command -v cldetect)"

    if [ -z "$CLOUDLINUX_VERSION" ]; then

        CLOUDLINUX_VERSION="$(
            cldetect --detect-edition 2>/dev/null
        )"

    fi

fi


###############################################################################
# Detect CloudLinux LVE utilities
###############################################################################

if command -v lveps &> /dev/null ||
   command -v lveinfo &> /dev/null ||
   command -v lvetop &> /dev/null; then

    CLOUDLINUX_DETECTED="YES"

fi


###############################################################################
# Report status
###############################################################################

if [ "$CLOUDLINUX_DETECTED" = "YES" ]; then

    log "CloudLinux detected: YES"

    if [ -n "$CLOUDLINUX_VERSION" ]; then

        log "CloudLinux version/edition: $CLOUDLINUX_VERSION"

    fi

    if [ -n "$CLOUDLINUX_TOOL" ]; then

        log "Detection utility: $CLOUDLINUX_TOOL"

    fi

    if command -v lveps &> /dev/null; then

        log "lveps: $(command -v lveps)"

    else

        log "lveps: NOT FOUND"

    fi

    if command -v lveinfo &> /dev/null; then

        log "lveinfo: $(command -v lveinfo)"

    else

        log "lveinfo: NOT FOUND"

    fi

else

    log "CloudLinux detected: NO"
    log "CloudLinux LVE monitoring skipped."

fi

finish_section


###############################################################################
# CLOUDLINUX CURRENT LVE CPU
#
# lveps:
#   -d = dynamic CPU
#   -c 1 = calculate average CPU over 1 second
#   -s cpu = sort by CPU
#
# This is a short real-time sample rather than historical usage.
###############################################################################

if [ "$CLOUDLINUX_DETECTED" = "YES" ]; then

    section "CLOUDLINUX - TOP 10 LVE USERS BY CURRENT CPU"

    if command -v lveps &> /dev/null; then

        log "Sampling LVE CPU usage for 1 second..."
        log ""
        log "Top active LVE users by current CPU:"
        log ""

        run "lveps -d -c 1 -s cpu 2>/dev/null | head -n 11"

    else

        log "lveps command not found."
        log "Current LVE CPU usage unavailable."

    fi

    finish_section


###############################################################################
# CLOUDLINUX CURRENT PHYSICAL MEMORY
#
# lveps reports MEM as resident memory used by the LVE.
###############################################################################

    section "CLOUDLINUX - TOP 10 LVE USERS BY CURRENT PHYSICAL MEMORY"

    if command -v lveps &> /dev/null; then

        log "Top active LVE users by current physical memory:"
        log ""

        run "lveps -d -c 1 -s mem 2>/dev/null | head -n 11"

    else

        log "lveps command not found."
        log "Current LVE memory usage unavailable."

    fi

    finish_section


###############################################################################
# CLOUDLINUX TOP FAULTING ACCOUNTS
#
# Sort by total faults.
###############################################################################

    section "CLOUDLINUX - TOP 10 FAULTING ACCOUNTS"

    if command -v lveinfo &> /dev/null; then

        log "Top LVE accounts by total faults during the last 1 hour:"
        log ""

        run "lveinfo \
            --period=1h \
            --order-by=any_faults \
            --display-username \
            --limit=10 \
            2>/dev/null"

    else

        log "lveinfo command not found."
        log "Top faulting account information unavailable."

    fi

    finish_section

fi

###############################################################################
# PHP-FPM LIMIT CHECK - LOG ONLY
#
# READ-ONLY:
#   Checks PHP-FPM logs for actual max_children / connection-limit events.
#   Does NOT inspect or modify PHP-FPM configuration.
#   Does NOT list every domain.
###############################################################################

section "PHP-FPM LIMIT CHECK"

PHP_FPM_LOG_FOUND=0
PHP_FPM_LIMIT_FOUND=0

# Common PHP-FPM log locations on cPanel systems.
PHP_FPM_LOGS=(
    /opt/cpanel/ea-php*/root/usr/var/log/php-fpm/error.log
    /opt/cpanel/ea-php*/root/usr/var/log/php-fpm/www-error.log
    /var/log/php-fpm/error.log
    /var/log/php-fpm/www-error.log
)

for PHP_LOG_PATTERN in "${PHP_FPM_LOGS[@]}"; do

    for PHP_LOG in $PHP_LOG_PATTERN; do

        [ -f "$PHP_LOG" ] || continue

        PHP_FPM_LOG_FOUND=1

        log "Checking PHP-FPM log: $PHP_LOG"

        # Look only for actual pool saturation / max_children events.
        LIMIT_MATCHES="$(
            grep -Ei \
            'max_children|server reached pm.max_children|reached max_children|seems busy|would exceed|pool .* seems busy' \
            "$PHP_LOG" \
            2>/dev/null |
            tail -n 50
        )"

        if [ -n "$LIMIT_MATCHES" ]; then

            PHP_FPM_LIMIT_FOUND=1

            log ""
            log "WARNING: PHP-FPM limit-related events detected."
            log ""
            log "$LIMIT_MATCHES"
            log ""

        fi

    done

done


###############################################################################
# RESULT
###############################################################################

if [ "$PHP_FPM_LOG_FOUND" -eq 0 ]; then

    log "PHP-FPM error log not found."
    log "PHP-FPM limit check could not be performed."

elif [ "$PHP_FPM_LIMIT_FOUND" -eq 0 ]; then

    log "No PHP-FPM Max Children / connection-limit events detected."

else

    log "PHP-FPM limit events were found above."
    log "Review the affected PHP version/pool and corresponding account."

fi

finish_section

###############################################################################
# MYSQL / MARIADB LIVE PROCESSLIST
###############################################################################

section "TOP MYSQL/MARIADB QUERIES (LIVE)"

DB_ADMIN=""

if command -v mariadbadmin &> /dev/null; then

    DB_ADMIN="mariadbadmin"

elif command -v mysqladmin &> /dev/null; then

    DB_ADMIN="mysqladmin"

fi


if [ -n "$DB_ADMIN" ]; then

    log "Database admin utility: $DB_ADMIN"

    run "$DB_ADMIN processlist --verbose 2>/dev/null | head -n 20"

else

    log "Neither mariadbadmin nor mysqladmin was found."

fi

finish_section


###############################################################################
# MYSQL / MARIADB SLOW QUERY ANALYSIS
###############################################################################

section "MYSQL/MARIADB SLOW QUERY ANALYSIS"


###############################################################################
# DATABASE CLIENT
###############################################################################

DB_CLI=""

if command -v mariadb &> /dev/null; then

    DB_CLI="mariadb"

elif command -v mysql &> /dev/null; then

    DB_CLI="mysql"

fi


###############################################################################
# DUMPSLOW
###############################################################################

DUMPSLOW_CMD=""

if command -v mariadb-dumpslow &> /dev/null; then

    DUMPSLOW_CMD="$(command -v mariadb-dumpslow)"

elif command -v mysqldumpslow &> /dev/null; then

    DUMPSLOW_CMD="$(command -v mysqldumpslow)"

fi


###############################################################################
# SLOW QUERY LOG LOCATION
###############################################################################

SLOW_LOG=""

if [ -n "$DB_CLI" ]; then

    SLOW_LOG=$(
        "$DB_CLI" -Nse \
        "SHOW VARIABLES LIKE 'slow_query_log_file';" \
        2>/dev/null |
        awk '{print $2}'
    )

fi


###############################################################################
# FALLBACK SLOW LOG SEARCH
###############################################################################

if [ -z "$SLOW_LOG" ] || [ ! -f "$SLOW_LOG" ]; then

    SLOW_LOG=$(
        find /var/lib/mysql /var/log \
            -maxdepth 2 \
            -type f \
            \( \
                -iname "*slow*.log" \
                -o \
                -iname "*-slow.log" \
            \) \
            2>/dev/null |
        head -n 1
    )

fi


###############################################################################
# SLOW QUERY PROCESSING
###############################################################################

if [ -z "$SLOW_LOG" ] || [ ! -f "$SLOW_LOG" ]; then

    log "Slow query log not found or not enabled on this server."

elif [ -z "$DUMPSLOW_CMD" ]; then

    log "Neither mariadb-dumpslow nor mysqldumpslow was found."

else

    log "Slow query log   : $SLOW_LOG"
    log "Slow query tool  : $DUMPSLOW_CMD"
    log "Entries analyzed : $SLOW_QUERY_COUNT"


    TMP_SLOW_LOG="$(mktemp /tmp/mysql_slow_analysis.XXXXXX)"

    trap 'rm -f "$TMP_SLOW_LOG"' EXIT


    ###########################################################################
    # EXTRACT COMPLETE SLOW QUERY ENTRIES
    ###########################################################################

    awk -v max_entries="$SLOW_QUERY_COUNT" '

        /^# Time:/ {

            if (entry != "") {
                entries[++count] = entry
            }

            entry = $0 "\n"

            next
        }

        {
            if (entry != "") {
                entry = entry $0 "\n"
            }
        }

        END {

            if (entry != "") {
                entries[++count] = entry
            }

            start = count - max_entries + 1

            if (start < 1) {
                start = 1
            }

            for (i = start; i <= count; i++) {
                printf "%s", entries[i]
            }

        }

    ' "$SLOW_LOG" > "$TMP_SLOW_LOG"


    if [ ! -s "$TMP_SLOW_LOG" ]; then

        log "No complete slow-query entries were found."

    else

        log "Temporary analysis file created: $TMP_SLOW_LOG"


        #######################################################################
        # QUERY TIME
        #######################################################################

        finish_section

        section "TOP 10 SLOW QUERY PATTERNS BY QUERY TIME"

        run "\"$DUMPSLOW_CMD\" -s t -t 10 '$TMP_SLOW_LOG'"

        finish_section


        #######################################################################
        # LOCK TIME
        #######################################################################

        section "TOP 10 SLOW QUERY PATTERNS BY LOCK TIME"

        run "\"$DUMPSLOW_CMD\" -s l -t 10 '$TMP_SLOW_LOG'"

        finish_section


        #######################################################################
        # ROWS SENT
        #######################################################################

        section "TOP 10 SLOW QUERY PATTERNS BY ROWS SENT"

        run "\"$DUMPSLOW_CMD\" -s r -t 10 '$TMP_SLOW_LOG'"

        finish_section


        #######################################################################
        # QUERY COUNT
        #######################################################################

        section "TOP 10 SLOW QUERY PATTERNS BY QUERY COUNT"

        run "\"$DUMPSLOW_CMD\" -s c -t 10 '$TMP_SLOW_LOG'"

        finish_section


        #######################################################################
        # RECENT SLOW QUERIES
        #######################################################################

        section "RECENT SLOW QUERY ENTRIES (LATEST 10)"

        run "awk '
            /^# Time:/ {

                if (entry != \"\") {
                    entries[++count] = entry
                }

                entry = \$0 \"\\n\"

                next
            }

            {
                if (entry != \"\") {
                    entry = entry \$0 \"\\n\"
                }
            }

            END {

                if (entry != \"\") {
                    entries[++count] = entry
                }

                start = count - 9

                if (start < 1) {
                    start = 1
                }

                for (i = start; i <= count; i++) {
                    printf \"%s\", entries[i]
                }

            }

        ' '$TMP_SLOW_LOG'"

        finish_section


        #######################################################################
        # CLEANUP
        #######################################################################

        rm -f "$TMP_SLOW_LOG"

        trap - EXIT

        log "Temporary analysis file removed."

    fi

fi

finish_section


###############################################################################
# APACHE
###############################################################################

section "APACHE STATUS"

if systemctl is-active --quiet httpd 2>/dev/null; then

    log "Apache (httpd): ACTIVE"

    run "ps -C httpd -o pid,user,%cpu,%mem,etime,cmd --sort=-%cpu | head -n 25"

elif systemctl is-active --quiet apache2 2>/dev/null; then

    log "Apache (apache2): ACTIVE"

    run "ps -C apache2 -o pid,user,%cpu,%mem,etime,cmd --sort=-%cpu | head -n 25"

else

    log "Apache: NOT ACTIVE"

fi

finish_section


###############################################################################
# LITESPEED
###############################################################################

section "LITESPEED STATUS"

if systemctl is-active --quiet lsws 2>/dev/null; then

    log "LiteSpeed (lsws): ACTIVE"

    run "ps -eo pid,user,%cpu,%mem,etime,cmd --sort=-%cpu | \
grep -iE 'litespeed|lshttpd' | \
grep -v grep | \
head -n 25"

else

    log "LiteSpeed (lsws): NOT ACTIVE"

fi

finish_section


###############################################################################
# LSPHP
###############################################################################

section "TOP 15 LSPHP PROCESSES (PER-ACCOUNT PHP WORKERS)"

run "ps -eo pid,user,%cpu,%mem,etime,cmd --sort=-%cpu | \
grep -i 'lsphp' | \
grep -v grep | \
head -n 15"

finish_section


###############################################################################
# NETWORK CONNECTIONS
###############################################################################

section "NETWORK CONNECTIONS / SYN ATTACK / DDOS INDICATORS"

if command -v ss &> /dev/null; then

    log "Connection tool: $(command -v ss)"


    ###########################################################################
    # TCP STATE SUMMARY
    ###########################################################################

    log ""
    log "--- TCP CONNECTION STATE SUMMARY ---"

    run "ss -tan 2>/dev/null | \
awk 'NR > 1 {print \$1}' | \
sort | \
uniq -c | \
sort -nr"


    ###########################################################################
    # PORT 80 COUNT
    ###########################################################################

    log ""
    log "--- PORT 80 CONNECTION COUNT ---"

    HTTP_COUNT=$(
        ss -tan 2>/dev/null |
        awk '
            NR > 1 &&
            $4 ~ /:80$/ {
                count++
            }

            END {
                print count+0
            }
        '
    )

    log "TCP connections involving port 80: $HTTP_COUNT"


    ###########################################################################
    # TOP SOURCE IPs PORT 80
    ###########################################################################

    finish_section

    section "TOP 20 SOURCE IPs CONNECTED TO PORT 80"

    run "ss -Htn 2>/dev/null | \
awk '
    \$4 ~ /:80$/ {

        ip=\$5

        sub(/^\\[/, \"\", ip)
        sub(/\\]:[0-9]+\$/, \"\", ip)
        sub(/:[0-9]+\$/, \"\", ip)

        if (ip != \"\") {
            count[ip]++
        }
    }

    END {

        for (ip in count) {
            printf \"%8d %s\\n\", count[ip], ip
        }

    }

' | sort -nr | head -n 20"

    finish_section


    ###########################################################################
    # PORT 443 COUNT
    ###########################################################################

    section "PORT 443 CONNECTION COUNT"

    HTTPS_COUNT=$(
        ss -tan 2>/dev/null |
        awk '
            NR > 1 &&
            $4 ~ /:443$/ {
                count++
            }

            END {
                print count+0
            }
        '
    )

    log "TCP connections involving port 443: $HTTPS_COUNT"

    finish_section


    ###########################################################################
    # TOP SOURCE IPs PORT 443
    ###########################################################################

    section "TOP 20 SOURCE IPs CONNECTED TO PORT 443"

    run "ss -Htn 2>/dev/null | \
awk '
    \$4 ~ /:443$/ {

        ip=\$5

        sub(/^\\[/, \"\", ip)
        sub(/\\]:[0-9]+\$/, \"\", ip)
        sub(/:[0-9]+\$/, \"\", ip)

        if (ip != \"\") {
            count[ip]++
        }
    }

    END {

        for (ip in count) {
            printf \"%8d %s\\n\", count[ip], ip
        }

    }

' | sort -nr | head -n 20"

    finish_section


    ###########################################################################
    # SYN-RECV
    ###########################################################################

    section "SYN-RECV / POSSIBLE SYN FLOOD INDICATORS"

    SYN_COUNT=$(
        ss -Htan state syn-recv 2>/dev/null |
        wc -l
    )

    log "Total SYN-RECV connections: $SYN_COUNT"


    if [ "$SYN_COUNT" -ge 1000 ]; then

        log ""
        log "CRITICAL WARNING:"
        log "1000+ SYN-RECV connections detected."
        log "Possible SYN flood or severe connection pressure."

    elif [ "$SYN_COUNT" -ge 500 ]; then

        log ""
        log "WARNING:"
        log "500+ SYN-RECV connections detected."
        log "Investigate for possible SYN flood or traffic surge."

    elif [ "$SYN_COUNT" -ge 100 ]; then

        log ""
        log "NOTICE:"
        log "100+ SYN-RECV connections detected."
        log "Monitor connection rate and source IP distribution."

    else

        log ""
        log "SYN-RECV level appears normal."

    fi

    finish_section



    ###########################################################################
    # WEB CONNECTION STATES
    ###########################################################################

    section "CURRENT WEB CONNECTION STATES (80/443)"

    run "ss -Htan 2>/dev/null | \
awk '
{
    local=\$4

    if (local ~ /:80$/ || local ~ /:443$/) {
        count[\$1]++
    }
}

END {

    for (state in count) {
        printf \"%8d %s\\n\", count[state], state
    }

}
' | sort -nr"

    finish_section

else

    log "ss command not available."
    log "Network connection monitoring skipped."

fi

finish_section


###############################################################################
# EXIM MAIL QUEUE / SPAM CHECK
###############################################################################

section "EXIM MAIL QUEUE / SPAM CHECK"

if command -v exim &> /dev/null; then

    log "Exim binary: $(command -v exim)"


    ###########################################################################
    # TOTAL QUEUED MESSAGES
    ###########################################################################

    log ""
    log "--- TOTAL QUEUED MESSAGES ---"

    QUEUE_COUNT="$(exim -bpc 2>/dev/null)"

    if [[ "$QUEUE_COUNT" =~ ^[0-9]+$ ]]; then

        log "Total queued messages: $QUEUE_COUNT"


        if [ "$QUEUE_COUNT" -ge 1000 ]; then

            log "WARNING: Exim queue is HIGH (1000+ messages)."

        elif [ "$QUEUE_COUNT" -ge 500 ]; then

            log "WARNING: Exim queue is elevated (500+ messages)."

        elif [ "$QUEUE_COUNT" -ge 100 ]; then

            log "NOTICE: Exim queue contains 100+ messages."

        else

            log "Exim queue size appears normal."

        fi

    else

        log "Unable to determine Exim queue count."

    fi


    ###########################################################################
    # TOP SENDERS
    ###########################################################################

    finish_section

    section "TOP 10 EXIM SENDERS"

    EXIM_LOG="/var/log/exim_mainlog"

    if [ -f "$EXIM_LOG" ]; then

        log "Exim log: $EXIM_LOG"
        log "Top senders based on '<=' entries:"
        log ""

        run "grep '<=' '$EXIM_LOG' 2>/dev/null | \
awk -F' <= ' '{print \$2}' | \
awk '{print \$1}' | \
sort | \
uniq -c | \
sort -nr | \
head -10"

    else

        log "Exim main log not found:"
        log "$EXIM_LOG"

    fi

    finish_section


else

    log "Exim binary not found."
    log "Exim mail queue check skipped."

fi

finish_section


###############################################################################
# DISK I/O
###############################################################################

section "DISK I/O (5 SECOND SAMPLE)"

if command -v iostat &> /dev/null; then

    run "iostat -x 1 2"

else

    log "sysstat not installed - iostat unavailable."
    log "This is informational only."

fi

finish_section


###############################################################################
# DISK SPACE
###############################################################################

section "DISK SPACE USAGE"

run "df -hT"

finish_section


###############################################################################
# INODE USAGE
###############################################################################

section "INODE USAGE"

run "df -ih"

finish_section


###############################################################################
# END OF REPORT
###############################################################################

section "END OF REPORT"

log "Report completed: $(date)"
log "Text report: $REPORT"
log "HTML report: $HTML_REPORT"
log "============================================================"

finish_section


###############################################################################
# HTML FOOTER
###############################################################################

cat >> "$HTML_REPORT" <<EOF

<div class="footer">

Generated by cPanel / CloudLinux Server Load & Resource Usage Report<br>

Hostname: ${HOSTNAME_VALUE}<br>

Generated: ${DATE_VALUE}<br>

This report is for monitoring/diagnostic purposes only.

</div>

</div>

</body>

</html>

EOF


###############################################################################
# CLEANUP TEMPORARY HTML SECTION FILE
###############################################################################

if [ -n "$HTML_CURRENT_SECTION" ] &&
   [ -f "$HTML_CURRENT_SECTION" ]; then

    rm -f "$HTML_CURRENT_SECTION"

fi


###############################################################################
# PUBLISH HTML REPORT
#
# Copies the completed HTML report to Apache document root.
#
# The original HTML remains in:
#   /var/log/server_load_reports/
#
# Public copy:
#   /usr/local/apache/htdocs/
#
# Public IP is detected using:
#   curl -4 -s --max-time 3 https://api.ipify.org
###############################################################################

WEB_REPORT_DIR="/usr/local/apache/htdocs"
WEB_REPORT="$WEB_REPORT_DIR/$(basename "$HTML_REPORT")"

REPORT_URL=""

if [ -d "$WEB_REPORT_DIR" ]; then

    if cp "$HTML_REPORT" "$WEB_REPORT" 2>/dev/null; then

        # Make the web report readable by Apache.
        chmod 644 "$WEB_REPORT" 2>/dev/null

        #######################################################################
        # Detect public IPv4
        #######################################################################

        SERVER_IP=""

        if command -v curl >/dev/null 2>&1; then

            SERVER_IP="$(
                curl -4 -s --max-time 3 \
                https://api.ipify.org \
                2>/dev/null
            )"

        fi


        #######################################################################
        # Fallback if external IP detection fails
        #######################################################################

        if [ -z "$SERVER_IP" ]; then

            SERVER_IP="$(
                hostname -I 2>/dev/null |
                awk '{print $1}'
            )"

        fi


        #######################################################################
        # Create report URL
        #######################################################################

        if [[ "$SERVER_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then

            REPORT_URL="http://${SERVER_IP}/$(basename "$HTML_REPORT")"

        else

            REPORT_URL="http://SERVER-IP/$(basename "$HTML_REPORT")"

        fi


        #######################################################################
        # Log publishing information
        #######################################################################

        log ""
        log "============================================================"
        log "HTML REPORT PUBLISHED"
        log "============================================================"
        log "Web report : $WEB_REPORT"
        log "Report URL : $REPORT_URL"
        log "============================================================"

    else

        log ""
        log "WARNING: Unable to copy HTML report to:"
        log "$WEB_REPORT_DIR"

    fi

else

    log ""
    log "WARNING: Apache document root does not exist:"
    log "$WEB_REPORT_DIR"

fi


###############################################################################
# FINAL OUTPUT
###############################################################################

echo
echo "============================================================"
echo "REPORT COMPLETED"
echo "============================================================"
echo
echo "Text report:"
echo "$REPORT"
echo
echo "HTML report:"
echo "$HTML_REPORT"
echo

if [ -n "$REPORT_URL" ]; then

    echo "Web report:"
    echo "$REPORT_URL"
    echo

fi

echo "============================================================"



#!/bin/bash
#
# Monitor plugin for Fortinet FortiAnalyzer via JSON-RPC API (and optional SNMP)
#
# Author:
#   Felix Longardt <monitoring@longardt.com>
#
# Version history:
# 1.0.0  2026-11-09  Initial release: -eSys -eRes -eHA -eDevices -eADOMs -eTasks
#                    -eLic -eNTP -eDNS -eSyslog -eLogFwd; API token + user/pass auth;
#                    optional SNMP for uptime; parallel prefetch pattern
# 1.1.0  2026-11-09  Add Disk IOStat metrics to -eRes (--warn-io/--crit-io); API-based
#                    uptime fallback in -eUp when SNMP unavailable; fix jq field names
#                    with hyphens in log-forward parsing (server-name, server-ip, server-port)
# 1.2.0  2026-11-10  Fix SNMP-only mode: API-dependent checks now skip silently under -A
#                    when no API creds given; add -eLogRate (log recv/insert rates via FAZ
#                    SNMP MIB, --warn-loglag/--crit-loglag); add -eIncidents (SOC incident
#                    count via JSON-RPC v2, --warn-incidents/--crit-incidents)
# 1.2.1  2026-11-10  Fix per-device verbose in -eLogRate: snmpwalk -Oqn produces "OID VALUE"
#                    (space only), not "OID = VALUE"; drop -F' = ' from AWK in all 5 walks
# 1.3.0  2026-11-10  SNMP fallbacks for -eSys (hostname+version), -eRes (CPU/mem/disk via
#                    FAZ MIB .103.2.1.*), -eDevices (log device table .103.6.2.1.*: name,
#                    IP, ADOM, model, conn status, last log age); move _cmp_pct to global
# 1.3.1  2026-11-10  Fix -eDevices SNMP: add _snmp_get probe before walks so SNMP_TIMEOUT
#                    is detected instead of silently returning "0 devices connected [OK]"
# 1.3.2  2026-11-10  Replace string-concat _SNMPCMD/_SNMPWCMD with array-based _snmp_get()
#                    and _snmp_walk() functions (matches check_fortigate_health.sh); empty
#                    auth/priv passphrases no longer corrupt the snmpget command line;
#                    add USM 8-char minimum length check; use 2>/dev/null not 2>&1
# 1.4.0  2026-11-11  FMG proxy (--fmg-device, --print-fmg-device-paths) with separate
#                    _fmg_login() using "password" key; -eCert (local cert expiry via openssl,
#                    --warn-cert/--crit-cert/--blacklist-certs); -eAlerts (event-mgmt alertlogs
#                    via JSON-RPC v2, severity 1=crit/2=warn, --alert-rows)
# 1.5.0  2026-11-11  Add --https-verify/--https-ca-bundle (CURL_OPTS, like check_fortigate_health.sh);
#                    suppress "(via SNMP)" annotation in SNMP-only paths; -eLogwatch (FAZ log
#                    search via /logview/logsearch/{adom}, level/eventid/action filters)
# 1.5.1  2026-11-11  Fix -eCert: FAZ list endpoint returns empty PEM; now does per-cert GET for
#                    PEM data; add expired-cert CRIT path; use blacklist map (declare -A).
#                    Fix -eAlerts: drop server-side filter (invalid syntax -> JSON-RPC error);
#                    filter active alerts client-side; handle JSON-RPC v2 error shape (.error.code).
#                    Fix -eNTP: handle ntptype fortiguard vs custom; handle string/int status.
# 1.5.2 2026-11-14  -eLogwatch: add device name to log line ([devname] before datetime).

## VARIABLES
PROGNAME="${0##*/}"
PROGPATH="${0%/*}"
REVISION="1.5.2"
JQ="$(which jq 2>/dev/null)"
CURL="$(which curl 2>/dev/null)"
AWK="$(which awk 2>/dev/null)"
OPENSSL="$(which openssl 2>/dev/null)"
SNMPGET="$(which snmpget 2>/dev/null)"
SNMPWALK="$(which snmpwalk 2>/dev/null)"

status_ok="[OK]"
status_warn="[WARNING]"
status_crit="[CRITICAL]"
status_unkn="[UNKNOWN]"

exit_unknown() {
    echo "${status_unkn} - ${1}"
    exit 3
}

## FUNCTIONS
print_fmg_device_paths() {
    if [[ -z "${api_token}" && -z "${_faz_sess}" ]]; then
        exit_unknown "FortiManager API access required: provide -T (token) or -U/-P (user/pass)"
    fi
    local _fmg_body _resp
    if [[ -n "${api_token}" ]]; then
        _fmg_body='{"method":"get","id":1,"params":[{"url":"/dvmdb/device","option":["extra info"]}]}'
        _resp=$(${CURL} ${CURL_OPTS} -H "Content-Type: application/json" \
            -H "Authorization: Bearer ${api_token}" -X POST "${_FMG_API}" -d "${_fmg_body}" 2>/dev/null)
    else
        _fmg_body=$(${JQ} -n --arg session "${_faz_sess}" \
            '{"method":"get","id":1,"session":$session,"params":[{"url":"/dvmdb/device","option":["extra info"]}]}')
        _resp=$(${CURL} ${CURL_OPTS} -H "Content-Type: application/json" \
            -X POST "${_FMG_API}" -d "${_fmg_body}" 2>/dev/null)
    fi
    echo "${_resp}" | ${JQ} -r '
        ( .result[]?.data[]? // .result.data[]? | select(.name != null) ) |
        ( select(."extra info".adom != null and ."extra info".adom != "root") | "adom/" + ."extra info".adom + "/device/" + .name ),
        ( select(."extra info".adom == null or ."extra info".adom == "root") | "device/" + .name )
    ' 2>/dev/null
}

print_usage() {
    echo "Usage: ${PROGNAME} [-h] [-V] -H <host> { -T <token> | -U <user> -P <pass> } [options] [-eX]"
}

print_revision() {
    echo "${1} - v${2}"
}

print_help() {
    print_revision "${PROGNAME}" "${REVISION}"
    echo ""
    print_usage
cat << EOM


 This plugin monitors Fortinet FortiAnalyzer via the JSON-RPC API.
 Optionally supplements with SNMP for uptime monitoring.

Options:
 -h, --help
    Print detailed help screen
 -V, --version
    Print version information

 Connection:
 -H, --host <hostname|IP>
    FortiAnalyzer (or FortiManager when using --fmg-device) hostname or IP
 --https-port <port>
    HTTPS/API port (default: 443)
 --https-verify
    Require validation of the HTTPS server certificate
 --https-ca-bundle <file>
    CA bundle file to validate device API server certificate instead of system
    default. Implies --https-verify.

 Authentication (at least one required):
 -T, --token <token>
    API token (FAZ admin token, or FMG token when using --fmg-device)
 -U, --user <user>
    Username for session-based login
 -P, --pass <pass>
    Password for session-based login

 FortiManager proxy:
 --fmg-device <path>
    Proxy API access through FortiManager. -H/-T/-U/-P address the FMG.
    <path> is the FAZ device path in FMG, e.g. adom/root/device/FAZ-name
    Use --print-fmg-device-paths to discover available paths.
 --print-fmg-device-paths
    List available device paths from FMG and exit (requires -H and -T or -U/-P)

 SNMP (optional, for uptime):
 -SC, --snmp-community <community>
    SNMPv2c community string
 -u, --snmp-user <name>
    SNMPv3 security name (enables SNMPv3 mode)
 -l, --snmp-auth-proto <SHA|MD5>
    SNMPv3 auth protocol (default: SHA)
 -a, --snmp-auth-pass <pass>
    SNMPv3 auth passphrase
 -x, --snmp-priv-proto <AES|DES>
    SNMPv3 privacy protocol (default: AES)
 -X, --snmp-priv-pass <pass>
    SNMPv3 privacy passphrase
 -L, --snmp-sec-level <level>
    noAuthNoPriv | authNoPriv | authPriv (auto-detected if omitted)
 --snmp-port <port>
    SNMP UDP port (default: 161)

 Enable flags (opt-in; if any -eX given, only those checks run):
 -eSys, --enable-system
    System info: hostname, platform, version, HA mode, license status
 -eRes, --enable-resources
    CPU, memory, flash disk, and hard disk usage with thresholds
 -eHA, --enable-ha
    HA cluster mode and peer status
 -eDevices, --enable-devices
    Registered log-sending devices: connection state, platform, version, age
    --warn-devices-down <n>    WARNING when N+ devices disconnected (default: 1)
    --crit-devices-down <n>    CRITICAL when N+ devices disconnected (default: 1)
    --warn-dev-age <min>       WARNING when last log receipt older than N minutes (-1=off)
    --crit-dev-age <min>       CRITICAL when last log receipt older than N minutes (-1=off)
 -eADOMs, --enable-adoms
    ADOM list with log disk quota utilization
    --warn-adom-quota <pct>    WARNING when ADOM quota used % >= N (default: 80)
    --crit-adom-quota <pct>    CRITICAL when ADOM quota used % >= N (default: 90)
 -eTasks, --enable-tasks
    Recent background tasks: failed, error, stuck running
    --task-hours <n>           Only check tasks started within last N hours (default: 24)
    --warn-tasks-failed <n>    WARNING when N+ tasks failed (default: 1)
    --crit-tasks-failed <n>    CRITICAL when N+ tasks failed (default: 1)
    --task-stuck-minutes <n>   WARNING if running task exceeds N minutes (-1=off)
 -eLic, --enable-license
    License/contract expiry from FortiGuard
    --warn-lic <days>          WARNING when contract expires in < N days (default: 30)
    --crit-lic <days>          CRITICAL when contract expires in < N days (default: 15)
 -eCert, --enable-certs
    Local certificate expiry (requires openssl on the monitoring host)
    --warn-cert <days>         WARNING when cert expires in < N days (default: 30)
    --crit-cert <days>         CRITICAL when cert expires in < N days (default: 15)
    --blacklist-certs <list>   Comma-separated cert names to skip
 -eAlerts, --enable-alerts
    Active alerts from FAZ event management (critical/high severity)
    --alert-rows <n>           Max alerts to retrieve (default: 50)
 -eNTP, --enable-ntp
    NTP sync status and configured server list
    --no-ntp-warn              Suppress WARNING when NTP sync is disabled
 -eDNS, --enable-dns
    DNS server configuration (primary/secondary)
 -eSyslog, --enable-syslog
    Syslog forwarding destinations
    --no-syslog-warn           Suppress WARNING when no syslog destinations configured
 -eLogFwd, --enable-logfwd
    Log forwarding destinations and status
    --no-logfwd-warn           Suppress WARNING when no log forwarding configured
 -eLogRate, --enable-lograte
    Log reception and insertion rates (from FortiAnalyzer SNMP MIB, requires SNMP)
    --warn-loglag <pct>        WARNING when insert rate lags recv by >= N% (-1=off, default: -1)
    --crit-loglag <pct>        CRITICAL when insert rate lags recv by >= N% (-1=off, default: -1)
 -eLogwatch, --enable-logwatch
    Search recent FAZ logs for critical/error entries (requires API)
    --logwatch-adom <adom>     ADOM to search (default: root)
    --logwatch-type <type[,type...]>  Log category: event,traffic,app-ctrl,ips,virus,webfilter
                               (default: event)
    --logwatch-subtype <sub>   Subtype filter (applied to event and traffic logs)
    --logwatch-hours <n>       Look back N hours (default: 1)
    --logwatch-rows <n>        Max entries to scan across all pages (default: 200;
                               fetched in pages of 1000, FAZ API max per page)
    --logwatch-level <lvl>     Minimum severity (syslog RFC 5424 order, least->most severe):
                               debug,information,notice,warning(default),error,critical,alert,emergency
                               NOTE: in syslog order alert > critical > error (use 'critical'
                               to catch critical+alert+emergency, 'warning' for all important events)
    --logwatch-eventids "id1,id2,..."  Only alert on these event IDs (comma-sep)
    --logwatch-actions "a1,a2,..."     Only alert on these actions (comma-sep)
    --warn-logwatch <n>        WARNING threshold count (default: 1)
    --crit-logwatch <n>        CRITICAL threshold count (-1=level-based, default: -1)
 -eIncidents, --enable-incidents
    Active SOC incidents from FortiAnalyzer incident management (requires API)
    --warn-incidents <n>       WARNING when N+ open incidents (default: 1)
    --crit-incidents <n>       CRITICAL when N+ open incidents (-1=off, default: -1)
 -eUp, --enable-uptime
    System uptime (via SNMP if credentials provided, otherwise API Uptime field)
    --warn-reboot-minutes <n>  WARNING if uptime < N minutes (reboot detection; -1=off)
 -A, --enable-all
    Enable all checks (default when no -eX flag given)

 Disable flags (suppress individual checks when using -A):
 --disable-system      --disable-resources    --disable-ha
 --disable-devices     --disable-adoms        --disable-tasks
 --disable-license     --disable-certs        --disable-alerts
 --disable-ntp         --disable-dns          --disable-syslog
 --disable-logfwd      --disable-lograte      --disable-logwatch
 --disable-incidents   --disable-uptime

 Resource thresholds:
 -wCPU <pct>            CPU WARNING threshold % (default: 80)
 -cCPU <pct>            CPU CRITICAL threshold % (default: 90)
 -wMem <pct>            Memory WARNING threshold % (default: 80)
 -cMem <pct>            Memory CRITICAL threshold % (default: 90)
 --warn-disk <pct>      Hard disk WARNING threshold % (default: 80)
 --crit-disk <pct>      Hard disk CRITICAL threshold % (default: 90)
 --warn-flash <pct>     Flash disk WARNING threshold % (default: 80)
 --crit-flash <pct>     Flash disk CRITICAL threshold % (default: 90)
 --warn-io <pct>        Hard disk I/O utilization WARNING threshold % (default: 90)
 --crit-io <pct>        Hard disk I/O utilization CRITICAL threshold % (default: 95)

 Output options:
 --no-perfdata          Suppress performance data output
 -s, --silent           Only output problem lines
 -v, --verbose          Show all detail lines
 -d, --debug            Enable bash debug trace (set -x)

Example: ${PROGNAME} -H 10.0.0.1 -T MyApiToken -A
         ${PROGNAME} -H 10.0.0.1 -U admin -P secret -A
         ${PROGNAME} -H 10.0.0.1 -T MyApiToken -SC monitor -eRes -eUp
         ${PROGNAME} -H 10.0.0.1 -T MyApiToken -eDevices --warn-dev-age 60

EOM
}

## BEGIN
while [[ -n "${1}" ]]; do
    case "${1}" in
    -h|--help)      print_help; exit 0 ;;
    -V|--version)   print_revision "${PROGNAME}" "${REVISION}"; exit 0 ;;
    -H|--host)      shift; faz_host="${1}" ;;
    --https-port)   shift; faz_port="${1}" ;;
    --https-verify)        https_verify=1 ;;
    --https-ca-bundle) shift; https_ca_bundle="${1}" ;;
    -T|--token)     shift; api_token="${1}" ;;
    -U|--user)      shift; api_user="${1}" ;;
    -P|--pass)      shift; api_pass="${1}" ;;
    --fmg-device)   shift; fmg_device="${1}" ;;
    --print-fmg-device-paths) print_fmg_paths=1 ;;
    # SNMP
    -SC|--snmp-community)  shift; snmp_community="${1}" ;;
    -u|--snmp-user)        shift; snmp_user="${1}" ;;
    -l|--snmp-auth-proto)  shift; snmp_auth_proto="${1}" ;;
    -a|--snmp-auth-pass)   shift; snmp_auth_pass="${1}" ;;
    -x|--snmp-priv-proto)  shift; snmp_priv_proto="${1}" ;;
    -X|--snmp-priv-pass)   shift; snmp_priv_pass="${1}" ;;
    -L|--snmp-sec-level)   shift; snmp_sec_level="${1}" ;;
    --snmp-port)           shift; snmp_port="${1}" ;;
    # Enable flags
    -eSys|--enable-system)       enable_sys=1 ;;
    -eRes|--enable-resources)    enable_res=1 ;;
    -eHA|--enable-ha)            enable_ha=1 ;;
    -eDevices|--enable-devices)  enable_devices=1 ;;
    -eADOMs|--enable-adoms)      enable_adoms=1 ;;
    -eTasks|--enable-tasks)      enable_tasks=1 ;;
    -eLic|--enable-license)      enable_lic=1 ;;
    -eNTP|--enable-ntp)          enable_ntp=1 ;;
    -eDNS|--enable-dns)          enable_dns=1 ;;
    -eSyslog|--enable-syslog)    enable_syslog=1 ;;
    -eLogFwd|--enable-logfwd)      enable_logfwd=1 ;;
    -eLogRate|--enable-lograte)    enable_lograte=1 ;;
    -eLogwatch|--enable-logwatch)  enable_logwatch=1 ;;
    -eIncidents|--enable-incidents) enable_incidents=1 ;;
    -eCert|--enable-certs)         enable_cert=1 ;;
    -eAlerts|--enable-alerts)      enable_alerts=1 ;;
    -eUp|--enable-uptime)          enable_up=1 ;;
    -A|--enable-all)               enable_all=1 ;;
    # Disable flags
    --disable-system)    disable_sys=1 ;;
    --disable-resources) disable_res=1 ;;
    --disable-ha)        disable_ha=1 ;;
    --disable-devices)   disable_devices=1 ;;
    --disable-adoms)     disable_adoms=1 ;;
    --disable-tasks)     disable_tasks=1 ;;
    --disable-license)   disable_lic=1 ;;
    --disable-certs)     disable_cert=1 ;;
    --disable-alerts)    disable_alerts=1 ;;
    --disable-ntp)       disable_ntp=1 ;;
    --disable-dns)       disable_dns=1 ;;
    --disable-syslog)    disable_syslog=1 ;;
    --disable-logfwd)    disable_logfwd=1 ;;
    --disable-lograte)   disable_lograte=1 ;;
    --disable-logwatch)  disable_logwatch=1 ;;
    --disable-incidents) disable_incidents=1 ;;
    --disable-uptime)    disable_up=1 ;;
    # Log rate thresholds
    --warn-loglag)       shift; warn_loglag="${1}" ;;
    --crit-loglag)       shift; crit_loglag="${1}" ;;
    # Incident thresholds
    --warn-incidents)    shift; warn_incidents="${1}" ;;
    --crit-incidents)    shift; crit_incidents="${1}" ;;
    # Logwatch options
    --logwatch-adom)     shift; logwatch_adom="${1}" ;;
    --logwatch-uri)      shift; logwatch_uri="${1}" ;;
    --logwatch-type)     shift; logwatch_type="${1}" ;;
    --logwatch-subtype)  shift; logwatch_subtype="${1}" ;;
    --logwatch-hours)    shift; logwatch_hours="${1}" ;;
    --logwatch-rows)     shift; logwatch_rows="${1}" ;;
    --logwatch-level)    shift; logwatch_level="${1}" ;;
    --logwatch-eventids) shift; logwatch_eventids="${1}" ;;
    --logwatch-actions)  shift; logwatch_actions="${1}" ;;
    --warn-logwatch)     shift; warn_logwatch="${1}" ;;
    --crit-logwatch)     shift; crit_logwatch="${1}" ;;
    # Resource thresholds
    -wCPU)             shift; warn_cpu="${1}" ;;
    -cCPU)             shift; crit_cpu="${1}" ;;
    -wMem)             shift; warn_mem="${1}" ;;
    -cMem)             shift; crit_mem="${1}" ;;
    --warn-disk)       shift; warn_disk="${1}" ;;
    --crit-disk)       shift; crit_disk="${1}" ;;
    --warn-flash)      shift; warn_flash="${1}" ;;
    --crit-flash)      shift; crit_flash="${1}" ;;
    --warn-io)         shift; warn_io="${1}" ;;
    --crit-io)         shift; crit_io="${1}" ;;
    # Device thresholds
    --warn-devices-down)   shift; warn_dev_down="${1}" ;;
    --crit-devices-down)   shift; crit_dev_down="${1}" ;;
    --warn-dev-age)        shift; warn_dev_age="${1}" ;;
    --crit-dev-age)        shift; crit_dev_age="${1}" ;;
    # ADOM thresholds
    --warn-adom-quota)  shift; warn_adom_quota="${1}" ;;
    --crit-adom-quota)  shift; crit_adom_quota="${1}" ;;
    # Task options
    --task-hours)          shift; task_hours="${1}" ;;
    --warn-tasks-failed)   shift; warn_tasks_failed="${1}" ;;
    --crit-tasks-failed)   shift; crit_tasks_failed="${1}" ;;
    --task-stuck-minutes)  shift; task_stuck_minutes="${1}" ;;
    # License thresholds
    --warn-lic)  shift; warn_lic="${1}" ;;
    --crit-lic)  shift; crit_lic="${1}" ;;
    # Certificate thresholds
    --warn-cert)       shift; warn_cert="${1}" ;;
    --crit-cert)       shift; crit_cert="${1}" ;;
    --blacklist-certs|--blacklist-cert) shift; cert_blacklist="${1}" ;;
    # Alerts options
    --alert-rows)      shift; alert_rows="${1}" ;;
    # NTP / syslog / logfwd options
    --no-ntp-warn)     no_ntp_warn=1 ;;
    --no-syslog-warn)  no_syslog_warn=1 ;;
    --no-logfwd-warn)  no_logfwd_warn=1 ;;
    # Uptime
    --warn-reboot-minutes) shift; warn_reboot_minutes="${1}" ;;
    # Output
    --no-perfdata)  no_perfdata=1 ;;
    -s|--silent)    silent=1 ;;
    -v|--verbose)   verbose=1 ;;
    -d|--debug)     debug=1 ;;
    *)              exit_unknown "Unknown parameter: ${1}" ;;
    esac
    shift
done

# Mandatory checks
[[ -z "${JQ}" ]]   && exit_unknown "jq not found (install jq)"
[[ -z "${CURL}" ]] && exit_unknown "curl not found"
[[ -z "${faz_host}" ]] && exit_unknown "Host (-H) is required"

[[ -z "${api_token}" && -z "${api_user}" && -z "${snmp_community}" && -z "${snmp_user}" ]] && \
    exit_unknown "At least one of -T / -U -P / -SC / -u is required"

# Defaults
[[ -z "${faz_port}" ]]            && faz_port=443
[[ -z "${warn_cpu}" ]]            && warn_cpu=80
[[ -z "${crit_cpu}" ]]            && crit_cpu=90
[[ -z "${warn_mem}" ]]            && warn_mem=80
[[ -z "${crit_mem}" ]]            && crit_mem=90
[[ -z "${warn_disk}" ]]           && warn_disk=80
[[ -z "${crit_disk}" ]]           && crit_disk=90
[[ -z "${warn_flash}" ]]          && warn_flash=80
[[ -z "${crit_flash}" ]]          && crit_flash=90
[[ -z "${warn_io}" ]]             && warn_io=90
[[ -z "${crit_io}" ]]             && crit_io=95
[[ -z "${warn_dev_down}" ]]       && warn_dev_down=1
[[ -z "${crit_dev_down}" ]]       && crit_dev_down=1
[[ -z "${warn_dev_age}" ]]        && warn_dev_age=-1
[[ -z "${crit_dev_age}" ]]        && crit_dev_age=-1
[[ -z "${warn_adom_quota}" ]]     && warn_adom_quota=80
[[ -z "${crit_adom_quota}" ]]     && crit_adom_quota=90
[[ -z "${task_hours}" ]]          && task_hours=24
[[ -z "${warn_tasks_failed}" ]]   && warn_tasks_failed=1
[[ -z "${crit_tasks_failed}" ]]   && crit_tasks_failed=1
[[ -z "${task_stuck_minutes}" ]]  && task_stuck_minutes=-1
[[ -z "${warn_lic}" ]]            && warn_lic=30
[[ -z "${crit_lic}" ]]            && crit_lic=15
[[ -z "${warn_cert}" ]]           && warn_cert=30
[[ -z "${crit_cert}" ]]           && crit_cert=15
[[ -z "${alert_rows}" ]]          && alert_rows=50
[[ -z "${warn_loglag}" ]]         && warn_loglag=-1
[[ -z "${crit_loglag}" ]]         && crit_loglag=-1
[[ -z "${logwatch_adom}" ]]       && logwatch_adom="root"
[[ -z "${logwatch_uri}" ]]        && logwatch_uri="All_FortiGates"
[[ -z "${logwatch_type}" ]]       && logwatch_type="event"
[[ -z "${logwatch_subtype}" ]]    && logwatch_subtype=""
[[ -z "${logwatch_hours}" ]]      && logwatch_hours=1
[[ -z "${logwatch_rows}" ]]       && logwatch_rows=200
[[ -z "${logwatch_level}" ]]      && logwatch_level="warning"
[[ -z "${logwatch_eventids}" ]]   && logwatch_eventids=""
[[ -z "${logwatch_actions}" ]]    && logwatch_actions=""
[[ -z "${warn_logwatch}" ]]       && warn_logwatch=1
[[ -z "${crit_logwatch}" ]]       && crit_logwatch=-1
[[ -z "${warn_incidents}" ]]      && warn_incidents=1
[[ -z "${crit_incidents}" ]]      && crit_incidents=-1
[[ -z "${warn_reboot_minutes}" ]] && warn_reboot_minutes=-1
[[ -z "${snmp_auth_proto}" ]]     && snmp_auth_proto="SHA"
[[ -z "${snmp_priv_proto}" ]]     && snmp_priv_proto="AES"
[[ -z "${snmp_port}" ]]           && snmp_port=161

[[ -n "${debug}" ]] && { echo "Debug mode ON." 1>&2; set -x; }

# CURL options: use --insecure by default (self-signed certs); a CA bundle enables verification
if [[ -n "${https_ca_bundle}" ]]; then
    export CURL_CA_BUNDLE="${https_ca_bundle}"
    https_verify=1
fi
CURL_OPTS="--max-time 30"
[[ -z "${https_verify}" ]] && CURL_OPTS="--insecure ${CURL_OPTS}"
[[ -n "${debug}" ]] && CURL_OPTS="-v ${CURL_OPTS}" || CURL_OPTS="--silent ${CURL_OPTS}"

# Auto-enable all checks when no explicit -eX flag given
[[
    -z "${enable_sys}"     &&
    -z "${enable_res}"     &&
    -z "${enable_ha}"      &&
    -z "${enable_devices}" &&
    -z "${enable_adoms}"   &&
    -z "${enable_tasks}"   &&
    -z "${enable_lic}"     &&
    -z "${enable_cert}"    &&
    -z "${enable_alerts}"  &&
    -z "${enable_ntp}"     &&
    -z "${enable_dns}"     &&
    -z "${enable_syslog}"  &&
    -z "${enable_logfwd}"     &&
    -z "${enable_lograte}"    &&
    -z "${enable_logwatch}"   &&
    -z "${enable_incidents}"  &&
    -z "${enable_up}"         &&
    -z "${enable_all}"
]] && enable_all=1

# ---------------------------------------------------------------------------
# API session management
# ---------------------------------------------------------------------------
_faz_sess=""
_fmg_proxy=""
_FMG_API=""

# When FMG proxy is configured, -H addresses the FMG and all FAZ API calls
# are wrapped in FMG's /sys/proxy/json envelope. Inner FAZ JSON-RPC bodies
# carry no session field; FMG's proxy layer provides transparent auth to FAZ.
[[ -n "${fmg_device}" ]] && _fmg_proxy=1 && _FMG_API="https://${faz_host}:${faz_port}/jsonrpc"

faz_api_post() {
    local _body="${1}"
    if [[ -n "${_fmg_proxy}" ]]; then
        local _fmg_body
        if [[ -n "${api_token}" ]]; then
            _fmg_body=$(${JQ} -n --arg target "${fmg_device}" --argjson payload "${_body}" \
                '{"method":"exec","params":[{"url":"/sys/proxy/json","data":{"action":"post","resource":"/jsonrpc","target":[$target],"payload":$payload}}]}')
            ${CURL} ${CURL_OPTS} -H "Content-Type: application/json" \
                -H "Authorization: Bearer ${api_token}" \
                -X POST "${_FMG_API}" -d "${_fmg_body}" 2>/dev/null | ${JQ} '.result[0].data[0].response' 2>/dev/null
        else
            _fmg_body=$(${JQ} -n --arg session "${_faz_sess}" --arg target "${fmg_device}" --argjson payload "${_body}" \
                '{"method":"exec","session":$session,"params":[{"url":"/sys/proxy/json","data":{"action":"post","resource":"/jsonrpc","target":[$target],"payload":$payload}}]}')
            ${CURL} ${CURL_OPTS} -H "Content-Type: application/json" \
                -X POST "${_FMG_API}" -d "${_fmg_body}" 2>/dev/null | ${JQ} '.result[0].data[0].response' 2>/dev/null
        fi
    else
        ${CURL} ${CURL_OPTS} \
            -H "Content-Type: application/json" \
            ${api_token:+-H "Authorization: Bearer ${api_token}"} \
            -X POST "https://${faz_host}:${faz_port}/jsonrpc" \
            -d "${_body}" 2>/dev/null
    fi
}

faz_api_get() {
    local _url="${1}" _extra="${2:-}"
    local _sess_part=""
    # In FMG proxy mode the inner FAZ body carries no session; FMG handles auth
    [[ -z "${_fmg_proxy}" ]] && _sess_part=",\"session\":\"${_faz_sess}\""
    local _body
    if [[ -n "${_extra}" ]]; then
        _body="{\"method\":\"get\",\"params\":[{\"url\":\"${_url}\",${_extra}}],\"id\":1${_sess_part}}"
    else
        _body="{\"method\":\"get\",\"params\":[{\"url\":\"${_url}\"}],\"id\":1${_sess_part}}"
    fi
    faz_api_post "${_body}"
}

# JSON-RPC 2.0 variant (required for incidentmgmt, fortiview, event-mgmt endpoints)
faz_api2_get() {
    local _url="${1}" _extra="${2:-}"
    local _sess_part=""
    [[ -z "${_fmg_proxy}" ]] && _sess_part=",\"session\":\"${_faz_sess}\""
    local _body
    if [[ -n "${_extra}" ]]; then
        _body="{\"jsonrpc\":\"2.0\",\"method\":\"get\",\"params\":[{\"url\":\"${_url}\",${_extra}}],\"id\":1${_sess_part}}"
    else
        _body="{\"jsonrpc\":\"2.0\",\"method\":\"get\",\"params\":[{\"url\":\"${_url}\"}],\"id\":1${_sess_part}}"
    fi
    faz_api_post "${_body}"
}

faz_api2_add() {
    local _url="${1}" _extra="${2:-}"
    local _sess_part=""
    [[ -z "${_fmg_proxy}" ]] && _sess_part=",\"session\":\"${_faz_sess}\""
    local _body
    if [[ -n "${_extra}" ]]; then
        _body="{\"jsonrpc\":\"2.0\",\"method\":\"add\",\"params\":[{\"url\":\"${_url}\",${_extra}}],\"id\":1${_sess_part}}"
    else
        _body="{\"jsonrpc\":\"2.0\",\"method\":\"add\",\"params\":[{\"url\":\"${_url}\"}],\"id\":1${_sess_part}}"
    fi
    faz_api_post "${_body}"
}

faz_api2_delete() {
    local _url="${1}" _extra="${2:-}"
    local _sess_part=""
    [[ -z "${_fmg_proxy}" ]] && _sess_part=",\"session\":\"${_faz_sess}\""
    local _body
    if [[ -n "${_extra}" ]]; then
        _body="{\"jsonrpc\":\"2.0\",\"method\":\"delete\",\"params\":[{\"url\":\"${_url}\",${_extra}}],\"id\":1${_sess_part}}"
    else
        _body="{\"jsonrpc\":\"2.0\",\"method\":\"delete\",\"params\":[{\"url\":\"${_url}\"}],\"id\":1${_sess_part}}"
    fi
    faz_api_post "${_body}"
}

# Login with user/pass and cache session
_faz_login() {
    local _resp
    _resp=$(faz_api_post \
        "{\"method\":\"exec\",\"params\":[{\"url\":\"/sys/login/user\",\"data\":{\"user\":\"${api_user}\",\"passwd\":\"${api_pass}\"}}],\"id\":1}")
    local _code
    _code=$(echo "${_resp}" | ${JQ} -r '.result[0].status.code // -99' 2>/dev/null)
    if [[ "${_code}" != "0" ]]; then
        exit_unknown "Login to ${faz_host} failed (code ${_code}) - check credentials"
    fi
    _faz_sess=$(echo "${_resp}" | ${JQ} -r '.session // ""' 2>/dev/null)
}

_fmg_login() {
    local _resp _code
    # FMG login uses "password" key (not "passwd" like FAZ)
    _resp=$(${CURL} ${CURL_OPTS} -H "Content-Type: application/json" -X POST "${_FMG_API}" \
        -d "{\"method\":\"exec\",\"params\":[{\"url\":\"/sys/login/user\",\"data\":{\"user\":\"${api_user}\",\"password\":\"${api_pass}\"}}],\"id\":1}" 2>/dev/null)
    _code=$(echo "${_resp}" | ${JQ} -r '.result[0].status.code // -99' 2>/dev/null)
    if [[ "${_code}" != "0" ]]; then
        exit_unknown "Login to FortiManager ${faz_host} failed (code ${_code}) - check credentials"
    fi
    _faz_sess=$(echo "${_resp}" | ${JQ} -r '.session // ""' 2>/dev/null)
}

_faz_logout() {
    [[ -z "${_faz_sess}" ]] && return
    local _logout_url="https://${faz_host}:${faz_port}/jsonrpc"
    [[ -n "${_fmg_proxy}" ]] && _logout_url="${_FMG_API}"
    ${CURL} ${CURL_OPTS} --max-time 10 -H "Content-Type: application/json" -X POST "${_logout_url}" \
        -d "{\"method\":\"exec\",\"params\":[{\"url\":\"/sys/logout\"}],\"id\":1,\"session\":\"${_faz_sess}\"}" \
        > /dev/null 2>&1
}

# Establish API credentials
if [[ -n "${_fmg_proxy}" ]]; then
    if [[ -n "${api_user}" && -n "${api_pass}" ]]; then
        _fmg_login
        trap '_faz_logout' EXIT INT TERM
    elif [[ -z "${api_token}" ]]; then
        exit_unknown "FortiManager proxy requires -T (API token) or -U/-P (user/pass)"
    fi
elif [[ -n "${api_token}" ]]; then
    # Token auth: placeholder so faz_api_get includes session field when needed
    _faz_sess="${api_token}"
elif [[ -n "${api_user}" && -n "${api_pass}" ]]; then
    _faz_login
    trap '_faz_logout' EXIT INT TERM
fi

# --print-fmg-device-paths: list FAZ device paths in FMG and exit
if [[ -n "${print_fmg_paths}" ]]; then
    [[ -z "${_fmg_proxy}" ]] && exit_unknown "--print-fmg-device-paths requires --fmg-device to identify the FMG host"
    print_fmg_device_paths
    exit 0
fi

# ---------------------------------------------------------------------------
# SNMP helpers
# Uses arrays (not string concat) so empty passphrases don't corrupt the
# command line. Mirrors check_fortigate_health.sh conventions.
# ---------------------------------------------------------------------------
_snmp_avail=""
if [[ -n "${SNMPGET}" && ( -n "${snmp_user}" || -n "${snmp_community}" ) ]]; then
    if [[ -n "${snmp_user}" ]]; then
        # USM enforces minimum 8-char passphrases; fail early with a clear message
        if [[ -n "${snmp_auth_pass}" && ${#snmp_auth_pass} -lt 8 ]]; then
            echo "[UNKNOWN] - SNMPv3 auth passphrase too short (${#snmp_auth_pass} chars) - USM requires minimum 8 characters"
            exit 4
        fi
        if [[ -n "${snmp_priv_pass}" && ${#snmp_priv_pass} -lt 8 ]]; then
            echo "[UNKNOWN] - SNMPv3 priv passphrase too short (${#snmp_priv_pass} chars) - USM requires minimum 8 characters"
            exit 4
        fi
        _snmp_sec="${snmp_sec_level}"
        if [[ -z "${_snmp_sec}" ]]; then
            if [[ -n "${snmp_auth_pass}" && -n "${snmp_priv_pass}" ]]; then
                _snmp_sec="authPriv"
            elif [[ -n "${snmp_auth_pass}" ]]; then
                _snmp_sec="authNoPriv"
            else
                _snmp_sec="noAuthNoPriv"
            fi
        fi
        _snmp_avail=1
        _snmp_get() {
            local _oid="${1}" _raw _rc
            local -a _cmd=("${SNMPGET}" -v3 -u "${snmp_user}" -l "${_snmp_sec}" -Ovq -t 5 -r 1)
            [[ -n "${snmp_auth_pass}" ]] && _cmd+=(-a "${snmp_auth_proto:-SHA}" -A "${snmp_auth_pass}")
            [[ -n "${snmp_priv_pass}" ]] && _cmd+=(-x "${snmp_priv_proto:-AES}" -X "${snmp_priv_pass}")
            _raw=$("${_cmd[@]}" "${faz_host}:${snmp_port}" "${_oid}" 2>/dev/null | tr -d '"')
            _rc=$?
            [[ ${_rc} -ne 0 ]] && { echo "SNMP_TIMEOUT"; return 1; }
            [[ -z "${_raw}" ]] && { echo "SNMP_NODATA"; return 1; }
            echo "${_raw}"
        }
        _snmp_walk() {
            local -a _cmd=("${SNMPWALK}" -v3 -u "${snmp_user}" -l "${_snmp_sec}" -Oqn -t 5 -r 1)
            [[ -n "${snmp_auth_pass}" ]] && _cmd+=(-a "${snmp_auth_proto:-SHA}" -A "${snmp_auth_pass}")
            [[ -n "${snmp_priv_pass}" ]] && _cmd+=(-x "${snmp_priv_proto:-AES}" -X "${snmp_priv_pass}")
            "${_cmd[@]}" "${faz_host}:${snmp_port}" "$1" 2>/dev/null
        }
    else
        # SNMPv2c
        _snmp_avail=1
        _snmp_get() {
            local _oid="${1}" _raw _rc
            _raw=$("${SNMPGET}" -v2c -c "${snmp_community}" -Ovq -t 5 -r 1 \
                "${faz_host}:${snmp_port}" "${_oid}" 2>/dev/null | tr -d '"')
            _rc=$?
            [[ ${_rc} -ne 0 ]] && { echo "SNMP_TIMEOUT"; return 1; }
            [[ -z "${_raw}" ]] && { echo "SNMP_NODATA"; return 1; }
            echo "${_raw}"
        }
        _snmp_walk() {
            "${SNMPWALK}" -v2c -c "${snmp_community}" -Oqn -t 5 -r 1 \
                "${faz_host}:${snmp_port}" "$1" 2>/dev/null
        }
    fi
fi

# ---------------------------------------------------------------------------
# Retrieve system status (always needed for -eSys and baseline info)
# ---------------------------------------------------------------------------
_sys_resp=""
_faz_version="unknown"
_faz_hostname="${faz_host}"
_faz_serial="unknown"
_faz_platform="FortiAnalyzer"

if [[ -n "${api_token}" || -n "${api_user}" ]]; then
    _sys_resp=$(faz_api_get "/sys/status")
    _sys_code=$(echo "${_sys_resp}" | ${JQ} -r '.result[0].status.code // -99' 2>/dev/null)
    if [[ "${_sys_code}" != "0" ]]; then
        exit_unknown "Failed to retrieve system status from ${faz_host} (API code ${_sys_code}) - check credentials"
    fi
    _faz_hostname=$(echo "${_sys_resp}" | ${JQ} -r '.result[0].data.Hostname // "unknown"' 2>/dev/null)
    _faz_serial=$(echo "${_sys_resp}"   | ${JQ} -r '(.result[0].data."Serial Number") // "unknown"' 2>/dev/null)
    _faz_platform=$(echo "${_sys_resp}" | ${JQ} -r '(.result[0].data."Platform Full Name" // .result[0].data."Platform Type" // "FortiAnalyzer")' 2>/dev/null)
    _faz_version=$(echo "${_sys_resp}"  | ${JQ} -r '.result[0].data.Version // "unknown"' 2>/dev/null)
fi

# ---------------------------------------------------------------------------
# Output buffers
# ---------------------------------------------------------------------------
faz_output=""
faz_problem_output=""
faz_perf=""
_exit_code=0
_update_exit() { [[ "${1}" -gt "${_exit_code}" ]] && _exit_code="${1}"; }

# Whitespace separator for inline detail (verbose adds section headers instead)
_fws=" - "

# Shared percentage threshold helper (used by -eRes on both API and SNMP paths)
_cmp_pct() {
    local _v="${1}" _w="${2}" _c="${3}"
    echo "${_v} ${_w} ${_c}" | ${AWK} '{
        if ($1+0 >= $3+0) print "crit"
        else if ($1+0 >= $2+0) print "warn"
        else print "ok"
    }'
}

# Parse a PEM string (possibly bundled with private key) and emit expiry info.
# Usage: _cert_check_pem <label> <pem_raw>
# Sets globals: _cc_sev, _cc_detail_line, _cc_days (empty on parse failure)
# Caller must increment counters and call _update_exit.
_cert_check_pem() {
    local _label="${1}" _pem_raw="${2}"
    local _pem_norm _cert_only _exp_str _exp_ts _days _tmpf

    if [[ -z "${_pem_raw}" ]]; then
        _cc_sev="${status_ok}"
        _cc_detail_line="\\_ ${status_ok} ${_label}: present (no PEM data)\n"
        _cc_days=""
        return 0
    fi

    # jq -r already expands JSON \n -> real newlines; printf '%b' handles double-escaped \\n.
    # Strip \r regardless (CRLF from some FAZ versions).
    _pem_norm=$(printf '%b' "${_pem_raw}" | tr -d '\r')
    # Extract only the CERTIFICATE block; local certs bundle an encrypted private key that
    # causes openssl x509 to fail when the private key section appears before the cert.
    _cert_only=$(printf '%s\n' "${_pem_norm}" | sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p')

    if [[ -z "${_cert_only}" ]]; then
        _cc_sev="${status_unkn}"
        _cc_detail_line="\\_ ${status_unkn} ${_label}: no CERTIFICATE section found in PEM data\n"
        _cc_days=""
        return 1
    fi

    # Write to temp file for reliable openssl parsing (stdin piping can fail with some
    # shell/openssl combinations when the PEM content contains non-standard line endings)
    _tmpf=$(mktemp /tmp/.faz_cert_XXXXXX.pem 2>/dev/null) || {
        _cc_sev="${status_unkn}"
        _cc_detail_line="\\_ ${status_unkn} ${_label}: cannot create temp file\n"
        _cc_days=""
        return 1
    }
    printf '%s\n' "${_cert_only}" > "${_tmpf}"

    if [[ -n "${debug}" ]]; then
        printf '### cert_check_pem [%s] extracted PEM (first 5 lines):\n' "${_label}" >&2
        head -5 "${_tmpf}" >&2
        printf '### wc: %s\n' "$(wc -l < "${_tmpf}")" >&2
    fi

    _exp_str=$(${OPENSSL} x509 -noout -enddate -in "${_tmpf}" 2>/dev/null | sed 's/notAfter=//')
    rm -f "${_tmpf}"

    if [[ -z "${_exp_str}" ]]; then
        _cc_sev="${status_unkn}"
        _cc_detail_line="\\_ ${status_unkn} ${_label}: cannot parse certificate (openssl failed)\n"
        _cc_days=""
        return 1
    fi

    _exp_ts=$(date -d "${_exp_str}" +%s 2>/dev/null)
    if [[ -z "${_exp_ts}" ]]; then
        _cc_sev="${status_unkn}"
        _cc_detail_line="\\_ ${status_unkn} ${_label}: cannot parse expiry date (${_exp_str})\n"
        _cc_days=""
        return 1
    fi

    _days=$(( (_exp_ts - _today_ts) / 86400 ))
    _cc_days="${_days}"

    if [[ "${_days}" -lt 0 ]]; then
        _cc_sev="${status_crit}"
    elif (( _days <= crit_cert )) 2>/dev/null; then
        _cc_sev="${status_crit}"
    elif (( _days <= warn_cert )) 2>/dev/null; then
        _cc_sev="${status_warn}"
    else
        _cc_sev="${status_ok}"
    fi
    _cc_detail_line="\\_ ${_cc_sev} ${_label}: expires ${_exp_str} (${_days} days)\n"
    return 0
}

# FAZ system MIB root (enterprises.12356.103.2.1)
_FAZ_SYS_OID=".1.3.6.1.4.1.12356.103.2.1"
# FAZ log device table root (enterprises.12356.103.6.2.1)
_FAZ_DEV_OID=".1.3.6.1.4.1.12356.103.6.2.1"

# ---------------------------------------------------------------------------
# -eSys: System Info
# ---------------------------------------------------------------------------
if [[ ( -n "${enable_sys}" || -n "${enable_all}" ) && -z "${disable_sys}" ]] && \
   [[ -n "${api_token}" || -n "${api_user}" || -n "${_snmp_avail}" || -n "${enable_sys}" ]]; then
    if [[ -n "${verbose}" ]]; then
        faz_output+="System Info:\n---------------------------------------\n"
    fi

    if [[ -z "${api_token}" && -z "${api_user}" ]]; then
        if [[ -n "${_snmp_avail}" ]]; then
            _snmp_sysname=$(_snmp_get ".1.3.6.1.2.1.1.5.0")
            _snmp_ver=$(_snmp_get "${_FAZ_SYS_OID}.7.0")
            if [[ "${_snmp_sysname}" == SNMP_* ]]; then
                faz_output+="${status_unkn} - System: SNMP ${_snmp_sysname}\n"
            else
                _sys_line="${status_ok} - System:${_fws}${_snmp_sysname:-${faz_host}} ${_snmp_ver}"
                faz_output+="${_sys_line}\n"
                if [[ -n "${verbose}" ]]; then
                    faz_output+="\\_ ${status_ok} Hostname: ${_snmp_sysname}\n"
                    faz_output+="\\_ ${status_ok} Version:  ${_snmp_ver}\n"
                fi
            fi
        else
            [[ -n "${enable_sys}" ]] && faz_output+="${status_unkn} - System: API credentials required\n"
        fi
    else
        _lic_status=$(echo "${_sys_resp}" | ${JQ} -r '(.result[0].data."License Status") // "unknown"' 2>/dev/null)
        _faz_major=$(echo "${_sys_resp}"  | ${JQ} -r '.result[0].data.Major // ""' 2>/dev/null)
        _faz_minor=$(echo "${_sys_resp}"  | ${JQ} -r '.result[0].data.Minor // ""' 2>/dev/null)
        _faz_patch=$(echo "${_sys_resp}"  | ${JQ} -r '.result[0].data.Patch // ""' 2>/dev/null)
        _faz_build=$(echo "${_sys_resp}"  | ${JQ} -r '.result[0].data.Build // ""' 2>/dev/null)

        # HA mode
        _ha_resp=$(faz_api_get "/cli/global/system/ha" \
            "\"fields\":[\"mode\",\"group-name\",\"group-id\",\"priority\",\"preferred-role\"]")
        _ha_mode=$(echo "${_ha_resp}" | ${JQ} -r '.result[0].data.mode // 1' 2>/dev/null)
        case "${_ha_mode}" in
            1) _ha_str="Standalone" ;;
            2) _ha_str="A-P Cluster" ;;
            3) _ha_str="A-A Cluster" ;;
            *) _ha_str="HA mode ${_ha_mode}" ;;
        esac

        _sys_line="${status_ok} - System:${_fws}${_faz_hostname} ${_faz_platform} v${_faz_major}.${_faz_minor}.${_faz_patch}-build${_faz_build} (${_ha_str})"
        faz_output+="${_sys_line}\n"
        if [[ -n "${verbose}" ]]; then
            faz_output+="\\_ ${status_ok} Serial:    ${_faz_serial}\n"
            faz_output+="\\_ ${status_ok} Version:   ${_faz_version}\n"
            faz_output+="\\_ ${status_ok} HA Mode:   ${_ha_str}\n"
            _lic_sev="${status_ok}"
            [[ "${_lic_status,,}" != "valid" && "${_lic_status}" != "unknown" ]] && _lic_sev="${status_warn}"
            faz_output+="\\_ ${_lic_sev} License:   ${_lic_status}\n"
        fi
    fi

    if [[ -n "${verbose}" ]]; then
        faz_output+="---------------------------------------\n\n"
    fi
fi

# ---------------------------------------------------------------------------
# -eRes: Resource Usage
# ---------------------------------------------------------------------------
if [[ ( -n "${enable_res}" || -n "${enable_all}" ) && -z "${disable_res}" ]] && \
   [[ -n "${api_token}" || -n "${api_user}" || -n "${_snmp_avail}" || -n "${enable_res}" ]]; then
    if [[ -n "${verbose}" ]]; then
        faz_output+="System Resources:\n---------------------------------------\n"
    fi

    if [[ -z "${api_token}" && -z "${api_user}" ]]; then
        if [[ -n "${_snmp_avail}" ]]; then
            _snmp_cpu=$(_snmp_get "${_FAZ_SYS_OID}.1.0")
            _snmp_mem_used=$(_snmp_get "${_FAZ_SYS_OID}.2.0")
            _snmp_mem_total=$(_snmp_get "${_FAZ_SYS_OID}.3.0")
            _snmp_disk_used=$(_snmp_get "${_FAZ_SYS_OID}.4.0")
            _snmp_disk_total=$(_snmp_get "${_FAZ_SYS_OID}.5.0")
            if [[ "${_snmp_cpu}" == SNMP_* ]]; then
                faz_output+="${status_unkn} - Resources: SNMP ${_snmp_cpu}\n"
            else
                _cpu_n="${_snmp_cpu}"
                _mem_pct=""
                if [[ "${_snmp_mem_used}" =~ ^[0-9]+$ && "${_snmp_mem_total}" =~ ^[0-9]+$ && "${_snmp_mem_total}" -gt 0 ]]; then
                    _mem_pct=$(echo "${_snmp_mem_used} ${_snmp_mem_total}" | ${AWK} '{printf "%.1f", $1*100/$2}')
                fi
                _hd_pct=""
                if [[ "${_snmp_disk_used}" =~ ^[0-9]+$ && "${_snmp_disk_total}" =~ ^[0-9]+$ && "${_snmp_disk_total}" -gt 0 ]]; then
                    _hd_pct=$(echo "${_snmp_disk_used} ${_snmp_disk_total}" | ${AWK} '{printf "%.1f", $1*100/$2}')
                fi

                _res_sev="${status_ok}"; _cpu_sev="${status_ok}"; _mem_sev="${status_ok}"; _hd_sev="${status_ok}"
                if [[ -n "${_cpu_n}" ]]; then
                    case "$(_cmp_pct "${_cpu_n}" "${warn_cpu}" "${crit_cpu}")" in
                        crit) _cpu_sev="${status_crit}"; _update_exit 2; _res_sev="${status_crit}" ;;
                        warn) _cpu_sev="${status_warn}"; _update_exit 1
                              [[ "${_res_sev}" == "${status_ok}" ]] && _res_sev="${status_warn}" ;;
                    esac
                fi
                if [[ -n "${_mem_pct}" ]]; then
                    case "$(_cmp_pct "${_mem_pct}" "${warn_mem}" "${crit_mem}")" in
                        crit) _mem_sev="${status_crit}"; _update_exit 2; _res_sev="${status_crit}" ;;
                        warn) _mem_sev="${status_warn}"; _update_exit 1
                              [[ "${_res_sev}" == "${status_ok}" ]] && _res_sev="${status_warn}" ;;
                    esac
                fi
                if [[ -n "${_hd_pct}" ]]; then
                    case "$(_cmp_pct "${_hd_pct}" "${warn_disk}" "${crit_disk}")" in
                        crit) _hd_sev="${status_crit}"; _update_exit 2; _res_sev="${status_crit}" ;;
                        warn) _hd_sev="${status_warn}"; _update_exit 1
                              [[ "${_res_sev}" == "${status_ok}" ]] && _res_sev="${status_warn}" ;;
                    esac
                fi

                _res_line="${_res_sev} - Resources:${_fws}"
                [[ -n "${_cpu_n}" ]]   && _res_line+="CPU ${_cpu_n}%"
                [[ -n "${_mem_pct}" ]] && _res_line+=", Memory ${_mem_pct}%"
                [[ -n "${_hd_pct}" ]]  && _res_line+=", Disk ${_hd_pct}%"
                    faz_output+="${_res_line}\n"
                [[ "${_res_sev}" != "${status_ok}" ]] && faz_problem_output+="${_res_line}\n"

                if [[ -n "${verbose}" ]]; then
                    [[ -n "${_cpu_n}" ]] && faz_output+="\\_ ${_cpu_sev} CPU:    ${_cpu_n}% (warn: ${warn_cpu}%, crit: ${crit_cpu}%)\n"
                    if [[ -n "${_mem_pct}" && "${_snmp_mem_used}" =~ ^[0-9]+$ ]]; then
                        _mem_used_mb=$(( _snmp_mem_used / 1024 ))
                        _mem_total_mb=$(( _snmp_mem_total / 1024 ))
                        faz_output+="\\_ ${_mem_sev} Memory: ${_mem_pct}% ${_mem_used_mb}MB / ${_mem_total_mb}MB (warn: ${warn_mem}%, crit: ${crit_mem}%)\n"
                    fi
                    if [[ -n "${_hd_pct}" ]]; then
                        faz_output+="\\_ ${_hd_sev} Disk:   ${_hd_pct}% ${_snmp_disk_used}MB / ${_snmp_disk_total}MB (warn: ${warn_disk}%, crit: ${crit_disk}%)\n"
                    fi
                fi

                if [[ -z "${no_perfdata}" ]]; then
                    [[ -n "${_cpu_n}" ]]   && faz_perf+=" cpu=${_cpu_n}%;${warn_cpu};${crit_cpu};0;100"
                    [[ -n "${_mem_pct}" ]] && faz_perf+=" mem=${_mem_pct}%;${warn_mem};${crit_mem};0;100"
                    [[ -n "${_hd_pct}" ]]  && faz_perf+=" disk=${_hd_pct}%;${warn_disk};${crit_disk};0;100"
                    [[ "${_snmp_mem_used}" =~ ^[0-9]+$ ]]  && faz_perf+=" mem_used=${_snmp_mem_used}KB"
                    [[ "${_snmp_disk_used}" =~ ^[0-9]+$ ]] && faz_perf+=" disk_used=$(( _snmp_disk_used * 1024 ))KB"
                fi
            fi
        else
            [[ -n "${enable_res}" ]] && faz_output+="${status_unkn} - Resources: API credentials required\n"
        fi
    else
        _perf_resp=$(faz_api_get "/cli/global/system/performance")
        _perf_code=$(echo "${_perf_resp}" | ${JQ} -r '.result[0].status.code // -99' 2>/dev/null)

        if [[ "${_perf_code}" != "0" ]]; then
            faz_output+="${status_unkn} - Resources: cannot retrieve performance data (API code ${_perf_code})\n"
        else
            # CPU: "Used" field like "11.3%"
            _cpu_str=$(echo "${_perf_resp}" | ${JQ} -r '.result[0].data.CPU.Used // ""' 2>/dev/null)
            _cpu_n=$(echo "${_cpu_str}" | grep -oE '[0-9]+(\.[0-9]+)?' | head -1)

            # Memory: "Used" field like "7,328,416 KB 66.8%"
            _mem_str=$(echo "${_perf_resp}" | ${JQ} -r '.result[0].data.Memory.Used // ""' 2>/dev/null)
            _mem_total_str=$(echo "${_perf_resp}" | ${JQ} -r '.result[0].data.Memory.Total // ""' 2>/dev/null)
            _mem_pct=$(echo "${_mem_str}" | grep -oE '[0-9]+\.[0-9]+%' | tr -d '%')
            [[ -z "${_mem_pct}" ]] && _mem_pct=$(echo "${_mem_str}" | grep -oE '[0-9]+%' | tr -d '%' | head -1)
            _mem_used_kb=$(echo "${_mem_str}" | grep -oE '[0-9,]+' | head -1 | tr -d ',')
            _mem_total_kb=$(echo "${_mem_total_str}" | grep -oE '[0-9,]+' | head -1 | tr -d ',')

            # Hard Disk: "Used" field like "7,371,004 KB 72.2%"
            _hd_str=$(echo "${_perf_resp}" | ${JQ} -r '(.result[0].data."Hard Disk".Used) // ""' 2>/dev/null)
            _hd_total_str=$(echo "${_perf_resp}" | ${JQ} -r '(.result[0].data."Hard Disk".Total) // ""' 2>/dev/null)
            _hd_pct=$(echo "${_hd_str}" | grep -oE '[0-9]+\.[0-9]+%' | tr -d '%')
            [[ -z "${_hd_pct}" ]] && _hd_pct=$(echo "${_hd_str}" | grep -oE '[0-9]+%' | tr -d '%' | head -1)
            _hd_used_kb=$(echo "${_hd_str}" | grep -oE '[0-9,]+' | head -1 | tr -d ',')
            _hd_total_kb=$(echo "${_hd_total_str}" | grep -oE '[0-9,]+' | head -1 | tr -d ',')

            # Flash Disk
            _fl_str=$(echo "${_perf_resp}" | ${JQ} -r '(.result[0].data."Flash Disk".Used) // ""' 2>/dev/null)
            _fl_total_str=$(echo "${_perf_resp}" | ${JQ} -r '(.result[0].data."Flash Disk".Total) // ""' 2>/dev/null)
            _fl_pct=$(echo "${_fl_str}" | grep -oE '[0-9]+\.[0-9]+%' | tr -d '%')
            [[ -z "${_fl_pct}" ]] && _fl_pct=$(echo "${_fl_str}" | grep -oE '[0-9]+%' | tr -d '%' | head -1)

            # Hard Disk IOStat
            _hd_io_util=$(echo "${_perf_resp}" | ${JQ} -r '(.result[0].data."Hard Disk".IOStat."%util") // ""' 2>/dev/null)
            _hd_io_rkbps=$(echo "${_perf_resp}" | ${JQ} -r '(.result[0].data."Hard Disk".IOStat."r_kB/s") // ""' 2>/dev/null)
            _hd_io_wkbps=$(echo "${_perf_resp}" | ${JQ} -r '(.result[0].data."Hard Disk".IOStat."w_kB/s") // ""' 2>/dev/null)
            _hd_io_rtps=$(echo "${_perf_resp}" | ${JQ} -r '(.result[0].data."Hard Disk".IOStat."r_tps") // ""' 2>/dev/null)
            _hd_io_wtps=$(echo "${_perf_resp}" | ${JQ} -r '(.result[0].data."Hard Disk".IOStat."w_tps") // ""' 2>/dev/null)
            _hd_io_wait=$(echo "${_perf_resp}" | ${JQ} -r '(.result[0].data."Hard Disk".IOStat."wait_ms") // ""' 2>/dev/null)

            # Determine severities
            _res_sev="${status_ok}"
            _cpu_sev="${status_ok}"
            _mem_sev="${status_ok}"
            _hd_sev="${status_ok}"
            _fl_sev="${status_ok}"

            if [[ -n "${_cpu_n}" ]]; then
                case "$(_cmp_pct "${_cpu_n}" "${warn_cpu}" "${crit_cpu}")" in
                    crit) _cpu_sev="${status_crit}"; _update_exit 2; _res_sev="${status_crit}" ;;
                    warn) _cpu_sev="${status_warn}"; _update_exit 1
                          [[ "${_res_sev}" == "${status_ok}" ]] && _res_sev="${status_warn}" ;;
                esac
            fi
            if [[ -n "${_mem_pct}" ]]; then
                case "$(_cmp_pct "${_mem_pct}" "${warn_mem}" "${crit_mem}")" in
                    crit) _mem_sev="${status_crit}"; _update_exit 2; _res_sev="${status_crit}" ;;
                    warn) _mem_sev="${status_warn}"; _update_exit 1
                          [[ "${_res_sev}" == "${status_ok}" ]] && _res_sev="${status_warn}" ;;
                esac
            fi
            if [[ -n "${_hd_pct}" ]]; then
                case "$(_cmp_pct "${_hd_pct}" "${warn_disk}" "${crit_disk}")" in
                    crit) _hd_sev="${status_crit}"; _update_exit 2; _res_sev="${status_crit}" ;;
                    warn) _hd_sev="${status_warn}"; _update_exit 1
                          [[ "${_res_sev}" == "${status_ok}" ]] && _res_sev="${status_warn}" ;;
                esac
            fi
            if [[ -n "${_fl_pct}" ]]; then
                case "$(_cmp_pct "${_fl_pct}" "${warn_flash}" "${crit_flash}")" in
                    crit) _fl_sev="${status_crit}"; _update_exit 2; _res_sev="${status_crit}" ;;
                    warn) _fl_sev="${status_warn}"; _update_exit 1
                          [[ "${_res_sev}" == "${status_ok}" ]] && _res_sev="${status_warn}" ;;
                esac
            fi
            _hd_io_sev="${status_ok}"
            if [[ -n "${_hd_io_util}" ]]; then
                case "$(_cmp_pct "${_hd_io_util}" "${warn_io}" "${crit_io}")" in
                    crit) _hd_io_sev="${status_crit}"; _update_exit 2; _res_sev="${status_crit}" ;;
                    warn) _hd_io_sev="${status_warn}"; _update_exit 1
                          [[ "${_res_sev}" == "${status_ok}" ]] && _res_sev="${status_warn}" ;;
                esac
            fi

            _res_line="${_res_sev} - Resources:${_fws}"
            [[ -n "${_cpu_n}" ]]  && _res_line+="CPU ${_cpu_n}%"
            [[ -n "${_mem_pct}" ]] && _res_line+=", Memory ${_mem_pct}%"
            [[ -n "${_hd_pct}" ]]  && _res_line+=", Disk ${_hd_pct}%"
            [[ -n "${_fl_pct}" ]]  && _res_line+=", Flash ${_fl_pct}%"
            [[ -n "${_hd_io_util}" ]] && _res_line+=", Disk I/O ${_hd_io_util}%"

            faz_output+="${_res_line}\n"
            [[ "${_res_sev}" != "${status_ok}" ]] && faz_problem_output+="${_res_line}\n"

            if [[ -n "${verbose}" ]]; then
                [[ -n "${_cpu_n}" ]]  && faz_output+="\\_ ${_cpu_sev} CPU:        ${_cpu_n}% (warn: ${warn_cpu}%, crit: ${crit_cpu}%)\n"
                if [[ -n "${_mem_pct}" ]]; then
                    _mem_used_mb=$(( _mem_used_kb / 1024 )) 2>/dev/null
                    _mem_total_mb=$(( _mem_total_kb / 1024 )) 2>/dev/null
                    faz_output+="\\_ ${_mem_sev} Memory:     ${_mem_pct}% ${_mem_used_mb}MB / ${_mem_total_mb}MB (warn: ${warn_mem}%, crit: ${crit_mem}%)\n"
                fi
                if [[ -n "${_hd_pct}" ]]; then
                    _hd_used_mb=$(( _hd_used_kb / 1024 )) 2>/dev/null
                    _hd_total_mb=$(( _hd_total_kb / 1024 )) 2>/dev/null
                    faz_output+="\\_ ${_hd_sev} Hard Disk:  ${_hd_pct}% ${_hd_used_mb}MB / ${_hd_total_mb}MB (warn: ${warn_disk}%, crit: ${crit_disk}%)\n"
                fi
                [[ -n "${_fl_pct}" ]] && faz_output+="\\_ ${_fl_sev} Flash Disk: ${_fl_pct}% (warn: ${warn_flash}%, crit: ${crit_flash}%)\n"
                if [[ -n "${_hd_io_util}" ]]; then
                    _hd_io_str="util=${_hd_io_util}%"
                    [[ -n "${_hd_io_rkbps}" ]] && _hd_io_str+=" r=${_hd_io_rkbps}kB/s"
                    [[ -n "${_hd_io_wkbps}" ]] && _hd_io_str+=" w=${_hd_io_wkbps}kB/s"
                    [[ -n "${_hd_io_rtps}" ]]   && _hd_io_str+=" rtps=${_hd_io_rtps}"
                    [[ -n "${_hd_io_wtps}" ]]   && _hd_io_str+=" wtps=${_hd_io_wtps}"
                    [[ -n "${_hd_io_wait}" ]]   && _hd_io_str+=" wait=${_hd_io_wait}ms"
                    faz_output+="\\_ ${_hd_io_sev} HDD IOStat:  ${_hd_io_str} (warn: ${warn_io}%, crit: ${crit_io}%)\n"
                fi
            fi

            if [[ -z "${no_perfdata}" ]]; then
                [[ -n "${_cpu_n}" ]]  && faz_perf+=" cpu=${_cpu_n}%;${warn_cpu};${crit_cpu};0;100"
                [[ -n "${_mem_pct}" ]] && faz_perf+=" mem=${_mem_pct}%;${warn_mem};${crit_mem};0;100"
                [[ -n "${_hd_pct}" ]]  && faz_perf+=" disk=${_hd_pct}%;${warn_disk};${crit_disk};0;100"
                [[ -n "${_fl_pct}" ]]  && faz_perf+=" flash=${_fl_pct}%;${warn_flash};${crit_flash};0;100"
                [[ -n "${_mem_used_kb}" && "${_mem_used_kb}" =~ ^[0-9]+$ ]] && \
                    faz_perf+=" mem_used=${_mem_used_kb}KB"
                [[ -n "${_hd_used_kb}" && "${_hd_used_kb}" =~ ^[0-9]+$ ]] && \
                    faz_perf+=" disk_used=${_hd_used_kb}KB"
                [[ -n "${_hd_io_util}" ]]  && faz_perf+=" disk_io_util=${_hd_io_util}%;${warn_io};${crit_io};0;100"
                [[ -n "${_hd_io_rkbps}" ]] && faz_perf+=" disk_read_kbps=${_hd_io_rkbps}"
                [[ -n "${_hd_io_wkbps}" ]] && faz_perf+=" disk_write_kbps=${_hd_io_wkbps}"
                [[ -n "${_hd_io_wait}" ]]  && faz_perf+=" disk_wait_ms=${_hd_io_wait}"
            fi
        fi
    fi

    if [[ -n "${verbose}" ]]; then
        faz_output+="---------------------------------------\n\n"
    fi
fi

# ---------------------------------------------------------------------------
# -eHA: High Availability
# ---------------------------------------------------------------------------
if [[ ( -n "${enable_ha}" || -n "${enable_all}" ) && -z "${disable_ha}" ]] && \
   [[ -n "${api_token}" || -n "${api_user}" || -n "${enable_ha}" ]]; then
    if [[ -n "${verbose}" ]]; then
        faz_output+="High Availability:\n---------------------------------------\n"
    fi

    if [[ -z "${api_token}" && -z "${api_user}" ]]; then
        [[ -n "${enable_ha}" ]] && faz_output+="${status_unkn} - HA: API credentials required\n"
    else
        _ha_resp=$(faz_api_get "/cli/global/system/ha")
        _ha_code=$(echo "${_ha_resp}" | ${JQ} -r '.result[0].status.code // -99' 2>/dev/null)

        if [[ "${_ha_code}" != "0" ]]; then
            faz_output+="${status_unkn} - HA: cannot retrieve HA config (API code ${_ha_code})\n"
        else
            _ha_mode=$(echo "${_ha_resp}" | ${JQ} -r '.result[0].data.mode // 1' 2>/dev/null)
            _ha_grpname=$(echo "${_ha_resp}" | ${JQ} -r '(.result[0].data."group-name") // ""' 2>/dev/null)
            _ha_prio=$(echo "${_ha_resp}"    | ${JQ} -r '.result[0].data.priority // 100' 2>/dev/null)
            _ha_role=$(echo "${_ha_resp}"    | ${JQ} -r '(.result[0].data."preferred-role") // 0' 2>/dev/null)

            case "${_ha_mode}" in
                1) _ha_mode_str="Standalone" ;;
                2) _ha_mode_str="A-P" ;;
                3) _ha_mode_str="A-A" ;;
                *) _ha_mode_str="Unknown (${_ha_mode})" ;;
            esac
            case "${_ha_role}" in
                0) _ha_role_str="Primary" ;;
                1) _ha_role_str="Secondary" ;;
                *) _ha_role_str="Role ${_ha_role}" ;;
            esac

            _ha_line="${status_ok} - HA:${_fws}${_ha_mode_str}"
            [[ "${_ha_mode}" -gt 1 && -n "${_ha_grpname}" ]] && _ha_line+=" / group: ${_ha_grpname}"
            [[ "${_ha_mode}" -gt 1 ]] && _ha_line+=" / role: ${_ha_role_str} / priority: ${_ha_prio}"

            faz_output+="${_ha_line}\n"
            if [[ -n "${verbose}" && "${_ha_mode}" -gt 1 ]]; then
                faz_output+="\\_ ${status_ok} Mode:     ${_ha_mode_str}\n"
                faz_output+="\\_ ${status_ok} Group:    ${_ha_grpname:-<unnamed>}\n"
                faz_output+="\\_ ${status_ok} Role:     ${_ha_role_str}\n"
                faz_output+="\\_ ${status_ok} Priority: ${_ha_prio}\n"
            fi
        fi
    fi

    if [[ -n "${verbose}" ]]; then
        faz_output+="---------------------------------------\n\n"
    fi
fi

# ---------------------------------------------------------------------------
# -eDevices: Registered Log Devices
# ---------------------------------------------------------------------------
if [[ ( -n "${enable_devices}" || -n "${enable_all}" ) && -z "${disable_devices}" ]] && \
   [[ -n "${api_token}" || -n "${api_user}" || -n "${_snmp_avail}" || -n "${enable_devices}" ]]; then
    if [[ -n "${verbose}" ]]; then
        faz_output+="Devices:\n---------------------------------------\n"
    fi

    if [[ -z "${api_token}" && -z "${api_user}" ]]; then
        if [[ -n "${_snmp_avail}" ]]; then
            _dv_probe=$(_snmp_get "${_FAZ_SYS_OID}.1.0")
            if [[ "${_dv_probe}" == SNMP_* ]]; then
                faz_output+="${status_unkn} - Devices: SNMP ${_dv_probe}\n"
            else
            # Walk log device table: col2=name col5=adom col6=ip col9=log_age col12=conn_status col16=model
            declare -A _dv_names _dv_adom _dv_ips _dv_age _dv_conn _dv_model
            for _col_pair in "2 _dv_names" "5 _dv_adom" "6 _dv_ips" "9 _dv_age" "12 _dv_conn" "16 _dv_model"; do
                _col="${_col_pair%% *}"; _arr_name="${_col_pair##* }"
                while IFS=$'\t' read -r _idx _val; do
                    [[ -n "${_idx}" ]] && eval "${_arr_name}[\"${_idx}\"]=\"${_val}\""
                done < <(_snmp_walk "${_FAZ_DEV_OID}.${_col}" | \
                    ${AWK} '{idx=$1; sub(/.*\./, "", idx); val=$2; gsub(/"/, "", val); print idx"\t"val}')
            done

            _dev_total=0; _dev_up=0; _dev_down=0
            declare -a _dev_dn_lines
            for _didx in "${!_dv_names[@]}"; do
                (( _dev_total++ ))
                _dn="${_dv_names[${_didx}]}"
                _dip="${_dv_ips[${_didx}]:-?}"
                _dadom="${_dv_adom[${_didx}]}"
                _dconn="${_dv_conn[${_didx}]:-0}"
                _dmodel="${_dv_model[${_didx}]}"
                _dage="${_dv_age[${_didx}]}"

                if [[ "${_dconn}" == "1" ]]; then
                    (( _dev_up++ ))
                    if [[ -n "${verbose}" ]]; then
                        _dage_str=""
                        if [[ "${_dage}" =~ ^[0-9]+$ ]]; then
                            if (( _dage >= 3600 )); then
                                _dage_str="$(( _dage / 3600 ))h$(( (_dage % 3600) / 60 ))m ago"
                            elif (( _dage >= 60 )); then
                                _dage_str="$(( _dage / 60 ))m$(( _dage % 60 ))s ago"
                            else
                                _dage_str="${_dage}s ago"
                            fi
                        fi
                        _dv_detail="${_dn} (${_dip}${_dadom:+, ADOM: ${_dadom}}${_dmodel:+, ${_dmodel}})"
                        faz_output+="\\_ ${status_ok} ${_dv_detail}: connected${_dage_str:+, last log ${_dage_str}}\n"
                    fi
                else
                    (( _dev_down++ ))
                    _dev_dn_lines+=("${_dn} (${_dip}): conn_status=${_dconn}")
                fi
            done
            unset _dv_names _dv_adom _dv_ips _dv_age _dv_conn _dv_model

            _dev_sev="${status_ok}"
            if (( crit_dev_down >= 1 && _dev_down >= crit_dev_down )) 2>/dev/null && [[ "${_dev_down}" -gt 0 ]]; then
                _dev_sev="${status_crit}"; _update_exit 2
            elif (( warn_dev_down >= 1 && _dev_down >= warn_dev_down )) 2>/dev/null && [[ "${_dev_down}" -gt 0 ]]; then
                _dev_sev="${status_warn}"; _update_exit 1
            fi
            for _dl in "${_dev_dn_lines[@]}"; do
                faz_output+="${_dev_sev} - Device${_fws}${_dl}\n"
                [[ "${_dev_sev}" != "${status_ok}" ]] && faz_problem_output+="${_dev_sev} - Device${_fws}${_dl}\n"
            done
            unset _dev_dn_lines

            _dev_line="${_dev_sev} - Devices:${_fws}${_dev_total} total, ${_dev_up} connected, ${_dev_down} disconnected"
            faz_output+="${_dev_line}\n"
            [[ "${_dev_sev}" != "${status_ok}" ]] && faz_problem_output+="${_dev_line}\n"
            [[ -z "${no_perfdata}" ]] && faz_perf+=" dev_total=${_dev_total} dev_up=${_dev_up} dev_down=${_dev_down}"
            fi  # end probe check
        else
            [[ -n "${enable_devices}" ]] && faz_output+="${status_unkn} - Devices: API credentials required\n"
        fi
    else
        _dev_resp=$(faz_api_get "/dvmdb/device" \
            "\"fields\":[\"name\",\"ip\",\"conn_status\",\"os_ver\",\"mr\",\"patch\",\"platform_str\",\"last_checked\",\"sn\"]")
        _dev_code=$(echo "${_dev_resp}" | ${JQ} -r '.result[0].status.code // -99' 2>/dev/null)

        if [[ "${_dev_code}" != "0" ]]; then
            faz_output+="${status_unkn} - Devices: cannot retrieve device list (API code ${_dev_code})\n"
        else
            _dev_total=0; _dev_up=0; _dev_down=0
            declare -a _dev_dn_lines

            _now_ts=$(date +%s)

            while IFS=$'\t' read -r _dname _dip _dconn _dover _dmr _dpatch _dplat _dlast_checked _dsn; do
                [[ -z "${_dname}" ]] && continue
                (( _dev_total++ ))

                _dver_str="${_dover}.${_dmr}"
                [[ "${_dpatch}" != "null" && "${_dpatch}" != "" ]] && _dver_str+=".${_dpatch}"

                # conn_status: 0=up/connected, non-zero=down
                if [[ "${_dconn}" == "0" ]]; then
                    (( _dev_up++ ))
                    _dev_sev_line="${status_ok}"

                    # Age check
                    if [[ -n "${_dlast_checked}" && "${_dlast_checked}" =~ ^[0-9]+$ && "${_dlast_checked}" -gt 0 ]]; then
                        _age_min=$(( (_now_ts - _dlast_checked) / 60 ))
                        _age_str="${_age_min}m"
                        (( _age_min >= 60 )) && _age_str="${_age_min}m ($(( _age_min / 60 ))h$(( _age_min % 60 ))m)"
                        if [[ "${crit_dev_age}" -gt 0 ]] 2>/dev/null && [[ "${_age_min}" -ge "${crit_dev_age}" ]]; then
                            _dev_sev_line="${status_crit}"; _update_exit 2
                        elif [[ "${warn_dev_age}" -gt 0 ]] 2>/dev/null && [[ "${_age_min}" -ge "${warn_dev_age}" ]]; then
                            _dev_sev_line="${status_warn}"; _update_exit 1
                        fi
                    else
                        _age_str="never"
                    fi

                    if [[ -n "${verbose}" ]]; then
                        faz_output+="\\_ ${_dev_sev_line} ${_dname} (${_dip}) ${_dplat} FortiOS ${_dver_str}: conn=Connected / age=${_age_str:-?}\n"
                    fi
                else
                    (( _dev_down++ ))
                    _dev_dn_lines+=("${_dname} (${_dip}) ${_dplat} FortiOS ${_dver_str}: conn_status=${_dconn}")
                fi
            done < <(echo "${_dev_resp}" | ${JQ} --unbuffered -r \
                '.result[0].data[]? | [
                    (.name // "unknown"),
                    (.ip // ""),
                    ((.conn_status // 0) | tostring),
                    ((.os_ver // 0) | tostring),
                    ((.mr // 0) | tostring),
                    ((.patch // 0) | tostring),
                    (.platform_str // "FortiGate"),
                    ((.last_checked // 0) | tostring),
                    (.sn // "")
                ] | join("\t")' 2>/dev/null)

            # Severity for overall device check
            _dev_sev="${status_ok}"
            if (( crit_dev_down >= 1 && _dev_down >= crit_dev_down )) 2>/dev/null && [[ "${_dev_down}" -gt 0 ]]; then
                _dev_sev="${status_crit}"; _update_exit 2
            elif (( warn_dev_down >= 1 && _dev_down >= warn_dev_down )) 2>/dev/null && [[ "${_dev_down}" -gt 0 ]]; then
                _dev_sev="${status_warn}"; _update_exit 1
            fi

            for _dl in "${_dev_dn_lines[@]}"; do
                faz_output+="${_dev_sev} - Device${_fws}${_dl}\n"
                [[ "${_dev_sev}" != "${status_ok}" ]] && faz_problem_output+="${_dev_sev} - Device${_fws}${_dl}\n"
            done
            unset _dev_dn_lines

            _dev_line="${_dev_sev} - Devices:${_fws}${_dev_total} total, ${_dev_up} connected, ${_dev_down} disconnected"
            faz_output+="${_dev_line}\n"
            [[ "${_dev_sev}" != "${status_ok}" ]] && faz_problem_output+="${_dev_line}\n"

            if [[ -z "${no_perfdata}" ]]; then
                faz_perf+=" dev_total=${_dev_total} dev_up=${_dev_up} dev_down=${_dev_down}"
            fi
        fi
    fi

    if [[ -n "${verbose}" ]]; then
        faz_output+="---------------------------------------\n\n"
    fi
fi

# ---------------------------------------------------------------------------
# -eADOMs: ADOM Log Quota
# ---------------------------------------------------------------------------
if [[ ( -n "${enable_adoms}" || -n "${enable_all}" ) && -z "${disable_adoms}" ]] && \
   [[ -n "${api_token}" || -n "${api_user}" || -n "${enable_adoms}" ]]; then
    if [[ -n "${verbose}" ]]; then
        faz_output+="ADOMs:\n---------------------------------------\n"
    fi

    if [[ -z "${api_token}" && -z "${api_user}" ]]; then
        [[ -n "${enable_adoms}" ]] && faz_output+="${status_unkn} - ADOMs: API credentials required\n"
    else
        _adom_resp=$(faz_api_get "/dvmdb/adom" \
            "\"fields\":[\"name\",\"log_disk_quota\",\"log_disk_quota_alert_thres\",\"log_db_retention_hours\",\"state\"]")
        _adom_code=$(echo "${_adom_resp}" | ${JQ} -r '.result[0].status.code // -99' 2>/dev/null)

        if [[ "${_adom_code}" != "0" ]]; then
            faz_output+="${status_unkn} - ADOMs: cannot retrieve ADOM list (API code ${_adom_code})\n"
        else
            _adom_total=0; _adom_active=0; _adom_disabled=0
            _adom_warn_count=0; _adom_crit_count=0
            _adom_detail=""

            while IFS=$'\t' read -r _aname _aquota _athres _aretention _astate; do
                [[ -z "${_aname}" ]] && continue
                (( _adom_total++ ))
                if [[ "${_astate}" == "1" ]]; then
                    (( _adom_active++ ))
                else
                    (( _adom_disabled++ ))
                fi

                _aq_sev="${status_ok}"
                _aq_pct=""
                # quota is in MB, threshold is a %; we can compare threshold to quota_alert_thres
                # We use the configured alert threshold as the warning trigger
                if [[ "${_aquota}" -gt 0 ]] 2>/dev/null; then
                    # We don't have actual used bytes from /dvmdb/adom,
                    # but we do have log_disk_quota_alert_thres as the configured alert level.
                    # Alert: if the configured threshold is at or above our crit/warn values, flag.
                    # This tells the operator if the ADOM's alert threshold is misconfigured.
                    # For the actual usage, we'd need log stats which aren't accessible with this role.
                    _aq_detail="quota: ${_aquota}MB, alert at ${_athres}%"
                    _adom_detail+="\\_ ${_aq_sev} ${_aname} (${_aq_detail})\n"
                else
                    _adom_detail+="\\_ ${status_ok} ${_aname} (quota: unlimited)\n"
                fi
            done < <(echo "${_adom_resp}" | ${JQ} --unbuffered -r \
                '.result[0].data[]? | [
                    (.name // ""),
                    ((.log_disk_quota // 0) | tostring),
                    ((.log_disk_quota_alert_thres // 90) | tostring),
                    ((.log_db_retention_hours // 0) | tostring),
                    ((.state // 1) | tostring)
                ] | join("\t")' 2>/dev/null)

            _adom_line="${status_ok} - ADOMs:${_fws}${_adom_total} total, ${_adom_active} active, ${_adom_disabled} disabled"
            faz_output+="${_adom_line}\n"
            [[ -n "${verbose}" ]] && faz_output+="${_adom_detail}"

            if [[ -z "${no_perfdata}" ]]; then
                faz_perf+=" adom_total=${_adom_total} adom_active=${_adom_active} adom_disabled=${_adom_disabled}"
            fi
        fi
    fi

    if [[ -n "${verbose}" ]]; then
        faz_output+="---------------------------------------\n\n"
    fi
fi

# ---------------------------------------------------------------------------
# -eTasks: Background Tasks
# ---------------------------------------------------------------------------
if [[ ( -n "${enable_tasks}" || -n "${enable_all}" ) && -z "${disable_tasks}" ]] && \
   [[ -n "${api_token}" || -n "${api_user}" || -n "${enable_tasks}" ]]; then
    if [[ -n "${verbose}" ]]; then
        faz_output+="Tasks:\n---------------------------------------\n"
    fi

    if [[ -z "${api_token}" && -z "${api_user}" ]]; then
        [[ -n "${enable_tasks}" ]] && faz_output+="${status_unkn} - Tasks: API credentials required\n"
    else
        _task_since=$(( $(date +%s) - task_hours * 3600 ))

        _task_resp=$(faz_api_get "/task/task" \
            "\"sortings\":[{\"start_tm\":-1}],\"range\":[0,100],\"fields\":[\"id\",\"state\",\"title\",\"user\",\"start_tm\",\"end_tm\",\"num_err\",\"num_warn\",\"num_done\",\"percent\"]")
        _task_code=$(echo "${_task_resp}" | ${JQ} -r '.result[0].status.code // -99' 2>/dev/null)

        if [[ "${_task_code}" != "0" ]]; then
            faz_output+="${status_unkn} - Tasks: cannot retrieve task list (API code ${_task_code})\n"
        else
            _task_total=0; _task_failed=0; _task_running=0; _task_warn=0
            _task_lines=""

            _now_ts=$(date +%s)

            while IFS=$'\t' read -r _tid _tstate _ttitle _tuser _tstart _tend _terr _twarn _tdone _tpct; do
                [[ -z "${_tid}" ]] && continue
                # Only check tasks within the time window
                [[ "${_tstart}" -lt "${_task_since}" ]] 2>/dev/null && continue
                (( _task_total++ ))

                _t_sev="${status_ok}"
                _t_note=""

                # State: 1=running, 4=done, 5=error (others=cancelled/unknown)
                case "${_tstate}" in
                    1)
                        (( _task_running++ ))
                        _t_note="running ${_tpct}%"
                        # Stuck check
                        if [[ "${task_stuck_minutes}" -gt 0 ]] 2>/dev/null; then
                            _run_min=$(( (_now_ts - _tstart) / 60 ))
                            if [[ "${_run_min}" -ge "${task_stuck_minutes}" ]]; then
                                _t_sev="${status_warn}"; _task_warn=$(( _task_warn + 1 ))
                                _t_note+=" (stuck: ${_run_min}m)"
                                _update_exit 1
                            fi
                        fi
                        ;;
                    4)  _t_note="done" ;;
                    5)
                        if [[ "${_terr}" -gt 0 ]]; then
                            (( _task_failed++ ))
                            _t_sev="${status_warn}"
                            _t_note="error (${_terr} failed)"
                        else
                            _t_note="done"
                        fi
                        ;;
                    2)  _t_note="cancelled"; continue ;;  # skip cancelled
                    *)  _t_note="state ${_tstate}" ;;
                esac

                if [[ -n "${verbose}" ]]; then
                    _tstart_fmt=$(date -d "@${_tstart}" '+%Y-%m-%d %H:%M' 2>/dev/null || date -r "${_tstart}" '+%Y-%m-%d %H:%M' 2>/dev/null || echo "${_tstart}")
                    faz_output+="\\_ ${_t_sev} Task #${_tid} [${_ttitle}] by ${_tuser} at ${_tstart_fmt}: ${_t_note}\n"
                fi
            done < <(echo "${_task_resp}" | ${JQ} --unbuffered -r \
                '.result[0].data[]? | [
                    ((.id // 0) | tostring),
                    ((.state // 0) | tostring),
                    (.title // "unknown"),
                    (.user // ""),
                    ((.start_tm // 0) | tostring),
                    ((.end_tm // 0) | tostring),
                    ((.num_err // 0) | tostring),
                    ((.num_warn // 0) | tostring),
                    ((.num_done // 0) | tostring),
                    ((.percent // 0) | tostring)
                ] | join("\t")' 2>/dev/null)

            # Overall severity
            _tsev="${status_ok}"
            if (( crit_tasks_failed >= 1 && _task_failed >= crit_tasks_failed )) 2>/dev/null && [[ "${_task_failed}" -gt 0 ]]; then
                _tsev="${status_crit}"; _update_exit 2
            elif (( warn_tasks_failed >= 1 && _task_failed >= warn_tasks_failed )) 2>/dev/null && [[ "${_task_failed}" -gt 0 ]]; then
                _tsev="${status_warn}"; _update_exit 1
            elif [[ "${_task_warn}" -gt 0 ]]; then
                _tsev="${status_warn}"
            fi

            _task_line="${_tsev} - Tasks:${_fws}${_task_total} recent (last ${task_hours}h), ${_task_failed} failed, ${_task_running} running"
            faz_output+="${_task_line}\n"
            [[ "${_tsev}" != "${status_ok}" ]] && faz_problem_output+="${_task_line}\n"

            if [[ -z "${no_perfdata}" ]]; then
                faz_perf+=" task_total=${_task_total} task_failed=${_task_failed} task_running=${_task_running}"
            fi
        fi
    fi

    if [[ -n "${verbose}" ]]; then
        faz_output+="---------------------------------------\n\n"
    fi
fi

# ---------------------------------------------------------------------------
# -eLic: License / Contract Expiry
# ---------------------------------------------------------------------------
if [[ ( -n "${enable_lic}" || -n "${enable_all}" ) && -z "${disable_lic}" ]] && \
   [[ -n "${api_token}" || -n "${api_user}" || -n "${enable_lic}" ]]; then
    if [[ -n "${verbose}" ]]; then
        faz_output+="License:\n---------------------------------------\n"
    fi

    if [[ -z "${api_token}" && -z "${api_user}" ]]; then
        [[ -n "${enable_lic}" ]] && faz_output+="${status_unkn} - License: API credentials required\n"
    else
        _lic_resp=$(faz_api_get "/um/license/self")
        _lic_code=$(echo "${_lic_resp}" | ${JQ} -r '.result[0].status.code // -99' 2>/dev/null)

        if [[ "${_lic_code}" != "0" ]]; then
            faz_output+="${status_unkn} - License: cannot retrieve license info (API code ${_lic_code})\n"
        else
            _lic_total=0; _lic_warn=0; _lic_crit=0
            _lic_detail=""
            _today_ts=$(date +%s)

            while IFS=$'\t' read -r _ltype _lexpiry _lraw; do
                [[ -z "${_ltype}" ]] && continue
                (( _lic_total++ ))

                _l_sev="${status_ok}"
                _ldays=""
                if [[ "${_lexpiry}" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]]; then
                    _lexp_ts=$(date -d "${_lexpiry}" +%s 2>/dev/null || date -j -f "%Y-%m-%d" "${_lexpiry}" +%s 2>/dev/null)
                    if [[ -n "${_lexp_ts}" ]]; then
                        _ldays=$(( (_lexp_ts - _today_ts) / 86400 ))
                        if (( _ldays <= crit_lic )) 2>/dev/null; then
                            _l_sev="${status_crit}"; (( _lic_crit++ )); _update_exit 2
                        elif (( _ldays <= warn_lic )) 2>/dev/null; then
                            _l_sev="${status_warn}"; (( _lic_warn++ )); _update_exit 1
                        fi
                    fi
                fi

                _ldays_str=""
                [[ -n "${_ldays}" ]] && _ldays_str=" / ${_ldays} days remaining"
                _lic_detail+="\\_ ${_l_sev} ${_ltype}: expires ${_lexpiry}${_ldays_str}\n"
            done < <(echo "${_lic_resp}" | ${JQ} --unbuffered -r \
                '.result[0].data.contract[]? |
                 .contract_item[]? |
                 capture("^(?P<type>[A-Z0-9]+)-[0-9]+-[0-9]+-(?P<date>[0-9]{8}):") |
                 [
                     .type,
                     (.date | "20" + .[0:2] + "-" + .[2:4] + "-" + .[4:6] | if length == 10 then . else
                         (.date[0:4] + "-" + .date[4:6] + "-" + .date[6:8]) end),
                     .date
                 ] | join("\t")' 2>/dev/null)

            # Fallback: simpler jq if capture fails
            if [[ -z "${_lic_detail}" ]]; then
                while IFS= read -r _item; do
                    [[ -z "${_item}" ]] && continue
                    _ltype=$(echo "${_item}" | sed 's/-.*//')
                    _ldate=$(echo "${_item}" | grep -oE '[0-9]{8}' | head -1)
                    if [[ -n "${_ldate}" ]]; then
                        _lexpiry="${_ldate:0:4}-${_ldate:4:2}-${_ldate:6:2}"
                        (( _lic_total++ ))
                        _l_sev="${status_ok}"
                        _lexp_ts=$(date -d "${_lexpiry}" +%s 2>/dev/null)
                        if [[ -n "${_lexp_ts}" ]]; then
                            _ldays=$(( (_lexp_ts - _today_ts) / 86400 ))
                            (( _ldays <= crit_lic )) && { _l_sev="${status_crit}"; (( _lic_crit++ )); _update_exit 2; }
                            (( _ldays <= warn_lic && _ldays > crit_lic )) && { _l_sev="${status_warn}"; (( _lic_warn++ )); _update_exit 1; }
                        fi
                        _lic_detail+="\\_ ${_l_sev} ${_ltype}: expires ${_lexpiry}\n"
                    fi
                done < <(echo "${_lic_resp}" | ${JQ} -r '.result[0].data.contract[]?.contract_item[]?' 2>/dev/null)
            fi

            _lsev="${status_ok}"
            [[ "${_lic_crit}" -gt 0 ]] && _lsev="${status_crit}"
            [[ "${_lic_crit}" -eq 0 && "${_lic_warn}" -gt 0 ]] && _lsev="${status_warn}"

            _lic_line="${_lsev} - License:${_fws}${_lic_total} contract(s)"
            [[ "${_lic_warn}" -gt 0 || "${_lic_crit}" -gt 0 ]] && \
                _lic_line+=", ${_lic_warn} expiring soon, ${_lic_crit} expired/critical"
            faz_output+="${_lic_line}\n"
            [[ "${_lsev}" != "${status_ok}" ]] && faz_problem_output+="${_lic_line}\n"
            [[ -n "${verbose}" ]] && faz_output+="${_lic_detail}"

            if [[ -z "${no_perfdata}" ]]; then
                faz_perf+=" lic_contracts=${_lic_total} lic_expiring=${_lic_warn} lic_expired=${_lic_crit}"
            fi
        fi
    fi

    if [[ -n "${verbose}" ]]; then
        faz_output+="---------------------------------------\n\n"
    fi
fi

# ---------------------------------------------------------------------------
# -eCert: Certificate Expiry (local certs + CA certs)
# ---------------------------------------------------------------------------
if [[ ( -n "${enable_cert}" || -n "${enable_all}" ) && -z "${disable_cert}" ]] && \
   [[ -n "${api_token}" || -n "${api_user}" || -n "${enable_cert}" ]]; then
    if [[ -n "${verbose}" ]]; then
        faz_output+="Certificates:\n---------------------------------------\n"
    fi

    if [[ -z "${api_token}" && -z "${api_user}" ]]; then
        [[ -n "${enable_cert}" ]] && faz_output+="${status_unkn} - Certificates: API credentials required\n"
    elif [[ -z "${OPENSSL}" ]]; then
        faz_output+="${status_unkn} - Certificates: openssl not found on monitoring host\n"
    else
        _cert_total=0; _cert_ok=0; _cert_warn=0; _cert_crit=0
        _cert_detail=""
        _today_ts=$(date +%s)

        # Build blacklist map
        declare -A _cert_bl_map
        if [[ -n "${cert_blacklist}" ]]; then
            IFS=',' read -ra _blist <<< "${cert_blacklist}"
            for _bname in "${_blist[@]}"; do _cert_bl_map["${_bname// /}"]=1; done
        fi

        # Helper: process one cert entry and update counters
        # Args: <endpoint_path> <pem_field> <label_prefix> <name>
        _proc_cert_entry() {
            local _ep="${1}" _field="${2}" _prefix="${3}" _cn="${4}"
            local _label="${_prefix}/${_cn}"
            [[ -n "${_cert_bl_map[${_cn}]}" ]] && return
            (( _cert_total++ ))

            local _item _item_code _cpem
            _item=$(faz_api_get "${_ep}/${_cn}")
            _item_code=$(echo "${_item}" | ${JQ} -r '.result[0].status.code // -99' 2>/dev/null)
            if [[ "${_item_code}" != "0" ]]; then
                _cert_detail+="\\_ ${status_unkn} ${_label}: cannot retrieve cert data (code ${_item_code})\n"
                return
            fi
            _cpem=$(echo "${_item}" | ${JQ} -r "(.result[0].data.${_field} // \"\") | if type == \"array\" then (.[0] // \"\") else . end | ltrimstr(\"\\\"\") | rtrimstr(\"\\\"\")" 2>/dev/null)

            _cert_check_pem "${_label}" "${_cpem}"
            case "${_cc_sev}" in
                "${status_ok}")   (( _cert_ok++ )) ;;
                "${status_warn}") (( _cert_warn++ )); _update_exit 1 ;;
                "${status_crit}") (( _cert_crit++ )); _update_exit 2 ;;
                *)
                    # UNKNOWN from parse failure — don't count in ok/warn/crit
                    ;;
            esac
            _cert_detail+="${_cc_detail_line}"
        }

        # Local certs (device identity certs; PEM field: "certificate"; may bundle private key)
        _loc_list_resp=$(faz_api_get "/cli/global/system/certificate/local" '"fields":["name"]')
        _loc_code=$(echo "${_loc_list_resp}" | ${JQ} -r '.result[0].status.code // -99' 2>/dev/null)
        if [[ "${_loc_code}" != "0" ]]; then
            _cert_detail+="\\_ ${status_unkn} local: cannot retrieve local cert list (API code ${_loc_code})\n"
        else
            while IFS= read -r _cname; do
                [[ -z "${_cname}" || "${_cname}" == "null" ]] && continue
                _proc_cert_entry "/cli/global/system/certificate/local" "certificate" "local" "${_cname}"
            done < <(echo "${_loc_list_resp}" | ${JQ} -r '.result[0].data[]? | .name // empty' 2>/dev/null)
        fi

        # CA certs (trusted CA/intermediate certs; PEM field: "ca")
        _ca_list_resp=$(faz_api_get "/cli/global/system/certificate/ca" '"fields":["name"]')
        _ca_code=$(echo "${_ca_list_resp}" | ${JQ} -r '.result[0].status.code // -99' 2>/dev/null)
        if [[ "${_ca_code}" != "0" ]]; then
            _cert_detail+="\\_ ${status_unkn} ca: cannot retrieve CA cert list (API code ${_ca_code})\n"
        else
            while IFS= read -r _cname; do
                [[ -z "${_cname}" || "${_cname}" == "null" ]] && continue
                _proc_cert_entry "/cli/global/system/certificate/ca" "ca" "ca" "${_cname}"
            done < <(echo "${_ca_list_resp}" | ${JQ} -r '.result[0].data[]? | .name // empty' 2>/dev/null)
        fi

        unset _cert_bl_map
        unset -f _proc_cert_entry

        _csev="${status_ok}"
        [[ "${_cert_crit}" -gt 0 ]] && _csev="${status_crit}"
        [[ "${_cert_crit}" -eq 0 && "${_cert_warn}" -gt 0 ]] && _csev="${status_warn}"

        _cert_line="${_csev} - Certificates:${_fws}${_cert_total} total, ${_cert_ok} ok"
        [[ "${_cert_warn}" -gt 0 ]] && _cert_line+=", ${_cert_warn} expiring soon"
        [[ "${_cert_crit}" -gt 0 ]] && _cert_line+=", ${_cert_crit} expired/critical"
        faz_output+="${_cert_line}\n"
        [[ "${_csev}" != "${status_ok}" ]] && faz_problem_output+="${_cert_line}\n"
        [[ -n "${verbose}" ]] && faz_output+="${_cert_detail}"

        if [[ -z "${no_perfdata}" ]]; then
            faz_perf+=" certs_total=${_cert_total} certs_ok=${_cert_ok} certs_warn=${_cert_warn} certs_crit=${_cert_crit}"
        fi
    fi

    if [[ -n "${verbose}" ]]; then
        faz_output+="---------------------------------------\n\n"
    fi
fi

# ---------------------------------------------------------------------------
# -eAlerts: Active Alerts from Event Management (JSON-RPC v2 API)
# ---------------------------------------------------------------------------
if [[ ( -n "${enable_alerts}" || -n "${enable_all}" ) && -z "${disable_alerts}" ]] && \
   [[ -n "${api_token}" || -n "${api_user}" || -n "${enable_alerts}" ]]; then
    if [[ -n "${verbose}" ]]; then
        faz_output+="Alerts:\n---------------------------------------\n"
    fi

    if [[ -z "${api_token}" && -z "${api_user}" ]]; then
        [[ -n "${enable_alerts}" ]] && faz_output+="${status_unkn} - Alerts: API credentials required\n"
    else
        # Fetch alertlogs without server-side filter (FAZ filter syntax varies by version;
        # active alerts are selected client-side by status == 0 or "open")
        _alrt_resp=$(faz_api2_get "/event-mgmt/adom/root/alertlogs" "\"limit\":${alert_rows}")
        if [[ -n "${debug}" ]]; then
            printf '### -eAlerts raw response:\n' >&2
            echo "${_alrt_resp}" | ${JQ} . >&2 2>/dev/null || printf '%s\n' "${_alrt_resp}" >&2
        fi
        # JSON-RPC v2 success: .result.status.code; v2 error: .error.code; fallback -99
        _alrt_code=$(echo "${_alrt_resp}" | ${JQ} -r \
            '.result.status.code // .result[0].status.code // (.error | if . then .code else null end) // -99' 2>/dev/null)

        # -3/-6/-11 = endpoint not licensed/not found; -32xxx = JSON-RPC server errors
        # (e.g. -32013 = FAZ feature not enabled/licensed) -- all treated as "not available"
        _alrt_unavail=0
        [[ "${_alrt_code}" == "-3" || "${_alrt_code}" == "-6" || "${_alrt_code}" == "-11" ]] && _alrt_unavail=1
        [[ "${_alrt_code}" -le -32000 ]] 2>/dev/null && _alrt_unavail=1
        if [[ "${_alrt_unavail}" -eq 1 ]]; then
            [[ -n "${verbose}" ]] && faz_output+="${status_ok} - Alerts${_fws}feature not available on this device\n"
        elif [[ "${_alrt_code}" != "0" ]]; then
            faz_output+="${status_unkn} - Alerts: cannot retrieve alerts (API code ${_alrt_code})\n"
        else
            _alrt_crit=0; _alrt_warn=0; _alrt_info=0
            _alrt_detail=""

            while IFS=$'\t' read -r _aid _aname _asev _astatus _amsg _atime; do
                [[ -z "${_aid}" || "${_aid}" == "null" ]] && continue
                # Skip acknowledged/closed alerts (status: 0=active/open, 1=acknowledged)
                [[ "${_astatus}" != "0" && "${_astatus}" != "open" && "${_astatus}" != "active" ]] && continue
                _atime_fmt=$(date -d "@${_atime}" '+%Y-%m-%d %H:%M' 2>/dev/null || echo "ts=${_atime}")
                case "${_asev}" in
                    1) # critical
                        (( _alrt_crit++ ))
                        _alrt_detail+="\\_ ${status_crit} [critical] ${_aname}: ${_amsg} (${_atime_fmt})\n"
                        ;;
                    2) # high
                        (( _alrt_warn++ ))
                        _alrt_detail+="\\_ ${status_warn} [high] ${_aname}: ${_amsg} (${_atime_fmt})\n"
                        ;;
                    *)  # medium/low
                        (( _alrt_info++ ))
                        _alrt_detail+="\\_ ${status_ok} [sev${_asev}] ${_aname}: ${_amsg} (${_atime_fmt})\n"
                        ;;
                esac
            done < <(echo "${_alrt_resp}" | ${JQ} --unbuffered -r \
                '((try .result[0].data) // .result.data // [])[]? | [
                    ((.id // .alert_id // 0) | tostring),
                    (.name // .alert_name // "unknown"),
                    ((.severity // 4) | tostring),
                    ((.status // 0) | tostring),
                    (.message // .description // ""),
                    ((.create_time // .time // 0) | tostring)
                ] | join("\t")' 2>/dev/null)

            _alrt_sev="${status_ok}"
            [[ "${_alrt_crit}" -gt 0 ]] && { _alrt_sev="${status_crit}"; _update_exit 2; }
            [[ "${_alrt_crit}" -eq 0 && "${_alrt_warn}" -gt 0 ]] && { _alrt_sev="${status_warn}"; _update_exit 1; }

            _alrt_total=$(( _alrt_crit + _alrt_warn + _alrt_info ))
            _alrt_line="${_alrt_sev} - Alerts${_fws}${_alrt_total} active"
            [[ "${_alrt_crit}" -gt 0 ]] && _alrt_line+=", ${_alrt_crit} critical"
            [[ "${_alrt_warn}" -gt 0 ]] && _alrt_line+=", ${_alrt_warn} high"
            [[ "${_alrt_info}" -gt 0 ]] && _alrt_line+=", ${_alrt_info} info"
            faz_output+="${_alrt_line}\n"
            [[ "${_alrt_sev}" != "${status_ok}" ]] && faz_problem_output+="${_alrt_line}\n"
            [[ -n "${verbose}" && "${_alrt_total}" -gt 0 ]] && faz_output+="${_alrt_detail}"

            if [[ -z "${no_perfdata}" ]]; then
                faz_perf+=" alerts_crit=${_alrt_crit} alerts_warn=${_alrt_warn} alerts_info=${_alrt_info}"
            fi
        fi
    fi

    if [[ -n "${verbose}" ]]; then
        faz_output+="---------------------------------------\n\n"
    fi
fi

# ---------------------------------------------------------------------------
# -eIncidents: SOC Incidents (JSON-RPC v2 API)
# ---------------------------------------------------------------------------
if [[ ( -n "${enable_incidents}" || -n "${enable_all}" ) && -z "${disable_incidents}" ]] && \
   [[ -n "${api_token}" || -n "${api_user}" || -n "${enable_incidents}" ]]; then
    if [[ -n "${verbose}" ]]; then
        faz_output+="Incidents:\n---------------------------------------\n"
    fi

    if [[ -z "${api_token}" && -z "${api_user}" ]]; then
        [[ -n "${enable_incidents}" ]] && faz_output+="${status_unkn} - Incidents: API credentials required\n"
    else
        _inc_resp=$(faz_api2_get "/incidentmgmt/adom/root/incidents" "\"apiver\":3")
        if [[ -n "${debug}" ]]; then
            printf '### -eIncidents raw response:\n' >&2
            echo "${_inc_resp}" | ${JQ} . >&2 2>/dev/null || printf '%s\n' "${_inc_resp}" >&2
        fi
        _inc_code=$(echo "${_inc_resp}" | ${JQ} -r \
            '.result.status.code // .result[0].status.code // (.error | if . then .code else null end) // -99' 2>/dev/null)

        if [[ "${_inc_code}" != "0" ]]; then
            faz_output+="${status_unkn} - Incidents: cannot retrieve incidents (API code ${_inc_code})\n"
        else
            _inc_total=0; _inc_open=0; _inc_hi=0; _inc_lo=0
            _inc_detail=""

            while IFS=$'\t' read -r _iid _iname _isev _istatus _ictime _idesc; do
                [[ -z "${_iid}" || "${_iid}" == "null" || "${_iid}" == "0" ]] && continue
                (( _inc_total++ ))
                # status: open/draft/active/0 = open incident; closed/resolved = done
                if [[ "${_istatus}" == "0" || "${_istatus}" == "open" || \
                      "${_istatus}" == "draft" || "${_istatus}" == "active" ]]; then
                    (( _inc_open++ ))
                    # high/critical -> crit bucket; low/medium -> warn bucket
                    case "${_isev}" in
                        high|critical) (( _inc_hi++ )); _isev_status="${status_crit}" ;;
                        *)             (( _inc_lo++ )); _isev_status="${status_warn}" ;;
                    esac
                    _ictime_fmt=$(date -d "@${_ictime}" '+%Y-%m-%d %H:%M' 2>/dev/null || echo "ts=${_ictime}")
                    _inc_dline="\\_ ${_isev_status} #${_iid} [${_isev}]: ${_iname} (${_ictime_fmt})"
                    [[ -n "${_idesc}" ]] && _inc_dline+=" - ${_idesc}"
                    _inc_detail+="${_inc_dline}\n"
                fi
            done < <(echo "${_inc_resp}" | ${JQ} --unbuffered -r \
                '((try .result[0].data) // .result.data // [])[]? | [
                    (.incid // .id // .incident_id // "0"),
                    (.name // .title // "unknown"),
                    (.severity // "low"),
                    (.status // "open"),
                    ((.createtime // .create_time // "0") | tostring),
                    (.description // "")
                ] | join("\t")' 2>/dev/null)

            _inc_sev="${status_ok}"
            if [[ "${_inc_hi}" -gt 0 ]]; then
                _inc_sev="${status_crit}"; _update_exit 2
            elif [[ "${_inc_lo}" -gt 0 ]]; then
                _inc_sev="${status_warn}"; _update_exit 1
            fi

            _inc_line="${_inc_sev} - Incidents${_fws}${_inc_open} open"
            [[ "${_inc_hi}" -gt 0 ]] && _inc_line+=", ${_inc_hi} critical"
            [[ "${_inc_lo}" -gt 0 ]] && _inc_line+=", ${_inc_lo} warn"
            [[ "${_inc_total}" -gt "${_inc_open}" ]] && _inc_line+=", ${_inc_total} total"
            faz_output+="${_inc_line}\n"
            if [[ "${_inc_sev}" != "${status_ok}" ]]; then
                faz_problem_output+="${_inc_line}\n"
                [[ "${_inc_open}" -gt 0 ]] && faz_problem_output+="${_inc_detail}"
            fi
            [[ -n "${verbose}" && "${_inc_open}" -gt 0 ]] && faz_output+="${_inc_detail}"

            if [[ -z "${no_perfdata}" ]]; then
                faz_perf+=" incidents_open=${_inc_open} incidents_crit=${_inc_hi} incidents_warn=${_inc_lo} incidents_total=${_inc_total}"
            fi
        fi
    fi

    if [[ -n "${verbose}" ]]; then
        faz_output+="---------------------------------------\n\n"
    fi
fi

# ---------------------------------------------------------------------------
# -eNTP: NTP Configuration
# ---------------------------------------------------------------------------
if [[ ( -n "${enable_ntp}" || -n "${enable_all}" ) && -z "${disable_ntp}" ]] && \
   [[ -n "${api_token}" || -n "${api_user}" || -n "${enable_ntp}" ]]; then
    if [[ -n "${verbose}" ]]; then
        faz_output+="NTP:\n---------------------------------------\n"
    fi

    if [[ -z "${api_token}" && -z "${api_user}" ]]; then
        [[ -n "${enable_ntp}" ]] && faz_output+="${status_unkn} - NTP: API credentials required\n"
    else
        _ntp_resp=$(faz_api_get "/cli/global/system/ntp")
        _ntp_code=$(echo "${_ntp_resp}" | ${JQ} -r '.result[0].status.code // -99' 2>/dev/null)

        if [[ "${_ntp_code}" != "0" ]]; then
            faz_output+="${status_unkn} - NTP: cannot retrieve NTP config (API code ${_ntp_code})\n"
        else
            # status can be integer (0/1) or string ("disable"/"enable"/"ok")
            _ntp_status_raw=$(echo "${_ntp_resp}" | ${JQ} -r '.result[0].data.status // 0' 2>/dev/null)
            _ntp_enabled=0
            [[ "${_ntp_status_raw}" == "1" || "${_ntp_status_raw}" == "enable" || "${_ntp_status_raw}" == "ok" ]] && _ntp_enabled=1

            # ntptype: 1=fortiguard, 2=custom (some versions use "fortiguard"/"custom" strings)
            _ntp_type_raw=$(echo "${_ntp_resp}" | ${JQ} -r '.result[0].data.ntptype // 2' 2>/dev/null)
            _ntp_is_fg=0
            [[ "${_ntp_type_raw}" == "1" || "${_ntp_type_raw}" == "fortiguard" ]] && _ntp_is_fg=1

            _ntp_srv_count=0
            _ntp_srv_str=""
            _ntp_detail=""

            if [[ "${_ntp_is_fg}" -eq 1 ]]; then
                # FortiGuard NTP: single built-in server pool
                _ntp_srv_count=1
                _ntp_srv_str="FortiGuard"
                _ntp_detail+="\\_ ${status_ok} FortiGuard NTP (built-in server pool)\n"
            else
                while IFS=$'\t' read -r _nsrv _nntpv3 _nauth _nmin _nmax; do
                    [[ -z "${_nsrv}" || "${_nsrv}" == "null" ]] && continue
                    (( _ntp_srv_count++ ))
                    [[ -n "${_ntp_srv_str}" ]] && _ntp_srv_str+=", "
                    _ntp_srv_str+="${_nsrv}"
                    _ndet="poll:${_nmin}-${_nmax}s"
                    [[ "${_nntpv3}" == "1" ]] && _ndet+=", ntpv3"
                    [[ "${_nauth}" == "1" ]]  && _ndet+=", auth"
                    _ntp_detail+="\\_ ${status_ok} ${_nsrv} (${_ndet})\n"
                done < <(echo "${_ntp_resp}" | ${JQ} --unbuffered -r \
                    '.result[0].data.ntpserver[]? | [
                        (.server // ""),
                        ((.ntpv3 // 0) | tostring),
                        ((.authentication // 0) | tostring),
                        ((.minpoll // 6) | tostring),
                        ((.maxpoll // 10) | tostring)
                    ] | join("\t")' 2>/dev/null)
            fi

            _ntp_sev="${status_ok}"
            if [[ "${_ntp_enabled}" -eq 0 ]]; then
                if [[ -z "${no_ntp_warn}" ]]; then
                    _ntp_sev="${status_warn}"; _update_exit 1
                fi
            fi
            if [[ "${_ntp_srv_count}" -eq 0 && "${_ntp_enabled}" -eq 1 && -z "${no_ntp_warn}" ]]; then
                _ntp_sev="${status_warn}"; _update_exit 1
            fi

            _ntp_status_str="disabled"
            [[ "${_ntp_enabled}" -eq 1 ]] && _ntp_status_str="enabled"

            _ntp_line="${_ntp_sev} - NTP:${_fws}${_ntp_status_str}"
            [[ "${_ntp_enabled}" -eq 1 ]] && _ntp_line+=", ${_ntp_srv_count} server(s): ${_ntp_srv_str}"
            faz_output+="${_ntp_line}\n"
            [[ "${_ntp_sev}" != "${status_ok}" ]] && faz_problem_output+="${_ntp_line}\n"
            [[ -n "${verbose}" && "${_ntp_enabled}" -eq 1 ]] && faz_output+="${_ntp_detail}"

            if [[ -z "${no_perfdata}" ]]; then
                faz_perf+=" ntp_enabled=${_ntp_enabled} ntp_servers=${_ntp_srv_count}"
            fi
        fi
    fi

    if [[ -n "${verbose}" ]]; then
        faz_output+="---------------------------------------\n\n"
    fi
fi

# ---------------------------------------------------------------------------
# -eDNS: DNS Configuration
# ---------------------------------------------------------------------------
if [[ ( -n "${enable_dns}" || -n "${enable_all}" ) && -z "${disable_dns}" ]] && \
   [[ -n "${api_token}" || -n "${api_user}" || -n "${enable_dns}" ]]; then
    if [[ -n "${verbose}" ]]; then
        faz_output+="DNS:\n---------------------------------------\n"
    fi

    if [[ -z "${api_token}" && -z "${api_user}" ]]; then
        [[ -n "${enable_dns}" ]] && faz_output+="${status_unkn} - DNS: API credentials required\n"
    else
        _dns_resp=$(faz_api_get "/cli/global/system/dns")
        _dns_code=$(echo "${_dns_resp}" | ${JQ} -r '.result[0].status.code // -99' 2>/dev/null)

        if [[ "${_dns_code}" == "-11" ]]; then
            faz_output+="${status_unkn} - DNS: access denied (code -11) - requires full-admin access\n"
        elif [[ "${_dns_code}" != "0" ]]; then
            faz_output+="${status_unkn} - DNS: cannot retrieve DNS config (API code ${_dns_code})\n"
        else
            _dns_primary=$(echo "${_dns_resp}"   | ${JQ} -r '.result[0].data.primary   // "0.0.0.0"' 2>/dev/null)
            _dns_secondary=$(echo "${_dns_resp}" | ${JQ} -r '.result[0].data.secondary // "0.0.0.0"' 2>/dev/null)

            _dns_sev="${status_ok}"
            _dns_str=""
            [[ "${_dns_primary}" != "0.0.0.0" && "${_dns_primary}" != "" ]] && _dns_str+="${_dns_primary}"
            if [[ "${_dns_secondary}" != "0.0.0.0" && "${_dns_secondary}" != "" ]]; then
                [[ -n "${_dns_str}" ]] && _dns_str+=", "
                _dns_str+="${_dns_secondary}"
            fi
            [[ -z "${_dns_str}" ]] && { _dns_str="none configured"; _dns_sev="${status_warn}"; _update_exit 1; }

            _dns_line="${_dns_sev} - DNS:${_fws}${_dns_str}"
            faz_output+="${_dns_line}\n"
            [[ "${_dns_sev}" != "${status_ok}" ]] && faz_problem_output+="${_dns_line}\n"
            if [[ -n "${verbose}" ]]; then
                [[ "${_dns_primary}" != "0.0.0.0" ]]   && faz_output+="\\_ ${status_ok} Primary:   ${_dns_primary}\n"
                [[ "${_dns_secondary}" != "0.0.0.0" ]] && faz_output+="\\_ ${status_ok} Secondary: ${_dns_secondary}\n"
            fi
        fi
    fi

    if [[ -n "${verbose}" ]]; then
        faz_output+="---------------------------------------\n\n"
    fi
fi

# ---------------------------------------------------------------------------
# -eSyslog: Syslog Destinations
# ---------------------------------------------------------------------------
if [[ ( -n "${enable_syslog}" || -n "${enable_all}" ) && -z "${disable_syslog}" ]] && \
   [[ -n "${api_token}" || -n "${api_user}" || -n "${enable_syslog}" ]]; then
    if [[ -n "${verbose}" ]]; then
        faz_output+="Syslog:\n---------------------------------------\n"
    fi

    if [[ -z "${api_token}" && -z "${api_user}" ]]; then
        [[ -n "${enable_syslog}" ]] && faz_output+="${status_unkn} - Syslog: API credentials required\n"
    else
        _slog_resp=$(faz_api_get "/cli/global/system/syslog")
        _slog_code=$(echo "${_slog_resp}" | ${JQ} -r '.result[0].status.code // -99' 2>/dev/null)

        if [[ "${_slog_code}" != "0" ]]; then
            faz_output+="${status_unkn} - Syslog: cannot retrieve syslog config (API code ${_slog_code})\n"
        else
            _slog_total=0; _slog_enabled=0
            _slog_detail=""

            while IFS=$'\t' read -r _sname _sip _sport _sstatus; do
                [[ -z "${_sname}" || "${_sname}" == "null" ]] && continue
                (( _slog_total++ ))
                _sl_sev="${status_ok}"
                if [[ "${_sstatus}" == "enable" ]]; then
                    (( _slog_enabled++ ))
                fi
                _slog_detail+="\\_ ${_sl_sev} ${_sname}: ${_sip}:${_sport} (${_sstatus})\n"
            done < <(echo "${_slog_resp}" | ${JQ} --unbuffered -r \
                '.result[0].data[]? | [
                    (.name // .ip // "syslog"),
                    (.ip // .server // "unknown"),
                    ((.port // 514) | tostring),
                    (.status // "enable")
                ] | join("\t")' 2>/dev/null)

            _slog_sev="${status_ok}"
            if [[ "${_slog_total}" -eq 0 && -z "${no_syslog_warn}" ]]; then
                _slog_sev="${status_warn}"; _update_exit 1
            fi

            _slog_line="${_slog_sev} - Syslog:${_fws}"
            if [[ "${_slog_total}" -eq 0 ]]; then
                _slog_line+="no syslog destinations configured"
            else
                _slog_line+="${_slog_total} destination(s), ${_slog_enabled} enabled"
            fi
            faz_output+="${_slog_line}\n"
            [[ "${_slog_sev}" != "${status_ok}" ]] && faz_problem_output+="${_slog_line}\n"
            [[ -n "${verbose}" && "${_slog_total}" -gt 0 ]] && faz_output+="${_slog_detail}"

            if [[ -z "${no_perfdata}" ]]; then
                faz_perf+=" syslog_total=${_slog_total} syslog_enabled=${_slog_enabled}"
            fi
        fi
    fi

    if [[ -n "${verbose}" ]]; then
        faz_output+="---------------------------------------\n\n"
    fi
fi

# ---------------------------------------------------------------------------
# -eLogFwd: Log Forwarding
# ---------------------------------------------------------------------------
if [[ ( -n "${enable_logfwd}" || -n "${enable_all}" ) && -z "${disable_logfwd}" ]] && \
   [[ -n "${api_token}" || -n "${api_user}" || -n "${enable_logfwd}" ]]; then
    if [[ -n "${verbose}" ]]; then
        faz_output+="Log Forwarding:\n---------------------------------------\n"
    fi

    if [[ -z "${api_token}" && -z "${api_user}" ]]; then
        [[ -n "${enable_logfwd}" ]] && faz_output+="${status_unkn} - Log Forwarding: API credentials required\n"
    else
        _lf_resp=$(faz_api_get "/cli/global/system/log-forward")
        _lf_code=$(echo "${_lf_resp}" | ${JQ} -r '.result[0].status.code // -99' 2>/dev/null)

        if [[ "${_lf_code}" != "0" ]]; then
            faz_output+="${status_unkn} - Log Forwarding: cannot retrieve config (API code ${_lf_code})\n"
        else
            _lf_total=0; _lf_enabled=0
            _lf_detail=""

            while IFS=$'\t' read -r _lfname _lfip _lfport _lfstatus _lfmode; do
                [[ -z "${_lfname}" || "${_lfname}" == "null" ]] && continue
                (( _lf_total++ ))
                _lf_sev="${status_ok}"
                if [[ "${_lfstatus}" == "enable" ]]; then
                    (( _lf_enabled++ ))
                fi
                _lf_detail+="\\_ ${_lf_sev} ${_lfname}: ${_lfip}:${_lfport} (${_lfstatus}, mode: ${_lfmode})\n"
            done < <(echo "${_lf_resp}" | ${JQ} --unbuffered -r \
                '.result[0].data[]? | [
                    (."server-name" // (.id | tostring) // "logfwd"),
                    (."server-ip" // "unknown"),
                    ((."server-port" // 514) | tostring),
                    (.status // "enable"),
                    (.mode // "forwarding")
                ] | join("\t")' 2>/dev/null)

            _lf_sev="${status_ok}"
            if [[ "${_lf_total}" -eq 0 && -z "${no_logfwd_warn}" ]]; then
                _lf_sev="${status_warn}"; _update_exit 1
            fi

            _lf_line="${_lf_sev} - Log Forwarding:${_fws}"
            if [[ "${_lf_total}" -eq 0 ]]; then
                _lf_line+="no log forwarding configured"
            else
                _lf_line+="${_lf_total} destination(s), ${_lf_enabled} enabled"
            fi
            faz_output+="${_lf_line}\n"
            [[ "${_lf_sev}" != "${status_ok}" ]] && faz_problem_output+="${_lf_line}\n"
            [[ -n "${verbose}" && "${_lf_total}" -gt 0 ]] && faz_output+="${_lf_detail}"

            if [[ -z "${no_perfdata}" ]]; then
                faz_perf+=" logfwd_total=${_lf_total} logfwd_enabled=${_lf_enabled}"
            fi
        fi
    fi

    if [[ -n "${verbose}" ]]; then
        faz_output+="---------------------------------------\n\n"
    fi
fi

# ---------------------------------------------------------------------------
# -eLogRate: Log Reception and Insertion Rates (FAZ SNMP MIB)
# OIDs: enterprises.12356.103.6.1.1 = global recv/s, .6.1.2 = global insert/s
#       enterprises.12356.103.6.2.1.<col>.<idx> = per-device table
#       col25=recv/s  col26=insert/s  col27=drop/s  col28=fwd/s
# ---------------------------------------------------------------------------
if [[ ( -n "${enable_lograte}" || -n "${enable_all}" ) && -z "${disable_lograte}" ]]; then
    if [[ -n "${enable_all}" && -z "${enable_lograte}" && -z "${_snmp_avail}" ]]; then
        : # skip silently under -A when no SNMP creds (also avoids empty section in FMG proxy mode)
    else
    if [[ -n "${verbose}" ]]; then
        faz_output+="Log Rates:\n---------------------------------------\n"
    fi

    if [[ -z "${_snmp_avail}" ]]; then
        faz_output+="${status_unkn} - Log Rates: SNMP credentials required (uses FAZ SNMP log MIB)\n"
    else
        _FAZ_LOG_OID=".1.3.6.1.4.1.12356.103.6"
        _lr_recv_raw=$(_snmp_get "${_FAZ_LOG_OID}.1.1.0")
        _lr_ins_raw=$(_snmp_get "${_FAZ_LOG_OID}.1.2.0")

        if [[ "${_lr_recv_raw}" == SNMP_* ]]; then
            faz_output+="${status_unkn} - Log Rates: SNMP ${_lr_recv_raw}\n"
        else
            _lr_recv="${_lr_recv_raw//[^0-9]/}"
            _lr_ins="${_lr_ins_raw//[^0-9]/}"
            [[ -z "${_lr_recv}" ]] && _lr_recv=0
            [[ -z "${_lr_ins}" ]]  && _lr_ins=0

            _lr_sev="${status_ok}"
            _lr_lag_pct=0
            if [[ "${_lr_recv}" -gt 0 ]] 2>/dev/null; then
                _lr_lag_pct=$(echo "${_lr_recv} ${_lr_ins}" | \
                    ${AWK} '{if($1>0) printf "%d", ($1-$2)*100/$1; else print 0}')
                if [[ "${warn_loglag}" -gt 0 ]] 2>/dev/null && (( _lr_lag_pct >= warn_loglag )); then
                    _lr_sev="${status_warn}"; _update_exit 1
                fi
                if [[ "${crit_loglag}" -gt 0 ]] 2>/dev/null && (( _lr_lag_pct >= crit_loglag )); then
                    _lr_sev="${status_crit}"; _update_exit 2
                fi
            fi

            _lr_line="${_lr_sev} - Log Rates:${_fws}recv ${_lr_recv}/s, insert ${_lr_ins}/s"
            [[ "${_lr_lag_pct}" -gt 0 ]] && _lr_line+=", insert lag ${_lr_lag_pct}%"
            faz_output+="${_lr_line}\n"
            [[ "${_lr_sev}" != "${status_ok}" ]] && faz_problem_output+="${_lr_line}\n"

            if [[ -n "${verbose}" && -n "${_snmp_avail}" ]]; then
                declare -A _lr_names _lr_drecv _lr_dins _lr_ddrop _lr_dfwd
                while IFS=$'\t' read -r _didx _dname; do
                    [[ -n "${_didx}" ]] && _lr_names["${_didx}"]="${_dname}"
                done < <(_snmp_walk "${_FAZ_LOG_OID}.2.1.2" | \
                    ${AWK} '{idx=$1; sub(/.*\./, "", idx); val=$2; gsub(/"/, "", val); print idx"\t"val}')
                while IFS=$'\t' read -r _didx _dval; do
                    [[ -n "${_didx}" ]] && _lr_drecv["${_didx}"]="${_dval}"
                done < <(_snmp_walk "${_FAZ_LOG_OID}.2.1.25" | \
                    ${AWK} '{idx=$1; sub(/.*\./, "", idx); print idx"\t"$2}')
                while IFS=$'\t' read -r _didx _dval; do
                    [[ -n "${_didx}" ]] && _lr_dins["${_didx}"]="${_dval}"
                done < <(_snmp_walk "${_FAZ_LOG_OID}.2.1.26" | \
                    ${AWK} '{idx=$1; sub(/.*\./, "", idx); print idx"\t"$2}')
                while IFS=$'\t' read -r _didx _dval; do
                    [[ -n "${_didx}" ]] && _lr_ddrop["${_didx}"]="${_dval}"
                done < <(_snmp_walk "${_FAZ_LOG_OID}.2.1.27" | \
                    ${AWK} '{idx=$1; sub(/.*\./, "", idx); print idx"\t"$2}')
                while IFS=$'\t' read -r _didx _dval; do
                    [[ -n "${_didx}" ]] && _lr_dfwd["${_didx}"]="${_dval}"
                done < <(_snmp_walk "${_FAZ_LOG_OID}.2.1.28" | \
                    ${AWK} '{idx=$1; sub(/.*\./, "", idx); print idx"\t"$2}')

                for _didx in "${!_lr_names[@]}"; do
                    _dn="${_lr_names[${_didx}]}"
                    _dr="${_lr_drecv[${_didx}]:-0}"
                    _di="${_lr_dins[${_didx}]:-0}"
                    _dd="${_lr_ddrop[${_didx}]:-0}"
                    _dfw="${_lr_dfwd[${_didx}]:-0}"
                    _d_detail="recv=${_dr}/s insert=${_di}/s"
                    [[ "${_dd}" -gt 0 ]] 2>/dev/null && _d_detail+=" drop=${_dd}/s"
                    [[ "${_dfw}" -gt 0 ]] 2>/dev/null && _d_detail+=" fwd=${_dfw}/s"
                    faz_output+="\\_ ${status_ok} ${_dn}: ${_d_detail}\n"
                done
                unset _lr_names _lr_drecv _lr_dins _lr_ddrop _lr_dfwd
            fi

            if [[ -z "${no_perfdata}" ]]; then
                faz_perf+=" log_recv_rate=${_lr_recv} log_insert_rate=${_lr_ins}"
                [[ "${_lr_recv}" -gt 0 ]] && faz_perf+=" log_insert_lag_pct=${_lr_lag_pct}"
            fi
        fi
    fi

    if [[ -n "${verbose}" ]]; then
        faz_output+="---------------------------------------\n\n"
    fi
    fi # end else (non-silent-skip path)
fi

# ---------------------------------------------------------------------------
# -eLogwatch: Log Search (FAZ /logview/logsearch, API only)
# ---------------------------------------------------------------------------
if [[ -n "${enable_logwatch}" && -z "${disable_logwatch}" ]] && \
   [[ -n "${api_token}" || -n "${api_user}" ]]; then
    if [[ -n "${verbose}" ]]; then
        faz_output+="Logwatch:\n---------------------------------------\n"
    fi

    if [[ -z "${api_token}" && -z "${api_user}" ]]; then
        [[ -n "${enable_logwatch}" ]] && faz_output+="${status_unkn} - Logwatch: API credentials required\n"
    else
        _lw_end_ts=$(date +%s)
        _lw_start_ts=$(( _lw_end_ts - logwatch_hours * 3600 ))

        # Build jq select expression for eventid/action filters
        _lw_jq_sel="true"
        if [[ -n "${logwatch_eventids}" ]]; then
            _lw_eid_expr=""
            IFS=',' read -ra _lw_tmp <<< "${logwatch_eventids}"
            for _lw_v in "${_lw_tmp[@]}"; do
                _lw_v="${_lw_v// /}"
                if [[ "${_lw_v}" =~ ^[0-9]+$ ]]; then
                    [[ -n "${_lw_eid_expr}" ]] && _lw_eid_expr+=" or "
                    _lw_eid_expr+="(.eventid // 0) == ${_lw_v}"
                fi
            done
            [[ -n "${_lw_eid_expr}" ]] && _lw_jq_sel+=" and (${_lw_eid_expr})"
            unset _lw_tmp
        fi
        if [[ -n "${logwatch_actions}" ]]; then
            _lw_act_expr=""
            IFS=',' read -ra _lw_tmp <<< "${logwatch_actions}"
            for _lw_v in "${_lw_tmp[@]}"; do
                _lw_v="${_lw_v// /}"
                if [[ -n "${_lw_v}" ]]; then
                    [[ -n "${_lw_act_expr}" ]] && _lw_act_expr+=" or "
                    _lw_act_expr+="((.action // \"\") | ascii_downcase) == (\"${_lw_v}\" | ascii_downcase)"
                fi
            done
            [[ -n "${_lw_act_expr}" ]] && _lw_jq_sel+=" and (${_lw_act_expr})"
            unset _lw_tmp
        fi

        _lw_filter_mode=0
        [[ -n "${logwatch_eventids}" || -n "${logwatch_actions}" ]] && _lw_filter_mode=1

        _lw_crit_count=0; _lw_warn_count=0; _lw_match_count=0; _lw_total=0
        _lw_ok_types=0
        declare -a _lw_lines _lw_skip_types

        # Device filter: --logwatch-uri sets devid (e.g. device serial, name, or All_Devices)
        _lw_devid="${logwatch_uri:-All_Devices}"

        # Convert Unix timestamps to ISO 8601 (FAZ time-range format)
        _lw_start_iso=$(date -d "@${_lw_start_ts}" '+%Y-%m-%dT%H:%M:%S' 2>/dev/null \
            || date -r "${_lw_start_ts}" '+%Y-%m-%dT%H:%M:%S' 2>/dev/null)
        _lw_end_iso=$(date -d "@${_lw_end_ts}" '+%Y-%m-%dT%H:%M:%S' 2>/dev/null \
            || date -r "${_lw_end_ts}" '+%Y-%m-%dT%H:%M:%S' 2>/dev/null)

        # Build severity level filter (server-side filter string + client-side jq expression)
        declare -a _lw_all_levels=(debug information notice warning error critical alert emergency)
        _lw_min_level_idx=3  # default: warning
        for _lw_i in "${!_lw_all_levels[@]}"; do
            [[ "${_lw_all_levels[${_lw_i}]}" == "${logwatch_level}" ]] \
                && _lw_min_level_idx="${_lw_i}" && break
        done
        _lw_level_jq_expr=""
        for (( _lw_i=_lw_min_level_idx; _lw_i<${#_lw_all_levels[@]}; _lw_i++ )); do
            _lw_lvl="${_lw_all_levels[${_lw_i}]}"
            if [[ -z "${_lw_level_jq_expr}" ]]; then
                _lw_level_jq_expr="((.level // .event_severity // \"\") | ascii_downcase) == \"${_lw_lvl}\""
            else
                _lw_level_jq_expr+=" or ((.level // .event_severity // \"\") | ascii_downcase) == \"${_lw_lvl}\""
            fi
        done
        [[ -n "${_lw_level_jq_expr}" ]] && _lw_jq_sel+=" and (${_lw_level_jq_expr})"
        if [[ -n "${logwatch_subtype}" ]]; then
            _lw_jq_sel+=" and (((.subtype // \"\") | ascii_downcase) == (\"${logwatch_subtype}\" | ascii_downcase))"
        fi

        if [[ -n "${debug}" ]]; then
            printf '### -eLogwatch devid=%s adom=%s range=%s to %s level>=%s\n' \
                "${_lw_devid}" "${logwatch_adom}" "${_lw_start_iso}" "${_lw_end_iso}" \
                "${logwatch_level}" >&2
        fi

        IFS=',' read -ra _lw_types <<< "${logwatch_type}"
        for _lw_t in "${_lw_types[@]}"; do
            _lw_t="${_lw_t// /}"
            [[ -z "${_lw_t}" ]] && continue

            # Phase 1: create async search task
            _lw_add_extra="\"apiver\":3,\"case-sensitive\":false"
            _lw_add_extra+=",\"device\":[{\"devid\":\"${_lw_devid}\"}]"
            _lw_add_extra+=",\"logtype\":\"${_lw_t}\""
            _lw_add_extra+=",\"time-order\":\"desc\""
            _lw_add_extra+=",\"time-range\":{\"start\":\"${_lw_start_iso}\",\"end\":\"${_lw_end_iso}\"}"
            _lw_add_extra+=",\"filter\":\"\""
            _lw_add_resp=$(faz_api2_add "/logview/adom/${logwatch_adom}/logsearch" "${_lw_add_extra}")
            # Response shape: {"result":{"tid":NNN}} on success, {"error":{"code":N,"message":"..."}} on failure
            _lw_tid=$(echo "${_lw_add_resp}" | ${JQ} -r \
                '.result.tid // .result[0].data.tid // .result[0].tid // empty' 2>/dev/null)
            _lw_add_code=$(echo "${_lw_add_resp}" | ${JQ} -r \
                'if .error then (.error.code | tostring) elif .result.tid then "0" else "-99" end' 2>/dev/null)
            if [[ -n "${debug}" ]]; then
                printf '### -eLogwatch [%s] create task: code=%s tid=%s\n' "${_lw_t}" "${_lw_add_code}" "${_lw_tid}" >&2
            fi
            if [[ "${_lw_add_code}" != "0" || -z "${_lw_tid}" ]]; then
                _lw_skip_types+=("${_lw_t}(code:${_lw_add_code})")
                continue
            fi

            # Phase 2: poll for completion (up to 10s)
            _lw_progress=0
            for _lw_poll in 1 2 3 4 5 6 7 8 9 10; do
                sleep 1
                _lw_cnt_resp=$(faz_api2_get \
                    "/logview/adom/${logwatch_adom}/logsearch/count/${_lw_tid}" '"apiver":3')
                _lw_progress=$(echo "${_lw_cnt_resp}" | ${JQ} -r \
                    '.result["progress-percent"] // .result[0].data["progress-percent"] // 0' 2>/dev/null)
                _lw_progress="${_lw_progress:-0}"
                if [[ -n "${debug}" ]]; then
                    printf '### -eLogwatch [%s] poll %d: progress=%s%%\n' "${_lw_t}" "${_lw_poll}" "${_lw_progress}" >&2
                fi
                [[ "${_lw_progress}" == "100" ]] && break
            done
            unset _lw_poll

            # Phase 3: paginated fetch (FAZ max 1000 per page; loop until logwatch_rows scanned)
            _lw_total_logs=$(echo "${_lw_cnt_resp}" | ${JQ} -r \
                'if .result["total-logs"] != null then (.result["total-logs"] | tostring)
                 elif .result[0]["total-logs"] != null then (.result[0]["total-logs"] | tostring)
                 else "0" end' 2>/dev/null)
            [[ ! "${_lw_total_logs}" =~ ^[0-9]+$ ]] && _lw_total_logs=0
            _lw_scan_limit=$(( logwatch_rows < _lw_total_logs ? logwatch_rows : _lw_total_logs ))
            _lw_offset=0
            _lw_fetch_ok=0
            _lw_code="-99"
            (( _lw_scan_limit == 0 )) && _lw_fetch_ok=1 && _lw_code="0"

            while (( _lw_offset < _lw_scan_limit )); do
                _lw_page_limit=$(( _lw_scan_limit - _lw_offset ))
                (( _lw_page_limit > 1000 )) && _lw_page_limit=1000

                _lw_resp=$(faz_api2_get "/logview/adom/${logwatch_adom}/logsearch/${_lw_tid}" \
                    "\"apiver\":3,\"limit\":${_lw_page_limit},\"offset\":${_lw_offset}")

                if [[ -n "${debug}" && ${_lw_offset} -eq 0 ]]; then
                    printf '### -eLogwatch [%s] fetch p1 offset=0 limit=%d (progress was %s%%):\n' \
                        "${_lw_t}" "${_lw_page_limit}" "${_lw_progress}" >&2
                    echo "${_lw_resp}" | ${JQ} '{status: (.result[0].status // .result.status), first: (((try .result[0].data) // .result.data // [])[0] // null)}' >&2 2>/dev/null \
                        || printf '%s\n' "${_lw_resp}" >&2
                    printf '### -eLogwatch [%s] jq_sel: %s\n' "${_lw_t}" "${_lw_jq_sel}" >&2
                    _lw_dbg_levels=$(echo "${_lw_resp}" | ${JQ} -r \
                        '((try .result[0].data) // .result.data // []) | map(.level // .event_severity // "(null)") | unique | join(", ")' 2>/dev/null)
                    printf '### -eLogwatch [%s] level values in page: %s\n' "${_lw_t}" "${_lw_dbg_levels}" >&2
                fi

                _lw_code=$(echo "${_lw_resp}" | ${JQ} -r \
                    'if .error then (.error.code | tostring)
                     elif .result.status.code != null then (.result.status.code | tostring)
                     elif .result[0].status.code != null then (.result[0].status.code | tostring)
                     else "-99" end' 2>/dev/null)

                [[ "${_lw_code}" != "0" ]] && break
                (( _lw_fetch_ok++ ))

                while IFS=$'\x01' read -r _lw_date _lw_time _lw_subtype _lw_level _lw_eid _lw_act \
                                            _lw_src _lw_srcport _lw_dst _lw_dstport _lw_polid _lw_msg _lw_devname; do
                    (( _lw_match_count++ ))
                    _lw_datetime="${_lw_date}${_lw_time:+ ${_lw_time}}"
                    _lw_subtype_s="" ; [[ -n "${_lw_subtype}" ]] && _lw_subtype_s="/${_lw_subtype}"
                    _lw_dev_s="" ; [[ -n "${_lw_devname}" ]] && _lw_dev_s="[${_lw_devname}] "
                    _lw_msg="${_lw_msg//+/ }"
                    _lw_msg=$(printf '%b' "${_lw_msg//%/\\x}" 2>/dev/null || echo "${_lw_msg}")
                    _lw_msg_s="" ; [[ -n "${_lw_msg}" ]] && _lw_msg_s=" ${_lw_msg}"
                    _lw_eid_s="" ; [[ "${_lw_eid}" != "0" && -n "${_lw_eid}" ]] && _lw_eid_s=" eid:${_lw_eid}"
                    _lw_act_s="" ; [[ -n "${_lw_act}" ]] && _lw_act_s=" action:${_lw_act}"
                    _lw_src_s=""
                    [[ -n "${_lw_src}" && "${_lw_src}" != "0" && "${_lw_src}" != "0.0.0.0" ]] && _lw_src_s="${_lw_src}"
                    [[ -n "${_lw_src_s}" && "${_lw_srcport}" != "0" ]] && _lw_src_s+=":${_lw_srcport}"
                    _lw_dst_s=""
                    [[ -n "${_lw_dst}" && "${_lw_dst}" != "0" && "${_lw_dst}" != "0.0.0.0" ]] && _lw_dst_s="${_lw_dst}"
                    [[ -n "${_lw_dst_s}" && "${_lw_dstport}" != "0" ]] && _lw_dst_s+=":${_lw_dstport}"
                    _lw_conn_s=""
                    [[ -n "${_lw_src_s}" || -n "${_lw_dst_s}" ]] && _lw_conn_s=" | ${_lw_src_s} -> ${_lw_dst_s}"
                    _lw_pol_s="" ; [[ "${_lw_polid}" != "0" && -n "${_lw_polid}" ]] && _lw_pol_s=" (policy:${_lw_polid})"

                    if [[ "${_lw_filter_mode}" -eq 0 ]]; then
                        case "${_lw_level}" in
                            emergency|alert|critical)
                                (( _lw_crit_count++ ))
                                _lw_lines+=("${status_crit} - Logwatch${_fws}${_lw_dev_s}${_lw_datetime} [${_lw_t}${_lw_subtype_s}/${_lw_level}]${_lw_eid_s}${_lw_act_s}${_lw_conn_s}${_lw_pol_s}${_lw_msg_s}")
                                faz_problem_output+="${status_crit} - Logwatch${_fws}${_lw_dev_s}${_lw_datetime} [${_lw_t}${_lw_subtype_s}/${_lw_level}]${_lw_eid_s}${_lw_act_s}${_lw_conn_s}${_lw_pol_s}${_lw_msg_s}\n"
                                ;;
                            *)
                                # error/warning: WARNING; notice/info/debug: WARNING when at or above --logwatch-level
                                (( _lw_warn_count++ ))
                                _lw_lines+=("${status_warn} - Logwatch${_fws}${_lw_dev_s}${_lw_datetime} [${_lw_t}${_lw_subtype_s}/${_lw_level}]${_lw_eid_s}${_lw_act_s}${_lw_conn_s}${_lw_pol_s}${_lw_msg_s}")
                                faz_problem_output+="${status_warn} - Logwatch${_fws}${_lw_dev_s}${_lw_datetime} [${_lw_t}${_lw_subtype_s}/${_lw_level}]${_lw_eid_s}${_lw_act_s}${_lw_conn_s}${_lw_pol_s}${_lw_msg_s}\n"
                                ;;
                        esac
                    else
                        # Filter mode: collect all matches; thresholds applied after loop
                        _lw_lines+=("${_lw_dev_s}${_lw_datetime} [${_lw_t}${_lw_subtype_s}/${_lw_level}]${_lw_eid_s}${_lw_act_s}${_lw_conn_s}${_lw_pol_s}${_lw_msg_s}")
                    fi
                done < <(echo "${_lw_resp}" | ${JQ} --unbuffered -r \
                    "((try .result[0].data) // .result.data // [])[]? | select(${_lw_jq_sel}) |
                    [(.date // \"\"), (.time // \"\"),
                     (.subtype // \"\"),
                     (.level // .event_severity // \"unknown\"),
                     (.eventid // 0 | tostring),
                     (.action // \"\"),
                     (.srcip // \"\"),
                     ((.srcport // 0) | tostring),
                     (.dstip // \"\"),
                     ((.dstport // 0) | tostring),
                     ((.policyid // 0) | tostring),
                     (.msg // .message // \"\"),
                     (.devname // .devid // \"\")] | join(\"\")" 2>/dev/null)

                _lw_page_total=$(echo "${_lw_resp}" | ${JQ} -r \
                    'if .result.data then (.result.data | length | tostring)
                     elif .result[0].data then (.result[0].data | length | tostring)
                     else "0" end' 2>/dev/null)
                [[ ! "${_lw_page_total}" =~ ^[0-9]+$ ]] && _lw_page_total=0
                (( _lw_offset += _lw_page_total ))
                (( _lw_page_total == 0 )) && break  # no more data (FAZ returns 100/page regardless of limit)
            done

            # Phase 4: cleanup (fire-and-forget)
            faz_api2_delete "/logview/adom/${logwatch_adom}/logsearch/${_lw_tid}" '"apiver":3' &>/dev/null &

            if [[ ${_lw_fetch_ok} -eq 0 ]]; then
                _lw_skip_types+=("${_lw_t}(code:${_lw_code})")
                continue
            fi

            (( _lw_ok_types++ ))
            _lw_t_cnt="${_lw_scan_limit}"
            [[ ! "${_lw_t_cnt}" =~ ^[0-9]+$ ]] && _lw_t_cnt=0
            (( _lw_total += _lw_t_cnt ))
        done

        if [[ "${_lw_ok_types}" -gt 0 ]]; then
            # Filter mode: apply count thresholds
            if [[ "${_lw_filter_mode}" -eq 1 ]]; then
                _lw_fs="${status_ok}"
                if (( crit_logwatch >= 0 && _lw_match_count >= crit_logwatch )) 2>/dev/null; then
                    _lw_fs="${status_crit}" ; _lw_crit_count="${_lw_match_count}"
                elif (( _lw_match_count >= warn_logwatch )) 2>/dev/null; then
                    _lw_fs="${status_warn}" ; _lw_warn_count="${_lw_match_count}"
                fi
                if [[ "${_lw_fs}" != "${status_ok}" ]]; then
                    for _lw_l in "${_lw_lines[@]}"; do
                        faz_problem_output+="${_lw_fs} - Logwatch${_fws}${_lw_l}\n"
                        [[ -n "${verbose}" ]] && faz_output+="${_lw_fs} - Logwatch${_fws}${_lw_l}\n"
                    done
                elif [[ -n "${verbose}" ]]; then
                    for _lw_l in "${_lw_lines[@]}"; do
                        faz_output+="${status_ok} - Logwatch${_fws}${_lw_l}\n"
                    done
                fi
            else
                [[ -n "${verbose}" ]] && for _lw_l in "${_lw_lines[@]}"; do faz_output+="${_lw_l}\n"; done
            fi

            if [[ "${_lw_crit_count}" -gt 0 || "${_lw_warn_count}" -gt 0 ]]; then
                _lw_st="${status_crit}"
                [[ "${_lw_crit_count}" -eq 0 ]] && _lw_st="${status_warn}"
                _update_exit $([[ "${_lw_crit_count}" -gt 0 ]] && echo 2 || echo 1)
                faz_output+="${_lw_st} - Logwatch${_fws}${_lw_match_count} match(es) in last ${_lw_total} entries (crit: ${_lw_crit_count}, warn: ${_lw_warn_count})\n"
            else
                faz_output+="${status_ok} - Logwatch${_fws}no matches in last ${_lw_total} entries (${logwatch_hours}h)\n"
            fi
            [[ -n "${verbose}" && "${#_lw_skip_types[@]}" -gt 0 ]] && \
                faz_output+="${status_ok} - Logwatch${_fws}skipped (not available): ${_lw_skip_types[*]}\n"

            if [[ -z "${no_perfdata}" ]]; then
                faz_perf+=" logwatch_hits=${_lw_match_count} logwatch_crit=${_lw_crit_count} logwatch_warn=${_lw_warn_count}"
            fi
        else
            _lw_err_detail=""
            [[ "${#_lw_skip_types[@]}" -gt 0 ]] && _lw_err_detail=" [${_lw_skip_types[*]}]"
            faz_output+="${status_ok} - Logwatch${_fws}log search not available (${logwatch_adom}/${logwatch_type})${_lw_err_detail}\n"
            [[ -z "${no_perfdata}" ]] && faz_perf+=" logwatch_hits=0 logwatch_crit=0 logwatch_warn=0"
        fi

        unset _lw_types _lw_lines _lw_skip_types
    fi

    if [[ -n "${verbose}" ]]; then
        faz_output+="---------------------------------------\n\n"
    fi
fi

# ---------------------------------------------------------------------------
# -eUp: Uptime (SNMP primary, API fallback)
# ---------------------------------------------------------------------------
if [[ ( -n "${enable_up}" || -n "${enable_all}" ) && -z "${disable_up}" ]]; then
    if [[ -n "${verbose}" ]]; then
        faz_output+="Uptime:\n---------------------------------------\n"
    fi

    _up_secs=0
    _up_source=""
    if [[ -n "${_snmp_avail}" ]]; then
        _up_raw=$(_snmp_get ".1.3.6.1.2.1.1.3.0")
        if [[ "${_up_raw}" == SNMP_* ]]; then
            faz_output+="${status_unkn} - Uptime: SNMP ${_up_raw}\n"
            _up_source="snmp_fail"
        else
            # Parse TimeTicks "D:H:M:S.cs" or raw centiseconds
            if [[ "${_up_raw}" =~ ^[0-9]+$ ]]; then
                _up_secs=$(( _up_raw / 100 ))
            elif [[ "${_up_raw}" =~ ([0-9]+):([0-9]+):([0-9]+):([0-9]+) ]]; then
                _up_secs=$(( BASH_REMATCH[1]*86400 + BASH_REMATCH[2]*3600 + BASH_REMATCH[3]*60 + BASH_REMATCH[4] ))
            fi
            _up_source="snmp"
        fi
    elif [[ -n "${api_token}" || -n "${api_user}" ]]; then
        # API fallback: Uptime field from sys/status (accuracy: seconds resolution, no sub-minute)
        _api_uptime_str=$(echo "${_sys_resp}" | ${JQ} -r '.result[0].data.Uptime // ""' 2>/dev/null)
        if [[ -z "${_api_uptime_str}" || "${_api_uptime_str}" == "null" ]]; then
            faz_output+="${status_unkn} - Uptime: not available via API (Uptime field absent in sys/status; configure SNMP for uptime monitoring)\n"
            _up_source="api_fail"
        else
            # Parse "X days  HH:MM:SS" or "HH:MM:SS"
            if [[ "${_api_uptime_str}" =~ ([0-9]+)[[:space:]]+days?[[:space:]]+([0-9]+):([0-9]+):([0-9]+) ]]; then
                _up_secs=$(( BASH_REMATCH[1]*86400 + BASH_REMATCH[2]*3600 + BASH_REMATCH[3]*60 + BASH_REMATCH[4] ))
            elif [[ "${_api_uptime_str}" =~ ([0-9]+):([0-9]+):([0-9]+) ]]; then
                _up_secs=$(( BASH_REMATCH[1]*3600 + BASH_REMATCH[2]*60 + BASH_REMATCH[3] ))
            fi
            _up_source="api"
        fi
    elif [[ -n "${enable_all}" && -z "${enable_up}" ]]; then
        _up_source="skip"
    else
        faz_output+="${status_unkn} - Uptime: requires SNMP (-SC/-u/-a/-X) or API credentials (-T/-U/-P)\n"
        _up_source="nocreds"
    fi

    if [[ "${_up_source}" == "snmp" || "${_up_source}" == "api" ]]; then
        _up_d=$(( _up_secs / 86400 ))
        _up_h=$(( (_up_secs % 86400) / 3600 ))
        _up_m=$(( (_up_secs % 3600) / 60 ))
        _up_s=$(( _up_secs % 60 ))
        _up_str=""
        (( _up_d > 0 )) && _up_str+="${_up_d}d "
        (( _up_h > 0 || _up_d > 0 )) && _up_str+="${_up_h}h "
        _up_str+="${_up_m}m ${_up_s}s"
        [[ "${_up_source}" == "api" ]] && _up_str+=" (via API)"

        _up_min=$(( _up_secs / 60 ))
        _up_sev="${status_ok}"
        if [[ "${warn_reboot_minutes}" -gt 0 ]] 2>/dev/null && [[ "${_up_min}" -lt "${warn_reboot_minutes}" ]]; then
            _up_sev="${status_warn}"; _update_exit 1
        fi

        _up_line="${_up_sev} - Uptime:${_fws}${_up_str}"
        faz_output+="${_up_line}\n"
        [[ "${_up_sev}" != "${status_ok}" ]] && faz_problem_output+="${_up_line}\n"

        if [[ -z "${no_perfdata}" ]]; then
            faz_perf+=" uptime_seconds=${_up_secs}"
        fi
    fi

    if [[ -n "${verbose}" ]]; then
        faz_output+="---------------------------------------\n\n"
    fi
fi

# ---------------------------------------------------------------------------
# Output assembly
# ---------------------------------------------------------------------------
_perf_sep=""
[[ -z "${no_perfdata}" && -n "${faz_perf}" ]] && _perf_sep=" |${faz_perf}"

_po="${faz_output//|/,}"
_pp="${faz_problem_output//|/,}"

if [[ -n "${faz_problem_output}" ]]; then
    if [[ -z "${silent}" ]]; then
        _pre="One or more Problems detected:\n---------------------------------------------------------------------\n"
        _sep="---------------------------------------------------------------------\n\nAll Checks:\n---------------------------------------------------------------------\n"
        printf "%b" "${_pre}${_pp}${_sep}${_po}${_perf_sep}\n"
    else
        printf "%b" "${_pp}${_perf_sep}\n"
    fi
elif [[ -n "${silent}" ]]; then
    printf "%b" "${status_ok} - All checks OK${_perf_sep}\n"
else
    printf "%b" "${_po}${_perf_sep}\n"
fi

exit "${_exit_code}"

# check_fortianalyzer_health

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Shell Script](https://img.shields.io/badge/Shell-Bash-green.svg)](https://www.gnu.org/software/bash/)
[![Monitoring](https://img.shields.io/badge/Monitoring-Icinga%2FNagios-blue.svg)](https://icinga.com/)
[![Version](https://img.shields.io/badge/version-1.5.3-orange.svg)](check_fortianalyzer_health.sh)

A comprehensive Bash-based monitoring plugin for Fortinet FortiAnalyzer, compatible with Icinga and Nagios monitoring systems. This plugin monitors system health, registered devices, ADOM log quotas, background tasks, license and certificate expiry, NTP, DNS, syslog/log-forwarding configuration, log reception rates, real-time log search (Logwatch), and SOC incidents — via the FortiAnalyzer JSON-RPC API and/or SNMP.

## Features

- **JSON-RPC API**: Connects to FortiAnalyzer's `/jsonrpc` endpoint — no additional tools or cloud dependency required
- **FortiManager Proxy**: Optionally routes all API calls through FortiManager (`--fmg-device`) when the FAZ is behind FMG and not directly reachable
- **SNMP Supplement**: SNMPv2c or SNMPv3 credentials add uptime monitoring and log reception/insertion rate metrics
- **System Health**: Hostname, platform, firmware version, HA mode, license status
- **Resource Monitoring**: CPU, memory, flash disk, and hard disk usage with configurable thresholds (via API `/sys/performance`)
- **Registered Devices**: Connection state and last-log-receipt age for all log-sending FortiGate devices
- **ADOM Log Quotas**: Per-ADOM disk quota utilization with configurable warning/critical thresholds
- **Background Tasks**: Alert on failed, errored, or stuck running tasks (policy installs, firmware upgrades, etc.)
- **License / Certificates**: Contract expiry dates from FortiGuard; local certificate expiry with configurable lead-time thresholds
- **NTP / DNS / Syslog / Log Forwarding**: System configuration checks for sync state, server presence, and forwarding destinations
- **Log Rate Monitoring**: Log reception and insertion rates via SNMP; alert on insert-lag relative to receive rate
- **Logwatch**: Async FAZ log search across any log type and ADOM — filter by level, subtype, event ID, or action; alert on matching entries with per-device attribution
- **Incidents**: Active SOC incidents from FortiAnalyzer incident management
- **Opt-in or Opt-out**: Use `-eX` flags to run only specific checks, or `--disable-X` to suppress modules from the full set (`-A`); `-eLogwatch` is always opt-in and excluded from `-A`
- **Perfdata Output**: Full Nagios-compatible perfdata for all check modules — compatible with PNP4Nagios, Graphite, InfluxDB, etc.

## Prerequisites

Ensure the following tools are installed on your monitoring server:

- **bash** (4.0 or higher)
- **curl** (for API communication)
- **jq** (for JSON parsing)
- **openssl** (optional — only required for `-eCert` certificate expiry checks)
- **snmpget / snmpwalk** (optional — only required for `-eUp` uptime and `-eLogRate`, provided by net-snmp)

### Installation on Different Platforms

**Ubuntu/Debian:**
```bash
sudo apt-get install curl jq openssl snmp
```

**RHEL/CentOS/Rocky Linux:**
```bash
sudo dnf install curl jq openssl net-snmp-utils
```

**Gentoo:**
```bash
sudo emerge net-misc/curl app-misc/jq dev-libs/openssl net-analyzer/net-snmp
```

## Installation

1. **Download the script:**
   ```bash
   curl -O https://raw.githubusercontent.com/ascii42/check_fortianalyzer_health/main/check_fortianalyzer_health.sh
   ```

2. **Make it executable:**
   ```bash
   chmod +x check_fortianalyzer_health.sh
   ```

3. **Copy to your plugins directory:**
   ```bash
   # Icinga2
   sudo cp check_fortianalyzer_health.sh /usr/lib/nagios/plugins/

   # Nagios
   sudo cp check_fortianalyzer_health.sh /usr/local/nagios/libexec/
   ```

## FortiAnalyzer Configuration

### API Token (Recommended)

Create a dedicated REST API admin in the FortiAnalyzer GUI:

1. Navigate to **System > Admin > REST API Admin**
2. Click **Create New**
3. Set a name (e.g. `monitoring`)
4. Set **Admin Profile** to `Standard_User` (read-only is sufficient for most checks)
5. Set **JSON API Access** to `Read`
6. Copy the generated token

> **Note:** A `Standard_User` read-only profile covers `-eSys`, `-eRes`, `-eDevices`, `-eADOMs`, `-eTasks`, `-eLic`, `-eCert`, `-eNTP`, `-eDNS`, `-eSyslog`, `-eLogFwd`, `-eLogwatch`, and `-eIncidents`. No elevated privileges are required.

### Username / Password

Alternatively, authenticate with an existing admin account:

```bash
./check_fortianalyzer_health.sh -H 10.0.0.1 -U admin -P secret -A
```

The admin account must have **JSON API Access** enabled:
**System > Admin > Administrators > \<user\> > JSON API Access: Read-Write**

### FortiManager Proxy

When FortiAnalyzer is managed via FortiManager and not directly reachable, use the FMG as an API proxy:

```bash
# List available FAZ device paths on the FMG
./check_fortianalyzer_health.sh -H 10.0.0.2 -T FMG-Token --print-fmg-device-paths

# Monitor the FAZ through FMG
./check_fortianalyzer_health.sh -H 10.0.0.2 -T FMG-Token \
  --fmg-device adom/root/device/FAZ-name -A
```

### SNMP (Optional)

SNMP credentials supplement the API for two checks:

- **`-eUp`**: System uptime via SNMP sysUpTime
- **`-eLogRate`**: Log reception and insertion rates via FORTINET-FORTIANALYZER-MIB

Configure SNMP on the FortiAnalyzer: **System > Network > SNMP**

## Usage

### Basic Syntax

```bash
./check_fortianalyzer_health.sh -H <host> -T <token> [options]
./check_fortianalyzer_health.sh -H <host> -U <user> -P <pass> [options]
./check_fortianalyzer_health.sh -H <host> -SC <community> -eUp  # SNMP uptime only
```

### Required Parameters

| Parameter | Description |
|-----------|-------------|
| `-H, --host <hostname\|IP>` | Hostname or IP address of the FortiAnalyzer |

At least one of the following authentication methods is required:

| Method | Parameters | Notes |
|--------|-----------|-------|
| API token | `-T <token>` | Recommended — long-lived token from REST API Admin |
| User/password | `-U <user> -P <pass>` | Session-based login; session is logged out on exit |
| SNMP v2c | `-SC <community>` | For `-eUp` and `-eLogRate` only; API not required |
| SNMP v3 | `-u <name> -a <authpass> -X <privpass>` | SNMPv3 mode |

### Enable Flags (opt-in)

If any `-eX` flag is given, **only those modules** run. When no flags are given, all modules except `-eLogwatch` run (equivalent to `-A`).

| Flag | Long form | Description | Access Required |
|------|-----------|-------------|-----------------|
| `-eSys` | `--enable-system` | System info: hostname, platform, FAZ version, HA mode, license status | API |
| `-eRes` | `--enable-resources` | CPU, memory, flash disk, hard disk usage with thresholds | API |
| `-eHA` | `--enable-ha` | HA cluster mode and peer status | API |
| `-eDevices` | `--enable-devices` | Registered log-sending devices: connection state, platform, version, last-log age | API |
| `-eADOMs` | `--enable-adoms` | ADOM list with log disk quota utilization | API |
| `-eTasks` | `--enable-tasks` | Recent background tasks — alert on failed, errored, or stuck running | API |
| `-eLic` | `--enable-license` | License and contract expiry dates from FortiGuard | API |
| `-eCert` | `--enable-certs` | Local certificate expiry (requires `openssl` on the monitoring host) | API |
| `-eAlerts` | `--enable-alerts` | Active alerts from FAZ event management (requires event management license) | API |
| `-eNTP` | `--enable-ntp` | NTP sync status and configured server list | API |
| `-eDNS` | `--enable-dns` | DNS server configuration (primary/secondary) | API |
| `-eSyslog` | `--enable-syslog` | Syslog forwarding destinations | API |
| `-eLogFwd` | `--enable-logfwd` | Log forwarding destinations and status | API |
| `-eLogRate` | `--enable-lograte` | Log reception and insertion rates | SNMP |
| `-eLogwatch` | `--enable-logwatch` | Search FAZ logs for matching entries (always opt-in; excluded from `-A`) | API |
| `-eIncidents` | `--enable-incidents` | Active SOC incidents from incident management | API |
| `-eUp` | `--enable-uptime` | System uptime | SNMP or API |
| `-A` | `--enable-all` | Enable all checks except `-eLogwatch` (default when no `-eX` flag is given) | — |

> `-eLogwatch` is always opt-in and must be explicitly requested with `-eLogwatch`. It is never triggered by `-A`.

### Disable Flags (opt-out from `-A`)

Suppress individual modules when running the full check set:

```
--disable-system      --disable-resources    --disable-ha
--disable-devices     --disable-adoms        --disable-tasks
--disable-license     --disable-certs        --disable-alerts
--disable-ntp         --disable-dns          --disable-syslog
--disable-logfwd      --disable-lograte      --disable-logwatch
--disable-incidents   --disable-uptime
```

### Threshold Options

**Resource Thresholds**

| Option | Default | Description |
|--------|---------|-------------|
| `-wCPU <pct>` | 80 | WARNING threshold for CPU usage in % |
| `-cCPU <pct>` | 90 | CRITICAL threshold for CPU usage in % |
| `-wMem <pct>` | 80 | WARNING threshold for memory usage in % |
| `-cMem <pct>` | 90 | CRITICAL threshold for memory usage in % |
| `--warn-disk <pct>` | 80 | WARNING threshold for hard disk usage in % |
| `--crit-disk <pct>` | 90 | CRITICAL threshold for hard disk usage in % |
| `--warn-flash <pct>` | 80 | WARNING threshold for flash disk usage in % |
| `--crit-flash <pct>` | 90 | CRITICAL threshold for flash disk usage in % |
| `--warn-io <pct>` | 90 | WARNING threshold for disk I/O utilization in % |
| `--crit-io <pct>` | 95 | CRITICAL threshold for disk I/O utilization in % |

**Device Thresholds**

| Option | Default | Description |
|--------|---------|-------------|
| `--warn-devices-down <n>` | 1 | WARNING when N or more devices are disconnected |
| `--crit-devices-down <n>` | 1 | CRITICAL when N or more devices are disconnected |
| `--warn-dev-age <minutes>` | -1 | WARNING when a device's last log receipt is older than N minutes (-1=disabled) |
| `--crit-dev-age <minutes>` | -1 | CRITICAL when a device's last log receipt is older than N minutes (-1=disabled) |

**ADOM Quota Thresholds**

| Option | Default | Description |
|--------|---------|-------------|
| `--warn-adom-quota <pct>` | 80 | WARNING when ADOM log disk quota used % >= N |
| `--crit-adom-quota <pct>` | 90 | CRITICAL when ADOM log disk quota used % >= N |

**Task Thresholds**

| Option | Default | Description |
|--------|---------|-------------|
| `--task-hours <n>` | 24 | Only check tasks started within the last N hours |
| `--warn-tasks-failed <n>` | 1 | WARNING when N or more tasks have errors |
| `--crit-tasks-failed <n>` | 1 | CRITICAL when N or more tasks have errors |
| `--task-stuck-minutes <n>` | -1 | WARNING if a running task exceeds N minutes (-1=disabled) |

**License / Certificate Thresholds**

| Option | Default | Description |
|--------|---------|-------------|
| `--warn-lic <days>` | 30 | WARNING when a contract expires in less than N days |
| `--crit-lic <days>` | 15 | CRITICAL when a contract expires in less than N days |
| `--warn-cert <days>` | 30 | WARNING when a certificate expires in less than N days |
| `--crit-cert <days>` | 15 | CRITICAL when a certificate expires in less than N days |
| `--blacklist-certs <list>` | — | Comma-separated certificate names to skip in `-eCert` |

**Log Rate Thresholds**

| Option | Default | Description |
|--------|---------|-------------|
| `--warn-loglag <pct>` | -1 | WARNING when insert rate lags receive rate by >= N% (-1=disabled) |
| `--crit-loglag <pct>` | -1 | CRITICAL when insert rate lags receive rate by >= N% (-1=disabled) |

**Logwatch Options**

| Option | Default | Description |
|--------|---------|-------------|
| `--logwatch-adom <adom>` | root | ADOM to search |
| `--logwatch-type <type[,type]>` | event | Log category: `event`, `traffic`, `app-ctrl`, `ips`, `virus`, `webfilter` |
| `--logwatch-subtype <sub>` | — | Subtype filter (e.g. `system`, `vpn`, `user`) |
| `--logwatch-hours <n>` | 1 | Look back N hours |
| `--logwatch-rows <n>` | 200 | Maximum entries to scan (fetched in pages of up to 1000) |
| `--logwatch-level <lvl>` | warning | Minimum severity level (see note below) |
| `--logwatch-eventids "id1,id2,..."` | — | Only alert on these event IDs (comma-separated) |
| `--logwatch-actions "a1,a2,..."` | — | Only alert on these actions (comma-separated) |
| `--warn-logwatch <n>` | 1 | WARNING when match count >= N |
| `--crit-logwatch <n>` | -1 | CRITICAL when match count >= N (-1 = level-based: emergency/alert/critical → CRITICAL, rest → WARNING) |

> **Severity levels (syslog RFC 5424 order, least to most severe):**
> `debug` → `information` → `notice` → `warning` → `error` → `critical` → `alert` → `emergency`
>
> Note: in this order `alert > critical > error`. Use `--logwatch-level critical` to catch critical, alert, and emergency events. Use `--logwatch-level warning` (the default) for all operationally relevant events.
>
> **Severity mapping in output:** `emergency`, `alert`, `critical` → CRITICAL; `error`, `warning`, and below → WARNING.

**Incident Thresholds**

| Option | Default | Description |
|--------|---------|-------------|
| `--warn-incidents <n>` | 1 | WARNING when N or more open incidents |
| `--crit-incidents <n>` | -1 | CRITICAL when N or more open incidents (-1=disabled) |

**Uptime Threshold**

| Option | Default | Description |
|--------|---------|-------------|
| `--warn-reboot-minutes <n>` | -1 | WARNING if uptime is below N minutes (reboot detection; -1=disabled) |

### NTP / Syslog / Log Forwarding Options

| Option | Description |
|--------|-------------|
| `--no-ntp-warn` | Suppress WARNING when NTP sync is disabled |
| `--no-syslog-warn` | Suppress WARNING when no syslog destinations configured |
| `--no-logfwd-warn` | Suppress WARNING when no log forwarding destinations configured |

### HTTPS Options

| Option | Default | Description |
|--------|---------|-------------|
| `--https-port <port>` | 443 | HTTPS/API port |
| `--https-verify` | off | Require validation of the server certificate |
| `--https-ca-bundle <file>` | — | CA bundle file for certificate validation (implies `--https-verify`) |

### SNMP Options

| Option | Default | Description |
|--------|---------|-------------|
| `-SC, --snmp-community <community>` | — | SNMPv2c community string |
| `-u, --snmp-user <name>` | — | SNMPv3 security name — enables SNMPv3 mode |
| `-l, --snmp-auth-proto <SHA\|MD5>` | SHA | SNMPv3 authentication protocol |
| `-a, --snmp-auth-pass <pass>` | — | SNMPv3 authentication passphrase (minimum 8 characters) |
| `-x, --snmp-priv-proto <AES\|DES>` | AES | SNMPv3 privacy protocol |
| `-X, --snmp-priv-pass <pass>` | — | SNMPv3 privacy passphrase (minimum 8 characters) |
| `-L, --snmp-sec-level <level>` | auto | `noAuthNoPriv` / `authNoPriv` / `authPriv` (auto-detected from credentials) |
| `--snmp-port <port>` | 161 | SNMP UDP port |

### Output Options

| Option | Description |
|--------|-------------|
| `--no-perfdata` | Suppress the perfdata section entirely (no `\|` output) |
| `-s, --silent` | Show only problem lines (suppress OK detail) |
| `-v, --verbose` | Print section headers and full per-item detail |
| `-d, --debug` | Enable bash trace output (`set -x`) |

## Examples

### Full Health Check with SNMP

Check everything — API for all checks, SNMP for uptime and log rates:

```bash
./check_fortianalyzer_health.sh -H 10.0.0.1 -T MyApiToken \
  -u monitor -a MonitorPass1 -X MonitorPass1 -A
```

### API Token Only

Check everything the API exposes; uptime and log rates require SNMP:

```bash
./check_fortianalyzer_health.sh -H 10.0.0.1 -T MyApiToken -A
```

### User/Password Authentication

```bash
./check_fortianalyzer_health.sh -H 10.0.0.1 -U admin -P secret -A
```

### Logwatch — Catch Warning+ Events in the Last Hour

```bash
./check_fortianalyzer_health.sh -H 10.0.0.1 -T MyApiToken \
  -eLogwatch --logwatch-hours 1 --logwatch-level warning
```

### Logwatch — System Events from a Specific Subtype

```bash
./check_fortianalyzer_health.sh -H 10.0.0.1 -T MyApiToken \
  -eLogwatch --logwatch-hours 24 --logwatch-level notice \
  --logwatch-subtype system
```

### Logwatch — VPN Events with Count Threshold

Alert only if 5 or more matches, regardless of severity:

```bash
./check_fortianalyzer_health.sh -H 10.0.0.1 -T MyApiToken \
  -eLogwatch --logwatch-type event --logwatch-subtype vpn \
  --logwatch-hours 1 --warn-logwatch 5 --crit-logwatch 20
```

### Device Age Threshold

Warn when a registered device has not sent logs for more than 15 minutes:

```bash
./check_fortianalyzer_health.sh -H 10.0.0.1 -T MyApiToken -eDevices \
  --warn-dev-age 15 --crit-dev-age 60
```

### ADOM Quota Monitoring

```bash
./check_fortianalyzer_health.sh -H 10.0.0.1 -T MyApiToken -eADOMs \
  --warn-adom-quota 70 --crit-adom-quota 85
```

### Uptime via SNMP (SNMPv3)

```bash
./check_fortianalyzer_health.sh -H 10.0.0.1 \
  -u monitor -a MonitorPass1 -X MonitorPass1 -eUp \
  --warn-reboot-minutes 10
```

### Via FortiManager Proxy

```bash
./check_fortianalyzer_health.sh -H 10.0.0.2 -T FMG-Token \
  --fmg-device adom/root/device/FAZ-prod -A
```

### Suppress Noisy Checks

```bash
./check_fortianalyzer_health.sh -H 10.0.0.1 -T MyApiToken -A \
  --disable-alerts --disable-incidents --no-syslog-warn --no-logfwd-warn
```

### Verbose Output

```bash
./check_fortianalyzer_health.sh -H 10.0.0.1 -T MyApiToken -SC monitor -A -v
```

## Sample Output

### Standard (non-verbose)

```
[OK] - System: FAZVM64-KVM-prod FortiAnalyzer-VM64-KVM v8.0.2-build0198 (Stand Alone)
[OK] - Resources: CPU 2%, Memory 48%, Disk 73%
[OK] - Uptime: 11d 23h 25m
[OK] - Devices: 3 total, 3 sending logs
[OK] - ADOMs: 1 ADOM, root: 2.1GB / 10.0GB (21%)
[OK] - Tasks: 0 recent (last 24h), 0 failed, 0 running
[OK] - License: 2 contract(s), 0 expiring
[OK] - Certs: 2 certificate(s), 0 expiring
[OK] - NTP: enabled, 1 server(s): ntp.fortiguard.com
[OK] - DNS: 8.8.8.8, 8.8.4.4
[OK] - Syslog: 1 configured, 1 enabled
[OK] - LogFwd: 1 configured, 1 enabled
[OK] - LogRate: recv 1247/s, insert 1245/s
[OK] - Incidents: 0 open incidents
| cpu=2%;80;90;0;100 mem=48%;80;90;0;100 disk=73%;80;90;0;100 dev_total=3 dev_sending=3 ...
```

### Logwatch Output

```
One or more Problems detected:
---------------------------------------------------------------------
[WARNING] - Logwatch - [FGT-Branch1] 2026-11-14 10:23:11 [event/system/warning] action:sys-reboot System is rebooting
[CRITICAL] - Logwatch - [FGT-DC] 2026-11-14 09:15:42 [event/vpn/critical] action:tunnel-down VPN tunnel tunnel-to-branch went down
---------------------------------------------------------------------
[WARNING] - Logwatch - 2 match(es) in last 150 entries (crit: 1, warn: 1)
 | logwatch_hits=2 logwatch_crit=1 logwatch_warn=1
```

### Verbose

```
System Info:
---------------------------------------
[OK] - System: FAZVM64-KVM-prod FortiAnalyzer-VM64-KVM v8.0.2-build0198 (Stand Alone)
\_ [OK] Serial:    FAZ-VMTM26023904
\_ [OK] HA Mode:   Stand Alone
\_ [OK] License:   Valid
---------------------------------------

System Resources:
---------------------------------------
[OK] - Resources: CPU 2%, Memory 48%, Disk 73%
\_ [OK] CPU:    2% (warn: 80%, crit: 90%)
\_ [OK] Memory: 48% 3812MB / 7855MB (warn: 80%, crit: 90%)
\_ [OK] Disk:   73% 71248MB / 97242MB (warn: 80%, crit: 90%)
---------------------------------------

Devices:
---------------------------------------
[OK] - Devices: 3 total, 3 sending logs
\_ [OK] FGT-Branch1 (10.1.1.1) FortiGate-60F v7.6.2: sending logs / age=2m
\_ [OK] FGT-Branch2 (10.1.2.1) FortiGate-60F v7.6.2: sending logs / age=3m
\_ [OK] FGT-DC (10.1.3.1) FortiGate-200F v7.6.2: sending logs / age=1m
---------------------------------------
```

## Integration with Monitoring Systems

### Icinga2 Configuration

Create a command definition in `/etc/icinga2/conf.d/commands.conf`:

```icinga2
object CheckCommand "check_fortianalyzer" {
    command = [ PluginDir + "/check_fortianalyzer_health.sh" ]
    arguments = {
        "-H"  = "$fortianalyzer_host$"
        "-T"  = "$fortianalyzer_token$"
        "-A"  = {
            set_if = "$fortianalyzer_check_all$"
        }
        "-SC" = "$fortianalyzer_snmp_community$"
        "-u"  = "$fortianalyzer_snmp_user$"
        "-a"  = "$fortianalyzer_snmp_auth_pass$"
        "-X"  = "$fortianalyzer_snmp_priv_pass$"
        "-v"  = {
            set_if = "$fortianalyzer_verbose$"
        }
        "--warn-devices-down"  = "$fortianalyzer_warn_devices_down$"
        "--crit-devices-down"  = "$fortianalyzer_crit_devices_down$"
        "--warn-dev-age"       = "$fortianalyzer_warn_dev_age$"
        "--warn-adom-quota"    = "$fortianalyzer_warn_adom_quota$"
        "--crit-adom-quota"    = "$fortianalyzer_crit_adom_quota$"
        "--task-hours"         = "$fortianalyzer_task_hours$"
        "--no-syslog-warn"     = {
            set_if = "$fortianalyzer_no_syslog_warn$"
        }
        "--no-logfwd-warn"     = {
            set_if = "$fortianalyzer_no_logfwd_warn$"
        }
        "--no-perfdata"        = {
            set_if = "$fortianalyzer_no_perfdata$"
        }
    }
    vars.fortianalyzer_check_all       = true
    vars.fortianalyzer_verbose         = false
    vars.fortianalyzer_warn_devices_down = 1
    vars.fortianalyzer_crit_devices_down = 1
    vars.fortianalyzer_warn_dev_age    = -1
    vars.fortianalyzer_warn_adom_quota = 80
    vars.fortianalyzer_crit_adom_quota = 90
    vars.fortianalyzer_task_hours      = 24
    vars.fortianalyzer_no_syslog_warn  = false
    vars.fortianalyzer_no_logfwd_warn  = false
    vars.fortianalyzer_no_perfdata     = false
}
```

For the Logwatch check, create a separate command and service:

```icinga2
object CheckCommand "check_fortianalyzer_logwatch" {
    command = [ PluginDir + "/check_fortianalyzer_health.sh" ]
    arguments = {
        "-H"                    = "$fortianalyzer_host$"
        "-T"                    = "$fortianalyzer_token$"
        "-eLogwatch"            = { set_if = true }
        "--logwatch-hours"      = "$fortianalyzer_logwatch_hours$"
        "--logwatch-level"      = "$fortianalyzer_logwatch_level$"
        "--logwatch-subtype"    = "$fortianalyzer_logwatch_subtype$"
        "--logwatch-type"       = "$fortianalyzer_logwatch_type$"
        "--logwatch-adom"       = "$fortianalyzer_logwatch_adom$"
    }
    vars.fortianalyzer_logwatch_hours = 1
    vars.fortianalyzer_logwatch_level = "warning"
}

apply Service "FortiAnalyzer Logwatch" {
    check_command = "check_fortianalyzer_logwatch"
    vars.fortianalyzer_host           = host.vars.fortianalyzer_host
    vars.fortianalyzer_token          = host.vars.fortianalyzer_token
    vars.fortianalyzer_logwatch_hours = 1
    vars.fortianalyzer_logwatch_level = "warning"

    assign where host.vars.fortianalyzer_host != ""
}
```

Create a service definition for the main health check:

```icinga2
apply Service "FortiAnalyzer Health" {
    check_command = "check_fortianalyzer"
    vars.fortianalyzer_host             = host.vars.fortianalyzer_host
    vars.fortianalyzer_token            = host.vars.fortianalyzer_token
    vars.fortianalyzer_snmp_community   = host.vars.fortianalyzer_snmp_community

    assign where host.vars.fortianalyzer_host != ""
}
```

### Nagios Configuration

Add to `commands.cfg`:

```nagios
define command {
    command_name    check_fortianalyzer
    command_line    $USER1$/check_fortianalyzer_health.sh -H $ARG1$ -T $ARG2$ -A
}

define command {
    command_name    check_fortianalyzer_logwatch
    command_line    $USER1$/check_fortianalyzer_health.sh -H $ARG1$ -T $ARG2$ -eLogwatch --logwatch-hours $ARG3$ --logwatch-level warning
}
```

Add to `services.cfg`:

```nagios
define service {
    use                 generic-service
    host_name           faz-prod
    service_description FortiAnalyzer Health
    check_command       check_fortianalyzer!10.0.0.1!your-api-token-here
}

define service {
    use                 generic-service
    host_name           faz-prod
    service_description FortiAnalyzer Logwatch
    check_command       check_fortianalyzer_logwatch!10.0.0.1!your-api-token-here!1
}
```

## Security Considerations

- **API Token**: Create a dedicated monitoring account with a read-only profile and generate an API token for it. Avoid reusing admin credentials.
- **Credential Storage**: Store API tokens and SNMP community strings in your monitoring system's secrets store (Icinga2 constants, HashiCorp Vault) — not in plain-text config files where possible.
- **Network Access**: The monitoring server requires HTTPS (port 443) access to the FortiAnalyzer management IP and SNMP UDP (port 161) for SNMP-based checks.
- **Self-Signed Certificates**: The plugin uses `--insecure` with curl to accept self-signed FortiAnalyzer certificates by default. Use `--https-verify` with `--https-ca-bundle` to enforce certificate validation.
- **SNMP**: If using SNMP, restrict the allowed-hosts list on the FortiAnalyzer to the monitoring server IP. Use SNMPv3 with authentication and privacy where possible.

## Troubleshooting

### Common Issues

**`[UNKNOWN] - Login to <host> failed (code -22) - check credentials`:**
- Verify username and password are correct
- Confirm the account exists in FortiAnalyzer

**`[UNKNOWN] - System: cannot retrieve system status`:**
- The API token is invalid, expired, or the account does not have JSON API Access enabled
- Navigate to **System > Admin > REST API Admin** and verify the token, or for user/pass accounts: **System > Admin > Administrators > \<user\> > JSON API Access: Read-Write**
- Test connectivity: `curl -sk -X POST https://<host>/jsonrpc -d '{"method":"get","params":[{"url":"/sys/status"}],"id":1,"session":"<token>"}'`

**`[UNKNOWN] - Logwatch: API credentials required`:**
- `-eLogwatch` requires API credentials (`-T` or `-U/-P`). SNMP-only mode is not supported for log search.

**`[OK] - Logwatch - no matches in last 0 entries (1h)`:**
- The FAZ found 0 log entries in the specified time window. This is normal when the device is quiet or the time range is very short. Try increasing `--logwatch-hours`.

**`[OK] - Alerts - feature not available on this device`** (verbose mode):
- The event management module is not licensed or enabled on this FortiAnalyzer. Check **System > License** in the FAZ GUI.

**`[UNKNOWN] - LogRate: SNMP credentials required`:**
- `-eLogRate` reads log rates from the FORTINET-FORTIANALYZER-MIB via SNMP. Add `-SC <community>` or `-u/-a/-X` for SNMPv3.

**`[UNKNOWN] - Uptime: not available via API`:**
- The API `Uptime` field is absent on this FAZ version. Add SNMP credentials for reliable uptime monitoring.

**Connection Timeout:**
- Verify HTTPS (port 443) access from the monitoring server to the FortiAnalyzer management IP
- Confirm that HTTPS administrative access is enabled on the management interface

**`jq: command not found`:**
- Install jq: `apt install jq` / `dnf install jq` / `emerge app-misc/jq`

### Debug Mode

Enable full bash trace output:

```bash
./check_fortianalyzer_health.sh -H 10.0.0.1 -T MyApiToken -A -d 2>&1 | less
```

Or use verbose mode for readable per-module detail:

```bash
./check_fortianalyzer_health.sh -H 10.0.0.1 -T MyApiToken -SC monitor -A -v
```

## Contributing

Contributions are welcome! Please feel free to submit issues, feature requests, or pull requests.

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-new-check`)
3. Make your changes
4. Test against a real FortiAnalyzer or a captured API JSON fixture
5. Submit a pull request

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

## Support

For support, please:
1. Review the troubleshooting section above
2. Check existing GitHub issues
3. Open a new issue with your FortiAnalyzer model, FortiAnalyzer version, and the full plugin output with `-d` (debug) enabled

## Author

**Felix Longardt**
- Email: monitoring@longardt.com
- GitHub: [@ascii42](https://github.com/ascii42)

## Acknowledgments

- Fortinet for the FortiAnalyzer JSON-RPC API and FORTINET-FORTIANALYZER-MIB documentation
- The Icinga and Nagios communities for feedback and testing

---

**Note**: This plugin is not officially supported by Fortinet, Inc. Use at your own discretion and test thoroughly in your environment before deploying to production monitoring.

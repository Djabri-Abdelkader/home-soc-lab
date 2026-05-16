#!/usr/bin/env bash
# =============================================================================
# SOC HOME LAB — TASK 5: rsyslog Configuration and Elastic Integration
# =============================================================================
# PURPOSE   : Configure rsyslog on Ubuntu SIEM VM, understand the syslog
#             protocol (RFC 5424), and ship logs to Elasticsearch via
#             Elastic Agent / Filebeat.
#
# ENVIRONMENT:
#   Ubuntu Server VM (SIEM) — 192.168.56.x
#   Elasticsearch + Kibana + Fleet Server + Elastic Agent all running
#
# THEORY SUMMARY:
#   rsyslog = "Rocket-fast System for Log processing"
#     - Userspace daemon, default on Ubuntu/Debian/RHEL
#     - Receives log messages from the kernel (via /dev/kmsg),
#       userspace processes (via /dev/log socket), and journald (imjournal)
#     - Routes messages based on facility.severity rules
#     - Can output to files, pipes, TCP/UDP syslog, or directly to Elasticsearch
#
#   RFC 5424 message format:
#     <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID MSG
#     PRI = (facility_number * 8) + severity_number
#     e.g. auth(4) * 8 + warning(4) = <36>
#
#   FACILITY CODES (source of message):
#     0  kern       Kernel messages
#     1  user       User-level processes
#     2  mail       Mail system
#     3  daemon     System daemons (sshd, cron, nginx)
#     4  auth       Security / authentication
#     5  syslog     Internal syslogd messages
#     9  cron       Cron / at daemons
#     10 authpriv   Private auth (sudo, su) - goes to /var/log/auth.log
#     16-23 local0-local7  Custom application use
#
#   SEVERITY LEVELS (0 = most critical, 7 = least):
#     0 emerg     System unusable
#     1 alert     Immediate action required
#     2 crit      Hardware/critical failure
#     3 err        Error conditions
#     4 warning   Warning conditions
#     5 notice    Normal but significant
#     6 info       Informational
#     7 debug     Debug messages
#
#   WHY rsyslog vs auditd?
#     auditd  - kernel-level, cannot be bypassed by userspace processes,
#               captures syscalls before they complete, structured records.
#               Use for: file access, process exec, privilege escalation.
#     rsyslog - userspace aggregator, collects what apps choose to log via
#               the POSIX syslog() API. Can be bypassed by malicious processes.
#               Use for: application events, service health, network telemetry.
#     In production: BOTH run side-by-side for full coverage.
# =============================================================================


# =============================================================================
# SECTION 1 — Verify rsyslog is installed and running
# =============================================================================

# Check service status
sudo systemctl status rsyslog
# Expected: active (running)

# Check rsyslog version (Ubuntu 22.04 ships 8.2112.0)
rsyslogd -v

# Check the main config file layout
# /etc/rsyslog.conf         = main config
# /etc/rsyslog.d/*.conf     = drop-in rules (ADD YOUR RULES HERE)
cat /etc/rsyslog.conf
ls /etc/rsyslog.d/


# =============================================================================
# SECTION 2 — Verify journal input modules are enabled
# =============================================================================
# imjournal = reads from systemd journal (modern Ubuntu services log here)
# imuxsock  = reads from the /dev/log UNIX socket (traditional syslog)

grep -n "imjournal\|imuxsock" /etc/rsyslog.conf
# Both should be present and uncommented


# =============================================================================
# SECTION 3 — Verify default log destinations
# =============================================================================

# On Ubuntu, rsyslog ships with rules that write to:
#   /var/log/syslog   - all messages (main destination)
#   /var/log/auth.log - auth and authpriv facility messages
#   /var/log/kern.log - kernel messages
#   /var/log/cron.log - cron daemon messages

ls -lh /var/log/syslog /var/log/auth.log /var/log/kern.log

# Tail the main syslog to confirm messages are flowing
sudo tail -f /var/log/syslog


# =============================================================================
# SECTION 4 — Test the logger utility (generate test syslog messages)
# =============================================================================
# logger(1) sends a message to the local syslog daemon from the command line.
# This is essential for testing rsyslog rules and verifying Kibana pickup.
# Syntax: logger -p <facility>.<severity> "message text"

# Basic test — sends to auth facility at warning severity
logger -p auth.warning "TEST: rsyslog task 5 auth warning"

# authpriv — private authentication events (sudo, su)
logger -p authpriv.notice "TEST: sudo session opened for analyst"

# daemon — background service events
logger -p daemon.info "TEST: nginx worker process started"

# local0 — custom application logging
logger -p local0.debug "TEST: custom detection script executed"

# Verify messages appeared in syslog
sudo grep "rsyslog task 5" /var/log/syslog
sudo grep "rsyslog task 5" /var/log/auth.log


# =============================================================================
# SECTION 5 — Configure JSON template output
# =============================================================================
# By default rsyslog writes BSD-format single-line text.
# Elastic prefers JSON for automatic field parsing (avoids needing a grok
# ingest pipeline). We define a JSON template and write to a separate file.

sudo tee /etc/rsyslog.d/01-json-template.conf > /dev/null << 'EOF'
# =============================================================================
# rsyslog JSON output template for Elastic Agent ingestion
# RFC 5424 compliant field names mapped to ECS-friendly keys
# =============================================================================

# Define the JSON template
template(name="JSONRsyslog" type="list") {
    constant(value="{")
    constant(value="\"@timestamp\":\"")     property(name="timereported" dateFormat="rfc3339")
    constant(value="\",\"host\":\"")        property(name="hostname")
    constant(value="\",\"program\":\"")     property(name="programname")
    constant(value="\",\"pid\":\"")         property(name="procid")
    constant(value="\",\"facility\":\"")    property(name="syslogfacility-text")
    constant(value="\",\"severity\":\"")    property(name="syslogseverity-text")
    constant(value="\",\"message\":\"")     property(name="msg" format="json")
    constant(value="\"}\n")
}

# Write ALL syslog messages as JSON to a dedicated file
*.* action(type="omfile" file="/var/log/syslog-json.log" template="JSONRsyslog")
EOF

# Validate the config syntax (exits 0 if valid)
sudo rsyslogd -N1
# Expected output: rsyslogd: version ... config validation run ... End of config validation

# Restart rsyslog to apply the new config
sudo systemctl restart rsyslog

# Verify rsyslog is still healthy after restart
sudo systemctl status rsyslog

# Send a test message and check the JSON file
logger -p local0.info "JSON format test from rsyslog task 5"
sudo tail -5 /var/log/syslog-json.log
# Expected: one-line JSON object per message


# =============================================================================
# SECTION 6 — Facility and severity matrix test
# =============================================================================
# Run this block to populate Kibana with events from every major facility/severity.
# Useful for verifying your Kibana queries and building detection logic.

# Authentication events (high SOC value)
logger -p auth.info    "AUTH INFO: user session started - task5 test"
logger -p auth.notice  "AUTH NOTICE: new login from 192.168.56.1 - task5 test"
logger -p auth.warning "AUTH WARNING: failed password attempt - task5 test"
logger -p auth.err     "AUTH ERR: PAM authentication module failure - task5 test"

# Private auth (sudo/su — goes to /var/log/auth.log on Ubuntu)
logger -p authpriv.notice "AUTHPRIV: sudo session opened for analyst - task5 test"
logger -p authpriv.warning "AUTHPRIV: unusual su attempt detected - task5 test"

# Daemon facility (web servers, SSH daemon, etc.)
logger -p daemon.info    "DAEMON INFO: sshd started successfully - task5 test"
logger -p daemon.warning "DAEMON WARNING: connection from unexpected IP - task5 test"
logger -p daemon.err     "DAEMON ERR: service failed to bind port 8080 - task5 test"

# Cron facility
logger -p cron.info    "CRON INFO: scheduled job executed - task5 test"
logger -p cron.warning "CRON WARNING: job duration exceeded threshold - task5 test"

# Local0 — custom scripts and tooling
logger -p local0.info  "LOCAL0 INFO: detection script run complete - task5 test"
logger -p local0.err   "LOCAL0 ERR: detection script failed with exit 1 - task5 test"

# Verify all test messages
sudo grep "task5 test" /var/log/syslog
sudo grep "task5 test" /var/log/syslog-json.log | python3 -m json.tool | head -40


# =============================================================================
# SECTION 7 — PRI calculation (interview prep)
# =============================================================================
# The PRI field = (facility_number * 8) + severity_number
# This is encoded as <N> at the start of every raw syslog packet.

python3 << 'EOF'
# PRI calculator — useful for reading raw packet captures (Wireshark, tcpdump)
facilities = {
    0: 'kern', 1: 'user', 2: 'mail', 3: 'daemon',
    4: 'auth', 5: 'syslog', 9: 'cron', 10: 'authpriv',
    16: 'local0', 17: 'local1'
}
severities = {
    0: 'emerg', 1: 'alert', 2: 'crit', 3: 'err',
    4: 'warning', 5: 'notice', 6: 'info', 7: 'debug'
}

print("Common PRI values you'll see in packet captures:")
for fname, fnum in [('auth',4),('authpriv',10),('daemon',3),('kern',0)]:
    for sname, snum in [('err',3),('warning',4),('info',6)]:
        pri = fnum * 8 + snum
        print(f"  <{pri:3d}>  {fname}.{sname}")
EOF


# =============================================================================
# SECTION 8 — Kibana verification queries (run in Discover)
# =============================================================================
# After Elastic Agent picks up /var/log/syslog and /var/log/syslog-json.log,
# use these KQL queries in Kibana Discover to verify ingestion.

# All syslog events from the System integration:
#   data_stream.dataset: "system.syslog"

# Filter by ECS syslog severity field:
#   log.syslog.severity.name: "warning"
#   log.syslog.severity.code <= 4    (warning and above = 0,1,2,3,4)

# Filter by facility:
#   log.syslog.facility.name: "auth"
#   log.syslog.facility.name: "authpriv"

# Find your test messages:
#   message: "task5 test"

# High-value security query — auth errors and warnings:
#   log.syslog.facility.name: ("auth" OR "authpriv") AND log.syslog.severity.code <= 4

# Specific program:
#   process.name: "sudo"
#   process.name: "sshd"


# =============================================================================
# SECTION 9 — Remote syslog forwarding (reference / theory)
# =============================================================================
# In enterprise environments, all hosts forward syslog to a central collector.
# This file shows the syntax — do NOT apply in lab without a receiver.

# sudo tee /etc/rsyslog.d/99-forward-remote.conf > /dev/null << 'EOF_REMOTE'
# # Forward syntax:
# #   @host:port   = UDP (unreliable, no ACK, low overhead)
# #   @@host:port  = TCP (reliable, ordered)
# #   @@(z9)host   = TCP + zlib compression level 9
# #   @@(o)host    = TCP + TLS (requires imtcp + gtls driver)
#
# # Forward only auth and authpriv to a remote SIEM collector:
# auth,authpriv.*  @@192.168.56.100:514
#
# # Forward everything:
# *.*  @@192.168.56.100:514
# EOF_REMOTE

# To RECEIVE syslog from other hosts (turn Ubuntu into a syslog collector):
# sudo tee -a /etc/rsyslog.conf > /dev/null << 'EOF_RECEIVE'
# # Enable TCP receiver on port 514
# module(load="imtcp")
# input(type="imtcp" port="514")
# # Enable UDP receiver on port 514
# module(load="imudp")
# input(type="imudp" port="514")
# EOF_RECEIVE
# sudo firewall-cmd --add-port=514/tcp --permanent  # if using firewalld
# sudo ufw allow 514/tcp                            # if using ufw


# =============================================================================
# SECTION 10 — Maintenance and troubleshooting
# =============================================================================

# Watch rsyslog process real-time messages
sudo journalctl -u rsyslog -f

# Check rsyslog internal statistics (message rates, queue depths)
sudo kill -USR1 $(pidof rsyslogd)   # sends SIGUSR1 to trigger stats dump
sudo grep "rsyslogd-pstats" /var/log/syslog | tail -5

# Validate config after any edit (always do this before restarting)
sudo rsyslogd -N1

# Check file permissions — rsyslog must be able to write to log files
ls -lah /var/log/syslog /var/log/auth.log /var/log/syslog-json.log
# Expected owner: syslog:adm

# Rotate logs manually (rsyslog uses logrotate to prevent runaway file growth)
sudo logrotate --force /etc/logrotate.d/rsyslog
ls -lh /var/log/syslog*


# =============================================================================
# END OF TASK 5 DOCUMENTATION
# =============================================================================
# NEXT: Task 5 complete. You now have:
#   - rsyslog shipping auth, daemon, cron, local0 facility logs to /var/log/syslog
#   - JSON-formatted output at /var/log/syslog-json.log for cleaner Elastic parsing
#   - Elastic Agent (via System integration) tailing both files into Elasticsearch
#   - Understanding of RFC 5424 fields, facility codes, and severity levels
#   - KQL queries to find syslog events in Kibana Discover
# =============================================================================
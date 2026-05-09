#!/usr/bin/env bash
# =============================================================================
# SOC HOME LAB — TASK 3: ZEEK INSTALLATION & ELASTIC SHIPPING
# =============================================================================
# Machine: Ubuntu Server VM (SIEM, 192.168.56.x)
# Purpose: Install Zeek, capture network metadata (conn.log, dns.log, http.log),
#          and ship those logs to Elasticsearch via Elastic Agent / Filebeat.
#
# WHAT IS ZEEK?
#   Zeek (formerly Bro) is a passive network analysis framework. Unlike host
#   agents (Elastic Agent on each VM), Zeek sits on a machine that can SEE
#   network traffic — it reads packets off a NIC in promiscuous mode and
#   converts raw packet streams into structured, human-readable log files.
#
#   Zeek does NOT inject packets or block traffic. It only observes.
#   Think of it as a "network DVR" that records what every connection did.
#
# HOW ZEEK DIFFERS FROM HOST AGENTS:
#   Host Agent (Elastic Agent / Sysmon):
#     - Runs INSIDE the endpoint
#     - Sees process-level data: which PID made a connection, which user
#     - Can see encrypted payload intent (e.g. process name doing TLS)
#     - Blind to traffic that bypasses the OS network stack
#
#   Zeek (Network-level):
#     - Runs on a network vantage point (SIEM VM or dedicated sensor)
#     - Sees ALL traffic passing through that interface
#     - Protocol-aware: parses HTTP headers, DNS queries, TLS certs
#     - Cannot see inside encrypted payloads (only metadata)
#     - OS-agnostic: one sensor covers Windows, Linux, IoT equally
#
#   In a real SOC: host agents + network sensors are COMPLEMENTARY.
#   You correlate: "Process X on host Y opened connection Z" with
#   "Connection Z transferred N bytes to IP A over 30 seconds."
# =============================================================================


# =============================================================================
# STEP 1 — ADD THE ZEEK REPOSITORY
# =============================================================================
# Zeek is not in Ubuntu's default apt repos. The official Zeek project
# maintains an OBS (Open Build Service) repo for each Ubuntu/Debian version.
#
# We add it so apt can find and install zeek packages.
# =============================================================================

# Install prerequisites for adding the repo
sudo apt-get install -y curl gnupg2 lsb-release

# Add Zeek's OpenPGP signing key so apt trusts packages from that repo
curl -fsSL https://download.opensuse.org/repositories/security:zeek/xUbuntu_22.04/Release.key \
  | sudo gpg --dearmor -o /etc/apt/trusted.gpg.d/zeek.gpg

# Add the Zeek apt repository for Ubuntu 22.04 (Jammy)
# If you are on Ubuntu 20.04 (Focal), change "xUbuntu_22.04" -> "xUbuntu_20.04"
echo "deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_22.04/ /" \
  | sudo tee /etc/apt/sources.list.d/zeek.list

# Refresh package lists so apt knows about zeek packages
sudo apt-get update


# =============================================================================
# STEP 2 — INSTALL ZEEK
# =============================================================================
# zeek              - the core package (installs to /opt/zeek/)
# zeekctl           - the ZeekControl management utility (start/stop/deploy)
#
# WHAT IS /opt/zeek/?
#   Zeek installs under /opt/zeek/ (not /usr/). Key directories:
#   /opt/zeek/bin/       - executables (zeek, zeekctl, etc.)
#   /opt/zeek/etc/       - configuration (networks.cfg, zeekctl.cfg, node.cfg)
#   /opt/zeek/logs/      - where current logs land (symlinked to dated dirs)
#   /opt/zeek/spool/     - internal state files
# =============================================================================

sudo apt-get install -y zeek zeekctl


# =============================================================================
# STEP 3 — ADD ZEEK TO PATH
# =============================================================================
# Zeek binaries are in /opt/zeek/bin/ which is not in the default PATH.
# We add it to /etc/environment so it persists for all users/sessions.
# =============================================================================

echo 'export PATH=$PATH:/opt/zeek/bin' | sudo tee -a /etc/profile.d/zeek.sh
source /etc/profile.d/zeek.sh

# Verify zeekctl is accessible
zeekctl --version


# =============================================================================
# STEP 4 — IDENTIFY YOUR NETWORK INTERFACE
# =============================================================================
# Zeek needs to know WHICH NIC to listen on. In VirtualBox host-only networks,
# the interface is usually enp0s3 or enp0s8 — confirm with:
#
#   ip addr show
#   ip link show
#
# Look for the interface with your 192.168.56.x address.
# Note it down — you'll use it in the Zeek node config below.
#
# WHAT IS PROMISCUOUS MODE?
#   Normally a NIC only passes frames addressed to its own MAC to the OS.
#   In promiscuous mode it passes ALL frames it sees on the wire.
#   Zeek automatically puts the interface into promiscuous mode.
#   On a host-only VirtualBox network, your Ubuntu VM sees all traffic
#   between the other VMs and itself — perfect for a SOC lab.
# =============================================================================

ip addr show   # Run this manually and note your interface name


# =============================================================================
# STEP 5 — CONFIGURE ZEEK (node.cfg)
# =============================================================================
# /opt/zeek/etc/node.cfg tells ZeekControl what mode to run in and which
# interface to monitor.
#
# We use "standalone" mode (one machine, one NIC).
# In production you'd use "cluster" mode with a dedicated sensor VM.
#
# REPLACE "enp0s8" below with your actual interface name.
# =============================================================================

sudo tee /opt/zeek/etc/node.cfg > /dev/null <<'EOF'
# node.cfg — ZeekControl node definition (standalone mode)
[zeek]
type=standalone
host=localhost
interface=enp0s8    # <-- CHANGE THIS to your host-only interface
EOF


# =============================================================================
# STEP 6 — CONFIGURE NETWORKS (networks.cfg)
# =============================================================================
# networks.cfg tells Zeek which IP ranges are "local" to your environment.
# This affects how Zeek labels connection endpoints (orig vs resp, local vs
# remote) in conn.log. For our host-only lab, 192.168.56.0/24 is local.
# =============================================================================

sudo tee /opt/zeek/etc/networks.cfg > /dev/null <<'EOF'
# networks.cfg — define what Zeek considers "local" networks
192.168.56.0/24   VirtualBox host-only network (SOC lab)
127.0.0.1/8       Loopback
EOF


# =============================================================================
# STEP 7 — CONFIGURE ZEEKCTL (zeekctl.cfg)
# =============================================================================
# zeekctl.cfg controls operational settings: log rotation, email alerts, etc.
# Key setting: LogDir — where logs are written.
# Default is /opt/zeek/logs/. We leave it as-is for this lab.
# =============================================================================

# Review current zeekctl.cfg (no changes needed for basic lab)
cat /opt/zeek/etc/zeekctl.cfg


# =============================================================================
# STEP 8 — ENABLE JSON LOG OUTPUT
# =============================================================================
# By default Zeek writes logs in tab-separated text format (TSV).
# Elasticsearch (and the Elastic Zeek integration) expects JSON Lines format.
#
# We enable JSON output by adding a line to Zeek's local.zeek policy file.
# local.zeek is the customisation entry point — Zeek loads it at startup.
# =============================================================================

# Enable JSON output globally for all Zeek log streams
echo '@load policy/tuning/json-logs' | sudo tee -a /opt/zeek/share/zeek/site/local.zeek

# Verify the line was added
grep json /opt/zeek/share/zeek/site/local.zeek


# =============================================================================
# STEP 9 — DEPLOY AND START ZEEK
# =============================================================================
# zeekctl deploy does three things in order:
#   1. install  — copies scripts into the spool dir, validates config
#   2. check    — syntax-checks all Zeek scripts
#   3. start    — starts the zeek process(es) defined in node.cfg
#
# After deploy, Zeek runs as a background process capturing traffic.
# =============================================================================

sudo zeekctl deploy

# Verify Zeek is running (should show "running")
sudo zeekctl status


# =============================================================================
# STEP 10 — VERIFY ZEEK LOG GENERATION
# =============================================================================
# Zeek writes logs to /opt/zeek/logs/current/ while running.
# After the first rotation (every hour by default), logs move to dated dirs
# like /opt/zeek/logs/2024-01-15/conn.15:00:00-16:00:00.log.gz
#
# Generate some traffic first so logs have data:
#   - ping 192.168.56.1        (ICMP, shows up in conn.log)
#   - curl http://example.com  (HTTP, shows up in http.log + conn.log)
#   - nslookup google.com      (DNS, shows up in dns.log + conn.log)
# =============================================================================

# Generate test traffic (run these from another VM or from this machine)
ping -c 4 192.168.56.1      # ICMP
curl -s http://example.com > /dev/null   # HTTP
nslookup google.com         # DNS

# Wait a few seconds, then check current logs
ls -la /opt/zeek/logs/current/

# Peek at conn.log (JSON format)
cat /opt/zeek/logs/current/conn.log | head -5 | python3 -m json.tool

# Peek at dns.log
cat /opt/zeek/logs/current/dns.log | head -5 | python3 -m json.tool

# Peek at http.log
cat /opt/zeek/logs/current/http.log | head -5 | python3 -m json.tool


# =============================================================================
# UNDERSTANDING CONN.LOG FIELDS
# =============================================================================
# conn.log is the most important Zeek log. Every completed TCP/UDP/ICMP
# connection gets one row. Key fields explained:
#
# ts          — Unix timestamp when the connection started
# uid         — Zeek's unique connection ID (e.g. "CXxyz123"). Links related
#               log entries across conn/dns/http logs for the SAME connection.
# id.orig_h   — Originator IP (who initiated the connection)
# id.orig_p   — Originator port
# id.resp_h   — Responder IP (who was connected to)
# id.resp_p   — Responder port (destination port — 80=HTTP, 443=HTTPS, 53=DNS)
# proto       — Transport protocol: tcp, udp, icmp
# service     — Zeek's application-layer detection (http, dns, ssl, ssh, etc.)
# duration    — How long the connection lasted (seconds)
# orig_bytes  — Bytes sent FROM the originator TO the responder
#               (payload bytes only, NOT including TCP/IP headers)
# resp_bytes  — Bytes sent FROM the responder BACK to the originator
#               An unusual ratio (huge resp_bytes, tiny orig_bytes) can
#               indicate data exfiltration or C2 beaconing.
# conn_state  — What happened at the TCP/UDP level (see states below)
# local_orig  — true if originator IP is in your networks.cfg
# local_resp  — true if responder IP is in your networks.cfg
# missed_bytes— Bytes Zeek couldn't reassemble (packet loss indicator)
#
# CONN_STATE VALUES — CRITICAL FOR DETECTION:
#   S0    — SYN sent, no response ever. Likely a port scan or dropped firewall.
#   S1    — Connection established, not cleanly closed (FIN/RST not seen).
#   SF    — Normal full TCP session: SYN, SYN-ACK, data, FIN. HEALTHY.
#   REJ   — Connection refused: SYN + RST received. Port was closed.
#   S2    — Connection established, originator sent FIN, responder didn't.
#   S3    — Connection established, responder sent FIN, originator didn't.
#   RSTO  — Originator aborted with RST.
#   RSTR  — Responder aborted with RST.
#   SH    — SYN + FIN sent by originator (malformed, possibly OS fingerprinting)
#   OTH   — Mid-stream traffic seen, no opening handshake observed.
#
# WHY THIS MATTERS IN DETECTION:
#   Hundreds of S0 connections to many ports = port scan (Nmap SYN scan)
#   Many REJ connections from one host = blocked scan, host is probing
#   Large resp_bytes with small orig_bytes over long duration = exfiltration
#   Periodic SF connections to unusual IP every N seconds = C2 beaconing
# =============================================================================


# =============================================================================
# STEP 11 — INSTALL ELASTIC AGENT ZEEK INTEGRATION
# =============================================================================
# The cleanest way to ship Zeek logs is via the Elastic "Zeek" integration,
# which uses the Elastic Agent's Filebeat component to tail Zeek log files,
# parse JSON, and map fields to the Elastic Common Schema (ECS).
#
# UI STEPS (do these in Kibana):
#   1. Kibana → Fleet → Agent Policies → click "Linux Agent Policy"
#   2. Click "Add integration"
#   3. Search for "Zeek" → click "Zeek" card
#   4. Click "Add Zeek"
#   5. Configure paths for each log type:
#
#      Connection log path:  /opt/zeek/logs/current/conn.log
#      DNS log path:         /opt/zeek/logs/current/dns.log
#      HTTP log path:        /opt/zeek/logs/current/http.log
#
#   6. Leave other options as default for this lab
#   7. Click "Save and continue" → "Save and deploy changes"
#
# NOTE: The Elastic Agent on the Ubuntu VM must have read permission on the
#       Zeek log directory. Check with:
#         ls -la /opt/zeek/logs/current/
#       If permission denied, run:
#         sudo chmod 755 /opt/zeek/logs/current/
#         sudo chmod 644 /opt/zeek/logs/current/*.log
# =============================================================================


# =============================================================================
# STEP 12 — FIX PERMISSIONS FOR ELASTIC AGENT
# =============================================================================
# Zeek runs as root (or the zeek user) and writes logs readable only by root.
# Elastic Agent runs as the "elastic-agent" user and needs read access.
# =============================================================================

# Option A: Grant read permission on Zeek log dir and files (simpler for lab)
sudo chmod 755 /opt/zeek/logs/
sudo chmod 755 /opt/zeek/logs/current/
sudo chmod 644 /opt/zeek/logs/current/*.log 2>/dev/null || true

# Option B (production): Add elastic-agent to a zeek group — more secure
# sudo groupadd zeeklogs
# sudo usermod -aG zeeklogs elastic-agent
# sudo chgrp -R zeeklogs /opt/zeek/logs/
# sudo chmod -R 750 /opt/zeek/logs/

# Verify elastic-agent can read the log (run as root/sudo)
sudo -u elastic-agent cat /opt/zeek/logs/current/conn.log | head -1 && echo "OK: agent can read conn.log"


# =============================================================================
# STEP 13 — VERIFY LOGS IN KIBANA (UI STEPS)
# =============================================================================
# After deploying the integration, wait ~60 seconds, then:
#
#   1. Kibana → Discover
#   2. Select data view: "logs-*" or "filebeat-*"
#   3. Add filter: event.dataset : "zeek.conn"
#   4. You should see conn.log entries with fields like:
#        zeek.conn.orig_bytes, zeek.conn.resp_bytes, zeek.conn.conn_state
#        network.protocol, source.ip, destination.ip
#   5. Try other datasets:
#        event.dataset : "zeek.dns"   (dns.log)
#        event.dataset : "zeek.http"  (http.log)
#
# USEFUL KQL QUERIES TO TRY IN DISCOVER:
#   Show only TCP connections:
#     network.transport : "tcp"
#
#   Show port scans (S0 state = SYN with no response):
#     zeek.conn.conn_state : "S0"
#
#   Show large data transfers (resp_bytes > 1MB):
#     zeek.conn.resp_bytes > 1000000
#
#   Show all DNS queries:
#     event.dataset : "zeek.dns" AND dns.question.name : *
#
#   Show HTTP requests with their URLs:
#     event.dataset : "zeek.http" AND url.full : *
# =============================================================================


# =============================================================================
# STEP 14 — AUTOSTART ZEEK ON BOOT
# =============================================================================
# ZeekControl doesn't create a systemd unit by default.
# We create one so Zeek restarts automatically after a VM reboot.
# =============================================================================

sudo tee /etc/systemd/system/zeek.service > /dev/null <<'EOF'
[Unit]
Description=Zeek Network Security Monitor
After=network.target

[Service]
Type=forking
ExecStart=/opt/zeek/bin/zeekctl start
ExecStop=/opt/zeek/bin/zeekctl stop
ExecReload=/opt/zeek/bin/zeekctl deploy
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable zeek.service
sudo systemctl status zeek.service   # Confirm it's enabled


# =============================================================================
# STEP 15 — USEFUL ZEEKCTL COMMANDS (REFERENCE)
# =============================================================================

sudo zeekctl status        # Show running status of all Zeek nodes
sudo zeekctl start         # Start Zeek (if stopped)
sudo zeekctl stop          # Gracefully stop Zeek
sudo zeekctl restart       # Stop + start
sudo zeekctl deploy        # Reload config changes (edit scripts, then deploy)
sudo zeekctl check         # Syntax-check Zeek scripts without restarting
sudo zeekctl cron          # Run scheduled tasks (log rotation, cleanup) — normally via crontab
sudo zeekctl logs          # Show recent Zeek process logs (errors go here)
sudo zeekctl netstats      # Show packet counters (drops indicate overload)

# Check for packet drops (important for lab validation)
# If "dropped" is increasing, your interface can't keep up — acceptable in a VM lab
sudo zeekctl netstats


# =============================================================================
# INTERVIEW PREP — KEY CONCEPTS FOR ZEEK / NETWORK MONITORING
# =============================================================================
#
# Q: Why use Zeek instead of just shipping all raw pcap to a SIEM?
# A: Raw pcap is enormous (GB/hour on busy networks). Zeek extracts metadata
#    only — one JSON line per connection — reducing data by 99%+ while keeping
#    actionable fields (IPs, ports, bytes, conn_state, protocol). SIEMs index
#    metadata; analysts pull raw pcap selectively from storage when needed.
#
# Q: What is a "network tap" vs monitoring a regular interface?
# A: In production, Zeek sensors receive traffic via a network TAP (hardware
#    device that passively copies all frames) or SPAN/mirror port (switch
#    feature). In our lab, the host-only virtual network means the Ubuntu VM
#    already sees traffic between VMs — no TAP needed.
#
# Q: How does Zeek identify application-layer protocols?
# A: Zeek uses "protocol analyzers" — built-in parsers for HTTP, DNS, TLS, SSH,
#    FTP, SMTP, etc. It does Dynamic Protocol Detection (DPD): if HTTP traffic
#    appears on port 8080 instead of 80, Zeek still identifies it as HTTP by
#    analysing the payload structure (not just port numbers).
#
# Q: What is the Zeek uid and why is it important?
# A: Every connection gets a unique ID (uid like "CXxyz..."). When Zeek writes
#    to multiple logs for the same connection (conn.log + http.log + ssl.log),
#    all entries share the same uid. This lets you JOIN logs: find the conn.log
#    entry for an http.log request, confirming bytes, duration, and conn_state.
#
# Q: How does Zeek conn_state help detect port scans?
# A: A SYN scan (nmap -sS) sends SYN but never completes the handshake.
#    Zeek sees SYN with no SYN-ACK response → conn_state = S0.
#    Hundreds of S0 connections from one source IP to many ports = port scan.
#    This is a basic but high-value detection rule in any SIEM.
#
# Q: What's the difference between orig_bytes and resp_bytes in detection?
# A: orig_bytes = client → server (request size)
#    resp_bytes = server → client (response size)
#    A tiny orig_bytes with huge resp_bytes over many connections can indicate
#    "low and slow" exfiltration or C2 using HTTP GET beacons (small request,
#    large command response). Normal web browsing has the opposite pattern.
# =============================================================================


# =============================================================================
# TROUBLESHOOTING
# =============================================================================

# Zeek won't start — check logs
sudo zeekctl diag

# No logs being generated — confirm interface is correct
sudo zeekctl check   # Look for interface errors

# Elastic Agent not picking up logs — check agent logs
sudo journalctl -u elastic-agent -f --since "10 min ago"

# Check Filebeat/agent input status
sudo /opt/Elastic/Agent/elastic-agent diagnostics

# Permission denied on log files
sudo chmod 644 /opt/zeek/logs/current/*.log

# Zeek logs in TSV not JSON — verify local.zeek edit
grep json /opt/zeek/share/zeek/site/local.zeek
# Should show: @load policy/tuning/json-logs
# If missing, re-add and run: sudo zeekctl deploy
# =============================================================================
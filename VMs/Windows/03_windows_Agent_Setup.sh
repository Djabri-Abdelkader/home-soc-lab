# =============================================================================
# SOC LAB - STEP 3: WINDOWS 10 ELASTIC AGENT + SYSMON SETUP
# Machine: Windows 10 VM (monitored endpoint)
# Role: Elastic Agent ships Windows logs + Sysmon events to Fleet Server
# =============================================================================
# Run all commands in PowerShell as Administrator
# Complete Ubuntu setup (01_ubuntu_siem_setup.sh) before this.
# Commands marked [UI] were performed via Kibana web interface.
# =============================================================================

# Variables - fill in your actual values before running
$FLEET_IP = "192.168.56.x"                      # Ubuntu host-only IP
$ELASTIC_VERSION = "8.x.x"                       # Must match your ES version exactly
$ENROLLMENT_TOKEN = "your-windows-token-here"    # Windows Token from Fleet


# =============================================================================
# SECTION 1: INSTALL ELASTIC AGENT ON WINDOWS
# =============================================================================

# Download the Elastic Agent zip for Windows
Invoke-WebRequest `
  -Uri "https://artifacts.elastic.co/downloads/beats/elastic-agent/elastic-agent-$ELASTIC_VERSION-windows-x86_64.zip" `
  -OutFile "$env:TEMP\elastic-agent.zip"

# Extract the archive
Expand-Archive "$env:TEMP\elastic-agent.zip" -DestinationPath "C:\elastic-agent"

# Navigate to the extracted folder
Set-Location "C:\elastic-agent\elastic-agent-$ELASTIC_VERSION-windows-x86_64"

# Install the agent and enroll it with Fleet Server
# --url: Fleet Server on Ubuntu
# --enrollment-token: assigns this agent to Windows Agent Policy
# --insecure: skips TLS cert verification (acceptable for a home lab)
#             To avoid --insecure, copy http_ca.crt from Ubuntu to Windows
#             and use --certificate-authorities="C:\path\to\http_ca.crt"
# --non-interactive: no prompts
.\elastic-agent.exe install `
  --url="https://$FLEET_IP`:8220" `
  --enrollment-token="$ENROLLMENT_TOKEN" `
  --insecure `
  --non-interactive


# =============================================================================
# SECTION 2: VERIFY ELASTIC AGENT IS RUNNING
# =============================================================================

# Check the Windows service status
Get-Service -Name "Elastic Agent"

# View agent logs if troubleshooting needed
Get-Content "C:\Program Files\Elastic\Agent\data\elastic-agent-*\logs\elastic-agent*.log" -Tail 50

# Test connectivity to Fleet Server
Test-NetConnection -ComputerName $FLEET_IP -Port 8220


# =============================================================================
# SECTION 3: UNDERSTAND WINDOWS LOG CHANNELS
# =============================================================================

# Windows stores logs in "channels" (Event Log system).
# Each channel is a named stream of events.
# The Windows integration you already added collects these main channels:
#
#   Security                          - Logins, privilege use, object access
#                                       Key Event IDs: 4624 (logon), 4625 (failed logon),
#                                       4688 (process created), 4720 (account created)
#
#   System                            - OS events, driver issues, service changes
#
#   Application                       - App-specific events
#
#   Microsoft-Windows-PowerShell/Operational  - PowerShell execution logs
#                                               Critical for detecting PS-based attacks
#
# After installing Sysmon, a NEW channel appears:
#   Microsoft-Windows-Sysmon/Operational      - Rich process/network/file events



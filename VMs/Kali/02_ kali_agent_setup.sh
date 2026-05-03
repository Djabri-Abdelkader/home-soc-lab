#!/bin/bash
# =============================================================================
# SOC LAB - STEP 2: KALI LINUX ELASTIC AGENT + AUDITD SETUP
# Machine: Kali Linux (attacker simulation machine / monitored endpoint)
# Role: Elastic Agent ships Kali's logs to Fleet Server on Ubuntu
# =============================================================================
# NOTE: Commands marked [UI] were performed via Kibana web interface.
#       Complete Ubuntu setup (01_ubuntu_siem_setup.sh) before this.
# =============================================================================

# Variables - fill in your actual values before running
FLEET_IP="192.168.56.x"          # Ubuntu host-only IP (your FLEET_IP)
ELASTIC_VERSION="8.x.x"          # Must match your Elasticsearch version exactly
ENROLLMENT_TOKEN="your-token"    # Linux Token from Fleet -> Enrollment tokens


# =============================================================================
# SECTION 1: GET THE CA CERTIFICATE FROM UBUNTU
# =============================================================================

# The agent needs to trust Elasticsearch's TLS certificate.
# Ubuntu should be serving it temporarily via python3 http.server (see ubuntu script).
wget http://${FLEET_IP}:8888/http_ca.crt -O /tmp/http_ca.crt

# Verify the cert downloaded correctly
openssl x509 -in /tmp/http_ca.crt -noout -subject -dates


# =============================================================================
# SECTION 2: DOWNLOAD AND INSTALL ELASTIC AGENT
# =============================================================================

cd /tmp

# Download the Elastic Agent for Linux x86_64
curl -L -O "https://artifacts.elastic.co/downloads/beats/elastic-agent/elastic-agent-${ELASTIC_VERSION}-linux-x86_64.tar.gz"

# Extract the archive
tar xzvf "elastic-agent-${ELASTIC_VERSION}-linux-x86_64.tar.gz"

cd "elastic-agent-${ELASTIC_VERSION}-linux-x86_64"

# Enroll and install the agent
# --url: Fleet Server address (running on Ubuntu)
# --enrollment-token: authenticates this agent to Fleet and assigns it a policy
# --certificate-authorities: tells the agent to trust our self-signed ES cert
# --non-interactive: skip confirmation prompts
sudo ./elastic-agent install \
  --url="https://${FLEET_IP}:8220" \
  --enrollment-token="${ENROLLMENT_TOKEN}" \
  --certificate-authorities=/tmp/http_ca.crt \
  --non-interactive

# Alternative if you have cert issues during testing (insecure mode - lab only):
# sudo ./elastic-agent install \
#   --url="https://${FLEET_IP}:8220" \
#   --enrollment-token="${ENROLLMENT_TOKEN}" \
#   --insecure \
#   --non-interactive


# =============================================================================
# SECTION 3: VERIFY ELASTIC AGENT IS RUNNING
# =============================================================================

# Check agent service status
sudo systemctl status elastic-agent

# Check agent logs if troubleshooting needed
sudo journalctl -u elastic-agent -f --no-pager | tail -50

# Test connectivity to Fleet Server (should return HTTP response)
curl -k https://${FLEET_IP}:8220/api/status



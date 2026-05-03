#!/bin/bash
# =============================================================================
# SOC LAB - STEP 1: UBUNTU SIEM SETUP
# Machine: Ubuntu Server (M SIEM / Fleet Server)
# Role: Runs Elasticsearch + Kibana + Fleet Server + Elastic Agent
# =============================================================================
# NOTE: Commands marked [UI] were performed via Kibana web interface,
#       not the terminal. They are documented here as comments for reference.
# =============================================================================

# --- PREREQUISITES: Elasticsearch + Kibana already installed and running ---
# Verify both services are healthy before proceeding
sudo systemctl status elasticsearch
sudo systemctl status kibana


# =============================================================================
# SECTION 1: GATHER NETWORK INFO
# =============================================================================

# Get the host-only adapter IP (this is your FLEET_IP)
# This is the IP all other VMs will use to reach Fleet Server
# Look for the 192.168.56.x address on the host-only interface
ip a | grep "inet " | grep -v 127
# --> Note this IP as FLEET_IP (e.g. 192.168.56.10)


# =============================================================================
# SECTION 2: CREATE A SERVICE TOKEN FOR FLEET SERVER
# =============================================================================

# Fleet Server needs a service token to authenticate with Elasticsearch
# This token is used ONCE during Fleet Server enrollment
sudo /usr/share/elasticsearch/bin/elasticsearch-service-tokens create elastic/fleet-server fleet-token
# --> Save the token output (looks like: AAEAAWVsYXN0aWMvZ...)


# =============================================================================
# SECTION 3: GET THE ELASTICSEARCH TLS FINGERPRINT
# =============================================================================

# Fleet Server and agents verify Elasticsearch's identity using this fingerprint
# You'll need this during elastic-agent install below
sudo openssl x509 -fingerprint -sha256 \
  -in /etc/elasticsearch/certs/http_ca.crt \
  -noout | sed 's/SHA256 Fingerprint=//' | tr -d ':'
# --> Save this fingerprint (long hex string, no colons)


# =============================================================================
# SECTION 4: [UI] CONFIGURE FLEET IN KIBANA
# =============================================================================

# Navigate to: http://<UBUNTU_IP>:5601/app/fleet

# [UI] Step 4a - Set Fleet Server host URL:
#   Fleet -> Settings -> Fleet Server hosts
#   Add: https://<FLEET_IP>:8220
#   Click "Save and apply settings"

# [UI] Step 4b - Fix Elasticsearch output URL (CRITICAL):
#   Fleet -> Settings -> Outputs -> Edit default output
#   Change the URL from https://localhost:9200
#   To: https://<FLEET_IP>:9200
#   (Agents on other VMs cannot reach "localhost" on the Ubuntu machine)
#   Save changes.

# [UI] Step 4c - Create Fleet Server Policy:
#   Fleet -> Agent Policies -> Create agent policy
#   Name: "Fleet Server Policy"
#   Leave all defaults -> Create agent policy


# =============================================================================
# SECTION 5: INSTALL ELASTIC AGENT AS FLEET SERVER ON UBUNTU
# =============================================================================

cd /tmp

# Detect the exact Elasticsearch version (agent version MUST match ES version)
ELASTIC_VERSION=$(sudo /usr/share/elasticsearch/bin/elasticsearch --version | grep -oP '\d+\.\d+\.\d+')
echo "Detected Elasticsearch version: $ELASTIC_VERSION"

# Download the Elastic Agent tarball
curl -L -O "https://artifacts.elastic.co/downloads/beats/elastic-agent/elastic-agent-${ELASTIC_VERSION}-linux-x86_64.tar.gz"

# Extract the archive
tar xzvf "elastic-agent-${ELASTIC_VERSION}-linux-x86_64.tar.gz"

cd "elastic-agent-${ELASTIC_VERSION}-linux-x86_64"

# Install the agent in Fleet Server mode
# This single agent serves a dual role:
#   1. Acts as the Fleet Server (management plane for all other agents)
#   2. Acts as a regular Elastic Agent (ships Ubuntu's own logs)
sudo ./elastic-agent install \
  --fleet-server-es=https://<FLEET_IP>:9200 \
  --fleet-server-service-token=<YOUR_SERVICE_TOKEN> \
  --fleet-server-policy=fleet-server-policy \
  --fleet-server-es-ca-trusted-fingerprint=<ES_FINGERPRINT> \
  --fleet-server-port=8220 \
  --certificate-authorities=/etc/elasticsearch/certs/http_ca.crt \
  --fleet-server-es-cert=/etc/elasticsearch/certs/http.crt \
  --fleet-server-es-cert-key=/etc/elasticsearch/certs/http.key \
  --non-interactive
# Replace <FLEET_IP>, <YOUR_SERVICE_TOKEN>, <ES_FINGERPRINT> with your actual values


# =============================================================================
# SECTION 6: VERIFY FLEET SERVER IS RUNNING
# =============================================================================

# Check the elastic-agent service status
sudo systemctl status elastic-agent

# Query Fleet Server health endpoint directly
# Expected response: {"name":"fleet-server","status":"HEALTHY"}
curl -k https://localhost:8220/api/status

# Open firewall ports so other VMs can reach this machine
sudo ufw allow 8220/tcp   # Fleet Server port (agent enrollment + management)
sudo ufw allow 9200/tcp   # Elasticsearch port (agents ship data here)
sudo ufw reload


# =============================================================================
# SECTION 7: [UI] CREATE ENROLLMENT TOKEN + AGENT POLICIES FOR OTHER VMs
# =============================================================================

# [UI] Create separate policies for Windows and Linux agents:
#   Fleet -> Agent Policies -> Create agent policy
#   Name: "Windows Agent Policy" -> Create
#
#   Fleet -> Agent Policies -> Create agent policy
#   Name: "Linux Agent Policy" -> Create
#
# WHY SEPARATE POLICIES?
# A policy is a configuration bundle pushed to agents.
# If you put Windows-only integrations (Sysmon) in a shared policy,
# the Linux agent will also try to collect Windows Event Logs and fail.
# Separate policies = clean separation of OS-specific configurations.

# [UI] Create enrollment tokens for each policy:
#   Fleet -> Enrollment tokens -> Create enrollment token
#   - Name: "Windows Token" -> Policy: Windows Agent Policy -> Create -> Copy token
#   - Name: "Linux Token"   -> Policy: Linux Agent Policy   -> Create -> Copy token


# =============================================================================
# SECTION 8: SERVE THE CA CERTIFICATE FOR OTHER VMs TO DOWNLOAD
# =============================================================================

# Agents need to trust Elasticsearch's TLS certificate.
# The easiest way to distribute it in a lab is a temporary HTTP server.
# Run this BEFORE enrolling other VMs, then kill it after.

sudo cp /etc/elasticsearch/certs/http_ca.crt /tmp/
cd /tmp
python3 -m http.server 8888
# On Kali: wget http://<FLEET_IP>:8888/http_ca.crt -O /tmp/http_ca.crt
# Kill this server (Ctrl+C) after other VMs have downloaded the cert


# =============================================================================
# VERIFICATION: All agents should appear healthy in Kibana
# =============================================================================
# Fleet -> Agents
# Expected:
#   ubuntu-siem  | Healthy | Fleet Server Policy
#   kali         | Healthy | Linux Agent Policy
#   windows-vm   | Healthy | Windows Agent Policy
# 🏠 Home SOC Lab

![Status](https://img.shields.io/badge/status-in_progress-yellow)
![Stack](https://img.shields.io/badge/stack-Elastic%20%7C%20Zeek%20%7C%20Sysmon-blue)
![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows-lightgrey)
![MITRE](https://img.shields.io/badge/framework-MITRE%20ATT%26CK-red)

## 📌 Description

A fully functional Security Operations Center (SOC) lab built on personal hardware, designed to simulate real enterprise detection workflows. The lab ingests multi-source telemetry — Linux audit logs (`syslog`, `auditd`), Windows event logs via `Sysmon`, and network traffic via `Zeek` — into a self-hosted Elastic Stack. Detection rules are written in KQL, validated against simulated MITRE ATT&CK techniques (T1059, T1003), and tuned iteratively. Every component was chosen to match tools used in production SOC environments.

---

## 🏗️ Architecture

<!-- REPLACE this placeholder with your draw.io export PNG -->
<!-- Export from draw.io: File > Export As > PNG, then commit to /docs/architecture.png -->
```
[architecture.png goes here — export from draw.io and commit to /docs/]
```
> **Draw.io file:** [`/docs/architecture.drawio`](./docs/architecture.drawio)

---

## 🧰 Tech Stack

| Layer | Tool | Purpose |
|---|---|---|
| SIEM | `Elasticsearch + Kibana` | Log storage, search, dashboards |
| Agent (Linux) | `Elastic Agent / Filebeat` | Collect syslog, auditd |
| Agent (Windows) | `Winlogbeat + Sysmon` | Windows event log collection |
| Network | `Zeek` | Network traffic analysis, conn.log |
| Detection | `KQL` | Detection rule language |
| Attack Sim | `Atomic Red Team` | MITRE technique simulation |

---

## ⚙️ Installation

### Prerequisites
- Linux host (Ubuntu 22.04+) with 8GB+ RAM
- Windows VM (for Sysmon telemetry)
- Docker (optional, for Elastic)

### Steps

```bash
# 1. Clone the repo
git clone https://github.com/Djabri-Abdelkader/home-soc-lab.git
cd home-soc-lab

# 2. Start Elastic Stack
docker-compose up -d   # or follow /docs/manual-install.md

# 3. Deploy agents
# Linux: see /docs/linux-agent-setup.md
# Windows: see /docs/windows-sysmon-setup.md

# 4. Load detection rules
# Kibana > Security > Rules > Import > /rules/*.ndjson
```

> Detailed setup guides in [`/docs/`](./docs/)

---

## 🚀 Usage Examples

### Sample: KQL Detection Rule — Suspicious PowerShell Execution (T1059.001)
```kql
event.code: "4104" and
powershell.file.script_block_text: (*IEX* or *Invoke-Expression* or *DownloadString*)
```

### Sample: Zeek conn.log alert — long duration outbound connection
```bash
# Query in Kibana or via CLI:
zeek-cut id.orig_h id.resp_h duration < conn.log | awk '$3 > 300'
```

### Sample Dashboard Output
```
[screenshot goes here — /docs/screenshots/dashboard.png]
```

---

## 📖 What I Learned

<!-- ADD entries as you progress — one bullet per discovery, dated -->

### Log Collection
- [ ] *[DATE]* — How auditd syscall rules work and why they're noisy by default
- [ ] *[DATE]* — Difference between Windows Security log channels and Sysmon channels

### Detection Engineering
- [ ] *[DATE]* — Why KQL `wildcard` queries are expensive vs field mapping
- [ ] *[DATE]* — How to reduce false positives by baselining normal PowerShell usage

### Infrastructure
- [ ] *[DATE]* — How Elastic indices work and why ILM (Index Lifecycle Management) matters

---

## 📋 Project Progress

> Tracked via [GitHub Issues](https://github.com/Djabri-Abdelkader/home-soc-lab/issues)

| Milestone | Status |
|---|---|
| Elastic Stack running locally | ⬜ |
| Linux log ingestion (syslog + auditd) | ⬜ |
| Sysmon + Winlogbeat configured | ⬜ |
| Zeek network capture pipeline | ⬜ |
| First KQL detection rule written | ⬜ |
| T1059 attack simulated + detected | ⬜ |
| T1003 attack simulated + detected | ⬜ |
| Dashboard built in Kibana | ⬜ |

---

## 📁 Repo Structure

```
home-soc-lab/
├── VMs/
    ├── Linux/
        ├── Elastic Stack Ubuntu Installation Guide.sh
    ├── Widnows
    ├── Kali
├── docs/
│   ├── architecture.drawio       # Draw.io source file
│   ├── architecture.png          # Exported diagram
│   ├── linux-agent-setup.md
│   ├── windows-sysmon-setup.md
│   └── screenshots/
├── rules/
│   └── *.ndjson                  # Exportable Elastic detection rules
├── configs/
│   ├── sysmon-config.xml
│   ├── filebeat.yml
│   └── zeek/
├── attack-simulations/
│   └── T1059-powershell.md       # Step-by-step attack + expected alert
└── docker-compose.yml
└──README.md

```

---

## 🔗 Related Projects

- [Log Parser CLI](https://github.com/Djabri-Abdelkader/log-parser-cli) — parses logs this lab generates
- [SOC Triage Agent](https://github.com/Djabri-Abdelkader/soc-triage-agent) — triages alerts from this lab
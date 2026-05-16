# 🏠 Home SOC Lab

![Status](https://img.shields.io/badge/status-in_progress-yellow)
![Stack](https://img.shields.io/badge/stack-Elastic%20%7C%20Zeek%20%7C%20Sysmon-blue)
![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows-lightgrey)
![MITRE](https://img.shields.io/badge/framework-MITRE%20ATT%26CK-red)

## 📌 Description

A fully functional Security Operations Center (SOC) lab built on personal hardware, designed to simulate real enterprise detection workflows. The lab ingests multi-source telemetry — Linux audit logs (`syslog`, `auditd`), Windows event logs via `Sysmon`, and network traffic via `Zeek` — into a self-hosted Elastic Stack. Detection rules are written in KQL, validated against simulated MITRE ATT&CK techniques (T1059, T1003), and tuned iteratively. Every component was chosen to match tools used in production SOC environments.

---

## 🏗️ Architecture



![image](https://github.com/Djabri-Abdelkader/home-soc-lab/blob/main/Images/soc_lab_architecture_final.png)

> **svg.io file:** [`/Images/soc_lab_architecture_final.svg`](./Images/soc_lab_architecture_final.svg)

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


## 📁 Repo Structure

```
home-soc-lab/
├── Images/
│   ├── soc_lab_architecture_final.png      
│   ├── soc_lab_architecture_final.svg          
├── VMs/
│   ├── Linux/
│   ├── ├── 01_ubuntu_siem_setup.sh
│   ├── ├── auditd.sh
│   ├── ├── elastic_stack_installation_guide.sh
│   ├── ├── zeek_config.sh
│   ├── Widnows
│   ├── ├── 03_windows_Agent_Setup.ps1
│   ├── ├── sysmon_windows.ps1
│   ├── ├── windows_event_channels.ps1
│   ├── Kali
│   ├── ├── 02_ kali_agent_setup.sh
├── rules/
│   └── *.ndjson                  # Exportable Elastic detection rules
├── configs/
│   ├── sysmon-config.xml
│   ├── filebeat.yml
│   └── zeek/
├── attack-simulations/
│   └── T1059-powershell.md       # Step-by-step attack + expected alert
└── docker-compose.yml

```

---

## 🔗 Related Projects

- [Log Parser CLI](https://github.com/Djabri-Abdelkader/log-parser-cli) — parses logs this lab generates
- [SOC Triage Agent](https://github.com/Djabri-Abdelkader/soc-triage-agent) — triages alerts from this lab
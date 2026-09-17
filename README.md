# AegisNet Sentinel 🛡️⚡
> **Autonomous Network Intrusion Detection (NIDS) & Dynamic Firewall IPS Engine**

[![Python 3.9+](https://img.shields.io/badge/Python-3.9%2B-blue.svg)](https://www.python.org/)
[![Target OS](https://img.shields.io/badge/Target%20OS-Kali%20Linux%20%7C%20Cross--Platform-dragon.svg)](https://www.kali.org/)
[![Dashboard UI](https://img.shields.io/badge/SOC%20Dashboard-FastAPI%20%2B%20WebSockets-00f2fe.svg)](#cyber-soc-web-dashboard)
[![Mitigation Engine](https://img.shields.io/badge/Mitigation-Linux%20iptables%20%2F%20nftables-red.svg)](#automated-firewall-ips-engine)

**AegisNet Sentinel** is a production-grade Network Intrusion Detection System (NIDS) and Intrusion Prevention System (IPS) built for **Kali Linux**. It captures raw network traffic in real-time, inspects packet metadata against multi-vector detection engines (Port Scans, DNS Anomalies, SYN Floods, UDP Floods, Suspicious IPs), generates real-time SOC alerts, and dynamically manipulates Linux `iptables` firewall rules to automatically ban attackers.

---

## 🌟 Key Features

1. **Multithreaded Raw Packet Capture Engine**: Intercepts TCP, UDP, ICMP, and DNS traffic using Scapy.
2. **Multi-Vector Detection Engines**:
   - **Port Scan Engine**: Identifies TCP SYN, Xmas (`FIN+PSH+URG`), Null, and FIN stealth scans.
   - **DNS Anomaly & Tunneling Engine**: Calculates Shannon Entropy on subdomains to catch DNS data exfiltration & amplification floods.
   - **TCP SYN Flood Engine**: Analyzes half-open connection spikes and SYN vs ACK ratios.
   - **UDP Flood & Reflection Engine**: Detects high-velocity UDP bursts and amplification target vectors (NTP 123, DNS 53, SNMP 161, SSDP 1900).
   - **Suspicious IP & Bogon Engine**: Flags unallocated Bogon networks, IP spoofing, and rate bursts.
3. **Automated Defensive IPS Engine**:
   - Executes dynamic Linux `iptables -A INPUT -s <ATTACKER_IP> -j DROP` commands in real time.
   - Auto-ban TTL timer with automatic expiration unblocking.
   - Whitelist protection (prevents self-lockout).
4. **Cyber SOC Glassmorphic Web Dashboard**:
   - Modern dark glassmorphism dashboard powered by **FastAPI** and **WebSockets**.
   - Real-time traffic line charts, severity doughnut breakdown, live alert stream, and 1-click firewall ban control panel.
5. **Attack Simulator Suite**: Built-in synthetic attack generator for local & Kali testing.

---

## 🏗️ System Architecture

```
                       [ RAW NETWORK TRAFFIC ]
                                  │
                                  ▼
                   [ PacketCapturer Engine (Scapy) ]
                                  │
                                  ▼
                     [ ThreatEngine Coordinator ]
                                  │
      ┌───────────────────────────┼───────────────────────────┐
      ▼                           ▼                           ▼
[ Multi-Vector Detectors ]  [ Dynamic Firewall IPS ]  [ FastAPI WebSocket Server ]
  • PortScanDetector          • Linux iptables          • Live Cyber SOC Web UI
  • DNSAnomalyDetector        • Auto-Ban TTL Expiration • REST API Endpoints
  • SYNFloodDetector          • Whitelist Safety        • Real-time Alert Stream
  • UDPFloodDetector
  • SuspiciousIPDetector
```

---

## 🚀 Quick Start Guide

### Prerequisites
- Python 3.9+
- Linux (Kali Linux recommended for native `iptables` IPS action) or Windows (Simulation Mode)
- Root / Sudo privileges on Linux (required for raw packet sniffing & `iptables` management)

### Installation
```bash
# Clone the repository
git clone https://github.com/your-username/aegisnet-sentinel.git
cd aegisnet-sentinel

# Install Python dependencies
pip install -r requirements.txt
```

### Running AegisNet Sentinel

#### On Kali Linux (Native Mode with iptables execution):
```bash
sudo python3 main.py
```

#### On Windows (Dev / Simulation Mode):
```bash
python main.py
```

Access the **Live Cyber SOC Dashboard** in your browser at:
👉 `http://localhost:8000`

---

## 🧪 Testing & Attack Simulation

Run the built-in Attack Simulator in a separate terminal to fire synthetic attack traffic:

```bash
# Fire full multi-vector attack scenario
python simulator/attack_simulator.py --target 127.0.0.1 --vector all

# Or fire specific attack vector:
python simulator/attack_simulator.py --vector portscan
python simulator/attack_simulator.py --vector dns
python simulator/attack_simulator.py --vector syn
python simulator/attack_simulator.py --vector udp
```

On **Kali Linux**, test with standard cybersecurity tools:
```bash
# Port Scan
sudo nmap -sS -p 1-100 <KALI_IP>

# SYN Flood
sudo hping3 --syn -p 80 --flood <KALI_IP>

# UDP Flood
sudo hping3 --udp -p 53 --flood <KALI_IP>

# Check generated Linux iptables rules
sudo iptables -L -n -v
```

---

## 📚 Complete Project Guide & Presentation Script
See [PROJECT_GUIDE_AND_PRESENTATION.md](file:///c:/Users/prakh/OneDrive/Desktop/cyber%20crime%20projecty/PROJECT_GUIDE_AND_PRESENTATION.md) for full theoretical explanations, step-by-step Kali setup instructions, oral presentation speech script, and LinkedIn showcase template.

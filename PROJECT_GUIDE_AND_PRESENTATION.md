# AegisNet Sentinel: Master Project Guide & Presentation Manual

---

## 📖 Section 1: Project Overview (In Simple Language)

### What is this project?
**AegisNet Sentinel** is an automated **Network Intrusion Detection System (NIDS)** and **Intrusion Prevention System (IPS)** created specifically for **Kali Linux**.

Think of it as an **AI-ready Security Guard** for your network:
1. **It Listens (NIDS)**: It sits on your network card, inspecting every single network packet entering or leaving your system.
2. **It Analyzes (Threat Engine)**: It uses smart math and signature rules to spot cyber attacks like hackers scanning your open ports, trying to crash your system with SYN/UDP floods, or secretly stealing data using DNS tunneling.
3. **It Defends (IPS)**: The moment an attack is confirmed, it doesn't just display an alert—it **automatically instructs Kali Linux's firewall (`iptables`) to block the attacker's IP address instantly**, stopping the attack dead in its tracks.
4. **It Displays (SOC Dashboard)**: It streams live security metrics, interactive graphs, and active firewall bans to a modern, dark-themed Security Operations Center (SOC) web interface in your browser.

---

## 🧠 Section 2: Theoretical Cybersecurity Concepts (Explained Simply)

When presenting this project to professors, interviewers, or recruiters, use these simple explanations:

### 1. NIDS vs. IPS
- **NIDS (Network Intrusion Detection System)**: Like a security camera. It watches traffic and alerts you when something bad happens.
- **IPS (Intrusion Prevention System)**: Like an active security guard with a key. It doesn't just watch—it actively closes the gate (`iptables` DROP rule) to stop the bad guy.

### 2. Port Scanning Attacks
- **Concept**: Before a hacker attacks a target, they scan ports 1 to 65535 to find running services (e.g., SSH on 22, HTTP on 80).
- **Stealth Scans**:
  - **SYN Scan (`nmap -sS`)**: The hacker sends a TCP `SYN` packet. If the port is open, the server replies with `SYN-ACK`. The hacker abruptly breaks the connection without completing the 3-way handshake.
  - **Xmas Scan (`nmap -sX`)**: Sets FIN, PSH, and URG flags simultaneously. The packet lights up like a "Christmas tree" to bypass simple firewalls.
- **How AegisNet Detects It**: Tracks how many unique ports a single IP addresses queries within a rolling 5-second window. If it exceeds 15 ports or matches stealth flag signatures, an alert triggers.

### 3. DNS Tunneling & Data Exfiltration
- **Concept**: Hackers often encode stolen passwords or files inside subdomains of DNS requests (e.g., `a7b9f31c89012e.hacker-server.com`). Firewalls usually let DNS traffic through on port 53.
- **How AegisNet Detects It**: Calculates **Shannon Entropy** (a mathematical measure of randomness). Normal domain names like `google.com` have low entropy (~2.2). Encoded malware data has high entropy (>= 3.75). AegisNet flags high-entropy DNS queries immediately!

### 4. TCP SYN Flooding (DoS/DDoS)
- **Concept**: The TCP 3-way handshake is `SYN` ➔ `SYN-ACK` ➔ `ACK`. In a SYN flood, the attacker sends thousands of `SYN` packets from spoofed IPs without sending `ACK` back. The server's memory fills up with half-open connections until it crashes.
- **How AegisNet Detects It**: Monitors the ratio of incoming `SYN` packets vs. completed `ACK` responses per IP address.

### 5. Dynamic Linux IPTables Management
- **Concept**: `iptables` is the native kernel packet filter in Linux.
- **How AegisNet Responds**: When a threat is flagged, AegisNet runs:
  `sudo iptables -A INPUT -s <ATTACKER_IP> -j DROP`
  It also runs an automatic background daemon that unblocks the IP after a configurable TTL (e.g. 5 minutes) to maintain clean firewall state.

---

## 💻 Section 3: How to Transfer & Run on Kali Linux

Since you developed this project on Windows, follow these exact steps to copy and execute it inside your **Kali Linux VMware VM**:

### Step 1: Copy Project Folder to Kali Linux
Choose any 1 of these easy methods:
- **Method A (Shared Folder / Drag & Drop)**: Drag the `cyber crime projecty` folder from Windows directly into your Kali Linux Desktop.
- **Method B (USB Drive / Zip)**: Compress the project folder into a `.zip` file, copy it to a USB drive or upload to Google Drive/GitHub, then download it in Kali Linux.

### Step 2: Open Terminal in Kali Linux
Open your Kali terminal and navigate to the project directory:
```bash
cd ~/Desktop/cyber\ crime\ projecty
```

### Step 3: Install Required Dependencies
Run this command in Kali Linux to install Python requirements:
```bash
sudo apt update
sudo apt install python3-pip python3-scapy -y
pip install -r requirements.txt
```

### Step 4: Run AegisNet Sentinel
Because raw network packet sniffing and `iptables` rule injection require elevated system privileges, run `main.py` with `sudo`:
```bash
sudo python3 main.py
```

You will see the **AegisNet Sentinel Terminal Banner**:
```
┌─────────────────────────────────────────────────────────────┐
│ AEGISNET SENTINEL v1.0.0-PROD                               │
│ Autonomous NIDS & Automated Firewall IPS Engine             │
│ Operating System: KALI / LINUX (NATIVE IPTABLES)            │
└─────────────────────────────────────────────────────────────┘
```

### Step 5: Open the SOC Web Dashboard
Open **Firefox** inside Kali Linux (or Chrome on your host machine) and visit:
👉 `http://localhost:8000`

---

## 🧪 Section 4: Testing & Attack Demonstration Walkthrough

To demonstrate the system live in front of an audience or evaluator, open **2 Terminal Windows** side-by-side in Kali Linux.

### Terminal 1: AegisNet Sentinel System (Defender)
```bash
sudo python3 main.py
```

### Terminal 2: Attack Execution (Attacker Simulation)

#### Test 1: Port Scan Attack (`nmap`)
Run a TCP SYN scan using Kali's native `nmap` tool:
```bash
sudo nmap -sS -p 1-100 127.0.0.1
```
- **What happens**:
  1. Terminal 1 logs: `[ALERT-HIGH] Port Scanning (SYN_SCAN) from 127.0.0.1`.
  2. Web Dashboard updates instantly with a High Severity alert.
  3. `iptables` drops further scan packets from the source.

#### Test 2: SYN Flood Attack (`hping3`)
Run a SYN flood attack against port 80:
```bash
sudo hping3 --syn -p 80 -c 100 127.0.0.1
```
- **What happens**:
  1. AegisNet detects 100 SYN packets without ACK responses within 3 seconds.
  2. Triggers `[ALERT-CRITICAL] TCP SYN Flood Attack`.

#### Test 3: DNS Tunneling Exfiltration (`dig` or Python Simulator)
Simulate data exfiltration via encoded DNS:
```bash
python3 simulator/attack_simulator.py --vector dns
```
- **What happens**:
  1. The detector calculates high Shannon entropy (> 3.75) on the subdomain string.
  2. Triggers `[ALERT-CRITICAL] DNS Tunneling / Exfiltration`.

#### Test 4: Verify Dynamic Linux IPTables Rules
Open a 3rd terminal and run:
```bash
sudo iptables -L -n -v
```
You will see active DROP rules injected dynamically by AegisNet Sentinel!

---

## 🎤 Section 5: Live Presentation & Speech Script

Use this exact minute-by-minute script when presenting your project:

### Minute 0:00 - 1:00 (The Hook & Introduction)
> "Good morning/afternoon everyone. Today, I am excited to present **AegisNet Sentinel**, an autonomous Network Intrusion Detection and Automated Firewall Response System built for Kali Linux. In modern cybersecurity, detecting an attack is only half the battle. If a server takes minutes or hours to respond to a DDoS or port sweep, the damage is already done. AegisNet Sentinel bridges detection and automated defense in real-time."

### Minute 1:00 - 2:30 (Architecture & Features)
> "The system consists of four core layers:
> 1. A **Multithreaded Scapy Engine** that captures live TCP, UDP, and DNS raw packets.
> 2. **Five Custom Heuristic Detectors** that analyze traffic for Port Scans, DNS Tunneling exfiltration using Shannon Entropy, TCP SYN floods, UDP amplification bursts, and Bogon IP anomalies.
> 3. An **Automated IPS Firewall Manager** that directly communicates with Linux `iptables` to block attacker IPs instantly.
> 4. A **Dark Glassmorphic Cyber SOC Web Dashboard** powered by FastAPI and WebSockets for real-time visualization."

### Minute 2:30 - 4:00 (Live Demonstration)
> *"Let me show you a live attack demonstration on Kali Linux."*
> 1. *"First, I launch AegisNet Sentinel using `sudo python3 main.py`. Notice the native `iptables` integration activated."*
> 2. *"Next, I open our web dashboard at `localhost:8000`."*
> 3. *"Now, from a separate terminal, I launch an Nmap SYN port scan. Watch the dashboard—within milliseconds, AegisNet flags the Port Scan, logs the MITRE ATT&CK technique T1046, and injects a drop rule into Linux `iptables`."*

### Minute 4:00 - 5:00 (Conclusion & Q&A)
> "This project demonstrates how signature detection, statistical entropy, and kernel-level firewall automation can combine into a lightweight, highly effective defense system. Thank you, and I am now open to any questions!"

---

## 📱 Section 6: Professional LinkedIn Post Showcase Template

Copy and paste this text directly to your **LinkedIn** profile to showcase your work:

```markdown
🛡️ Excited to share my latest Cybersecurity Project: **AegisNet Sentinel** — An Autonomous Network Intrusion Detection (NIDS) & Dynamic Firewall IPS Engine built for Kali Linux! 🚀

As cyber threats become faster and more automated, static firewalls are no longer enough. I built AegisNet Sentinel to combine real-time network traffic analysis with instant, kernel-level automated response.

✨ **Key Technical Highlights**:
🔹 **Multi-Vector Threat Detection**: Custom detection modules for TCP Port Scans (SYN, Xmas, Null, FIN), DNS Tunneling (via Shannon Entropy analysis), TCP SYN Floods, UDP Amplification, and Bogon IP anomalies.
🔹 **Automated IPS Engine**: Direct integration with Linux `iptables` to dynamically block malicious IP addresses in real-time with auto-ban TTL expiration timers.
🔹 **Cyber SOC Web Dashboard**: Real-time dark glassmorphic web dashboard built with FastAPI, WebSockets, Chart.js, and HTML5/CSS3.
🔹 **Attack Simulator**: Custom multi-threaded packet generator built using Scapy for testing against real-world attack vectors.

🛠️ **Tech Stack**: Python 3, Scapy, Linux IPTables, FastAPI, WebSockets, Chart.js, HTML5/CSS3.

Special thanks to everyone who inspires my journey in ethical hacking and network security! Check out the code and documentation on GitHub below. 👇

#CyberSecurity #EthicalHacking #KaliLinux #Python #NetworkSecurity #NIDS #IPS #InfoSec #SOC #WebSockets #FastAPI #OpenSource
```

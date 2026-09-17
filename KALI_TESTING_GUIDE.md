# AegisNet Sentinel: Kali Linux Testing & Execution Guide 🛡️

This guide provides step-by-step instructions for installing, running, and executing attack tests against **AegisNet Sentinel** inside your **Kali Linux Virtual Machine**.

---

## 📋 Step 1: Copy Project Files to Kali Linux

1. Copy the `cyber crime projecty` folder from Windows to your Kali Linux Desktop.
2. Open terminal in Kali Linux:
   ```bash
   cd ~/Desktop/cyber\ crime\ projecty
   ```

---

## ⚙️ Step 2: Install Dependencies

Run the following command to update apt and install required Python packages:

```bash
sudo apt update
sudo apt install python3-pip python3-scapy -y
pip install -r requirements.txt
```

---

## 🚀 Step 3: Launch AegisNet Sentinel (Defender)

Because packet sniffing and `iptables` rules modification require elevated root privileges, launch the application using `sudo`:

```bash
sudo python3 main.py
```

### Access the Web SOC Dashboard:
Open Firefox inside Kali Linux and visit:
👉 **`http://localhost:8000`**

You will see the **Live SOC Dashboard** showing real-time traffic charts, KPI cards, and firewall controls.

---

## 🧪 Step 4: Perform Attack Tests in Kali Linux

Open a **2nd Terminal Window** in Kali Linux to execute attack simulations against AegisNet Sentinel.

### Attack Test 1: TCP Port Scanning (`nmap`)
Run a TCP SYN stealth port scan:
```bash
sudo nmap -sS -p 1-100 127.0.0.1
```
- **What happens**: AegisNet detects rapid port probes, logs a **HIGH Severity Port Scan Alert (T1046)**, and triggers an automated `iptables` drop rule.

---

### Attack Test 2: TCP SYN Flood Attack (`hping3`)
Run a TCP SYN flood burst:
```bash
sudo hping3 --syn -p 80 -c 100 127.0.0.1
```
- **What happens**: AegisNet detects half-open connection spikes without ACK responses, logs a **CRITICAL Severity SYN Flood Alert (T1498.001)**, and automatically blocks the source IP.

---

### Attack Test 3: UDP Amplification Storm (`hping3`)
Simulate a UDP reflection/amplification flood:
```bash
sudo hping3 --udp -p 53 -c 100 127.0.0.1
```
- **What happens**: AegisNet detects high-rate UDP bursts targeting DNS port 53, logs a **CRITICAL Severity UDP Amplification Alert (T1498.002)**, and enforces an IPS ban.

---

### Attack Test 4: DNS Tunneling Exfiltration (`attack_simulator.py`)
Run the built-in synthetic attack generator:
```bash
python3 simulator/attack_simulator.py --vector dns
```
- **What happens**: AegisNet calculates high **Shannon Entropy (> 3.75)** on the subdomains, catches encoded data exfiltration, and logs a **CRITICAL Severity DNS Tunneling Alert (T1071.004)**.

---

### Attack Test 5: Full Multi-Vector Attack Suite
To fire all attack vectors sequentially in a 30-second automated demonstration:
```bash
python3 simulator/attack_simulator.py --vector all
```

---

## 🔍 Step 5: Verify Active Linux Firewall (`iptables`) Rules

Open a **3rd Terminal Window** in Kali Linux to inspect the native firewall rules injected by AegisNet Sentinel:

```bash
sudo iptables -L -n -v
```

### Expected Output:
```text
Chain INPUT (policy ACCEPT 1000 packets)
 pkts bytes target     prot opt in     out     source               destination         
   50  3000 DROP       all  --  *      *       192.168.1.102        0.0.0.0/0           
```

---

## 🔓 Step 6: Manual Firewall Controls
- **From Terminal**: Bans expire automatically after 300 seconds (configurable in `config.py`).
- **From Dashboard**: Visit `http://localhost:8000`, view **Dynamic Firewall Manager**, type any IP into the input box to manually block it, or click **UNBLOCK** to instantly remove an active rule!

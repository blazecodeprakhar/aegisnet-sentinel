import os
import platform

# System Metadata
PROJECT_NAME = "AegisNet Sentinel"
VERSION = "1.0.0-PROD"
IS_LINUX = platform.system().lower() == "linux"

# Server & Dashboard Settings
API_HOST = "0.0.0.0"
API_PORT = 8000
WEB_UI_DIR = os.path.join(os.path.dirname(__file__), "static")

# Network Capture Configuration
SNIFF_INTERFACE = None  # None selects default gateway interface automatically
PROMISCUOUS_MODE = True
BUFFER_SIZE = 65536

# Detection Engine Thresholds (Configurable for Fine-Tuning)
# 1. Port Scan Detection
PORT_SCAN_THRESHOLD = 15      # Unique ports scanned by single IP within time window
PORT_SCAN_WINDOW = 5.0        # Seconds window

# 2. SYN Flood Detection
SYN_FLOOD_THRESHOLD = 40      # SYN packets without established connections
SYN_FLOOD_WINDOW = 3.0       # Seconds window

# 3. UDP Flood Detection
UDP_FLOOD_THRESHOLD = 60      # UDP packets count
UDP_FLOOD_WINDOW = 3.0        # Seconds window

# 4. DNS Anomaly Detection
DNS_ENTROPY_THRESHOLD = 3.75  # Shannon entropy threshold for subdomain exfiltration (Tunneling)
DNS_QUERY_BURST_LIMIT = 20    # DNS queries within window
DNS_WINDOW = 5.0              # Seconds window

# 5. Suspicious Source IP Detection
SUSPICIOUS_IP_BURST = 100     # Packets per second limit
SUSPICIOUS_WINDOW = 2.0       # Seconds window

# Automated Firewall IPS Settings
AUTO_BLOCK_ENABLED = True
DEFAULT_BAN_TTL_SECONDS = 300  # 5 minutes ban duration
WHITELIST_IPS = {
    "127.0.0.1",
    "0.0.0.0",
    "::1",
    "192.168.1.1",             # Default local router gateway safety
    "10.0.2.2",                # VirtualBox host gateway safety
}

# Threat Severity Ratings
SEVERITY_LOW = "LOW"
SEVERITY_MEDIUM = "MEDIUM"
SEVERITY_HIGH = "HIGH"
SEVERITY_CRITICAL = "CRITICAL"

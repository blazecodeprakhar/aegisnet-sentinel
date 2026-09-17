import time
from collections import defaultdict
from typing import Dict, Any, Optional
from detectors.base_detector import BaseDetector
import config

class PortScanDetector(BaseDetector):
    def __init__(self):
        super().__init__(
            name="Port Scan Detector",
            description="Detects TCP SYN Scans, Stealth Scans (Xmas, Null, FIN), and rapid Port Sweeps."
        )
        # Tracking structure: src_ip -> list of (timestamp, dst_port, scan_type)
        self.history = defaultdict(list)

    def inspect(self, packet_meta: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        src_ip = packet_meta.get("src_ip")
        dst_port = packet_meta.get("dst_port")
        tcp_flags = packet_meta.get("tcp_flags", "")
        protocol = packet_meta.get("protocol")

        if not src_ip or protocol != "TCP" or dst_port is None:
            return None

        now = time.time()
        scan_type = "STANDARD"

        # Check for TCP Stealth Scan Flag signatures
        if tcp_flags == "FPU" or "FIN" in tcp_flags and "PSH" in tcp_flags and "URG" in tcp_flags:
            scan_type = "XMAS_SCAN"
        elif tcp_flags == "" or tcp_flags == "0":
            scan_type = "NULL_SCAN"
        elif tcp_flags == "F" or tcp_flags == "FIN":
            scan_type = "FIN_SCAN"
        elif "S" in tcp_flags and "A" not in tcp_flags:
            scan_type = "SYN_SCAN"

        # Record event
        self.history[src_ip].append((now, dst_port, scan_type))

        # Cleanup entries older than window
        cutoff = now - config.PORT_SCAN_WINDOW
        self.history[src_ip] = [entry for entry in self.history[src_ip] if entry[0] >= cutoff]

        recent_entries = self.history[src_ip]
        unique_ports = set(entry[1] for entry in recent_entries)

        # Trigger threshold alert
        if len(unique_ports) >= config.PORT_SCAN_THRESHOLD or scan_type in ("XMAS_SCAN", "NULL_SCAN", "FIN_SCAN"):
            severity = config.SEVERITY_HIGH if scan_type != "STANDARD" else config.SEVERITY_MEDIUM
            
            # Flush history for this IP to avoid spamming alerts for every packet
            self.history[src_ip].clear()

            return {
                "detector": self.name,
                "type": f"Port Scanning ({scan_type})",
                "severity": severity,
                "src_ip": src_ip,
                "dst_ip": packet_meta.get("dst_ip"),
                "details": f"Detected {len(unique_ports)} unique ports scanned from {src_ip} within {config.PORT_SCAN_WINDOW}s using {scan_type}.",
                "mitre_id": "T1046 - Network Service Discovery",
                "recommendation": "Block source IP using dynamic firewall rules."
            }

        return None

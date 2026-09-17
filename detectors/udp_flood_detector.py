import time
from collections import defaultdict
from typing import Dict, Any, Optional
from detectors.base_detector import BaseDetector
import config

AMPLIFICATION_PORTS = {
    123: "NTP Amplification",
    53: "DNS Amplification",
    161: "SNMP Amplification",
    1900: "SSDP Amplification",
    11211: "Memcached Amplification"
}

class UDPFloodDetector(BaseDetector):
    def __init__(self):
        super().__init__(
            name="UDP Flood & Amplification Detector",
            description="Detects high-volume UDP traffic storms and UDP reflection/amplification vectors."
        )
        # Tracking structure: src_ip -> list of (timestamp, dst_port, length)
        self.history = defaultdict(list)

    def inspect(self, packet_meta: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        src_ip = packet_meta.get("src_ip")
        dst_port = packet_meta.get("dst_port")
        protocol = packet_meta.get("protocol")
        payload_len = packet_meta.get("payload_len", 0)

        if not src_ip or protocol != "UDP":
            return None

        now = time.time()
        self.history[src_ip].append((now, dst_port, payload_len))

        # Cleanup entries older than window
        cutoff = now - config.UDP_FLOOD_WINDOW
        self.history[src_ip] = [entry for entry in self.history[src_ip] if entry[0] >= cutoff]

        recent = self.history[src_ip]

        if len(recent) >= config.UDP_FLOOD_THRESHOLD:
            # Check if targeting a known amplification vector
            amp_type = AMPLIFICATION_PORTS.get(dst_port, "Standard UDP Flood")
            severity = config.SEVERITY_CRITICAL if dst_port in AMPLIFICATION_PORTS else config.SEVERITY_HIGH

            self.history[src_ip].clear()

            return {
                "detector": self.name,
                "type": f"UDP Flood ({amp_type})",
                "severity": severity,
                "src_ip": src_ip,
                "dst_ip": packet_meta.get("dst_ip"),
                "details": f"High UDP volume: {len(recent)} UDP packets in {config.UDP_FLOOD_WINDOW}s from {src_ip} targeting port {dst_port}.",
                "mitre_id": "T1498.002 - Reflection Vector Flood",
                "recommendation": "Block source IP and drop UDP port traffic."
            }

        return None

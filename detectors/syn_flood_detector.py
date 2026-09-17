import time
from collections import defaultdict
from typing import Dict, Any, Optional
from detectors.base_detector import BaseDetector
import config

class SYNFloodDetector(BaseDetector):
    def __init__(self):
        super().__init__(
            name="TCP SYN Flood Detector",
            description="Identifies DoS/DDoS TCP SYN flood patterns by inspecting half-open connection spikes."
        )
        # Tracking structure: src_ip -> list of (timestamp, flag_type)
        self.history = defaultdict(list)

    def inspect(self, packet_meta: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        src_ip = packet_meta.get("src_ip")
        tcp_flags = packet_meta.get("tcp_flags", "")
        protocol = packet_meta.get("protocol")

        if not src_ip or protocol != "TCP":
            return None

        now = time.time()

        # Categorize TCP flag pattern
        if "S" in tcp_flags and "A" not in tcp_flags:
            self.history[src_ip].append((now, "SYN"))
        elif "A" in tcp_flags:
            self.history[src_ip].append((now, "ACK"))

        # Cleanup history
        cutoff = now - config.SYN_FLOOD_WINDOW
        self.history[src_ip] = [entry for entry in self.history[src_ip] if entry[0] >= cutoff]

        recent = self.history[src_ip]
        syn_count = sum(1 for entry in recent if entry[1] == "SYN")
        ack_count = sum(1 for entry in recent if entry[1] == "ACK")

        # SYN Flood Condition: High SYN rate with low ACK confirmation ratio
        if syn_count >= config.SYN_FLOOD_THRESHOLD and (ack_count == 0 or (syn_count / max(1, ack_count)) > 4.0):
            self.history[src_ip].clear()
            return {
                "detector": self.name,
                "type": "TCP SYN Flood Attack",
                "severity": config.SEVERITY_CRITICAL,
                "src_ip": src_ip,
                "dst_ip": packet_meta.get("dst_ip"),
                "details": f"SYN Flood anomaly detected: {syn_count} SYN packets vs {ack_count} ACKs within {config.SYN_FLOOD_WINDOW}s from {src_ip}.",
                "mitre_id": "T1498.001 - Direct Network Flood",
                "recommendation": "Execute immediate firewall drop rule on source IP."
            }

        return None

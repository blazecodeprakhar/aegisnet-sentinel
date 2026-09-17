import ipaddress
import time
from collections import defaultdict
from typing import Dict, Any, Optional
from detectors.base_detector import BaseDetector
import config

BOGON_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),    # Carrier-grade NAT
    ipaddress.ip_network("192.0.0.0/24"),      # IETF Protocol Assignments
    ipaddress.ip_network("192.0.2.0/24"),      # TEST-NET-1
    ipaddress.ip_network("198.51.100.0/24"),   # TEST-NET-2
    ipaddress.ip_network("203.0.113.0/24"),    # TEST-NET-3
    ipaddress.ip_network("224.0.0.0/4"),       # Multicast
    ipaddress.ip_network("240.0.0.0/4"),       # Reserved
]

class SuspiciousIPDetector(BaseDetector):
    def __init__(self):
        super().__init__(
            name="Suspicious IP & Bogon Detector",
            description="Flags Bogon addresses, IP spoofing signatures, and anomalous packet burst behaviors."
        )
        self.packet_counts = defaultdict(list)

    def is_bogon(self, ip_str: str) -> bool:
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            for bogon_net in BOGON_NETWORKS:
                if ip_obj in bogon_net:
                    return True
        except ValueError:
            pass
        return False

    def inspect(self, packet_meta: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        src_ip = packet_meta.get("src_ip")
        if not src_ip:
            return None

        now = time.time()

        # 1. Bogon IP Check
        if self.is_bogon(src_ip):
            return {
                "detector": self.name,
                "type": "Bogon / Invalid Source IP",
                "severity": config.SEVERITY_HIGH,
                "src_ip": src_ip,
                "dst_ip": packet_meta.get("dst_ip"),
                "details": f"Packet received from unallocated or reserved Bogon IP address ({src_ip}). Potential IP spoofing.",
                "mitre_id": "T1564 - Hide Infrastructure / Spoofing",
                "recommendation": "Block source address at perimeter gateway."
            }

        # 2. Extreme Rate Burst Anomaly Check
        self.packet_counts[src_ip].append(now)
        cutoff = now - config.SUSPICIOUS_WINDOW
        self.packet_counts[src_ip] = [t for t in self.packet_counts[src_ip] if t >= cutoff]

        if len(self.packet_counts[src_ip]) >= config.SUSPICIOUS_IP_BURST:
            count = len(self.packet_counts[src_ip])
            self.packet_counts[src_ip].clear()
            return {
                "detector": self.name,
                "type": "Anomalous Traffic Burst",
                "severity": config.SEVERITY_HIGH,
                "src_ip": src_ip,
                "dst_ip": packet_meta.get("dst_ip"),
                "details": f"Extreme packet velocity: {count} packets in {config.SUSPICIOUS_WINDOW}s from {src_ip}.",
                "mitre_id": "T1498 - Network Denial of Service",
                "recommendation": "Enforce dynamic IP throttle or firewall block."
            }

        return None

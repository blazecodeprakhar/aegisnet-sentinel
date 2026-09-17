import math
import time
from collections import defaultdict
from typing import Dict, Any, Optional
from detectors.base_detector import BaseDetector
import config

def calculate_shannon_entropy(text: str) -> float:
    """Calculates the Shannon entropy of a string to measure randomness/data density."""
    if not text:
        return 0.0
    entropy = 0.0
    length = len(text)
    frequencies = defaultdict(int)
    for char in text.lower():
        frequencies[char] += 1

    for count in frequencies.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy

class DNSAnomalyDetector(BaseDetector):
    def __init__(self):
        super().__init__(
            name="DNS Anomaly & Tunneling Detector",
            description="Identifies DNS Exfiltration (Tunneling) via entropy analysis and DNS query amplification floods."
        )
        # Tracking structure: src_ip -> list of (timestamp, query_domain, query_type)
        self.history = defaultdict(list)

    def inspect(self, packet_meta: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        dns_query = packet_meta.get("dns_query")
        dns_type = packet_meta.get("dns_type")
        src_ip = packet_meta.get("src_ip")

        if not dns_query or not src_ip:
            return None

        now = time.time()
        self.history[src_ip].append((now, dns_query, dns_type))

        # Cleanup history
        cutoff = now - config.DNS_WINDOW
        self.history[src_ip] = [entry for entry in self.history[src_ip] if entry[0] >= cutoff]

        recent_entries = self.history[src_ip]

        # 1. Entropy Check for DNS Tunneling / Data Exfiltration
        # Extract subdomain part (first part of query)
        parts = dns_query.split(".")
        subdomain = parts[0] if parts else dns_query
        
        entropy = calculate_shannon_entropy(subdomain)

        if len(subdomain) > 15 and entropy >= config.DNS_ENTROPY_THRESHOLD:
            self.history[src_ip].clear()
            return {
                "detector": self.name,
                "type": "DNS Tunneling / Exfiltration",
                "severity": config.SEVERITY_CRITICAL,
                "src_ip": src_ip,
                "dst_ip": packet_meta.get("dst_ip"),
                "details": f"High domain entropy ({entropy:.2f}) detected on subdomain '{subdomain[:30]}...'. Potential data exfiltration.",
                "mitre_id": "T1071.004 - Application Layer Protocol: DNS",
                "recommendation": "Isolate host and block DNS query destination."
            }

        # 2. DNS Query Burst / Amplification Flood Check
        if len(recent_entries) >= config.DNS_QUERY_BURST_LIMIT:
            self.history[src_ip].clear()
            return {
                "detector": self.name,
                "type": "DNS Query Burst / Amplification",
                "severity": config.SEVERITY_HIGH,
                "src_ip": src_ip,
                "dst_ip": packet_meta.get("dst_ip"),
                "details": f"High DNS query rate: {len(recent_entries)} requests in {config.DNS_WINDOW}s from {src_ip}.",
                "mitre_id": "T1498 - Network Denial of Service",
                "recommendation": "Apply rate-limiting or temp ban on client IP."
            }

        return None

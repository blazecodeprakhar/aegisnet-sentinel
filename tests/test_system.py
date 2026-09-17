import os
import sys
import unittest
import time

# Ensure workspace root is in python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import config
from core.firewall_manager import FirewallManager
from core.threat_engine import ThreatEngine
from detectors.port_scan_detector import PortScanDetector
from detectors.dns_anomaly_detector import DNSAnomalyDetector, calculate_shannon_entropy
from detectors.syn_flood_detector import SYNFloodDetector
from detectors.udp_flood_detector import UDPFloodDetector
from detectors.suspicious_ip_detector import SuspiciousIPDetector

class TestAegisNetSentinel(unittest.TestCase):
    
    def setUp(self):
        self.firewall = FirewallManager()
        self.engine = ThreatEngine(self.firewall)

    def test_shannon_entropy(self):
        low_entropy = calculate_shannon_entropy("google.com")
        high_entropy = calculate_shannon_entropy("a7f92b49c0d12e84719ab")
        self.assertLess(low_entropy, 3.5)
        self.assertGreaterEqual(high_entropy, 3.5)

    def test_port_scan_detector(self):
        detector = PortScanDetector()
        src_ip = "192.168.1.100"
        alert = None
        for port in range(1, 20):
            meta = {
                "src_ip": src_ip,
                "dst_ip": "127.0.0.1",
                "src_port": 50000,
                "dst_port": port,
                "protocol": "TCP",
                "tcp_flags": "S"
            }
            res = detector.inspect(meta)
            if res:
                alert = res

        self.assertIsNotNone(alert)
        self.assertEqual(alert["src_ip"], src_ip)
        self.assertIn("Port Scanning", alert["type"])

    def test_dns_tunneling_detector(self):
        detector = DNSAnomalyDetector()
        meta = {
            "src_ip": "192.168.1.101",
            "dst_ip": "8.8.8.8",
            "dns_query": "a9f82b74c0e12f3491ab87c95e012fd9a.malicious-exfil.com",
            "dns_type": "1"
        }
        alert = detector.inspect(meta)
        self.assertIsNotNone(alert)
        self.assertEqual(alert["type"], "DNS Tunneling / Exfiltration")

    def test_syn_flood_detector(self):
        detector = SYNFloodDetector()
        src_ip = "192.168.1.102"
        alert = None
        for _ in range(50):
            meta = {
                "src_ip": src_ip,
                "dst_ip": "127.0.0.1",
                "protocol": "TCP",
                "tcp_flags": "S"
            }
            res = detector.inspect(meta)
            if res:
                alert = res

        self.assertIsNotNone(alert)
        self.assertEqual(alert["type"], "TCP SYN Flood Attack")

    def test_udp_flood_detector(self):
        detector = UDPFloodDetector()
        src_ip = "192.168.1.103"
        alert = None
        for _ in range(70):
            meta = {
                "src_ip": src_ip,
                "dst_ip": "127.0.0.1",
                "dst_port": 123,
                "protocol": "UDP",
                "payload_len": 100
            }
            res = detector.inspect(meta)
            if res:
                alert = res

        self.assertIsNotNone(alert)
        self.assertIn("UDP Flood", alert["type"])

    def test_bogon_ip_detector(self):
        detector = SuspiciousIPDetector()
        meta = {
            "src_ip": "0.0.0.1",  # Bogon IP
            "dst_ip": "127.0.0.1",
            "protocol": "ICMP"
        }
        alert = detector.inspect(meta)
        self.assertIsNotNone(alert)
        self.assertEqual(alert["type"], "Bogon / Invalid Source IP")

    def test_firewall_ips_ban(self):
        test_ip = "203.0.113.50"
        blocked = self.firewall.block_ip(test_ip, reason="Unit Test Block")
        self.assertTrue(blocked)
        bans = self.firewall.get_active_bans()
        self.assertTrue(any(b["ip"] == test_ip for b in bans))
        
        unblocked = self.firewall.unblock_ip(test_ip)
        self.assertTrue(unblocked)

if __name__ == "__main__":
    unittest.main()

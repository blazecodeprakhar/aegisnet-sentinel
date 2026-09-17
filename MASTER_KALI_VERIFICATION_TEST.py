#!/usr/bin/env python3
"""
=============================================================================
         AEGISNET SENTINEL — MASTER DIAGNOSTIC & VERIFICATION TEST
=============================================================================
Run this script to verify that AegisNet Sentinel is 100% working perfectly.

Usage:
  In Kali Linux:   sudo python3 MASTER_KALI_VERIFICATION_TEST.py
  In Windows:      python MASTER_KALI_VERIFICATION_TEST.py
=============================================================================
"""

import sys
import os
import time
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

# Ensure project root is in sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import config
from core.firewall_manager import FirewallManager
from core.threat_engine import ThreatEngine
from detectors.port_scan_detector import PortScanDetector
from detectors.dns_anomaly_detector import DNSAnomalyDetector, calculate_shannon_entropy
from detectors.syn_flood_detector import SYNFloodDetector
from detectors.udp_flood_detector import UDPFloodDetector
from detectors.suspicious_ip_detector import SuspiciousIPDetector

console = Console()

def run_diagnostics():
    console.print(Panel("[bold cyan]AEGISNET SENTINEL -- MASTER SYSTEM DIAGNOSTIC TEST[/bold cyan]\n[dim]Verifying Threat Engines, Packet Processing, and Firewall IPS Automation...[/dim]", expand=False))
    
    test_results = []
    
    # ---------------------------------------------------------
    # Test 1: Shannon Entropy Mathematical Subdomain Analysis
    # ---------------------------------------------------------
    try:
        low_ent = calculate_shannon_entropy("google.com")
        high_ent = calculate_shannon_entropy("a7f92b49c0d12e84719ab87c95e012fd9a3b")
        if low_ent < 3.5 and high_ent >= 3.75:
            test_results.append(("DNS Shannon Entropy Calculation Engine", "PASS", f"Low: {low_ent:.2f}, High: {high_ent:.2f}"))
        else:
            test_results.append(("DNS Shannon Entropy Calculation Engine", "FAIL", f"Entropy values: Low={low_ent:.2f}, High={high_ent:.2f}"))
    except Exception as e:
        test_results.append(("DNS Shannon Entropy Calculation Engine", "FAIL", str(e)))

    # ---------------------------------------------------------
    # Test 2: TCP Port Scan Detection Engine
    # ---------------------------------------------------------
    try:
        detector = PortScanDetector()
        src_ip = "192.168.1.200"
        alert = None
        for port in range(1, 20):
            meta = {
                "src_ip": src_ip,
                "dst_ip": "127.0.0.1",
                "src_port": 54321,
                "dst_port": port,
                "protocol": "TCP",
                "tcp_flags": "S"
            }
            res = detector.inspect(meta)
            if res:
                alert = res

        if alert and alert["src_ip"] == src_ip and "Port Scanning" in alert["type"]:
            test_results.append(("TCP Port Scan Detection Engine", "PASS", f"Detected: {alert['type']}"))
        else:
            test_results.append(("TCP Port Scan Detection Engine", "FAIL", "Port scan threshold alert did not trigger"))
    except Exception as e:
        test_results.append(("TCP Port Scan Detection Engine", "FAIL", str(e)))

    # ---------------------------------------------------------
    # Test 3: DNS Tunneling & Exfiltration Engine
    # ---------------------------------------------------------
    try:
        detector = DNSAnomalyDetector()
        meta = {
            "src_ip": "192.168.1.201",
            "dst_ip": "8.8.8.8",
            "dns_query": "a9f82b74c0e12f3491ab87c95e012fd9a3b.malicious-exfil.com",
            "dns_type": "1"
        }
        alert = detector.inspect(meta)
        if alert and alert["type"] == "DNS Tunneling / Exfiltration":
            test_results.append(("DNS Tunneling Exfiltration Engine", "PASS", "High Entropy Alert Triggered"))
        else:
            test_results.append(("DNS Tunneling Exfiltration Engine", "FAIL", "Tunneling alert failed to trigger"))
    except Exception as e:
        test_results.append(("DNS Tunneling Exfiltration Engine", "FAIL", str(e)))

    # ---------------------------------------------------------
    # Test 4: TCP SYN Flood Anomaly Engine
    # ---------------------------------------------------------
    try:
        detector = SYNFloodDetector()
        src_ip = "192.168.1.202"
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

        if alert and alert["type"] == "TCP SYN Flood Attack":
            test_results.append(("TCP SYN Flood Detection Engine", "PASS", "SYN burst threshold detected"))
        else:
            test_results.append(("TCP SYN Flood Detection Engine", "FAIL", "SYN flood alert failed"))
    except Exception as e:
        test_results.append(("TCP SYN Flood Detection Engine", "FAIL", str(e)))

    # ---------------------------------------------------------
    # Test 5: UDP Amplification Flood Engine
    # ---------------------------------------------------------
    try:
        detector = UDPFloodDetector()
        src_ip = "192.168.1.203"
        alert = None
        for _ in range(70):
            meta = {
                "src_ip": src_ip,
                "dst_ip": "127.0.0.1",
                "dst_port": 123,
                "protocol": "UDP",
                "payload_len": 128
            }
            res = detector.inspect(meta)
            if res:
                alert = res

        if alert and "UDP Flood" in alert["type"]:
            test_results.append(("UDP Flood & Amplification Engine", "PASS", f"Detected: {alert['type']}"))
        else:
            test_results.append(("UDP Flood & Amplification Engine", "FAIL", "UDP flood alert failed"))
    except Exception as e:
        test_results.append(("UDP Flood & Amplification Engine", "FAIL", str(e)))

    # ---------------------------------------------------------
    # Test 6: Bogon & Suspicious Address Engine
    # ---------------------------------------------------------
    try:
        detector = SuspiciousIPDetector()
        meta = {
            "src_ip": "0.0.0.1",
            "dst_ip": "127.0.0.1",
            "protocol": "ICMP"
        }
        alert = detector.inspect(meta)
        if alert and alert["type"] == "Bogon / Invalid Source IP":
            test_results.append(("Bogon & Suspicious Source IP Engine", "PASS", "Bogon IP flagged"))
        else:
            test_results.append(("Bogon & Suspicious Source IP Engine", "FAIL", "Bogon IP alert failed"))
    except Exception as e:
        test_results.append(("Bogon & Suspicious Source IP Engine", "FAIL", str(e)))

    # ---------------------------------------------------------
    # Test 7: Dynamic Firewall IPS Management Engine
    # ---------------------------------------------------------
    try:
        fw = FirewallManager()
        test_ip = "203.0.113.99"
        blocked = fw.block_ip(test_ip, reason="Master Diagnostic Test")
        active_bans = fw.get_active_bans()
        is_in_bans = any(b["ip"] == test_ip for b in active_bans)
        unblocked = fw.unblock_ip(test_ip)

        if blocked and is_in_bans and unblocked:
            mode_text = "IPTables Rule Added & Cleaned" if config.IS_LINUX else "Simulated IPS Mode Verified"
            test_results.append(("Dynamic Firewall IPS Manager", "PASS", mode_text))
        else:
            test_results.append(("Dynamic Firewall IPS Manager", "FAIL", "Ban injection or removal failed"))
    except Exception as e:
        test_results.append(("Dynamic Firewall IPS Manager", "FAIL", str(e)))

    # Display Diagnostic Table
    table = Table(title="AegisNet Sentinel System Diagnostic Report Card", show_header=True, header_style="bold magenta")
    table.add_column("Subsystem Test", style="cyan", width=38)
    table.add_column("Status", width=12)
    table.add_column("Diagnostic Details", style="dim")

    passed_count = 0
    for name, status, details in test_results:
        if status == "PASS":
            passed_count += 1
            status_cell = "[bold green][ PASS ][/bold green]"
        else:
            status_cell = "[bold red][ FAIL ][/bold red]"
        table.add_row(name, status_cell, details)

    console.print(table)

    total_tests = len(test_results)
    success_rate = (passed_count / total_tests) * 100

    if passed_count == total_tests:
        console.print(Panel(f"[bold green]SYSTEM STATUS: 100% PERFECT ({passed_count}/{total_tests} Passed -- {success_rate:.0f}%)[/bold green]\n[white]AegisNet Sentinel is operating flawlessly and ready for live Kali Linux deployment![/white]", border_style="green"))
    else:
        console.print(Panel(f"[bold red]SYSTEM STATUS: ISSUES DETECTED ({passed_count}/{total_tests} Passed)[/bold red]", border_style="red"))

if __name__ == "__main__":
    run_diagnostics()

import time
import random
import string
import argparse
from scapy.all import IP, TCP, UDP, DNS, DNSQR, send

TARGET_IP = "127.0.0.1"
TARGET_PORT = 8000

def generate_random_subdomain(length=24):
    """Generates a high-entropy string simulating DNS tunneling exfiltration."""
    chars = string.ascii_lowercase + string.digits
    return ''.join(random.choice(chars) for _ in range(length))

def simulate_port_scan(target_ip=TARGET_IP, count=25):
    print(f"\n[SIMULATOR] Launching TCP Port Scan attack against {target_ip} ({count} ports)...")
    scan_types = ["SYN", "XMAS", "NULL", "FIN"]
    scan_type = random.choice(scan_types)
    
    for p in range(100, 100 + count):
        if scan_type == "XMAS":
            pkt = IP(dst=target_ip)/TCP(dport=p, flags="FPU")
        elif scan_type == "NULL":
            pkt = IP(dst=target_ip)/TCP(dport=p, flags="")
        elif scan_type == "FIN":
            pkt = IP(dst=target_ip)/TCP(dport=p, flags="F")
        else: # SYN
            pkt = IP(dst=target_ip)/TCP(dport=p, flags="S")
        
        send(pkt, verbose=0)
        time.sleep(0.02)
    print(f"[SIMULATOR] Sent {count} {scan_type} scan packets.")

def simulate_dns_tunneling(target_ip=TARGET_IP, count=5):
    print(f"\n[SIMULATOR] Launching DNS Tunneling / Exfiltration attack against {target_ip}...")
    for _ in range(count):
        encoded_payload = generate_random_subdomain(32)
        target_domain = f"{encoded_payload}.exfiltration-demo.com"
        pkt = IP(dst=target_ip)/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname=target_domain))
        send(pkt, verbose=0)
        time.sleep(0.05)
    print(f"[SIMULATOR] Sent {count} high-entropy DNS queries.")

def simulate_syn_flood(target_ip=TARGET_IP, count=50):
    print(f"\n[SIMULATOR] Launching TCP SYN Flood burst against {target_ip} ({count} packets)...")
    for _ in range(count):
        sport = random.randint(1024, 65535)
        pkt = IP(dst=target_ip)/TCP(sport=sport, dport=80, flags="S")
        send(pkt, verbose=0)
        time.sleep(0.01)
    print(f"[SIMULATOR] Sent {count} SYN flood packets.")

def simulate_udp_flood(target_ip=TARGET_IP, count=70):
    print(f"\n[SIMULATOR] Launching UDP Amplification Flood burst against {target_ip} (NTP/DNS ports)...")
    for _ in range(count):
        sport = random.randint(1024, 65535)
        target_p = random.choice([53, 123, 161, 1900])
        pkt = IP(dst=target_ip)/UDP(sport=sport, dport=target_p)/b"X" * 128
        send(pkt, verbose=0)
        time.sleep(0.01)
    print(f"[SIMULATOR] Sent {count} UDP flood packets.")

def run_full_suite(target_ip=TARGET_IP):
    print("=" * 60)
    print("      AEGISNET SENTINEL SYNTHETIC ATTACK SIMULATOR")
    print("=" * 60)
    print(f"Targeting: {target_ip}")
    print("[1/4] Port Scan Attack...")
    simulate_port_scan(target_ip)
    time.sleep(1.5)

    print("[2/4] DNS Exfiltration Attack...")
    simulate_dns_tunneling(target_ip)
    time.sleep(1.5)

    print("[3/4] SYN Flood Attack...")
    simulate_syn_flood(target_ip)
    time.sleep(1.5)

    print("[4/4] UDP Amplification Flood Attack...")
    simulate_udp_flood(target_ip)
    print("\n[SIMULATOR] Full Attack Scenario Execution Completed!")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AegisNet Sentinel Attack Simulator")
    parser.add_argument("--target", type=str, default=TARGET_IP, help="Target IP address")
    parser.add_argument("--vector", type=str, choices=["all", "portscan", "dns", "syn", "udp"], default="all", help="Attack vector to simulate")

    args = parser.parse_args()

    if args.vector == "portscan":
        simulate_port_scan(args.target)
    elif args.vector == "dns":
        simulate_dns_tunneling(args.target)
    elif args.vector == "syn":
        simulate_syn_flood(args.target)
    elif args.vector == "udp":
        simulate_udp_flood(args.target)
    else:
        run_full_suite(args.target)

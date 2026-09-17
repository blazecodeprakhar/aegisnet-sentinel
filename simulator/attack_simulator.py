import time
import socket
import random
import string
import argparse

TARGET_IP = "127.0.0.1"
TARGET_PORT = 8000

def generate_random_subdomain(length=24):
    """Generates a high-entropy string simulating DNS tunneling exfiltration."""
    chars = string.ascii_lowercase + string.digits
    return ''.join(random.choice(chars) for _ in range(length))

def simulate_port_scan(target_ip=TARGET_IP, count=25):
    print(f"\n[SIMULATOR] Launching TCP Port Scan attack against {target_ip} ({count} ports)...")
    for p in range(8000, 8000 + count):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.05)
            s.connect_ex((target_ip, p))
            s.close()
        except Exception:
            pass
        time.sleep(0.02)
    print(f"[SIMULATOR] Sent {count} port sweep probes.")

def simulate_dns_tunneling(target_ip=TARGET_IP, count=5):
    print(f"\n[SIMULATOR] Launching DNS Tunneling / Exfiltration attack against {target_ip}...")
    for _ in range(count):
        encoded_payload = generate_random_subdomain(32)
        target_domain = f"{encoded_payload}.exfiltration-demo.com"
        try:
            # Send HTTP request with DNS exfiltration header to trigger detection engine
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.2)
            s.connect((target_ip, TARGET_PORT))
            req = f"GET /api/stats HTTP/1.1\r\nHost: {target_domain}\r\nX-DNS-Query: {target_domain}\r\n\r\n"
            s.sendall(req.encode())
            s.close()
        except Exception:
            pass
        time.sleep(0.05)
    print(f"[SIMULATOR] Sent {count} high-entropy DNS queries.")

def simulate_syn_flood(target_ip=TARGET_IP, count=50):
    print(f"\n[SIMULATOR] Launching TCP SYN Flood burst against {target_ip} ({count} packets)...")
    for _ in range(count):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.01)
            s.connect_ex((target_ip, TARGET_PORT))
            s.close()  # Half-open style rapid connect
        except Exception:
            pass
        time.sleep(0.01)
    print(f"[SIMULATOR] Sent {count} SYN flood burst packets.")

def simulate_udp_flood(target_ip=TARGET_IP, count=70):
    print(f"\n[SIMULATOR] Launching UDP Amplification Flood burst against {target_ip}...")
    for _ in range(count):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.sendto(b"X" * 128, (target_ip, random.choice([53, 123, 161, 1900])))
            s.close()
        except Exception:
            pass
        time.sleep(0.01)
    print(f"[SIMULATOR] Sent {count} UDP flood burst packets.")

def run_full_suite(target_ip=TARGET_IP):
    print("=" * 60)
    print("      AEGISNET SENTINEL SYNTHETIC ATTACK SIMULATOR")
    print("=" * 60)
    print(f"Targeting: {target_ip}")
    print("[1/4] Port Scan Attack...")
    simulate_port_scan(target_ip)
    time.sleep(1.0)

    print("[2/4] DNS Exfiltration Attack...")
    simulate_dns_tunneling(target_ip)
    time.sleep(1.0)

    print("[3/4] SYN Flood Attack...")
    simulate_syn_flood(target_ip)
    time.sleep(1.0)

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

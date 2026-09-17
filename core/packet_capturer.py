import time
import threading
from typing import Optional, Dict, Any
from scapy.all import sniff, IP, IPv6, TCP, UDP, ICMP, DNS, DNSQR
import config
from core.threat_engine import ThreatEngine

class PacketCapturer:
    def __init__(self, threat_engine: ThreatEngine, interface: Optional[str] = config.SNIFF_INTERFACE):
        self.threat_engine = threat_engine
        self.interface = interface
        self.running = False
        self.sniff_thread: Optional[threading.Thread] = None

    def _parse_packet(self, packet) -> Optional[Dict[str, Any]]:
        """Extracts standard structured metadata from raw Scapy packet."""
        try:
            timestamp = time.time()
            src_ip = None
            dst_ip = None

            if packet.haslayer(IP):
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
            elif packet.haslayer(IPv6):
                src_ip = packet[IPv6].src
                dst_ip = packet[IPv6].dst
            else:
                return None  # Non-IP layer packet

            protocol = "OTHER"
            src_port = None
            dst_port = None
            tcp_flags = ""
            payload_len = len(packet)

            if packet.haslayer(TCP):
                protocol = "TCP"
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
                tcp_flags = packet[TCP].flags.flagstr
            elif packet.haslayer(UDP):
                protocol = "UDP"
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
            elif packet.haslayer(ICMP):
                protocol = "ICMP"

            dns_query = None
            dns_type = None
            if packet.haslayer(DNS) and packet.haslayer(DNSQR):
                try:
                    qname = packet[DNSQR].qname
                    if isinstance(qname, bytes):
                        dns_query = qname.decode("utf-8", errors="ignore").rstrip(".")
                    else:
                        dns_query = str(qname).rstrip(".")
                    dns_type = str(packet[DNSQR].qtype)
                except Exception:
                    pass

            return {
                "timestamp": timestamp,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "protocol": protocol,
                "tcp_flags": tcp_flags,
                "payload_len": payload_len,
                "dns_query": dns_query,
                "dns_type": dns_type
            }
        except Exception:
            return None

    def _packet_handler(self, packet):
        meta = self._parse_packet(packet)
        if meta:
            self.threat_engine.process_packet_meta(meta)

    def _sniff_loop(self):
        print(f"[PACKET-CAPTURER] Starting network sniffing loop on interface: {self.interface or 'Default Gateway Interface'}...")
        try:
            sniff(
                iface=self.interface,
                prn=self._packet_handler,
                store=False,
                stop_filter=lambda p: not self.running
            )
        except Exception as e:
            print(f"[PACKET-CAPTURER-ERROR] Error in packet capture loop: {e}")
            print("[PACKET-CAPTURER-INFO] If running without root/admin permissions, run as Sudo on Linux or Administrator on Windows.")

    def start(self):
        if self.running:
            return
        self.running = True
        self.sniff_thread = threading.Thread(target=self._sniff_loop, daemon=True)
        self.sniff_thread.start()

    def stop(self):
        self.running = False
        print("[PACKET-CAPTURER] Network sniffer stopped.")

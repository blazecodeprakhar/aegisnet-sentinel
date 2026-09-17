import json
import os
import time
import threading
from collections import deque
from typing import Dict, List, Any, Callable, Optional

import config
from core.firewall_manager import FirewallManager
from detectors.port_scan_detector import PortScanDetector
from detectors.dns_anomaly_detector import DNSAnomalyDetector
from detectors.syn_flood_detector import SYNFloodDetector
from detectors.udp_flood_detector import UDPFloodDetector
from detectors.suspicious_ip_detector import SuspiciousIPDetector

LOG_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "logs")
ALERT_LOG_FILE = os.path.join(LOG_DIR, "alerts.json")

class ThreatEngine:
    def __init__(self, firewall_mgr: FirewallManager):
        self.firewall_mgr = firewall_mgr
        self.detectors = [
            PortScanDetector(),
            DNSAnomalyDetector(),
            SYNFloodDetector(),
            UDPFloodDetector(),
            SuspiciousIPDetector()
        ]

        self.alerts_history = deque(maxlen=200)
        self.websocket_broadcast_cb: Optional[Callable[[Dict[str, Any]], None]] = None
        self.lock = threading.Lock()

        # Global Statistics
        self.stats = {
            "total_packets": 0,
            "tcp_packets": 0,
            "udp_packets": 0,
            "icmp_packets": 0,
            "other_packets": 0,
            "alerts_count": 0,
            "severity_counts": {
                config.SEVERITY_LOW: 0,
                config.SEVERITY_MEDIUM: 0,
                config.SEVERITY_HIGH: 0,
                config.SEVERITY_CRITICAL: 0
            },
            "start_time": time.time()
        }

        self._init_log_dir()

    def _init_log_dir(self):
        if not os.path.exists(LOG_DIR):
            os.makedirs(LOG_DIR, exist_ok=True)
        if not os.path.exists(ALERT_LOG_FILE):
            with open(ALERT_LOG_FILE, "w") as f:
                json.dump([], f)

    def set_websocket_callback(self, cb: Callable[[Dict[str, Any]], None]):
        self.websocket_broadcast_cb = cb

    def process_packet_meta(self, packet_meta: Dict[str, Any]):
        with self.lock:
            self.stats["total_packets"] += 1
            proto = packet_meta.get("protocol", "OTHER")
            if proto == "TCP":
                self.stats["tcp_packets"] += 1
            elif proto == "UDP":
                self.stats["udp_packets"] += 1
            elif proto == "ICMP":
                self.stats["icmp_packets"] += 1
            else:
                self.stats["other_packets"] += 1

        # Run packet through each enabled detector
        for detector in self.detectors:
            if not detector.enabled:
                continue

            alert = detector.inspect(packet_meta)
            if alert:
                self._handle_alert(alert)

    def _handle_alert(self, alert: Dict[str, Any]):
        alert_id = f"ALT-{int(time.time() * 1000)}"
        alert["id"] = alert_id
        alert["timestamp"] = time.time()
        alert["formatted_time"] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(alert["timestamp"]))

        with self.lock:
            self.stats["alerts_count"] += 1
            sev = alert.get("severity", config.SEVERITY_MEDIUM)
            self.stats["severity_counts"][sev] = self.stats["severity_counts"].get(sev, 0) + 1
            self.alerts_history.appendleft(alert)

        # Trigger Automated IPS Firewall Response
        src_ip = alert.get("src_ip")
        if src_ip and config.AUTO_BLOCK_ENABLED:
            blocked = self.firewall_mgr.block_ip(
                ip=src_ip,
                reason=f"{alert.get('type')} ({alert.get('detector')})",
                ttl_seconds=config.DEFAULT_BAN_TTL_SECONDS
            )
            alert["firewall_action"] = "BLOCKED" if blocked else "SKIPPED_WHITELIST"
        else:
            alert["firewall_action"] = "NO_ACTION"

        # Save alert to disk
        self._write_alert_to_file(alert)

        # Broadcast via WebSockets to Front-end UI
        if self.websocket_broadcast_cb:
            try:
                self.websocket_broadcast_cb({
                    "event": "NEW_ALERT",
                    "data": alert,
                    "stats": self.get_stats_summary()
                })
            except Exception as e:
                print(f"[THREAT-ENGINE] WS Broadcast error: {e}")

        print(f"[ALERT-{alert['severity']}] {alert['type']} from {alert['src_ip']} -> Action: {alert['firewall_action']}")

    def _write_alert_to_file(self, alert: Dict[str, Any]):
        try:
            with open(ALERT_LOG_FILE, "r+") as f:
                try:
                    data = json.load(f)
                except Exception:
                    data = []
                data.append(alert)
                f.seek(0)
                json.dump(data[-500:], f, indent=2)  # Keep last 500 log records
        except Exception as e:
            print(f"[THREAT-ENGINE] Failed writing alert to disk: {e}")

    def get_stats_summary(self) -> Dict[str, Any]:
        with self.lock:
            uptime = int(time.time() - self.stats["start_time"])
            return {
                "total_packets": self.stats["total_packets"],
                "tcp_packets": self.stats["tcp_packets"],
                "udp_packets": self.stats["udp_packets"],
                "icmp_packets": self.stats["icmp_packets"],
                "other_packets": self.stats["other_packets"],
                "alerts_count": self.stats["alerts_count"],
                "severity_counts": dict(self.stats["severity_counts"]),
                "active_bans_count": len(self.firewall_mgr.get_active_bans()),
                "uptime_seconds": uptime
            }

    def get_recent_alerts(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self.lock:
            return list(self.alerts_history)[:limit]

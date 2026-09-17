import os
import subprocess
import time
import threading
from typing import Dict, List, Any
import config

class FirewallManager:
    def __init__(self):
        self.active_bans: Dict[str, Dict[str, Any]] = {}
        self.lock = threading.Lock()
        self.running = True
        self._expiration_thread = threading.Thread(target=self._ban_expiration_loop, daemon=True)
        self._expiration_thread.start()

    def is_whitelisted(self, ip: str) -> bool:
        return ip in config.WHITELIST_IPS or ip.startswith("127.") or ip.startswith("169.254.")

    def block_ip(self, ip: str, reason: str = "Automated IPS Response", ttl_seconds: int = config.DEFAULT_BAN_TTL_SECONDS) -> bool:
        if self.is_whitelisted(ip):
            print(f"[FIREWALL] IP {ip} is Whitelisted. Skipping ban.")
            return False

        with self.lock:
            if ip in self.active_bans:
                # Update expiration time if already blocked
                self.active_bans[ip]["expire_time"] = time.time() + ttl_seconds
                return True

            ban_info = {
                "ip": ip,
                "reason": reason,
                "blocked_at": time.time(),
                "expire_time": time.time() + ttl_seconds,
                "ttl": ttl_seconds,
                "platform": "LINUX_IPTABLES" if config.IS_LINUX else "WINDOWS_SIMULATED"
            }

            if config.IS_LINUX:
                try:
                    # Check if already in iptables
                    check_cmd = ["iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"]
                    res = subprocess.run(["sudo"] + check_cmd, capture_output=True)
                    if res.returncode != 0:
                        # Add drop rule
                        add_cmd = ["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"]
                        subprocess.run(add_cmd, check=True)
                        print(f"[FIREWALL-LINUX] Executed: {' '.join(add_cmd)}")
                except Exception as e:
                    print(f"[FIREWALL-ERROR] Failed to execute iptables command for {ip}: {e}")
                    return False
            else:
                print(f"[FIREWALL-SIMULATION] Simulated IPTables Rule Added: DROP ALL FROM {ip} ({reason})")

            self.active_bans[ip] = ban_info
            return True

    def unblock_ip(self, ip: str) -> bool:
        with self.lock:
            if ip not in self.active_bans:
                return False

            if config.IS_LINUX:
                try:
                    del_cmd = ["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"]
                    subprocess.run(del_cmd, capture_output=True)
                    print(f"[FIREWALL-LINUX] Executed: {' '.join(del_cmd)}")
                except Exception as e:
                    print(f"[FIREWALL-ERROR] Failed to remove iptables rule for {ip}: {e}")

            else:
                print(f"[FIREWALL-SIMULATION] Simulated IPTables Rule Removed: UNBLOCK {ip}")

            del self.active_bans[ip]
            return True

    def get_active_bans(self) -> List[Dict[str, Any]]:
        with self.lock:
            now = time.time()
            res = []
            for ip, info in self.active_bans.items():
                info_copy = dict(info)
                info_copy["remaining_seconds"] = max(0, int(info["expire_time"] - now))
                res.append(info_copy)
            return res

    def _ban_expiration_loop(self):
        """Background daemon thread to auto-expire bans."""
        while self.running:
            time.sleep(5)
            now = time.time()
            to_unblock = []
            with self.lock:
                for ip, info in self.active_bans.items():
                    if now >= info["expire_time"]:
                        to_unblock.append(ip)

            for ip in to_unblock:
                print(f"[FIREWALL] Ban expired for IP {ip}. Automatically unblocking.")
                self.unblock_ip(ip)

    def stop(self):
        self.running = False

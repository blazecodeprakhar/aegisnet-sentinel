from abc import ABC, abstractmethod
from typing import Dict, Any, Optional

class BaseDetector(ABC):
    def __init__(self, name: str, description: str):
        self.name = name
        self.description = description
        self.enabled = True

    @abstractmethod
    def inspect(self, packet_meta: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Inspect parsed packet metadata dictionary.
        Returns an Alert dictionary if an anomaly/attack pattern is detected, otherwise None.
        
        packet_meta expected schema:
        {
            "timestamp": float,
            "src_ip": str,
            "dst_ip": str,
            "src_port": int,
            "dst_port": int,
            "protocol": str,
            "tcp_flags": str,
            "payload_len": int,
            "dns_query": str,
            "dns_type": str,
            "raw_packet": Packet (optional)
        }
        """
        pass

    def reset_state(self):
        """Reset internal detection buffers or historical windows."""
        pass

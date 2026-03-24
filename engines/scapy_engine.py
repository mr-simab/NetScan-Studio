from typing import List, Optional
from .base_engine import BaseScanEngine, ScanResult, ScanState
from utils import ValidationHelper
from utils.logger import get_logger

logger = get_logger("ScapyEngine")


class ScapyEngine(BaseScanEngine):
    """Advanced packet analysis using Scapy (optimized & stable)"""

    def __init__(self, target: str, ports: Optional[List[int]] = None,
                 analysis_type: str = "ttl"):
        super().__init__(target)
        self.ports = ports or [22, 80, 443]
        self.analysis_type = analysis_type

        try:
            from scapy.all import IP, TCP, sr1
            self.IP = IP
            self.TCP = TCP
            self.sr1 = sr1
            self.scapy_available = True
        except ImportError:
            logger.warning("Scapy not available")
            self.scapy_available = False

    def get_engine_name(self) -> str:
        return "Scapy Engine"

    def scan(self) -> List[ScanResult]:
        """Execute Scapy-based analysis"""
        self.state = ScanState.RUNNING
        self.results.clear()

        self.queue_log(f"[Scapy] Starting analysis ({self.analysis_type})")

        # Dependency check
        if not self.scapy_available:
            self.state = ScanState.FAILED
            self.queue_error("Scapy not installed")
            return []

        # Resolve target
        success, result = ValidationHelper.resolve_target(self.target)
        if not success:
            self.state = ScanState.FAILED
            self.queue_error(f"Resolution failed: {result}")
            return []

        ip = result
        self.queue_log(f"[Scapy] Target resolved → {ip}")

        try:
            if self.analysis_type == "ttl":
                self._analyze_ttl(ip)

            elif self.analysis_type == "firewall":
                self._detect_firewall(ip)

            elif self.analysis_type == "packet":
                self._craft_packets(ip)

            else:
                self.queue_error(f"Unknown analysis type: {self.analysis_type}")

            self.state = ScanState.COMPLETED if not self._stop_event.is_set() else ScanState.PAUSED
            self.queue_log("[Scapy] Analysis completed")

        except Exception as e:
            self.state = ScanState.FAILED
            error_msg = f"Scapy error: {str(e)}"
            self.queue_error(error_msg)
            logger.error(error_msg)

        return self.results

    # ---------------- TTL ANALYSIS ----------------
    def _analyze_ttl(self, ip: str):
        """Analyze TTL patterns for OS fingerprinting"""
        self.queue_log("[Scapy] TTL analysis started")

        for port in self.ports:
            if self._stop_event.is_set():
                break

            try:
                packet = self.IP(dst=ip) / self.TCP(dport=port, flags="S")
                response = self.sr1(packet, timeout=2, verbose=False)

                if not response:
                    continue

                ttl = response.ttl

                if ttl <= 64:
                    os_type = "Linux/Unix"
                elif ttl <= 128:
                    os_type = "Windows"
                else:
                    os_type = "Unknown"

                self.queue_result("ttl_analysis", {
                    "port": port,
                    "ttl": ttl,
                    "os_hint": os_type
                })

                self.queue_log(f"[TTL] Port {port}: TTL={ttl} → {os_type}")

            except Exception as e:
                self.queue_error(f"TTL error (port {port}): {e}")

    # ---------------- FIREWALL DETECTION ----------------
    def _detect_firewall(self, ip: str):
        """Detect firewall behavior"""
        self.queue_log("[Scapy] Firewall detection started")

        try:
            packet = self.IP(dst=ip) / self.TCP(dport=80, flags="S")
            response = self.sr1(packet, timeout=2, verbose=False)

            if response is None:
                result = {"detected": True, "type": "Silent/Filtered"}
                self.queue_log("[Firewall] No response → possible firewall")

            elif response.flags & 0x04:  # RST
                result = {"detected": False}
                self.queue_log("[Firewall] RST received → no firewall")

            else:
                result = {"detected": True, "type": "Filtered/Custom"}
                self.queue_log("[Firewall] Unusual response → possible firewall")

            self.queue_result("firewall_detection", result)

        except Exception as e:
            self.queue_error(f"Firewall detection error: {e}")

    # ---------------- PACKET CRAFTING ----------------
    def _craft_packets(self, ip: str):
        """Send crafted packets and analyze responses"""
        self.queue_log("[Scapy] Packet crafting started")

        for port in self.ports:
            if self._stop_event.is_set():
                break

            try:
                packet = self.IP(dst=ip) / self.TCP(dport=port, flags="S")
                response = self.sr1(packet, timeout=1, verbose=False)

                if response:
                    resp_type = "SYN-ACK" if response.flags & 0x12 else str(response.flags)

                    self.queue_result("packet_response", {
                        "port": port,
                        "response": resp_type
                    })

                    self.queue_log(f"[Packet] {ip}:{port} → {resp_type}")

            except Exception as e:
                self.queue_error(f"Packet error (port {port}): {e}")
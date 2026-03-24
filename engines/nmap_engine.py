import nmap
from typing import List
from .base_engine import BaseScanEngine, ScanResult, ScanState
from utils import ValidationHelper
from utils.logger import get_logger

logger = get_logger("NmapEngine")


class NmapEngine(BaseScanEngine):
    """Nmap-based scanning engine"""

    def __init__(self, target: str, args: str = "-sS -sV"):
        super().__init__(target)
        self.args = args

        try:
            self.nm = nmap.PortScanner()
        except Exception as e:
            logger.error(f"Nmap initialization failed: {e}")
            self.nm = None

    def get_engine_name(self) -> str:
        return "Nmap Engine"

    def scan(self) -> List[ScanResult]:
        """Execute Nmap scan"""
        self.state = ScanState.RUNNING
        self.results = []

        if not self.nm:
            self.state = ScanState.FAILED
            self.queue_error("Nmap is not installed or not accessible")
            return []

        self.queue_log(f"Starting Nmap scan with args: {self.args}")

        # Resolve target
        success, resolved_ip = ValidationHelper.resolve_target(self.target)
        if not success:
            self.state = ScanState.FAILED
            self.queue_error(f"Failed to resolve {self.target}: {resolved_ip}")
            return []

        self.queue_log(f"Target resolved: {self.target} → {resolved_ip}")

        try:
            self.queue_log(f"Running: nmap {resolved_ip} {self.args}")
            self.nm.scan(hosts=resolved_ip, arguments=self.args)

            for host in self.nm.all_hosts():
                if self._stop_event.is_set():
                    break

                self.queue_log(f"Scanning host: {host}")

                for proto in self.nm[host].all_protocols():
                    ports = list(self.nm[host][proto].keys())

                    for idx, port in enumerate(ports):
                        if self._stop_event.is_set():
                            break

                        port_info = self.nm[host][proto][port]
                        state = port_info.get('state', 'unknown')

                        # Progress update
                        self.queue_progress(idx + 1, len(ports))

                        if state == 'open':
                            service_name = port_info.get('name', 'unknown')
                            version = port_info.get('version', '') or None
                            product = port_info.get('product', '')
                            extra_info = port_info.get('extrainfo', '')

                            info = " ".join(filter(None, [product, extra_info])) or None

                            scan_result = ScanResult(
                                port=int(port),
                                service=service_name,
                                state=state,
                                version=version,
                                info=info
                            )

                            self.results.append(scan_result)
                            self.queue_result('port_found', scan_result)

                            logger.debug(f"[OK] {port}/{proto} {service_name} {version or ''}")

            if self._stop_event.is_set():
                self.state = ScanState.PAUSED
                self.queue_log("Nmap scan paused by user")
            else:
                self.state = ScanState.COMPLETED
                self.queue_log(f"Nmap scan completed. Found {len(self.results)} open ports")

        except Exception as e:
            self.state = ScanState.FAILED
            error_msg = f"Nmap scan failed: {str(e)}"
            self.queue_error(error_msg)
            logger.error(error_msg)

        return self.results

    def get_version(self) -> str:
        """Get Nmap version"""
        try:
            return ".".join(map(str, self.nm.nmap_version()))
        except Exception:
            return "Unknown"
import socket
import threading
from typing import List, Optional
from .base_engine import BaseScanEngine, ScanResult, ScanState
from utils import PortHelper, ValidationHelper
from utils.logger import get_logger

logger = get_logger("SocketEngine")


class SocketEngine(BaseScanEngine):
    """Fast and optimized socket-based port scanner"""

    def __init__(self, target: str, ports: Optional[List[int]] = None,
                 timeout: float = 0.5, max_threads: int = 100):
        super().__init__(target)
        self.ports = ports or list(range(1, 1025))
        self.timeout = timeout
        self.max_threads = max_threads
        self.scanned_count = 0
        self.lock = threading.Lock()

    def get_engine_name(self) -> str:
        return "Socket Engine"

    def scan(self) -> List[ScanResult]:
        """Execute socket-based scan"""
        self.state = ScanState.RUNNING
        self.results.clear()
        self.scanned_count = 0

        self.queue_log("[Socket] Starting scan...")

        # Resolve target
        success, result = ValidationHelper.resolve_target(self.target)
        if not success:
            self.state = ScanState.FAILED
            self.queue_error(f"Resolution failed: {result}")
            return []

        ip = result
        self.queue_log(f"[Socket] Target resolved → {ip}")

        threads = []
        semaphore = threading.Semaphore(self.max_threads)
        total_ports = len(self.ports)

        for port in self.ports:
            if self._stop_event.is_set():
                break

            semaphore.acquire()

            t = threading.Thread(
                target=self._worker,
                args=(semaphore, ip, port, total_ports),
                daemon=True
            )
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

        if self._stop_event.is_set():
            self.state = ScanState.PAUSED
            self.queue_log("[Socket] Scan paused")
        else:
            self.state = ScanState.COMPLETED
            self.queue_log(f"[Socket] Scan completed. Open ports: {len(self.results)}")

        return self.results

    def _worker(self, semaphore: threading.Semaphore, ip: str, port: int, total: int):
        """Thread worker"""
        try:
            if self._scan_port(ip, port):
                service = PortHelper.get_service_name(port)

                result = ScanResult(
                    port=port,
                    service=service,
                    state="open"
                )

                # Thread-safe append
                with self.lock:
                    self.results.append(result)

                self.queue_result("port_found", result)
                logger.debug(f"[OK] Port {port} ({service}) open")

        finally:
            semaphore.release()

            # Progress update (thread-safe)
            with self.lock:
                self.scanned_count += 1
                current = self.scanned_count

            self.queue_progress(current, total)

    def _scan_port(self, ip: str, port: int) -> bool:
        """Scan single port safely"""
        if self._stop_event.is_set():
            return False

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                return sock.connect_ex((ip, port)) == 0

        except socket.timeout:
            return False
        except Exception as e:
            logger.debug(f"[Socket] Error on port {port}: {e}")
            return False
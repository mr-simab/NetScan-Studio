from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import List, Optional
from enum import Enum
import threading
import queue


class ScanState(Enum):
    """Enum for scan states"""
    IDLE = "idle"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass
class ScanResult:
    """Data class for scan results"""
    port: int
    service: str
    state: str  # open, closed, filtered
    version: Optional[str] = None
    info: Optional[str] = None


class BaseScanEngine(ABC):
    """Base class for all scanning engines"""

    def __init__(self, target: str):
        self.target = target
        self.state = ScanState.IDLE
        self.results: List[ScanResult] = []
        self.errors: List[str] = []
        self._stop_event = threading.Event()
        self._lock = threading.Lock()
        self.result_queue = queue.Queue()

    @abstractmethod
    def scan(self, *args, **kwargs) -> List[ScanResult]:
        """Execute scan"""
        pass

    @abstractmethod
    def get_engine_name(self) -> str:
        """Return engine name"""
        pass

    def reset(self):
        """Reset engine state before new scan"""
        self.results.clear()
        self.errors.clear()
        self._stop_event.clear()
        self.state = ScanState.IDLE

    def stop(self):
        """Stop the scan"""
        self._stop_event.set()
        self.state = ScanState.PAUSED

    def is_running(self) -> bool:
        """Check if scan is running"""
        return self.state == ScanState.RUNNING

    def add_result(self, result: ScanResult):
        """Thread-safe result addition"""
        with self._lock:
            self.results.append(result)
        self.queue_result('port_found', result)

    def get_results(self) -> List[ScanResult]:
        """Get scan results"""
        with self._lock:
            return list(self.results)

    def queue_result(self, result_type: str, data):
        """Queue a result/message"""
        self.result_queue.put((result_type, data))

    def queue_log(self, message: str):
        """Queue a log message"""
        self.queue_result('log', message)

    def queue_progress(self, current: int, total: int):
        """Queue progress update"""
        self.queue_result('progress', {'current': current, 'total': total})

    def queue_error(self, error: str):
        """Queue error message"""
        with self._lock:
            self.errors.append(error)
        self.queue_result('error', error)

    def get_pending_messages(self) -> List[tuple]:
        """Get all pending messages from queue"""
        messages = []
        while not self.result_queue.empty():
            try:
                messages.append(self.result_queue.get_nowait())
            except queue.Empty:
                break
        return messages
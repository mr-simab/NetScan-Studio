import threading
import time
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field
from enum import Enum

from engines import SocketEngine, NmapEngine, ScapyEngine
from command import NmapCommandBuilder
from processing import InsightsEngine
from utils.logger import get_logger

logger = get_logger("ScannerManager")


# =========================================================
# ENUMS
# =========================================================

class ScanMode(Enum):
    QUICK = "Quick"
    STANDARD = "Standard"
    DEEP = "Deep"


# =========================================================
# CONFIG
# =========================================================

@dataclass
class ScanConfig:
    target: str
    mode: ScanMode
    tool: str

    scan_type: Optional[str] = None
    host_discovery: Optional[str] = None
    version_detection: bool = False
    os_detection: bool = False
    script: Optional[str] = None
    ports: Optional[str] = None

    # NEW 🔥
    timing: Optional[str] = None
    verbosity: Optional[str] = None
    port_strategy: Optional[str] = None

    extra_args: Dict[str, Any] = field(default_factory=dict)


# =========================================================
# MANAGER
# =========================================================

class ScannerManager:
    """Advanced scan orchestrator"""

    TOOL_RECOMMENDATIONS = {
        'Quick': {'tool': 'socket', 'status': 'Recommended'},
        'Standard': {'tool': 'nmap', 'status': 'Recommended'},
        'Deep': {'tool': 'hybrid', 'status': 'Advanced'},
    }

    def __init__(self):
        self.current_scan = None
        self.config: Optional[ScanConfig] = None
        self.results = []
        self.is_scanning = False
        self.start_time = None
        self.command_preview = ""

    # =========================================================
    # CONFIG
    # =========================================================

    def create_config(self, target: str, mode: str, tool: str, **kwargs) -> ScanConfig:
        scan_mode = ScanMode[mode.upper()] if mode.upper() in ScanMode.__members__ else ScanMode.STANDARD

        self.config = ScanConfig(
            target=target,
            mode=scan_mode,
            tool=tool.lower(),
            scan_type=kwargs.get('scan_type'),
            host_discovery=kwargs.get('host_discovery'),
            version_detection=kwargs.get('version_detection', False),
            os_detection=kwargs.get('os_detection', False),
            script=kwargs.get('script'),
            ports=kwargs.get('ports'),
            timing=kwargs.get('timing'),
            verbosity=kwargs.get('verbosity'),
            port_strategy=kwargs.get('port_strategy'),
            extra_args=kwargs
        )

        return self.config

    # =========================================================
    # COMMAND PREVIEW 🔥 (UI SYNC)
    # =========================================================

    def generate_command_preview(self) -> str:
        if not self.config:
            return ""

        if self.config.tool == "nmap":
            builder = self._build_nmap_command()
            self.command_preview = builder.build_command()
        else:
            self.command_preview = f"{self.config.tool} scan on {self.config.target}"

        return self.command_preview

    def _build_nmap_command(self) -> NmapCommandBuilder:
        builder = NmapCommandBuilder(self.config.target)

        if self.config.scan_type:
            builder.set_scan_type(self.config.scan_type)

        if self.config.host_discovery:
            builder.set_host_discovery(self.config.host_discovery)

        if self.config.version_detection:
            builder.enable_version_detection()

        if self.config.os_detection:
            builder.enable_os_detection()

        if self.config.script:
            builder.set_script(self.config.script)

        if self.config.ports:
            builder.set_ports(self.config.ports)

        # NEW 🔥
        if self.config.timing:
            builder.set_timing(self.config.timing)

        if self.config.verbosity:
            builder.set_verbosity(self.config.verbosity)

        if self.config.port_strategy:
            builder.set_port_strategy(self.config.port_strategy)

        return builder

    def get_tool_recommendation(self, mode: str) -> Dict[str, str]:
        """Get tool recommendation for a given scan mode"""
        if isinstance(mode, ScanMode):
            mode = mode.value
        return self.TOOL_RECOMMENDATIONS.get(mode, {'tool': 'nmap', 'status': 'Recommended'})

    # =========================================================
    # EXECUTION
    # =========================================================

    def execute_scan(self) -> bool:
        if not self.config or self.is_scanning:
            return False

        self.is_scanning = True
        self.results = []
        self.start_time = time.time()

        try:
            # Tool override logic 🔥
            if self.config.tool == "socket":
                self._execute_quick_scan()

            elif self.config.tool == "nmap":
                self._execute_standard_scan()

            elif self.config.tool == "scapy":
                self._execute_scapy_scan()

            elif self.config.tool == "hybrid":
                self._execute_deep_scan()

            else:
                logger.warning("Unknown tool, defaulting to Nmap")
                self._execute_standard_scan()

            return True

        except Exception as e:
            logger.error(f"Scan error: {e}")
            return False

        finally:
            self.is_scanning = False

    # =========================================================
    # ASYNC
    # =========================================================

    def execute_scan_async(self, callback=None):
        thread = threading.Thread(target=self._execute_async, args=(callback,), daemon=True)
        thread.start()
        return thread

    def _execute_async(self, callback=None):
        success = self.execute_scan()
        if callback:
            callback(success, self.results)

    # =========================================================
    # PIPELINE MODES
    # =========================================================

    def _execute_quick_scan(self):
        logger.info("Quick Scan (Socket)")

        ports = self._parse_ports(self.config.ports) if self.config.ports else list(range(1, 1025))

        engine = SocketEngine(self.config.target, ports=ports)
        self.current_scan = engine
        self.results = engine.scan()

    def _execute_standard_scan(self):
        logger.info("Standard Scan (Nmap)")

        builder = self._build_nmap_command()
        cmd = builder.build_command()

        args = cmd.replace('nmap ', '').replace(self.config.target, '').strip()

        engine = NmapEngine(self.config.target, args=args)
        self.current_scan = engine
        self.results = engine.scan()

    def _execute_scapy_scan(self):
        logger.info("Scapy Deep Scan")

        ports = self._parse_ports(self.config.ports) if self.config.ports else [80, 443]

        engine = ScapyEngine(self.config.target, ports=ports)
        self.current_scan = engine
        self.results = engine.scan()

    def _execute_deep_scan(self):
        logger.info("Deep Hybrid Scan")

        # Phase 1
        self._execute_quick_scan()

        # Phase 2
        if self.results:
            self._execute_standard_scan()

        # Phase 3
        if self.results:
            ports = [r.port for r in self.results[:5]]
            engine = ScapyEngine(self.config.target, ports=ports)
            self.current_scan = engine
            engine.scan()

    # =========================================================
    # UTIL
    # =========================================================

    def _parse_ports(self, port_string: str) -> List[int]:
        ports = []
        for part in port_string.split(','):
            if '-' in part:
                start, end = part.split('-')
                ports.extend(range(int(start), int(end) + 1))
            else:
                ports.append(int(part))
        return sorted(set(ports))

    # =========================================================
    # RESULTS + INSIGHTS
    # =========================================================

    def get_results(self):
        return self.results

    def generate_insights(self):
        engine = InsightsEngine()
        return engine.analyze(self.results)

    def generate_report_metadata(self) -> Dict[str, Any]:
        """🔥 For your report UI"""
        return {
            "project": "NetScan Studio",
            "author": "Mr.Sima",
            "target": self.config.target if self.config else None,
            "mode": self.config.mode.value if self.config else None,
            "tool": self.config.tool if self.config else None,
            "command": self.command_preview,
            "duration": round(time.time() - self.start_time, 2) if self.start_time else 0
        }

    # =========================================================
    # CONTROL
    # =========================================================

    def stop_scan(self):
        if self.current_scan:
            self.current_scan.stop()
            logger.info("Scan stopped")
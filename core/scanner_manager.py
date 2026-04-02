import threading
import time
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field
from enum import Enum

from engines import SocketEngine, NmapEngine, ScapyEngine, ScanResult, ScanState
from command import NmapCommandBuilder
from processing import InsightsEngine
from utils.logger import get_logger
from setup import platform_detector

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
    aggressive: bool = False
    script: Optional[str] = None
    ports: Optional[str] = None

    # NEW 🔥
    timing: Optional[str] = None
    verbosity: Optional[str] = None
    port_strategy: Optional[str] = None
    scapy_analysis: Optional[str] = None

    extra_args: Dict[str, Any] = field(default_factory=dict)


# =========================================================
# MANAGER
# =========================================================

class ScannerManager:
    """Advanced scan orchestrator"""

    MODE_ALIASES = {
        'QUICK': ScanMode.QUICK,
        'NORMAL': ScanMode.QUICK,
        'STANDARD': ScanMode.STANDARD,
        'MEDIUM': ScanMode.STANDARD,
        'DEEP': ScanMode.DEEP,
        'ADVANCED': ScanMode.DEEP,
    }

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
        self.compatibility_note = None

    # =========================================================
    # CONFIG
    # =========================================================

    def create_config(self, target: str, mode: str, tool: str, **kwargs) -> ScanConfig:
        scan_mode = self.MODE_ALIASES.get(str(mode).strip().upper(), ScanMode.STANDARD)

        self.config = ScanConfig(
            target=target,
            mode=scan_mode,
            tool=tool.lower(),
            scan_type=kwargs.get('scan_type'),
            host_discovery=kwargs.get('host_discovery'),
            version_detection=kwargs.get('version_detection', False),
            os_detection=kwargs.get('os_detection', False),
            aggressive=kwargs.get('aggressive', False),
            script=kwargs.get('script'),
            ports=kwargs.get('ports'),
            timing=kwargs.get('timing'),
            verbosity=kwargs.get('verbosity'),
            port_strategy=kwargs.get('port_strategy'),
            scapy_analysis=kwargs.get('scapy_analysis'),
            extra_args=kwargs
        )

        return self.config

    # =========================================================
    # COMMAND PREVIEW 🔥 (UI SYNC)
    # =========================================================

    def generate_command_preview(self) -> str:
        if not self.config:
            return ""

        self.compatibility_note = None

        if self.config.tool == "nmap":
            builder = self._build_nmap_command()
            self.command_preview = builder.build_command()
        elif self.config.tool == "socket":
            self.command_preview = self._build_socket_preview()
        elif self.config.tool == "scapy":
            self.command_preview = self._build_scapy_preview()
        elif self.config.tool == "hybrid":
            self.command_preview = self._build_hybrid_preview()
        else:
            self.command_preview = f"{self.config.tool} scan on {self.config.target}"

        return self.command_preview

    def _build_nmap_command(self) -> NmapCommandBuilder:
        builder = NmapCommandBuilder(self.config.target)

        effective_scan_type = self._get_effective_nmap_scan_type()
        if effective_scan_type:
            builder.set_scan_type(effective_scan_type)

        if self.config.host_discovery:
            builder.set_host_discovery(self.config.host_discovery)

        if self.config.version_detection:
            builder.enable_version_detection()

        if self.config.os_detection:
            builder.enable_os_detection()

        if self.config.aggressive:
            builder.enable_aggressive_scan()

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

    def _get_effective_nmap_scan_type(self) -> Optional[str]:
        requested = self.config.scan_type
        if not requested:
            return None

        raw_scan_types = {'SYN Scan', 'ACK Scan', 'UDP Scan', 'FIN Scan'}
        if requested in raw_scan_types and not platform_detector.supports_raw_packet_scans():
            self.compatibility_note = (
                f"{requested} requires administrator/root privileges on "
                f"{platform_detector.get_platform_label()}; falling back to TCP Connect."
            )
            logger.info(self.compatibility_note)
            return 'TCP Connect'

        return requested

    def _build_socket_preview(self) -> str:
        ports = self._resolve_socket_ports()
        port_display = self._format_ports_for_preview(ports)
        return f"socket-scan {self.config.target} --ports {port_display} --timeout 0.5 --threads 100"

    def _build_scapy_preview(self, ports: Optional[List[int]] = None) -> str:
        selected_ports = ports or self._resolve_scapy_ports()
        port_display = self._format_ports_for_preview(selected_ports)
        analysis = self.config.scapy_analysis or "ttl"
        return f"scapy-analyze {self.config.target} --analysis {analysis} --ports {port_display}"

    def _build_hybrid_preview(self) -> str:
        socket_preview = self._build_socket_preview()
        nmap_preview = self._build_nmap_command().build_command()
        scapy_preview = self._build_scapy_preview([80, 443])
        return f"{socket_preview} -> {nmap_preview} -> {scapy_preview}"

    def get_tool_recommendation(self, mode: str) -> Dict[str, str]:
        """Get tool recommendation for a given scan mode"""
        if isinstance(mode, ScanMode):
            mode = mode.value
        return self.TOOL_RECOMMENDATIONS.get(mode, {'tool': 'nmap', 'status': 'Recommended'})

    def get_compatibility_note(self) -> Optional[str]:
        return self.compatibility_note

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

            return not (self.current_scan and self.current_scan.state == ScanState.FAILED)

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

        ports = self._resolve_socket_ports()

        engine = SocketEngine(self.config.target, ports=ports)
        self.current_scan = engine
        self.results = engine.scan()

    def _execute_standard_scan(self):
        logger.info("Standard Scan (Nmap)")

        builder = self._build_nmap_command()
        args = builder.build_args()

        engine = NmapEngine(self.config.target, args=args)
        self.current_scan = engine
        self.results = engine.scan()

    def _execute_scapy_scan(self):
        logger.info("Scapy Deep Scan")

        ports = self._resolve_scapy_ports()
        analysis_type = self.config.scapy_analysis or "ttl"

        engine = ScapyEngine(self.config.target, ports=ports, analysis_type=analysis_type)
        self.current_scan = engine
        self.results = engine.scan()

    def _execute_deep_scan(self):
        logger.info("Deep Hybrid Scan")

        # Phase 1
        self._execute_quick_scan()
        quick_results = list(self.results)

        # Phase 2
        self._execute_standard_scan()
        nmap_results = list(self.results)

        # Phase 3
        scapy_seed_ports = [r.port for r in nmap_results[:5]] or [r.port for r in quick_results[:5]]
        if not scapy_seed_ports:
            scapy_seed_ports = self._resolve_scapy_ports()

        engine = ScapyEngine(
            self.config.target,
            ports=scapy_seed_ports,
            analysis_type=self.config.scapy_analysis or "ttl"
        )
        self.current_scan = engine
        scapy_results = engine.scan()

        self.results = self._merge_results(quick_results, nmap_results, scapy_results)

    # =========================================================
    # UTIL
    # =========================================================

    def _parse_ports(self, port_string: str) -> List[int]:
        if not port_string:
            return []

        ports = []
        for part in port_string.split(','):
            part = part.strip()
            if not part:
                continue
            if '-' in part:
                start, end = [piece.strip() for piece in part.split('-', 1)]
                if not start or not end:
                    raise ValueError(f"Invalid port range '{part}'. Use formats like 22,80,443 or 1-1024.")
                if not start.isdigit() or not end.isdigit():
                    raise ValueError(f"Invalid port range '{part}'. Ports must be numeric.")
                start_port = int(start)
                end_port = int(end)
                if start_port < 0 or end_port > 65535 or start_port > end_port:
                    raise ValueError(f"Invalid port range '{part}'. Ports must be between 0 and 65535.")
                ports.extend(range(start_port, end_port + 1))
            else:
                if not part.isdigit():
                    raise ValueError(f"Invalid port '{part}'. Ports must be numeric.")
                port = int(part)
                if port < 0 or port > 65535:
                    raise ValueError(f"Invalid port '{part}'. Ports must be between 0 and 65535.")
                ports.append(port)

        if not ports:
            raise ValueError("No valid ports were provided.")
        return sorted(set(ports))

    def _resolve_socket_ports(self) -> List[int]:
        if self.config.ports:
            return self._parse_ports(self.config.ports)
        if self.config.port_strategy == 'Top 100':
            return list(range(1, 101))
        return list(range(1, 1025))

    def _resolve_scapy_ports(self) -> List[int]:
        if self.config.ports:
            return self._parse_ports(self.config.ports)
        if self.config.port_strategy == 'Top 100':
            return [21, 22, 25, 53, 80, 110, 143, 443, 445, 3389]
        if self.config.port_strategy == 'Top 1000':
            return [21, 22, 23, 25, 53, 80, 110, 139, 143, 161, 389, 443, 445, 993, 995, 1723, 3306, 3389, 5432, 5900, 8080, 8443]
        return [22, 80, 443]

    def _format_ports_for_preview(self, ports: List[int]) -> str:
        if not ports:
            return "default"
        if len(ports) > 12:
            return f"{ports[0]}-{ports[-1]} ({len(ports)} ports)"
        return ",".join(str(port) for port in ports)

    def _merge_results(self, *groups: List[ScanResult]) -> List[ScanResult]:
        merged: Dict[int, ScanResult] = {}

        for group in groups:
            for result in group or []:
                existing = merged.get(result.port)
                if not existing:
                    merged[result.port] = result
                    continue

                info_parts = [existing.info, result.info]
                combined_info = " | ".join(part for idx, part in enumerate(info_parts) if part and part not in info_parts[:idx]) or None

                merged[result.port] = ScanResult(
                    port=result.port,
                    service=result.service if result.service != 'Unknown' else existing.service,
                    state=result.state if result.state not in {'unknown', 'closed'} else existing.state,
                    version=result.version or existing.version,
                    info=combined_info
                )

        return [merged[port] for port in sorted(merged)]

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

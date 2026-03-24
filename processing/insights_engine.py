from typing import List, Dict, Any
from engines import ScanResult
from utils.logger import get_logger

logger = get_logger("ProcessingEngine")


class InsightsEngine:
    """Advanced intelligent insights engine"""

    # ---------------------------
    # SERVICE RISK DATABASE
    # ---------------------------
    SERVICE_RISK = {
        'SSH': {'risk': 'medium', 'desc': 'Remote administration service'},
        'HTTP': {'risk': 'high', 'desc': 'Unencrypted web service'},
        'HTTPS': {'risk': 'low', 'desc': 'Secure web service'},
        'FTP': {'risk': 'critical', 'desc': 'Unencrypted file transfer'},
        'TELNET': {'risk': 'critical', 'desc': 'Insecure remote access'},
        'SMTP': {'risk': 'medium', 'desc': 'Email service'},
        'DNS': {'risk': 'medium', 'desc': 'Name resolution service'},
        'RDP': {'risk': 'high', 'desc': 'Remote desktop service'},
        'MYSQL': {'risk': 'high', 'desc': 'Database service'},
        'MONGODB': {'risk': 'critical', 'desc': 'Often misconfigured DB'},
        'SMB': {'risk': 'high', 'desc': 'Windows file sharing'},
    }

    COMMON_PORT_FLAGS = {
        21: "FTP detected (legacy, insecure)",
        22: "SSH access point",
        23: "Telnet detected (very insecure)",
        80: "HTTP service running",
        443: "HTTPS service running",
        3306: "MySQL database exposed",
        3389: "RDP exposed to network",
        8080: "Alternate web service",
    }

    def __init__(self):
        self.results = []
        self.insights = []
        self.recommendations = []
        self.risk_score = 0

    # =========================================================
    # MAIN ANALYSIS
    # =========================================================
    def analyze(self, results: List[ScanResult]) -> Dict[str, Any]:
        self.results = results
        self.insights = []
        self.recommendations = []
        self.risk_score = 0

        if not results:
            return {
                'summary': 'No open ports detected',
                'insights': ['Target appears filtered or offline'],
                'risk_level': 'low',
                'recommendations': [],
            }

        self._analyze_ports()
        self._analyze_services()
        self._detect_patterns()
        self._generate_recommendations()

        return {
            'summary': f'{len(results)} open ports detected',
            'insights': self.insights,
            'risk_level': self._calculate_risk(),
            'risk_score': self.risk_score,
            'recommendations': self.recommendations,
            'port_summary': self._port_summary(),
        }

    # =========================================================
    # PORT ANALYSIS
    # =========================================================
    def _analyze_ports(self):
        ports = [r.port for r in self.results]

        if len(ports) == 1:
            self.insights.append(f"Minimal exposure: single port {ports[0]}")
        elif len(ports) <= 5:
            self.insights.append(f"Limited exposure: {len(ports)} open ports")
        else:
            self.insights.append(f"High exposure: {len(ports)} open ports")

        for r in self.results:
            if r.port in self.COMMON_PORT_FLAGS:
                self.insights.append(f"{r.port}: {self.COMMON_PORT_FLAGS[r.port]}")

    # =========================================================
    # SERVICE ANALYSIS
    # =========================================================
    def _analyze_services(self):
        for r in self.results:
            service = r.service.upper()

            if service in self.SERVICE_RISK:
                risk_info = self.SERVICE_RISK[service]
                self.insights.append(
                    f"{r.service} → {risk_info['desc']} (Risk: {risk_info['risk']})"
                )

                # scoring
                if risk_info['risk'] == 'critical':
                    self.risk_score += 3
                elif risk_info['risk'] == 'high':
                    self.risk_score += 2
                elif risk_info['risk'] == 'medium':
                    self.risk_score += 1

            # Version awareness 🔥
            if r.version:
                if any(x in r.version.lower() for x in ['old', 'deprecated']):
                    self.insights.append(f"{r.service} may be outdated ({r.version})")
                    self.risk_score += 2

    # =========================================================
    # PATTERN DETECTION
    # =========================================================
    def _detect_patterns(self):
        services = [r.service.lower() for r in self.results]

        # Web stack
        if 'http' in services or 'https' in services:
            self.insights.append("Web attack surface detected (HTTP/HTTPS)")

        # Database exposed
        if any(s in services for s in ['mysql', 'mongodb']):
            self.insights.append("Database exposed to network")

        # Remote access combo
        if any(s in services for s in ['ssh', 'rdp', 'telnet']):
            self.insights.append("Remote access services detected")

        # Dangerous combo 🔥
        if 'ftp' in services and 'http' in services:
            self.insights.append("Multiple insecure services increase attack surface")
            self.risk_score += 2

    # =========================================================
    # RECOMMENDATIONS
    # =========================================================
    def _generate_recommendations(self):
        services = [r.service.lower() for r in self.results]

        if 'http' in services and 'https' not in services:
            self.recommendations.append("Migrate HTTP → HTTPS")

        if 'ftp' in services:
            self.recommendations.append("Replace FTP with SFTP")

        if 'telnet' in services:
            self.recommendations.append("Disable Telnet → Use SSH")

        if 'ssh' in services:
            self.recommendations.append("Use SSH keys + disable password login")

        if any(s in services for s in ['mysql', 'mongodb']):
            self.recommendations.append("Restrict database access (bind to localhost)")

        if len(self.results) > 10:
            self.recommendations.append("Reduce exposed ports via firewall")

    # =========================================================
    # RISK LEVEL
    # =========================================================
    def _calculate_risk(self) -> str:
        if self.risk_score >= 8:
            return 'critical'
        elif self.risk_score >= 5:
            return 'high'
        elif self.risk_score >= 2:
            return 'medium'
        return 'low'

    # =========================================================
    # SUMMARY
    # =========================================================
    def _port_summary(self) -> Dict[str, Any]:
        return {
            'total_ports': len(self.results),
            'services': list(set(r.service for r in self.results)),
            'ports': [r.port for r in self.results]
        }


# =========================================================
# RESULTS FORMATTER (UPGRADED)
# =========================================================

class ResultsParser:
    """Enhanced result formatter"""

    @staticmethod
    def format_results_table(results: List[ScanResult]) -> str:
        if not results:
            return "No results"

        lines = []
        lines.append("=" * 75)
        lines.append(f"{'Port':<8} {'Service':<18} {'State':<12} {'Version':<30}")
        lines.append("=" * 75)

        for r in sorted(results, key=lambda x: x.port):
            version = r.version if r.version else "-"
            lines.append(f"{r.port:<8} {r.service:<18} {r.state:<12} {version:<30}")

        lines.append("=" * 75)
        return "\n".join(lines)

    @staticmethod
    def to_dict(result: ScanResult) -> dict:
        return {
            'port': result.port,
            'service': result.service,
            'state': result.state,
            'version': result.version,
            'info': result.info,
        }

    @staticmethod
    def to_dict_list(results: List[ScanResult]) -> List[dict]:
        return [ResultsParser.to_dict(r) for r in results]
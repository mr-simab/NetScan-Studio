from typing import Dict, List, Optional
from utils.logger import get_logger
import re
import shlex

logger = get_logger("CommandBuilder")


class NmapCommandBuilder:
    """Builds advanced Nmap commands from configuration"""

    # ---------------------------
    # BASIC OPTIONS
    # ---------------------------
    SCAN_TYPES = {
        'TCP Connect': '-sT',
        'SYN Scan': '-sS',
        'ACK Scan': '-sA',
        'UDP Scan': '-sU',
        'FIN Scan': '-sF',
        'Ping Scan': '-sn',
    }

    HOST_DISCOVERY = {
        'Default': '',
        'Skip Ping': '-Pn',
        'Ping Scan Only': '-sn',
        'TCP SYN': '-PS',
        'TCP ACK': '-PA',
    }

    # ---------------------------
    # ADVANCED OPTIONS 🔥
    # ---------------------------
    TIMING_TEMPLATES = {
        'Paranoid': '-T0',
        'Sneaky': '-T1',
        'Polite': '-T2',
        'Normal': '-T3',
        'Aggressive': '-T4',
        'Insane': '-T5',
    }

    PORT_STRATEGY = {
        'Top 100': '--top-ports 100',
        'Top 1000': '--top-ports 1000',
        'Fast Scan': '-F',
        'All Ports': '-p-',
    }

    VERBOSITY = {
        'Normal': '',
        'Verbose': '-v',
        'Very Verbose': '-vv',
        'Debug': '-d',
    }

    OUTPUT_FORMATS = {
        'Normal': '-oN',
        'XML': '-oX',
        'Grepable': '-oG',
        'All': '-oA',
    }

    # ---------------------------
    # SCRIPT SYSTEM
    # ---------------------------
    SCRIPT_CATEGORIES = {
        'Vulnerability': 'vuln',
        'Discovery': 'discovery',
        'Safe': 'safe',
        'Auth': 'auth',
        'Default': 'default',
        'Brute Force': 'brute',
    }

    SCRIPTS_BY_CATEGORY = {
        'Vulnerability': [
            ('HTTP Vuln Scan', 'http-vuln*'),
            ('SMB Vuln Scan', 'smb-vuln*'),
            ('SSL Vuln Scan', 'ssl-*'),
        ],
        'Discovery': [
            ('HTTP Enum', 'http-enum'),
            ('DNS Brute', 'dns-brute'),
            ('SNMP Info', 'snmp-info'),
        ],
        'Auth': [
            ('FTP Brute', 'ftp-brute'),
            ('SSH Brute', 'ssh-brute'),
            ('Telnet Brute', 'telnet-brute'),
        ],
        'Safe': [
            ('Banner Grab', 'banner'),
            ('Service Info', 'service-info'),
        ],
    }

    # ---------------------------
    # INIT
    # ---------------------------
    def __init__(self, target: str):
        self.target = target
        self.components = {}

    # ---------------------------
    # BASIC SETTERS
    # ---------------------------
    def set_scan_type(self, scan_type: str):
        if scan_type in self.SCAN_TYPES:
            self.components['scan_type'] = self.SCAN_TYPES[scan_type]

    def set_host_discovery(self, discovery_type: str):
        if discovery_type in self.HOST_DISCOVERY:
            self.components['host_discovery'] = self.HOST_DISCOVERY[discovery_type]

    def enable_version_detection(self, enabled: bool = True):
        self._toggle('version_detection', '-sV', enabled)

    def enable_os_detection(self, enabled: bool = True):
        self._toggle('os_detection', '-O', enabled)

    def enable_aggressive_scan(self, enabled: bool = True):
        self._toggle('aggressive', '-A', enabled)

    def set_ports(self, ports: str):
        self.components['ports'] = f'-p {ports}'

    def set_script(self, script: str):
        if script:
            self.components['script'] = f'--script {script}'

    # ---------------------------
    # ADVANCED SETTERS 🔥
    # ---------------------------
    def set_timing(self, timing: str):
        if timing in self.TIMING_TEMPLATES:
            self.components['timing'] = self.TIMING_TEMPLATES[timing]

    def set_port_strategy(self, strategy: str):
        if strategy in self.PORT_STRATEGY:
            self.components['port_strategy'] = self.PORT_STRATEGY[strategy]

    def set_verbosity(self, level: str):
        if level in self.VERBOSITY:
            self.components['verbosity'] = self.VERBOSITY[level]

    def set_output(self, fmt: str, filename: str):
        if fmt in self.OUTPUT_FORMATS:
            self.components['output'] = f"{self.OUTPUT_FORMATS[fmt]} {filename}"

    def enable_fragmentation(self, enabled=True):
        self._toggle('fragment', '-f', enabled)

    def set_data_length(self, length: int):
        self.components['data_length'] = f'--data-length {length}'

    def set_decoy(self, ip: str):
        self.components['decoy'] = f'-D {ip}'

    def enable_ipv6(self, enabled=True):
        self._toggle('ipv6', '-6', enabled)

    # ---------------------------
    # INTERNAL HELPER
    # ---------------------------
    def _toggle(self, key, value, enabled):
        if enabled:
            self.components[key] = value
        else:
            self.components.pop(key, None)

    # ---------------------------
    # BUILD COMMAND
    # ---------------------------
    def _ordered_components(self) -> List[str]:
        order = [
            'ipv6',
            'scan_type',
            'host_discovery',
            'port_strategy',
            'ports',
            'timing',
            'version_detection',
            'os_detection',
            'aggressive',
            'script',
            'verbosity',
            'fragment',
            'data_length',
            'decoy',
            'output'
        ]

        ordered_components = []
        for comp in order:
            val = self.components.get(comp)
            if val:
                ordered_components.append(val)

        return ordered_components

    def build_args(self) -> str:
        return ' '.join(self._ordered_components())

    def build_command(self) -> str:
        cmd_parts = ['nmap']
        cmd_parts.extend(self._ordered_components())
        cmd_parts.append(self.target)

        return ' '.join(cmd_parts)

    def get_components(self) -> Dict:
        return self.components.copy()


# =========================================================
# 🔍 ADVANCED COMMAND PARSER
# =========================================================

class CommandParser:
    """Parses Nmap commands back to configuration"""

    def parse_nmap_command(self, command: str) -> Dict:
        config = {
            'scan_type': None,
            'host_discovery': None,
            'version_detection': False,
            'os_detection': False,
            'aggressive': False,
            'ports': None,
            'script': None,
            'target': None,
            'timing': None,
            'port_strategy': None,
            'verbosity': None,
            'fragment': False,
            'ipv6': False,
        }

        try:
            tokens = shlex.split(command)
        except ValueError:
            tokens = command.split()

        if not tokens or tokens[0] != 'nmap':
            return config

        option_tokens = {'nmap'}
        option_tokens.update(NmapCommandBuilder.SCAN_TYPES.values())
        option_tokens.update(filter(None, NmapCommandBuilder.HOST_DISCOVERY.values()))
        option_tokens.update(filter(None, NmapCommandBuilder.TIMING_TEMPLATES.values()))
        option_tokens.update(filter(None, NmapCommandBuilder.PORT_STRATEGY.values()))
        option_tokens.update(filter(None, NmapCommandBuilder.VERBOSITY.values()))
        option_tokens.update(['-sV', '-O', '-A', '-f', '-6'])

        value_flags = {'-p', '--top-ports', '--script', '-oN', '-oX', '-oG', '-oA', '--data-length', '-D'}
        idx = 1
        while idx < len(tokens):
            token = tokens[idx]
            if token in value_flags:
                idx += 2
                continue
            if token.startswith('-') or token in option_tokens:
                idx += 1
                continue
            config['target'] = token
            idx += 1

        # Scan Types
        for name, flag in NmapCommandBuilder.SCAN_TYPES.items():
            if flag in command:
                config['scan_type'] = name

        # Host Discovery
        if '-Pn' in command:
            config['host_discovery'] = 'Skip Ping'
        elif '-sn' in command:
            config['host_discovery'] = 'Ping Scan Only'
        elif '-PS' in command:
            config['host_discovery'] = 'TCP SYN'
        elif '-PA' in command:
            config['host_discovery'] = 'TCP ACK'

        # Flags
        config['version_detection'] = '-sV' in command
        config['os_detection'] = '-O' in command
        config['aggressive'] = '-A' in command
        config['fragment'] = '-f' in command
        config['ipv6'] = '-6' in command

        # Timing
        for name, flag in NmapCommandBuilder.TIMING_TEMPLATES.items():
            if flag in command:
                config['timing'] = name

        # Port Strategy
        if '-F' in command:
            config['port_strategy'] = 'Fast Scan'
        else:
            top_ports_match = re.search(r'--top-ports\s+(\d+)', command)
            if top_ports_match:
                top_ports = top_ports_match.group(1)
                if top_ports == '100':
                    config['port_strategy'] = 'Top 100'
                elif top_ports == '1000':
                    config['port_strategy'] = 'Top 1000'
                else:
                    config['port_strategy'] = f'Top {top_ports}'

        if '-v' in tokens:
            config['verbosity'] = 'Verbose'
        elif '-vv' in tokens:
            config['verbosity'] = 'Very Verbose'
        elif '-d' in tokens:
            config['verbosity'] = 'Debug'
        else:
            config['verbosity'] = 'Normal'

        # Ports
        port_match = re.search(r'-p\s+([^\s]+)', command)
        if port_match:
            config['ports'] = port_match.group(1)

        # Script
        script_match = re.search(r'--script\s+([^\s]+)', command)
        if script_match:
            config['script'] = script_match.group(1)

        return config

    def is_valid_nmap_command(self, command: str) -> bool:
        if not command.strip().startswith('nmap'):
            return False

        target_pattern = r'[0-9]{1,3}(\.[0-9]{1,3}){3}|[a-zA-Z0-9.-]+'
        return bool(re.search(target_pattern, command))

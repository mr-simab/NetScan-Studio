import socket
import re
from typing import Tuple, List

class ValidationHelper:
    """Helper functions for input validation"""
    
    @staticmethod
    def is_valid_ip(ip: str) -> bool:
        """Validate IP address format"""
        pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        if not re.match(pattern, ip):
            return False
        
        parts = ip.split('.')
        for part in parts:
            num = int(part)
            if num < 0 or num > 255:
                return False
        return True
    
    @staticmethod
    def is_valid_hostname(hostname: str) -> bool:
        """Validate hostname format"""
        if len(hostname) > 253:
            return False
        
        pattern = r'^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9]{1,63})*$'
        return re.match(pattern, hostname) is not None
    
    @staticmethod
    def is_valid_port(port: int) -> bool:
        """Validate port number"""
        return 0 <= port <= 65535
    
    @staticmethod
    def is_valid_port_range(start_port: int, end_port: int) -> bool:
        """Validate port range"""
        return (ValidationHelper.is_valid_port(start_port) and 
                ValidationHelper.is_valid_port(end_port) and 
                start_port <= end_port)
    
    @staticmethod
    def resolve_target(target: str) -> Tuple[bool, str]:
        """Resolve target (IP or hostname) to IP"""
        try:
            # Already an IP?
            if ValidationHelper.is_valid_ip(target):
                return True, target
            
            # Try DNS resolution
            ip = socket.gethostbyname(target)
            return True, ip
        except socket.gaierror:
            return False, f"Failed to resolve {target}"
        except Exception as e:
            return False, str(e)

class CommandHelper:
    """Helper functions for command building"""
    
    @staticmethod
    def sanitize_command_input(cmd: str) -> str:
        """Sanitize user command input"""
        return cmd.strip()
    
    @staticmethod
    def parse_nmap_flags(cmd: str) -> dict:
        """Parse Nmap command flags"""
        flags = {
            'scan_type': None,
            'host_discovery': None,
            'version_detection': False,
            'os_detection': False,
            'aggressive': False,
            'scripts': []
        }
        
        if '-sT' in cmd:
            flags['scan_type'] = '-sT'
        elif '-sS' in cmd:
            flags['scan_type'] = '-sS'
        elif '-sA' in cmd:
            flags['scan_type'] = '-sA'
        elif '-sU' in cmd:
            flags['scan_type'] = '-sU'
        
        if '-Pn' in cmd:
            flags['host_discovery'] = '-Pn'
        elif '-sn' in cmd:
            flags['host_discovery'] = '-sn'
        
        if '-sV' in cmd:
            flags['version_detection'] = True
        
        if '-O' in cmd:
            flags['os_detection'] = True
        
        if '-A' in cmd:
            flags['aggressive'] = True
        
        # Extract scripts
        import re
        script_match = re.search(r'--script\s+([^\s]+)', cmd)
        if script_match:
            flags['scripts'] = [script_match.group(1)]
        
        return flags

class PortHelper:
    """Helper functions for port operations"""
    
    COMMON_PORTS = {
        21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
        80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS',
        3306: 'MySQL', 3389: 'RDP', 5900: 'VNC', 8080: 'HTTP-Alt',
        8443: 'HTTPS-Alt', 5432: 'PostgreSQL', 27017: 'MongoDB'
    }
    
    @staticmethod
    def get_service_name(port: int) -> str:
        """Get service name for port"""
        return PortHelper.COMMON_PORTS.get(port, 'Unknown')
    
    @staticmethod
    def parse_port_range(port_input: str) -> List[int]:
        """Parse port range string (e.g., '22,80,443' or '1-1024')"""
        ports = []
        
        for part in port_input.split(','):
            part = part.strip()
            if '-' in part:
                start, end = part.split('-')
                ports.extend(range(int(start.strip()), int(end.strip()) + 1))
            else:
                ports.append(int(part))
        
        return sorted(list(set(ports)))

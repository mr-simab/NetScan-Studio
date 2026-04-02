import platform
import subprocess
import sys
import shutil
from typing import Dict, Tuple, Optional
from utils.logger import get_logger

logger = get_logger("DependencyManager")


class DependencyManager:
    """Enhanced dependency manager for NetScan Studio"""

    COMMON_NMAP_PATHS = (
        r"C:\Program Files\Nmap\nmap.exe",
        r"C:\Program Files (x86)\Nmap\nmap.exe",
        "/usr/bin/nmap",
        "/usr/local/bin/nmap",
        "/opt/local/bin/nmap",
        "/opt/homebrew/bin/nmap",
    )

    def __init__(self):
        self.os_name = platform.system()

        self.dependencies = {
            'nmap': {
                'check': self._check_nmap,
                'critical': True
            },
            'scapy': {
                'check': self._check_scapy,
                'critical': False
            },
            'pyqt5': {
                'check': self._check_pyqt5,
                'critical': True
            }
        }

        self.missing_deps = []
        self.installed_versions = {}

    def get_os(self) -> str:
        return self.os_name

    def check_all_dependencies(self) -> Dict[str, bool]:
        """Check all dependencies with version tracking"""
        results = {}

        for name, meta in self.dependencies.items():
            try:
                status, version = meta['check']()
                results[name] = status

                if version:
                    self.installed_versions[name] = version

                logger.info(f"{name}: {'[OK]' if status else '[FAIL]'} {version or ''}")

            except Exception as e:
                results[name] = False
                logger.error(f"{name} check failed: {e}")

        self.missing_deps = [k for k, v in results.items() if not v]
        return results

    # ------------------ CHECKERS ------------------ #

    @classmethod
    def find_nmap_path(cls) -> Optional[str]:
        """Locate the Nmap executable from PATH or common install locations."""
        import os

        path = shutil.which("nmap")
        if path:
            return path

        for nmap_path in cls.COMMON_NMAP_PATHS:
            if os.path.exists(nmap_path):
                return nmap_path

        return None

    def _check_nmap(self) -> Tuple[bool, Optional[str]]:
        """Check Nmap installation + version"""
        path = self.find_nmap_path()
        if not path:
            return False, None

        try:
            result = subprocess.check_output(
                [path, "--version"],
                stderr=subprocess.DEVNULL,
                text=True
            )
            version_line = result.split("\n")[0]
            return True, version_line
        except Exception:
            return False, None

    def _check_scapy(self) -> Tuple[bool, Optional[str]]:
        """Check Scapy"""
        try:
            import scapy
            return True, getattr(scapy, "__version__", "Unknown")
        except ImportError:
            return False, None

    def _check_pyqt5(self) -> Tuple[bool, Optional[str]]:
        """Check PyQt5"""
        try:
            from PyQt5.QtCore import QT_VERSION_STR
            return True, QT_VERSION_STR
        except ImportError:
            return False, None

    # ------------------ INSTALLATION ------------------ #

    def install_python_packages(self, packages: Optional[list] = None) -> Tuple[bool, str]:
        """Install specific or all missing Python packages"""
        try:
            if not packages:
                packages = [dep for dep in self.missing_deps if dep != "nmap"]

            if not packages:
                return True, "No Python packages needed"

            logger.info(f"Installing: {packages}")

            subprocess.check_call(
                [sys.executable, "-m", "pip", "install", *packages],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )

            return True, f"Installed: {packages}"

        except subprocess.CalledProcessError as e:
            logger.error(f"Installation failed: {e}")
            return False, f"Installation failed: {e}"

    # ------------------ GUIDES ------------------ #

    def get_installation_guide(self) -> str:
        """Get OS-specific Nmap installation guide"""
        guides = {
            "Windows": (
                "1. Download Nmap: https://nmap.org/download.html\n"
                "2. Install it\n"
                "3. If Windows asks, also install Npcap\n"
                "4. Add Nmap to PATH\n"
                "5. Restart the app"
            ),
            "Linux": (
                "Ubuntu/Debian/Kali: sudo apt install nmap\n"
                "RedHat: sudo yum install nmap\n"
                "Fedora: sudo dnf install nmap\n"
                "Arch: sudo pacman -S nmap"
            ),
            "Darwin": (
                "Homebrew: brew install nmap\n"
                "or download from https://nmap.org"
            )
        }

        return guides.get(self.os_name, guides["Linux"])

    # ------------------ SUMMARY ------------------ #

    def get_missing_dependencies_summary(self) -> Dict:
        """Detailed summary"""
        critical_missing = [
            dep for dep in self.missing_deps
            if self.dependencies[dep]['critical']
        ]

        return {
            "os": self.os_name,
            "missing": self.missing_deps,
            "critical_missing": critical_missing,
            "count": len(self.missing_deps),
            "installed_versions": self.installed_versions
        }


# ==========================================================
# SETUP HELPER
# ==========================================================

class SetupHelper:
    """Improved setup workflow"""

    def __init__(self):
        self.dep_manager = DependencyManager()
        self.logger = get_logger("SetupHelper")

    def run_initial_setup(self) -> Tuple[bool, str]:
        """Run full setup"""
        self.logger.info("Running setup check...")

        deps = self.dep_manager.check_all_dependencies()

        # Install missing Python deps only
        python_missing = [
            d for d in self.dep_manager.missing_deps if d != "nmap"
        ]

        if python_missing:
            self.logger.info("Installing missing Python dependencies...")
            success, msg = self.dep_manager.install_python_packages(python_missing)

            if success:
                deps = self.dep_manager.check_all_dependencies()
            else:
                return False, msg

        # Final validation
        summary = self.dep_manager.get_missing_dependencies_summary()

        if summary["critical_missing"]:
            return False, f"Critical dependencies missing: {summary['critical_missing']}"

        return True, "Setup completed successfully"

    def get_setup_status(self) -> Dict:
        """Get full system status"""
        deps = self.dep_manager.check_all_dependencies()

        return {
            "os": self.dep_manager.get_os(),
            "dependencies": deps,
            "versions": self.dep_manager.installed_versions,
            "all_satisfied": len(self.dep_manager.missing_deps) == 0,
            "missing": self.dep_manager.missing_deps
        }

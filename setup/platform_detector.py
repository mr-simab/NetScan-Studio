import platform
import os
import socket
from functools import lru_cache
from utils.logger import get_logger

logger = get_logger("PlatformDetector")


class PlatformDetector:
    """Enhanced platform detection & directory manager"""

    APP_NAME = "NetScan Studio"

    def __init__(self):
        self.os_name_raw = platform.system()
        self.os_name = self._normalize_os(self.os_name_raw)
        self.os_version = platform.release()
        self.architecture = platform.machine()
        self.python_version = platform.python_version()
        self.hostname = socket.gethostname()

        logger.info(f"Platform: {self.os_name} {self.os_version}")
        logger.info(f"Arch: {self.architecture} | Python: {self.python_version}")

    # ------------------ OS HELPERS ------------------ #

    def _normalize_os(self, name: str) -> str:
        if name == "Windows":
            return "Windows"
        elif name == "Darwin":
            return "macOS"
        elif name == "Linux":
            return "Linux"
        return name

    def is_windows(self) -> bool:
        return self.os_name == "Windows"

    def is_linux(self) -> bool:
        return self.os_name == "Linux"

    def is_macos(self) -> bool:
        return self.os_name == "macOS"

    def get_os_name(self) -> str:
        return self.os_name

    # ------------------ PATH HELPERS ------------------ #

    def get_home_directory(self) -> str:
        return os.path.expanduser("~")

    def _safe_mkdir(self, path: str) -> str:
        try:
            os.makedirs(path, exist_ok=True)
        except Exception as e:
            logger.error(f"Failed to create directory {path}: {e}")
        return path

    def _get_base_config_dir(self) -> str:
        """Support env override + OS-based paths"""

        # 🔥 ENV override (pro feature)
        env_path = os.getenv("NETSCAN_CONFIG_DIR")
        if env_path:
            return env_path

        home = self.get_home_directory()

        if self.is_windows():
            return os.path.join(home, "AppData", "Local", self.APP_NAME)
        elif self.is_macos():
            return os.path.join(home, "Library", "Application Support", self.APP_NAME)
        else:
            return os.path.join(home, ".config", "netscan-studio")

    # ------------------ DIRECTORIES (CACHED) ------------------ #

    @lru_cache(maxsize=None)
    def get_config_directory(self) -> str:
        return self._safe_mkdir(self._get_base_config_dir())

    @lru_cache(maxsize=None)
    def get_data_directory(self) -> str:
        return self._safe_mkdir(os.path.join(self.get_config_directory(), "data"))

    @lru_cache(maxsize=None)
    def get_logs_directory(self) -> str:
        return self._safe_mkdir(os.path.join(self.get_config_directory(), "logs"))

    @lru_cache(maxsize=None)
    def get_reports_directory(self) -> str:
        return self._safe_mkdir(os.path.join(self.get_config_directory(), "reports"))

    @lru_cache(maxsize=None)
    def get_temp_directory(self) -> str:
        return self._safe_mkdir(os.path.join(self.get_config_directory(), "temp"))

    # ------------------ SYSTEM INFO ------------------ #

    def get_platform_info(self) -> dict:
        return {
            "os_name": self.os_name,
            "os_version": self.os_version,
            "architecture": self.architecture,
            "python_version": self.python_version,
            "hostname": self.hostname,
            "home_directory": self.get_home_directory(),
            "config_directory": self.get_config_directory(),
            "data_directory": self.get_data_directory(),
            "logs_directory": self.get_logs_directory(),
            "reports_directory": self.get_reports_directory(),
            "temp_directory": self.get_temp_directory(),
        }


# Global instance (singleton-style)
platform_detector = PlatformDetector()
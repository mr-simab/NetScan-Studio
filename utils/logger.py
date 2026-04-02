import logging
import os
import platform
import sys
import tempfile
from datetime import datetime


def _default_log_dir() -> str:
    env_override = os.getenv("NETSCAN_LOG_DIR")
    if env_override:
        return env_override

    config_override = os.getenv("NETSCAN_CONFIG_DIR")
    if config_override:
        return os.path.join(config_override, "logs")

    home = os.path.expanduser("~")
    system = platform.system()

    if system == "Windows":
        return os.path.join(home, "AppData", "Local", "NetScan Studio", "logs")
    if system == "Darwin":
        return os.path.join(home, "Library", "Application Support", "NetScan Studio", "logs")

    state_home = os.getenv("XDG_STATE_HOME") or os.path.join(home, ".local", "state")
    return os.path.join(state_home, "netscan-studio", "logs")


class Logger:
    """Centralized logging system for NetScan Studio."""

    def __init__(self, log_dir=None):
        self.log_dir = log_dir or _default_log_dir()
        self.setup_logging()

    def _candidate_log_dirs(self):
        candidates = [self.log_dir]
        temp_dir = os.path.join(tempfile.gettempdir(), "netscan-studio", "logs")
        if temp_dir not in candidates:
            candidates.append(temp_dir)
        return candidates

    def _build_file_handler(self, formatter):
        log_name = f"netscan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"

        for directory in self._candidate_log_dirs():
            try:
                os.makedirs(directory, exist_ok=True)
                handler = logging.FileHandler(
                    os.path.join(directory, log_name),
                    encoding="utf-8",
                )
                handler.setLevel(logging.DEBUG)
                handler.setFormatter(formatter)
                self.log_dir = directory
                return handler
            except OSError:
                continue

        return None

    def setup_logging(self):
        """Configure logging with file logging when possible and console logging always."""
        root_logger = logging.getLogger()
        if getattr(root_logger, "_netscan_configured", False):
            self.logger = logging.getLogger("NetScan Studio")
            return

        if hasattr(sys.stdout, "reconfigure"):
            try:
                sys.stdout.reconfigure(encoding="utf-8", errors="replace")
            except Exception:
                pass

        formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
        root_logger.setLevel(logging.DEBUG)

        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging.DEBUG)
        console_handler.setFormatter(formatter)
        root_logger.addHandler(console_handler)

        file_handler = self._build_file_handler(formatter)
        if file_handler is not None:
            root_logger.addHandler(file_handler)
        else:
            root_logger.warning("File logging is disabled because no writable log directory was found.")

        root_logger._netscan_configured = True
        self.logger = logging.getLogger("NetScan Studio")

    def get_logger(self, name):
        """Get logger instance for a module."""
        return logging.getLogger(name)

    def info(self, message):
        self.logger.info(message)

    def error(self, message):
        self.logger.error(message)

    def warning(self, message):
        self.logger.warning(message)

    def debug(self, message):
        self.logger.debug(message)


_logger = Logger()
get_logger = _logger.get_logger

import json
import os
from typing import Dict, Any, Optional
from utils.logger import get_logger
from setup import platform_detector

logger = get_logger("ConfigManager")


class ConfigManager:
    """Advanced configuration manager"""

    CONFIG_VERSION = "1.0"

    DEFAULT_CONFIG = {
        'meta': {
            'version': CONFIG_VERSION
        },

        'appearance': {
            'theme': 'dark',
            'accent': 'cyan',
            'window_geometry': {'width': 1200, 'height': 800},
        },

        'scanning': {
            'socket_timeout': 0.5,
            'max_threads': 200,
            'default_ports': '1-1024',
        },

        'nmap': {
            'default_args': '-sS -sV',
            'timeout': 300,
        },

        'presets': {   # 🔥 NEW (for Quick/Standard/Deep profiles)
            'Quick': {
                'tool': 'socket',
                'ports': '1-1024'
            },
            'Standard': {
                'tool': 'nmap',
                'args': '-sS -sV'
            },
            'Deep': {
                'tool': 'hybrid',
                'args': '-A -T4'
            }
        },

        'general': {
            'auto_check_updates': True,
            'save_reports': True,
            'log_level': 'INFO',
        }
    }

    # =========================================================
    # INIT
    # =========================================================

    def __init__(self):
        self.config_dir = platform_detector.get_config_directory()
        self.config_file = os.path.join(self.config_dir, 'config.json')

        self._ensure_directory()

        self.config = {}
        self.load_config()

    # =========================================================
    # DIRECTORY SETUP
    # =========================================================

    def _ensure_directory(self):
        try:
            os.makedirs(self.config_dir, exist_ok=True)
        except Exception as e:
            logger.error(f"Failed to create config directory: {e}")

    # =========================================================
    # LOAD
    # =========================================================

    def load_config(self):
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r') as f:
                    user_config = json.load(f)

                # Deep merge 🔥
                self.config = self._deep_merge(self.DEFAULT_CONFIG, user_config)

                # Version check
                if self.config.get('meta', {}).get('version') != self.CONFIG_VERSION:
                    logger.info("Config version mismatch → updating")
                    self.config['meta']['version'] = self.CONFIG_VERSION
                    self.save_config()

                logger.info("Configuration loaded")

            else:
                self.config = self.DEFAULT_CONFIG.copy()
                self.save_config()

        except Exception as e:
            logger.warning(f"Config load failed: {e}")
            self.config = self.DEFAULT_CONFIG.copy()

    # =========================================================
    # SAVE
    # =========================================================

    def save_config(self) -> bool:
        try:
            with open(self.config_file, 'w') as f:
                json.dump(self.config, f, indent=2)

            logger.info("Configuration saved")
            return True

        except Exception as e:
            logger.error(f"Save failed: {e}")
            return False

    # =========================================================
    # GET / SET
    # =========================================================

    def get(self, section: str, key: Optional[str] = None) -> Any:
        try:
            if key is None:
                return self.config.get(section, {})
            return self.config.get(section, {}).get(key)
        except Exception:
            return None

    def set(self, section: str, key: str, value: Any):
        if section not in self.config:
            self.config[section] = {}

        self.config[section][key] = value
        logger.debug(f"{section}.{key} updated")

    def get_all(self) -> Dict:
        return self.config.copy()

    # =========================================================
    # PRESETS 🔥 (VERY IMPORTANT FOR YOUR UI)
    # =========================================================

    def get_preset(self, mode: str) -> Dict:
        return self.config.get('presets', {}).get(mode, {})

    def update_preset(self, mode: str, data: Dict):
        if 'presets' not in self.config:
            self.config['presets'] = {}

        self.config['presets'][mode] = data
        logger.info(f"Preset updated: {mode}")

    # =========================================================
    # RESET
    # =========================================================

    def reset_to_defaults(self):
        self.config = self.DEFAULT_CONFIG.copy()
        self.save_config()
        logger.info("Reset to default config")

    # =========================================================
    # VALIDATION 🔥
    # =========================================================

    def validate(self) -> bool:
        try:
            # Basic validation rules
            assert 'appearance' in self.config
            assert 'scanning' in self.config
            assert 'general' in self.config

            return True

        except Exception as e:
            logger.error(f"Config validation failed: {e}")
            return False

    # =========================================================
    # DEEP MERGE (CRITICAL FIX)
    # =========================================================

    def _deep_merge(self, default: Dict, custom: Dict) -> Dict:
        result = default.copy()

        for key, value in custom.items():
            if key in result and isinstance(result[key], dict):
                result[key] = self._deep_merge(result[key], value)
            else:
                result[key] = value

        return result
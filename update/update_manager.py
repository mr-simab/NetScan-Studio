import requests
import webbrowser
from typing import Tuple, Dict, Optional
from utils import VERSION, GITHUB_API_URL, GITHUB_REPO
from utils.logger import get_logger

logger = get_logger("UpdateManager")

class UpdateManager:
    """Manages application updates from GitHub"""
    
    def __init__(self):
        self.current_version = VERSION
        self.latest_version = None
        self.release_info = None
    
    def check_for_updates(self) -> Tuple[bool, str, Optional[Dict]]:
        """Check GitHub for latest release"""
        try:
            logger.info("Checking for updates...")
            response = requests.get(GITHUB_API_URL, timeout=5)
            response.raise_for_status()
            
            data = response.json()
            self.latest_version = data.get('tag_name', '').lstrip('v')
            
            # Store release info
            self.release_info = {
                'version': self.latest_version,
                'name': data.get('name', 'Unknown'),
                'body': data.get('body', ''),
                'html_url': data.get('html_url', GITHUB_REPO),
                'download_url': data.get('zipball_url', ''),
            }
            
            update_available = self._compare_versions(
                self.current_version,
                self.latest_version
            )
            
            if update_available:
                logger.info(f"Update available: {self.latest_version}")
                return True, f"Update available: v{self.latest_version}", self.release_info
            else:
                logger.info("Already on latest version")
                return False, f"Already on latest version (v{self.current_version})", None
        
        except requests.RequestException as e:
            logger.warning(f"Failed to check for updates: {e}")
            return False, f"Failed to check for updates: {e}", None
        except Exception as e:
            logger.error(f"Update check error: {e}")
            return False, f"Error checking updates: {e}", None
    
    def _compare_versions(self, current: str, latest: str) -> bool:
        """Compare version numbers"""
        try:
            # Simple version comparison (X.Y.Z format)
            current_parts = [int(x) for x in current.split('.')]
            latest_parts = [int(x) for x in latest.split('.')]
            
            return latest_parts > current_parts
        except:
            return False
    
    def open_release_page(self):
        """Open GitHub release page in browser"""
        if self.release_info:
            url = self.release_info['html_url']
        else:
            url = f"{GITHUB_REPO}/releases"
        
        try:
            webbrowser.open(url)
            logger.info(f"Opened release page: {url}")
            return True
        except Exception as e:
            logger.error(f"Failed to open browser: {e}")
            return False
    
    def get_changelog(self) -> str:
        """Get changelog from latest release"""
        if self.release_info:
            return self.release_info.get('body', 'No changelog available')
        return "No release information available"
    
    def get_current_version(self) -> str:
        """Get current version"""
        return self.current_version
    
    def get_latest_version(self) -> Optional[str]:
        """Get latest version from GitHub"""
        return self.latest_version
    
    def get_update_info(self) -> Dict:
        """Get complete update information"""
        return {
            'current_version': self.current_version,
            'latest_version': self.latest_version,
            'update_available': self._compare_versions(
                self.current_version,
                self.latest_version or self.current_version
            ),
            'release_info': self.release_info,
        }

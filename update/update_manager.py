import os
import re
import shutil
import subprocess
import sys
import textwrap
import webbrowser
import zipfile
from typing import Any, Dict, List, Optional, Tuple

import requests

from setup import platform_detector
from utils import GITHUB_API_URL, GITHUB_REPO, VERSION
from utils.logger import get_logger

logger = get_logger("UpdateManager")


class UpdateManager:
    """Manages release discovery and staged zip updates."""

    UNIVERSAL_KEYWORDS = {"universal", "portable", "generic", "all"}
    APP_MARKERS = (
        "main.py",
        os.path.join("ui", "main_window.py"),
        os.path.join("utils", "version.py"),
    )
    SKIP_COPY_DIRS = {".git", "__pycache__", "logs"}

    def __init__(self):
        self.current_version = VERSION
        self.latest_version = None
        self.release_info = None
        self.prepared_update = None
        self.app_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    def check_for_updates(self) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
        """Check GitHub for the latest release and choose the uploaded zip package."""
        try:
            logger.info("Checking for updates...")
            response = requests.get(GITHUB_API_URL, timeout=5)
            response.raise_for_status()

            data = response.json()
            self.latest_version = data.get("tag_name", "").lstrip("v")
            assets = data.get("assets", []) or []
            selected_asset = self.select_release_asset(assets)

            download_url = ""
            if selected_asset:
                download_url = selected_asset.get("browser_download_url", "")
            elif data.get("zipball_url"):
                download_url = data.get("zipball_url", "")

            self.release_info = {
                "version": self.latest_version,
                "name": data.get("name", "Unknown"),
                "body": data.get("body", ""),
                "html_url": data.get("html_url", f"{GITHUB_REPO}/releases"),
                "zipball_url": data.get("zipball_url", ""),
                "download_url": download_url,
                "assets": assets,
                "selected_asset": selected_asset,
            }

            update_available = self._compare_versions(self.current_version, self.latest_version)
            if not update_available:
                logger.info("Already on latest version")
                return False, f"Already on latest version (v{self.current_version})", None

            if selected_asset:
                message = (
                    f"Update available: v{self.latest_version}\n"
                    f"Release package: {selected_asset.get('name', 'Unknown package')}"
                )
            else:
                message = (
                    f"Update available: v{self.latest_version}\n"
                    "No uploaded release zip was found, so the GitHub source archive will be used as fallback."
                )

            logger.info(message.replace("\n", " | "))
            return True, message, self.release_info

        except requests.RequestException as exc:
            logger.warning(f"Failed to check for updates: {exc}")
            return False, f"Failed to check for updates: {exc}", None
        except Exception as exc:
            logger.error(f"Update check error: {exc}")
            return False, f"Error checking updates: {exc}", None

    def prepare_update(self) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
        """Download the selected release zip and stage it for installation."""
        if not self.release_info:
            return False, "No release information is available. Check for updates first.", None

        package = self.release_info.get("selected_asset")
        if not package and self.release_info.get("zipball_url"):
            package = {
                "name": f"netscan-studio-source-v{self.release_info.get('version', 'latest')}.zip",
                "browser_download_url": self.release_info["zipball_url"],
                "source_archive": True,
            }

        if not package:
            return False, "No downloadable zip package was found for this release.", None

        try:
            version = self.release_info.get("version") or "latest"
            staging_dir = os.path.join(
                platform_detector.get_temp_directory(),
                "updates",
                f"v{version}",
            )
            os.makedirs(staging_dir, exist_ok=True)

            archive_name = package.get("name") or f"netscan-studio-v{version}.zip"
            archive_path = os.path.join(staging_dir, archive_name)
            extracted_dir = os.path.join(staging_dir, "extracted")

            if os.path.isdir(extracted_dir):
                shutil.rmtree(extracted_dir, ignore_errors=True)
            os.makedirs(extracted_dir, exist_ok=True)

            self._download_file(package.get("browser_download_url", ""), archive_path)
            self._safe_extract_zip(archive_path, extracted_dir)
            package_root = self._find_package_root(extracted_dir)
            install_ready, install_note = self._can_install_in_place(package_root)

            self.prepared_update = {
                "version": version,
                "asset": package,
                "archive_path": archive_path,
                "staging_dir": staging_dir,
                "extracted_dir": extracted_dir,
                "package_root": package_root,
                "install_ready": install_ready,
                "install_note": install_note,
                "target_dir": self.app_root,
            }

            logger.info(f"Prepared update package: {archive_name} -> {package_root}")
            return True, f"Update package prepared: {archive_name}", self.prepared_update

        except requests.RequestException as exc:
            logger.error(f"Update download failed: {exc}")
            return False, f"Failed to download the update package: {exc}", None
        except zipfile.BadZipFile:
            logger.error("Downloaded update package is not a valid zip archive")
            return False, "The downloaded update package is not a valid zip archive.", None
        except Exception as exc:
            logger.error(f"Failed to prepare update: {exc}")
            return False, f"Failed to prepare the update package: {exc}", None

    def start_prepared_update(self) -> Tuple[bool, str]:
        """Launch the background updater for a prepared package."""
        if not self.prepared_update:
            return False, "No prepared update is available."

        if not self.prepared_update.get("install_ready"):
            return False, self.prepared_update.get(
                "install_note",
                "The prepared update cannot be installed automatically.",
            )

        try:
            script_path = self._write_updater_script(self.prepared_update)
            command = [
                sys.executable,
                script_path,
                "--source",
                self.prepared_update["package_root"],
                "--target",
                self.prepared_update["target_dir"],
                "--wait-pid",
                str(os.getpid()),
            ]

            popen_kwargs = {
                "cwd": self.prepared_update["staging_dir"],
                "stdout": subprocess.DEVNULL,
                "stderr": subprocess.DEVNULL,
                "close_fds": True,
            }

            if platform_detector.is_windows():
                creationflags = 0
                creationflags |= getattr(subprocess, "DETACHED_PROCESS", 0x00000008)
                creationflags |= getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0x00000200)
                popen_kwargs["creationflags"] = creationflags
            else:
                popen_kwargs["start_new_session"] = True

            subprocess.Popen(command, **popen_kwargs)
            logger.info(f"Started background updater from {script_path}")
            return True, "The updater has been started. NetScan Studio will close so the files can be replaced."
        except Exception as exc:
            logger.error(f"Failed to launch updater: {exc}")
            return False, f"Failed to launch the updater: {exc}"

    def select_release_asset(
        self,
        assets: List[Dict[str, Any]],
        os_name: Optional[str] = None,
        architecture: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """Select the uploaded universal zip package for the release."""
        zip_assets = [asset for asset in assets if self._is_zip_asset(asset)]
        if not zip_assets:
            return None

        if len(zip_assets) == 1:
            return zip_assets[0]

        universal_asset = self._select_universal_zip_asset(zip_assets)
        if universal_asset:
            return universal_asset

        for asset in zip_assets:
            name = (asset.get("name") or "").lower()
            if "netscan" in name:
                return asset

        return zip_assets[0]

    def open_release_page(self):
        """Open the GitHub release page in a browser."""
        if self.release_info:
            url = self.release_info["html_url"]
        else:
            url = f"{GITHUB_REPO}/releases"

        try:
            webbrowser.open(url)
            logger.info(f"Opened release page: {url}")
            return True
        except Exception as exc:
            logger.error(f"Failed to open browser: {exc}")
            return False

    def get_changelog(self) -> str:
        if self.release_info:
            return self.release_info.get("body", "No changelog available")
        return "No release information available"

    def get_current_version(self) -> str:
        return self.current_version

    def get_latest_version(self) -> Optional[str]:
        return self.latest_version

    def get_update_info(self) -> Dict[str, Any]:
        return {
            "current_version": self.current_version,
            "latest_version": self.latest_version,
            "update_available": self._compare_versions(
                self.current_version,
                self.latest_version or self.current_version,
            ),
            "release_info": self.release_info,
            "prepared_update": self.prepared_update,
        }

    def _compare_versions(self, current: str, latest: str) -> bool:
        try:
            current_parts = [int(part) for part in current.split(".")]
            latest_parts = [int(part) for part in latest.split(".")]
            return latest_parts > current_parts
        except Exception:
            return False

    def _is_zip_asset(self, asset: Dict[str, Any]) -> bool:
        name = (asset.get("name") or "").lower()
        url = (asset.get("browser_download_url") or "").lower()
        content_type = (asset.get("content_type") or "").lower()
        return name.endswith(".zip") or url.endswith(".zip") or "zip" in content_type

    def _tokenize_name(self, name: str) -> set:
        return set(re.findall(r"[a-z0-9_]+", (name or "").lower()))

    def _select_universal_zip_asset(self, assets: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        for asset in assets:
            tokens = self._tokenize_name(asset.get("name", ""))
            if tokens & self.UNIVERSAL_KEYWORDS:
                return asset
        return None

    def _download_file(self, url: str, destination: str):
        if not url:
            raise ValueError("Missing download URL for the selected update package.")

        response = requests.get(url, timeout=30, stream=True)
        response.raise_for_status()

        with open(destination, "wb") as file_handle:
            for chunk in response.iter_content(chunk_size=1024 * 64):
                if chunk:
                    file_handle.write(chunk)

    def _safe_extract_zip(self, archive_path: str, destination: str):
        destination_root = os.path.abspath(destination)

        with zipfile.ZipFile(archive_path, "r") as archive:
            for member in archive.infolist():
                target_path = os.path.abspath(os.path.join(destination_root, member.filename))
                if not target_path.startswith(destination_root + os.sep) and target_path != destination_root:
                    raise ValueError(f"Unsafe path in zip archive: {member.filename}")

            archive.extractall(destination_root)

    def _looks_like_app_root(self, path: str) -> bool:
        return all(os.path.exists(os.path.join(path, marker)) for marker in self.APP_MARKERS)

    def _find_package_root(self, extracted_dir: str) -> str:
        if self._looks_like_app_root(extracted_dir):
            return extracted_dir

        candidates = []
        for root, dirs, _files in os.walk(extracted_dir):
            dirs[:] = [directory for directory in dirs if directory not in self.SKIP_COPY_DIRS]
            if self._looks_like_app_root(root):
                depth = root.count(os.sep)
                candidates.append((depth, root))

        if candidates:
            candidates.sort(key=lambda item: item[0])
            return candidates[0][1]

        return extracted_dir

    def _can_install_in_place(self, package_root: str) -> Tuple[bool, str]:
        if not package_root or not os.path.isdir(package_root):
            return False, "The downloaded package could not be extracted correctly."

        if not self._looks_like_app_root(package_root):
            return False, (
                "The downloaded zip was staged, but its structure did not match the portable app layout. "
                "Install it manually from the staged folder."
            )

        if os.path.isdir(os.path.join(self.app_root, ".git")):
            return False, (
                "This copy looks like a development checkout, so the updater will not overwrite it automatically. "
                "Use the staged package manually."
            )

        if not os.access(self.app_root, os.W_OK):
            return False, (
                "The app does not have permission to update the current install directory automatically. "
                "Use the staged package manually."
            )

        return True, "Ready to install."

    def _write_updater_script(self, prepared_update: Dict[str, Any]) -> str:
        script_path = os.path.join(prepared_update["staging_dir"], "apply_update.py")
        skip_copy_dirs = sorted(self.SKIP_COPY_DIRS)

        script_content = textwrap.dedent(
            f"""
            import argparse
            import os
            import shutil
            import sys
            import time

            SKIP_DIRS = {skip_copy_dirs!r}

            def process_exists(pid):
                try:
                    os.kill(pid, 0)
                except OSError:
                    return False
                except PermissionError:
                    return True
                return True

            def wait_for_pid(pid, timeout=30):
                end_time = time.time() + timeout
                while time.time() < end_time and process_exists(pid):
                    time.sleep(0.5)

            def copy_tree(source, target):
                for root, dirs, files in os.walk(source):
                    dirs[:] = [directory for directory in dirs if directory not in SKIP_DIRS]
                    relative = os.path.relpath(root, source)
                    destination_root = target if relative == "." else os.path.join(target, relative)
                    os.makedirs(destination_root, exist_ok=True)

                    for filename in files:
                        source_file = os.path.join(root, filename)
                        target_file = os.path.join(destination_root, filename)
                        shutil.copy2(source_file, target_file)

            def main():
                parser = argparse.ArgumentParser()
                parser.add_argument("--source", required=True)
                parser.add_argument("--target", required=True)
                parser.add_argument("--wait-pid", type=int, required=True)
                args = parser.parse_args()

                wait_for_pid(args.wait_pid)
                copy_tree(args.source, args.target)

            if __name__ == "__main__":
                try:
                    main()
                except Exception:
                    sys.exit(1)
            """
        ).strip() + "\n"

        with open(script_path, "w", encoding="utf-8") as file_handle:
            file_handle.write(script_content)

        return script_path

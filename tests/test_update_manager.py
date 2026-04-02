import os
import shutil
import unittest

from update import UpdateManager


class UpdateManagerTests(unittest.TestCase):
    def setUp(self):
        self.manager = UpdateManager()

    def test_select_release_asset_prefers_universal_package(self):
        assets = [
            {"name": "netscan-studio-helper.zip", "browser_download_url": "https://example.com/helper.zip"},
            {"name": "netscan-studio-universal.zip", "browser_download_url": "https://example.com/universal.zip"},
        ]

        selected = self.manager.select_release_asset(assets)

        self.assertIsNotNone(selected)
        self.assertEqual(selected["name"], "netscan-studio-universal.zip")

    def test_select_release_asset_returns_only_zip_asset(self):
        assets = [
            {"name": "netscan-studio-v1.0.1.zip", "browser_download_url": "https://example.com/release.zip"},
        ]

        selected = self.manager.select_release_asset(assets)

        self.assertIsNotNone(selected)
        self.assertEqual(selected["name"], "netscan-studio-v1.0.1.zip")

    def test_select_release_asset_falls_back_to_first_netscan_zip(self):
        assets = [
            {"name": "notes.zip", "browser_download_url": "https://example.com/notes.zip"},
            {"name": "netscan-studio-release.zip", "browser_download_url": "https://example.com/release.zip"},
        ]

        selected = self.manager.select_release_asset(assets)

        self.assertIsNotNone(selected)
        self.assertEqual(selected["name"], "netscan-studio-release.zip")

    def test_can_install_in_place_blocks_git_checkout(self):
        workspace_temp = os.path.dirname(__file__)
        package_root = os.path.join(workspace_temp, "_update_package_fixture")
        try:
            shutil.rmtree(package_root, ignore_errors=True)
            os.makedirs(package_root, exist_ok=True)
            os.makedirs(os.path.join(package_root, "ui"), exist_ok=True)
            os.makedirs(os.path.join(package_root, "utils"), exist_ok=True)

            open(os.path.join(package_root, "main.py"), "w", encoding="utf-8").close()
            open(os.path.join(package_root, "ui", "main_window.py"), "w", encoding="utf-8").close()
            open(os.path.join(package_root, "utils", "version.py"), "w", encoding="utf-8").close()

            self.manager.app_root = os.path.dirname(workspace_temp)
            install_ready, note = self.manager._can_install_in_place(package_root)
        finally:
            shutil.rmtree(package_root, ignore_errors=True)

        self.assertFalse(install_ready)
        self.assertIn("development checkout", note.lower())


if __name__ == "__main__":
    unittest.main()

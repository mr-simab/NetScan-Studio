import unittest
from unittest import mock

from command import CommandParser, NmapCommandBuilder
from core import ScannerManager
from engines.nmap_engine import NmapEngine
from engines.scapy_engine import ScapyEngine


class DummyLayer:
    def __truediv__(self, other):
        return self


class DummyResponse:
    ttl = 64
    flags = 0x12


class ScanLogicTests(unittest.TestCase):
    def test_nmap_command_builder_keeps_target_last(self):
        builder = NmapCommandBuilder("scanme.nmap.org")
        builder.set_scan_type("SYN Scan")
        builder.enable_version_detection()

        self.assertEqual(builder.build_args(), "-sS -sV")
        self.assertEqual(builder.build_command(), "nmap -sS -sV scanme.nmap.org")

    def test_command_parser_round_trips_generated_nmap_command(self):
        builder = NmapCommandBuilder("scanme.nmap.org")
        builder.set_scan_type("SYN Scan")
        builder.enable_version_detection()
        builder.set_port_strategy("Top 1000")

        parsed = CommandParser().parse_nmap_command(builder.build_command())

        self.assertEqual(parsed["target"], "scanme.nmap.org")
        self.assertEqual(parsed["scan_type"], "SYN Scan")
        self.assertTrue(parsed["version_detection"])
        self.assertEqual(parsed["port_strategy"], "Top 1000")

    def test_scanner_manager_supports_mode_aliases(self):
        manager = ScannerManager()

        config = manager.create_config(
            target="scanme.nmap.org",
            mode="advanced",
            tool="hybrid",
            scan_type="SYN Scan",
            version_detection=True,
            os_detection=True,
            aggressive=True,
            port_strategy="Top 1000",
            scapy_analysis="ttl",
        )

        self.assertEqual(config.mode.value, "Deep")
        self.assertIn("nmap", manager.generate_command_preview())

    def test_scapy_engine_ttl_analysis_returns_scan_results(self):
        engine = ScapyEngine("127.0.0.1", ports=[80], analysis_type="ttl")
        engine.scapy_available = True
        engine.IP = lambda **kwargs: DummyLayer()
        engine.TCP = lambda **kwargs: DummyLayer()
        engine.sr1 = lambda packet, timeout=2, verbose=False: DummyResponse()

        with mock.patch(
            "engines.scapy_engine.platform_detector.supports_raw_packet_scans",
            return_value=True,
        ):
            results = engine.scan()

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].port, 80)
        self.assertEqual(results[0].state, "analyzed")
        self.assertEqual(results[0].version, "TTL=64")

    def test_invalid_port_ranges_raise_clear_error(self):
        manager = ScannerManager()

        with self.assertRaisesRegex(ValueError, "Invalid port range"):
            manager._parse_ports("1-")

    def test_nmap_engine_uses_detected_executable_path(self):
        with mock.patch("engines.nmap_engine.DependencyManager.find_nmap_path", return_value=r"C:\Program Files\Nmap\nmap.exe"), \
             mock.patch("engines.nmap_engine.nmap.PortScanner") as port_scanner:
            NmapEngine("scanme.nmap.org")

        port_scanner.assert_called_once_with(
            nmap_search_path=(r"C:\Program Files\Nmap\nmap.exe",)
        )


if __name__ == "__main__":
    unittest.main()

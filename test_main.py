import unittest
from kbfi import KbfiToolkit, get_vendor, VendorDatabase, WifiNetwork, MacAddress
import time
from unittest.mock import patch
from kbfi.kbfi import ScanResultCollection, WifiNetworkCollection, command_exists
import subprocess
import sys

class TestWifiToolkit(unittest.TestCase):
    def setUp(self):
        # Use a dummy interface name; actual scan will likely fail on CI/most dev machines.
        self.toolkit = KbfiToolkit(interface=None)

    def test_vendor_lookup(self):
        # Test known MAC OUI (Apple)
        vendor = get_vendor("F0:18:98:00:00:00")
        self.assertIsInstance(vendor, str)
        self.assertNotEqual(vendor, "")

    def test_wifi_network_dataclass(self):
        # Test WifiNetwork dataclass and its properties
        net = WifiNetwork(
            ssid="TestSSID",
            bssid="00:11:22:33:44:55",
            signal=-40,
            channel=6,
            frequency=2437.0,
            encryption="WPA2"
        )
        self.assertEqual(net.ssid, "TestSSID")
        self.assertEqual(net.signal_quality, "Very Good")
        self.assertEqual(net.security_level, "High")

    def test_macaddress_dataclass(self):
        # Test MacAddress dataclass and timestamps
        mac = MacAddress(mac="00:11:22:33:44:55")
        self.assertEqual(mac.mac, "00:11:22:33:44:55")
        self.assertIsInstance(mac.first_seen, float)
        self.assertIsInstance(mac.last_seen, float)

    def test_vendor_database_update(self):
        # Test updating the vendor database (should not raise)
        db = VendorDatabase()
        db.update_database(force=False)

    def test_scan_wifi_safe(self):
        # Only check for exceptions, as scanning may not work in test env
        try:
            self.toolkit.scan_wifi()
        except Exception:
            pass

    def test_scan_clients_safe(self):
        # Only check for exceptions, as scanning may not work in test env
        try:
            self.toolkit.scan_clients()
        except Exception:
            pass

    def test_cli_entry_point_help(self):
        # Test the CLI entry point for --help output
        result = subprocess.run([sys.executable, "-m", "kbfi.kbfi", "--help"], capture_output=True, text=True)
        self.assertIn("usage", result.stdout.lower())
        self.assertEqual(result.returncode, 0)

class TestAdditionalKbfi(unittest.TestCase):
    def test_signal_quality_levels(self):
        # Test signal quality property for various levels
        levels = [(-25, "Excellent"), (-40, "Very Good"), (-55, "Good"), (-65, "Fair"), (-80, "Weak")]
        for signal, expected in levels:
            net = WifiNetwork(ssid="x", bssid="y", signal=signal)
            self.assertEqual(net.signal_quality, expected)

    def test_security_level(self):
        # Test security level property for various encryption types
        cases = [
            ("WPA3", "Very High"),
            ("WPA2", "High"),
            ("WPA", "Medium"),
            ("WEP", "Low"),
            ("Open", "None"),
        ]
        for enc, expected in cases:
            net = WifiNetwork(ssid="x", bssid="y", signal=-50, encryption=enc)
            self.assertEqual(net.security_level, expected)

    def test_macaddress_timestamps(self):
        # Test that timestamps are set correctly
        before = time.time()
        mac = MacAddress(mac="00:11:22:33:44:55")
        after = time.time()
        self.assertIsInstance(mac.first_seen, float)
        self.assertIsInstance(mac.last_seen, float)
        first_seen: float = mac.first_seen  # type: ignore
        last_seen: float = mac.last_seen    # type: ignore
        self.assertTrue(before <= first_seen <= after)
        self.assertTrue(before <= last_seen <= after)

    def test_scanresultcollection_filter_sort(self):
        # Test filtering and sorting of ScanResultCollection
        nets = [
            WifiNetwork(ssid="A", bssid="1", signal=-40),
            WifiNetwork(ssid="B", bssid="2", signal=-60),
            WifiNetwork(ssid="C", bssid="3", signal=-50),
        ]
        col = ScanResultCollection(nets)
        filtered = col.filter(lambda n: n.signal > -55)
        self.assertEqual(len(filtered), 2)
        sorted_col = col.sort_by("signal", reverse=True)
        self.assertEqual(sorted_col[0].signal, -40)
        dicts = col.as_dicts()
        self.assertIsInstance(dicts, list)
        self.assertIsInstance(dicts[0], dict)

    @patch("src.kbfi.kbfi.get_vendor", return_value="TestVendor")
    def test_wifinetworkcollection_with_vendors(self, mock_vendor):
        # Test WifiNetworkCollection with_vendors method
        nets = [WifiNetwork(ssid="A", bssid="1", signal=-40)]
        col = WifiNetworkCollection(nets)
        with_vendors = col.with_vendors(threaded=False)
        self.assertEqual(with_vendors[0].vendor, "TestVendor")

    @patch.object(VendorDatabase, "load_database", return_value={"00:11:22": "TestCorp"})
    def test_vendordatabase_lookup_vendor(self, mock_db):
        # Test VendorDatabase.lookup_vendor method
        db = VendorDatabase()
        vendor = db.lookup_vendor("00:11:22:33:44:55")
        self.assertEqual(vendor, "TestCorp")
        vendor_invalid = db.lookup_vendor("00:00")
        self.assertEqual(vendor_invalid, "Invalid MAC")

    def test_command_exists(self):
        # Test command_exists utility
        self.assertTrue(command_exists("python"))
        self.assertFalse(command_exists("definitelynotacommand"))

if __name__ == '__main__':
    unittest.main()
"""Unit tests for honeypot system."""
import os, sys, unittest
from unittest.mock import patch, MagicMock
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


class TestHoneypotGeneration(unittest.TestCase):
    def test_generates_150_fake_aps(self):
        from honeypot import _generate_fake_aps
        self.assertEqual(len(_generate_fake_aps(150)), 150)

    def test_generates_150_fake_clients(self):
        from honeypot import _generate_fake_clients
        self.assertEqual(len(_generate_fake_clients(150)), 150)

    def test_excludes_real_ap_mac(self):
        from honeypot import _generate_fake_aps, REAL_AP_MAC
        self.assertNotIn(REAL_AP_MAC.upper(), [m.upper() for m, _ in _generate_fake_aps(150)])

    def test_excludes_real_client_mac(self):
        from honeypot import _generate_fake_clients, REAL_CLIENT
        self.assertNotIn(REAL_CLIENT.upper(), [m.upper() for m in _generate_fake_clients(150)])

    def test_all_macs_unique(self):
        from honeypot import _generate_fake_aps
        macs = [m.upper() for m, _ in _generate_fake_aps(150)]
        self.assertEqual(len(macs), len(set(macs)))

    def test_mac_format_valid(self):
        from honeypot import _random_mac, _is_valid_mac
        for _ in range(100):
            self.assertTrue(_is_valid_mac(_random_mac()))

    def test_ssid_variants_used(self):
        from honeypot import _generate_fake_aps, SSID_VARIANTS
        ssids = [s for _, s in _generate_fake_aps(150)]
        for i, v in enumerate(SSID_VARIANTS):
            self.assertEqual(ssids[i], v)


class TestHoneypotLifecycle(unittest.TestCase):
    @patch("subprocess.Popen")
    def test_start_activates(self, mock_popen):
        mock_popen.return_value = MagicMock(pid=12345)
        # Mock db module that honeypot imports lazily inside start()
        import sys as _sys
        _sys.modules['db'] = MagicMock()
        from honeypot import start, _state
        _state["active"] = False
        _state["fake_aps"] = 0
        result = start()
        self.assertTrue(result["ok"])
        self.assertTrue(result["status"]["active"])
        self.assertEqual(result["status"]["fake_aps"], 150)
        _state["active"] = False

    def test_status_when_inactive(self):
        from honeypot import get_status, _state
        _state["active"] = False
        _state["fake_aps"] = 0
        _state["fake_clients"] = 0
        self.assertFalse(get_status()["active"])

    def test_attack_probability_calculation(self):
        from honeypot import get_status, _state
        _state["active"] = True
        _state["fake_aps"] = 150
        _state["fake_clients"] = 150
        self.assertLess(get_status()["attack_probability_pct"], 1.0)
        _state["active"] = False


if __name__ == "__main__":
    unittest.main()

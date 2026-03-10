"""Unit tests for all 16 defense components across 4 levels."""
import os, sys, unittest
from unittest.mock import patch, MagicMock
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

class TestLevel1Components(unittest.TestCase):
    @patch("subprocess.run")
    def test_1a_okc(self, m):
        m.return_value = MagicMock(returncode=0, stdout="")
        from components import Component1A
        r = Component1A().apply({"attacker_mac": "AA:BB:CC:DD:EE:FF", "victim_mac": "11:22:33:44:55:66", "confidence": 50})
        self.assertTrue(r["ok"])
        self.assertIn("L1A", r["detail"])

    @patch("subprocess.run")
    def test_1b_probe(self, m):
        m.return_value = MagicMock(returncode=0, stdout="")
        from components import Component1B
        r = Component1B().apply({"attacker_mac": "AA:BB:CC:DD:EE:FF", "victim_mac": "11:22:33:44:55:66", "confidence": 50})
        self.assertTrue(r["ok"])
        self.assertIn("L1B", r["detail"])

    @patch("subprocess.run")
    def test_1c_channel(self, m):
        m.return_value = MagicMock(returncode=0, stdout="Channel 11")
        from components import Component1C
        r = Component1C().apply({"attacker_mac": "AA:BB:CC:DD:EE:FF", "victim_mac": "11:22:33:44:55:66", "confidence": 50})
        self.assertTrue(r["ok"])
        self.assertIn("L1C", r["detail"])

    @patch("subprocess.run")
    def test_1d_preauth(self, m):
        m.return_value = MagicMock(returncode=0, stdout="")
        from components import Component1D
        r = Component1D().apply({"attacker_mac": "AA:BB:CC:DD:EE:FF", "victim_mac": "11:22:33:44:55:66", "confidence": 80})
        self.assertTrue(r["ok"])
        self.assertIn("L1D", r["detail"])

    @patch("subprocess.run")
    def test_get_all_returns_4(self, m):
        from components import get_all_components
        self.assertEqual(len(get_all_components()), 4)


class TestLevel2Components(unittest.TestCase):
    @patch("subprocess.run")
    def test_2a_tcp(self, m):
        m.return_value = MagicMock(returncode=0, stdout="")
        from level2_components import Component2A
        r = Component2A().apply({"attacker_mac": "AA:BB:CC:DD:EE:FF", "victim_mac": "11:22:33:44:55:66", "confidence": 65})
        self.assertTrue(r["ok"])
        self.assertIn("L2A", r["detail"])

    @patch("subprocess.run")
    def test_2b_mptcp(self, m):
        m.return_value = MagicMock(returncode=0, stdout="")
        from level2_components import Component2B
        r = Component2B().apply({"attacker_mac": "AA:BB:CC:DD:EE:FF", "victim_mac": "11:22:33:44:55:66", "confidence": 65})
        self.assertTrue(r["ok"])
        self.assertIn("L2B", r["detail"])

    @patch("subprocess.run")
    def test_2c_buffers(self, m):
        m.return_value = MagicMock(returncode=0, stdout="")
        from level2_components import Component2C
        r = Component2C().apply({"attacker_mac": "AA:BB:CC:DD:EE:FF", "victim_mac": "11:22:33:44:55:66", "confidence": 65})
        self.assertTrue(r["ok"])
        self.assertIn("L2C", r["detail"])

    def test_2d_download(self):
        from level2_components import Component2D
        r = Component2D().apply({"attacker_mac": "AA:BB:CC:DD:EE:FF", "victim_mac": "11:22:33:44:55:66", "confidence": 65})
        self.assertTrue(r["ok"])
        self.assertIn("L2D", r["detail"])

    @patch("subprocess.run")
    def test_get_all_returns_4(self, m):
        from level2_components import get_l2_components
        self.assertEqual(len(get_l2_components()), 4)

    def test_threshold(self):
        from level2_components import should_apply_l2
        self.assertTrue(should_apply_l2(60))
        self.assertFalse(should_apply_l2(59))


class TestLevel3Components(unittest.TestCase):
    @patch("subprocess.run")
    def test_3a_masking(self, m):
        m.return_value = MagicMock(returncode=0, stdout="")
        from level3_components import Component3A
        r = Component3A().apply({"attacker_mac": "AA:BB:CC:DD:EE:FF", "victim_mac": "11:22:33:44:55:66", "confidence": 90})
        self.assertTrue(r["ok"])
        self.assertIn("L3A", r["detail"])

    @patch("subprocess.run")
    def test_3b_notification(self, m):
        m.return_value = MagicMock(returncode=0, stdout="")
        from level3_components import Component3B
        r = Component3B().apply({"attacker_mac": "AA:BB:CC:DD:EE:FF", "victim_mac": "11:22:33:44:55:66", "confidence": 90})
        self.assertTrue(r["ok"])
        self.assertIn("L3B", r["detail"])

    @patch("subprocess.run")
    def test_3c_handoff(self, m):
        m.return_value = MagicMock(returncode=0, stdout="")
        from level3_components import Component3C
        r = Component3C().apply({"attacker_mac": "AA:BB:CC:DD:EE:FF", "victim_mac": "11:22:33:44:55:66", "confidence": 90})
        self.assertTrue(r["ok"])
        self.assertIn("L3C", r["detail"])

    def test_3d_degradation(self):
        from level3_components import Component3D
        r = Component3D().apply({"attacker_mac": "AA:BB:CC:DD:EE:FF", "victim_mac": "11:22:33:44:55:66", "confidence": 90})
        self.assertTrue(r["ok"])
        self.assertIn("L3D", r["detail"])

    def test_threshold(self):
        from level3_components import should_apply_l3
        self.assertTrue(should_apply_l3(85))
        self.assertFalse(should_apply_l3(84))


class TestLevel4Components(unittest.TestCase):
    @patch("subprocess.run")
    def test_4a_cache(self, m):
        m.return_value = MagicMock(returncode=0, stdout="")
        from level4_components import Component4A
        r = Component4A().apply({"attacker_mac": "AA:BB:CC:DD:EE:FF", "victim_mac": "11:22:33:44:55:66", "confidence": 97})
        self.assertTrue(r["ok"])
        self.assertIn("L4A", r["detail"])

    @patch("subprocess.run")
    def test_4b_dualradio(self, m):
        m.return_value = MagicMock(returncode=0, stdout="available")
        from level4_components import Component4B
        r = Component4B().apply({"attacker_mac": "AA:BB:CC:DD:EE:FF", "victim_mac": "11:22:33:44:55:66", "confidence": 97})
        self.assertTrue(r["ok"])
        self.assertIn("L4B", r["detail"])

    @patch("subprocess.run")
    def test_4c_mesh(self, m):
        m.return_value = MagicMock(returncode=0, stdout="")
        from level4_components import Component4C
        r = Component4C().apply({"attacker_mac": "AA:BB:CC:DD:EE:FF", "victim_mac": "11:22:33:44:55:66", "confidence": 97})
        self.assertTrue(r["ok"])
        self.assertIn("L4C", r["detail"])

    @patch("subprocess.run")
    def test_4d_sdn(self, m):
        m.return_value = MagicMock(returncode=0, stdout="")
        from level4_components import Component4D
        r = Component4D().apply({"attacker_mac": "AA:BB:CC:DD:EE:FF", "victim_mac": "11:22:33:44:55:66", "confidence": 97})
        self.assertTrue(r["ok"])
        self.assertIn("L4D", r["detail"])

    def test_threshold(self):
        from level4_components import should_apply_l4
        self.assertTrue(should_apply_l4(95))
        self.assertFalse(should_apply_l4(94))


if __name__ == "__main__":
    unittest.main()

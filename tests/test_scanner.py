"""Unit tests for scanner.py.

These tests use mock sockets so no real network connections are made.
Run with:  python -m unittest discover tests/
"""
import unittest
from unittest.mock import patch, MagicMock

import scanner


class TestScanPort(unittest.TestCase):
    """Tests for scanner.scan_port() — single-port result dict."""

    def _make_mock_socket(self, recv_data: bytes = b""):
        """Return a mock socket whose recv() returns recv_data."""
        sock = MagicMock()
        sock.recv.return_value = recv_data
        return sock

    # ------------------------------------------------------------------
    # Open / closed basic behaviour
    # ------------------------------------------------------------------
    def test_open_port_returns_open_true(self):
        with patch("socket.create_connection", return_value=self._make_mock_socket()):
            result = scanner.scan_port("127.0.0.1", 22, timeout=0.1, grab_banner=False)

        self.assertEqual(result["port"], 22)
        self.assertTrue(result["open"])

    def test_closed_port_returns_open_false(self):
        with patch("socket.create_connection", side_effect=OSError()):
            result = scanner.scan_port("127.0.0.1", 12345, timeout=0.1)

        self.assertEqual(result["port"], 12345)
        self.assertFalse(result["open"])

    # ------------------------------------------------------------------
    # Result dict shape
    # ------------------------------------------------------------------
    def test_result_has_required_keys(self):
        with patch("socket.create_connection", side_effect=OSError()):
            result = scanner.scan_port("127.0.0.1", 80, timeout=0.1)

        for key in ("port", "open", "service", "banner", "version", "risk"):
            self.assertIn(key, result, msg=f"Missing key: {key}")

    def test_closed_port_risk_is_closed(self):
        with patch("socket.create_connection", side_effect=OSError()):
            result = scanner.scan_port("127.0.0.1", 22, timeout=0.1)

        self.assertEqual(result["risk"], "closed")

    # ------------------------------------------------------------------
    # Service name lookup
    # ------------------------------------------------------------------
    def test_known_service_name_resolved(self):
        with patch("socket.create_connection", return_value=self._make_mock_socket()):
            result = scanner.scan_port("127.0.0.1", 22, timeout=0.1, grab_banner=False)

        self.assertEqual(result["service"], "ssh")

    def test_known_high_risk_port(self):
        with patch("socket.create_connection", return_value=self._make_mock_socket()):
            result = scanner.scan_port("127.0.0.1", 3389, timeout=0.1, grab_banner=False)

        self.assertEqual(result["risk"], "high")

    def test_known_medium_risk_port(self):
        with patch("socket.create_connection", return_value=self._make_mock_socket()):
            result = scanner.scan_port("127.0.0.1", 80, timeout=0.1, grab_banner=False)

        self.assertEqual(result["risk"], "medium")

    # ------------------------------------------------------------------
    # Banner grabbing + fingerprinting
    # ------------------------------------------------------------------
    def test_ssh_banner_fingerprinted(self):
        ssh_banner = b"SSH-2.0-OpenSSH_9.3\r\n"
        with patch("socket.create_connection", return_value=self._make_mock_socket(ssh_banner)):
            result = scanner.scan_port("127.0.0.1", 22, timeout=0.1, grab_banner=True)

        self.assertIn("SSH", result["version"])
        self.assertNotEqual(result["banner"], "")

    def test_banner_empty_when_disabled(self):
        with patch("socket.create_connection", return_value=self._make_mock_socket(b"SSH-2.0-X")):
            result = scanner.scan_port("127.0.0.1", 22, timeout=0.1, grab_banner=False)

        self.assertEqual(result["banner"], "")
        self.assertEqual(result["version"], "")


class TestScanPorts(unittest.TestCase):
    """Tests for scanner.scan_ports() — multi-port concurrent scan."""

    def _side_effect(self, open_ports):
        """Factory: returns a create_connection side effect that opens only listed ports."""
        def _fn(addr, timeout):
            if addr[1] in open_ports:
                mock = MagicMock()
                mock.recv.return_value = b""
                return mock
            raise OSError("Connection refused")
        return _fn

    def test_returns_dict_keyed_by_port(self):
        ports = [22, 80, 9999]
        with patch("socket.create_connection", side_effect=self._side_effect({22})):
            results = scanner.scan_ports("127.0.0.1", ports, timeout=0.1, max_workers=5)

        self.assertIsInstance(results, dict)
        for p in ports:
            self.assertIn(p, results)

    def test_correct_open_closed_mapping(self):
        ports = [22, 80, 9999]
        with patch("socket.create_connection", side_effect=self._side_effect({22})):
            results = scanner.scan_ports("127.0.0.1", ports, timeout=0.1, max_workers=5)

        self.assertTrue(results[22]["open"])
        self.assertFalse(results[80]["open"])
        self.assertFalse(results[9999]["open"])

    def test_empty_port_list_returns_empty_dict(self):
        results = scanner.scan_ports("127.0.0.1", [], timeout=0.1)
        self.assertEqual(results, {})

    def test_results_sorted_by_port(self):
        ports = [443, 22, 80]
        with patch("socket.create_connection", side_effect=self._side_effect(set())):
            results = scanner.scan_ports("127.0.0.1", ports, timeout=0.1, max_workers=5)

        self.assertEqual(list(results.keys()), sorted(ports))

    def test_progress_tracking_with_scan_id(self):
        ports = [22, 80]
        scan_id = "test-scan-001"
        with patch("socket.create_connection", side_effect=self._side_effect({22})):
            scanner.scan_ports("127.0.0.1", ports, timeout=0.1,
                               max_workers=5, scan_id=scan_id)

        state = scanner.get_scan_state(scan_id)
        self.assertIsNotNone(state)
        self.assertEqual(state["status"], "done")
        self.assertEqual(state["done"], len(ports))
        self.assertEqual(state["total"], len(ports))


if __name__ == "__main__":
    unittest.main()

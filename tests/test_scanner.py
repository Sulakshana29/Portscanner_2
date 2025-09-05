import unittest
from unittest.mock import patch, MagicMock
import scanner


class ScannerTests(unittest.TestCase):
    def test_scan_port_open_and_closed(self):
        # Simulate open port by returning a dummy socket object
        with patch('socket.create_connection', return_value=MagicMock()):
            port, is_open, service = scanner.scan_port(
                '127.0.0.1', 22, timeout=0.1
            )
            self.assertEqual(port, 22)
            self.assertTrue(is_open)

        # Simulate closed port by raising an exception
        with patch('socket.create_connection', side_effect=OSError()):
            port, is_open, service = scanner.scan_port(
                '127.0.0.1', 12345, timeout=0.1
            )
            self.assertEqual(port, 12345)
            self.assertFalse(is_open)

    def test_scan_ports_uses_all_ports(self):
        ports = [22, 80, 9999]

        def fake_connect(addr, timeout):
            # only port 22 is open
            if addr[1] == 22:
                return MagicMock()
            raise OSError()

        with patch('socket.create_connection', side_effect=fake_connect):
            results = scanner.scan_ports(
                '127.0.0.1', ports, timeout=0.1, max_workers=5
            )
            self.assertIn(22, results)
            self.assertTrue(results[22]['open'])
            self.assertFalse(results[80]['open'])
            self.assertFalse(results[9999]['open'])


if __name__ == '__main__':
    unittest.main()

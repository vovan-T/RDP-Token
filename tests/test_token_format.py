import sys
import unittest
from pathlib import Path


TOKEN_ADMIN = Path(__file__).resolve().parents[1] / "token-admin"
sys.path.insert(0, str(TOKEN_ADMIN))

from adapters.token_format import normalize_rtadmin_serial


class RutokenSerialTests(unittest.TestCase):
    def test_braced_serial(self):
        self.assertEqual("1082933803", normalize_rtadmin_serial("{408c422b}"))

    def test_plain_serial(self):
        self.assertEqual("1082933803", normalize_rtadmin_serial(" 408c422b "))

    def test_decimal_serial(self):
        self.assertEqual("1082933803", normalize_rtadmin_serial("1082933803"))

    def test_invalid_serial(self):
        with self.assertRaises(RuntimeError):
            normalize_rtadmin_serial("Rutoken ECP 0")


if __name__ == "__main__":
    unittest.main()

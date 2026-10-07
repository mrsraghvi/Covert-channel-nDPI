import unittest

from app.engine import _split_endpoint


class EngineEndpointTests(unittest.TestCase):
    def test_splits_ipv4_endpoint(self):
        self.assertEqual(_split_endpoint("192.0.2.10:443"), ("192.0.2.10", 443))

    def test_splits_bracketed_ipv6_endpoint(self):
        self.assertEqual(_split_endpoint("[2001:db8::1]:443"), ("2001:db8::1", 443))

    def test_rejects_malformed_bracketed_endpoint(self):
        self.assertEqual(_split_endpoint("[2001:db8::1]443"), (None, None))


if __name__ == "__main__":
    unittest.main()

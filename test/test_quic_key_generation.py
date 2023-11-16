from unittest import TestCase
from tlexport.quic.quic_key_generation import dev_initial_keys
from cryptography.hazmat.primitives.hashes import SHA256


class TestQuicKeyGen(TestCase):
    def setUp(self) -> None:
        self.destination_connection_id = bytes.fromhex("8394c8f03e515708")

    def test_dev_initial_keys(self):
        initial_keys = dev_initial_keys(self.destination_connection_id, 16, 16, SHA256())
        self.assertEqual(initial_keys["client_initial_key"], bytes.fromhex("1f369613dd76d5467730efcbe3b1a22d"))
        self.assertEqual(initial_keys["client_initial_iv"], bytes.fromhex("fa044b2f42a3fd3b46fb255c"))
        self.assertEqual(initial_keys["client_initial_hp"], bytes.fromhex("9f50449e04a0e810283a1e9933adedd2"))
        self.assertEqual(initial_keys["server_initial_key"], bytes.fromhex("cf3a5331653c364c88f0f379b6067e37"))
        self.assertEqual(initial_keys["server_initial_iv"], bytes.fromhex("0ac1493ca1905853b0bba03e"))
        self.assertEqual(initial_keys["server_initial_hp"], bytes.fromhex("c206b8d9b9f0f37644430b490eeaa314"))

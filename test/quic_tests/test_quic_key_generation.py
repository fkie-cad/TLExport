from unittest import TestCase
from tlexport.quic.quic_key_generation import dev_initial_keys, dev_quic_keys, key_update
from cryptography.hazmat.primitives.hashes import SHA256
from tlexport.keylog_reader import Key
from tlexport.quic.quic_decryptor import QuicDecryptor
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305


class TestQuicKeyGen(TestCase):
    def setUp(self) -> None:
        self.destination_connection_id = bytes.fromhex("8394c8f03e515708")

        self.keylog = [
            Key("CLIENT_HANDSHAKE_TRAFFIC_SECRET 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f b8902ab5f9fe52fdec3aea54e9293e4b8eabf955fcd88536bf44b8b584f14982"),
            Key("SERVER_HANDSHAKE_TRAFFIC_SECRET 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f 88ad8d3b0986a71965a28d108b0f40ffffe629284a6028c80ddc5dc083b3f5d1"),
            Key("CLIENT_TRAFFIC_SECRET_0 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f a877a82fd5f89ba622eb03dc5868fd00a31cc2eb8646b362a75bc14893a8ef07"),
            Key("SERVER_TRAFFIC_SECRET_0 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f a1bfa69e7051fd609946fd9431a51992617c4ddb9c1269c9c0b70cc91b297751"),
            Key("CLIENT_EARLY_TRAFFIC_SECRET 8bff2e9772b22443167499eb0cb80ecac9709c649e8a94190b4820ad36ea299b 191c930430d813e11540996f2ed70b637f1722104d025530dedbd7f39acb1855")
        ]

    def test_dev_initial_keys(self):
        initial_keys = dev_initial_keys(self.destination_connection_id)
        self.assertEqual(initial_keys["client_initial_key"], bytes.fromhex("1f369613dd76d5467730efcbe3b1a22d"))
        self.assertEqual(initial_keys["client_initial_iv"], bytes.fromhex("fa044b2f42a3fd3b46fb255c"))
        self.assertEqual(initial_keys["client_initial_hp"], bytes.fromhex("9f50449e04a0e810283a1e9933adedd2"))
        self.assertEqual(initial_keys["server_initial_key"], bytes.fromhex("cf3a5331653c364c88f0f379b6067e37"))
        self.assertEqual(initial_keys["server_initial_iv"], bytes.fromhex("0ac1493ca1905853b0bba03e"))
        self.assertEqual(initial_keys["server_initial_hp"], bytes.fromhex("c206b8d9b9f0f37644430b490eeaa314"))

    def test_quic_tls_keys(self):
        quic_keys = dev_quic_keys(16,  self.keylog, SHA256())
        # Handshake Keys
        self.assertEqual(quic_keys["client_handshake_key"], bytes.fromhex("30a7e816f6a1e1b3434cf39cf4b415e7"))
        self.assertEqual(quic_keys["server_handshake_key"], bytes.fromhex("17abbf0a788f96c6986964660414e7ec"))
        self.assertEqual(quic_keys["client_handshake_iv"], bytes.fromhex("11e70a5d1361795d2bb04465"))
        self.assertEqual(quic_keys["server_handshake_iv"], bytes.fromhex("09597a2ea3b04c00487e71f3"))
        self.assertEqual(quic_keys["client_handshake_hp"], bytes.fromhex("84b3c21cacaf9f54c885e9a506459079"))
        self.assertEqual(quic_keys["server_handshake_hp"], bytes.fromhex("2a18061c396c2828582b41b0910ed536"))

        # Application Keys
        self.assertEqual(quic_keys["client_application_key"], bytes.fromhex("e010a295f0c2864f186b2a7e8fdc9ed7"))
        self.assertEqual(quic_keys["server_application_key"], bytes.fromhex("fd8c7da9de1b2da4d2ef9fd5188922d0"))
        self.assertEqual(quic_keys["client_application_iv"], bytes.fromhex("eb3fbc384a3199dcf6b4c808"))
        self.assertEqual(quic_keys["server_application_iv"], bytes.fromhex("02f6180e4f4aa456d7e8a602"))
        self.assertEqual(quic_keys["client_application_hp"], bytes.fromhex("8a6a38bc5cc40cb482a254dac68c9d2f"))
        self.assertEqual(quic_keys["server_application_hp"], bytes.fromhex("b7f6f021453e52b58940e4bba72a35d4"))

    def test_quic_key_update(self):
        decryptor_n = QuicDecryptor(
                [bytes.fromhex("c6d98ff3441c3fe1b2182094f69caa2ed4b716b65488960a7a984979fb23e1c8"), bytes.fromhex("e0459b3474bdd0e44a41c144"), bytes.fromhex("c6d98ff3441c3fe1b2182094f69caa2ed4b716b65488960a7a984979fb23e1c8"),
                 bytes.fromhex("e0459b3474bdd0e44a41c144"), bytes.fromhex("9ac312a7f877468ebe69422748ad00a15443f18203a07d6060f688f30f21632b"), bytes.fromhex("9ac312a7f877468ebe69422748ad00a15443f18203a07d6060f688f30f21632b")],ChaCha20Poly1305)

        updated = key_update(decryptor_n, SHA256(), 32, ChaCha20Poly1305)
        self.assertEqual(updated.keys[-1], bytes.fromhex("1223504755036d556342ee9361d253421a826c9ecdf3c7148684b36b714881f9"))

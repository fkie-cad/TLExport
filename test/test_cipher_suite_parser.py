from unittest import TestCase
from tlexport.cipher_suite_parser import cipher_suites, split_cipher_suite
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import algorithms, modes
from cryptography.hazmat.primitives.ciphers import aead

import sys

sys.path.append("../tlexport")


class TestCipherSuiteParser(TestCase):
    def test_cipher_suites(self):
        for suite in cipher_suites:
            match suite:
                case b'\x13\x02':
                    self.assertEqual(split_cipher_suite(suite),
                                     {"CryptoAlgo": (aead.AESGCM, 1),
                                      "Mode": (modes.GCM, 1),
                                      "MAC": hashes.SHA384,
                                      "KeyLength": 32,
                                      "TagLength": 16})

                case b'\x13\x03':
                    self.assertEqual(split_cipher_suite(suite),
                                     {"CryptoAlgo": (aead.ChaCha20Poly1305, 1),
                                      "Mode": (aead.ChaCha20Poly1305, 1),
                                      "MAC": hashes.SHA256,
                                      "KeyLength": 32,
                                      "TagLength": 16})
                case b'\x13\x01':
                    self.assertEqual(split_cipher_suite(suite),
                                     {"CryptoAlgo": (aead.AESGCM, 1),
                                      "Mode": (modes.GCM, 1),
                                      "MAC": hashes.SHA256,
                                      "KeyLength": 16,
                                      "TagLength": 16})
                case b'\x13\x04':
                    self.assertEqual(split_cipher_suite(suite),
                                     {"CryptoAlgo": (aead.AESCCM, 1),
                                      "Mode": (aead.AESCCM, 1),
                                      "MAC": hashes.SHA256,
                                      "KeyLength": 16,
                                      "TagLength": 16})
                case b'\x13\x05':
                    self.assertEqual(split_cipher_suite(suite),
                                     {"CryptoAlgo": (aead.AESCCM, 1),
                                      "Mode": (aead.AESCCM, 1),
                                      "MAC": hashes.SHA256,
                                      "KeyLength": 16,
                                      "TagLength": 8})
                case b'\xC0\x83':
                    self.assertEqual(split_cipher_suite(suite),
                                     {"CryptoAlgo": (algorithms.Camellia, 0),
                                      "Mode": (modes.GCM, 1),
                                      "MAC": hashes.SHA384,
                                      "KeyLength": 32,
                                      "TagLength": 16})
                case b'\x00\x24':
                    self.assertEqual(split_cipher_suite(suite),
                                     {"CryptoAlgo": (algorithms.ARC4, 0),
                                      "Mode": (None, 0),
                                      "MAC": hashes.MD5,
                                      "KeyLength": 16,
                                      "TagLength": 16})
                case b'\xC0\x08':
                    self.assertEqual(split_cipher_suite(suite),
                                     {"CryptoAlgo": (algorithms.TripleDES, 0),
                                      "Mode": (modes.CBC, 0),
                                      "MAC": hashes.SHA1,
                                      "KeyLength": 24,
                                      "TagLength": 16})


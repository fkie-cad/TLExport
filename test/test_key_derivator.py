from unittest import TestCase
import tlexport.key_derivator as kd
from cryptography.hazmat.primitives.ciphers.algorithms import ARC4, AES, TripleDES
from cryptography.hazmat.primitives.hashes import SHA256


class KeyGenerationTests(TestCase):
    def setUp(self) -> None:
        pass

    def test_ssl30_master_secret_gen(self):
        pass

    def test_ssl30_key_generation(self):
        self.assertEqual(kd.dev_ssl_30_keys(
            master_secret=bytes.fromhex("2f149d2d9a4c5586edcf4901f98850f6cd90f2daf7b21df3707e2c5c47119bbb45ae175214fd6c48b389a1cfcb0abb12f62736a0366d44aab2a1d430919836ba122e84436ea796c96412f30f8e9af6ca165676b32766235a696d8dec4eb5b6361c98cd37c0894354669d4cd0fe30e1ef"),
            server_random=bytes.fromhex("165676b32766235a696d8dec4eb5b6361c98cd37c0894354669d4cd0fe30e1ef"),
            client_random=bytes.fromhex("f62736a0366d44aab2a1d430919836ba122e84436ea796c96412f30f8e9af6ca"),
            key_length=16,
            mac_length=20,
            key_block_length=72,
            cipher_algo=ARC4,
            use_aead=0),

        {
        "client_write_MAC_secret": bytes.fromhex("27b0f02df5e0eac4f1c2f169723f489dc59dc72a"),
        "server_write_MAC_secret": bytes.fromhex("08d807876acd708ac8be4aa736e95c811c5ee834"),
        "client_write_key": bytes.fromhex("4317dade5961a2c2ec2a159e378e3fbf"),
        "server_write_key": bytes.fromhex("094248fe2aa2550eb92b9adefd024b8c"),
        "client_write_IV": bytes.fromhex("ef9fa205"),
        "server_write_IV": bytes.fromhex("f1725837")
        })

    def test_tls10_master_secret_gen(self):
        pass

    def test_tls10_key_generation(self):
        self.assertEqual(kd.dev_tls_10_11_keys(
            master_secret=bytes.fromhex(
                "de0388430b6540cc6719c520846372b8b07add09d7d4fb22894bc871cbe3679615b96e254928c271796734a99a71b96a"),
            server_random=bytes.fromhex("5ae72e31031a078d035e79a5dfeace288317e1cb33aa8525edfb0642f1b3925d"),
            client_random=bytes.fromhex("ad3a425b23e1fb2c50893f2ca8484baede685205f46238f573d37ae3297faa98"),
            key_length=24,
            mac_length=20,
            key_block_length=88,
            cipher_algo=TripleDES,
            use_aead=0),

            {
                "client_write_MAC_secret": bytes.fromhex("d3c122820fb226ab679e6913e52714aa2293c5c2"),
                "server_write_MAC_secret": bytes.fromhex("1fb0d84eebe0049a69d13d6fcdc6e3f4bb501667"),
                "client_write_key": bytes.fromhex("2d7afb026c41e24f987945b79c317b3b9adbc7e243fa5f51"),
                "server_write_key": bytes.fromhex("57d65d2c1c58d69270ff1d8af3374c0917ee5e618fb303f6"),
                "client_write_IV": bytes.fromhex("a688a99db4fa773d"),
                "server_write_IV": bytes.fromhex("006d9f3e58e97944")
            })

    def test_tls11_master_secret_gen(self):
        pass

    def test_tls11_key_generation(self):
        pass

    def test_tls12_master_secret_gen(self):
        self.assertEqual(kd.gen_master_secret_tls_12(
            pm_secret=bytes.fromhex("df4a291baa1eb7cfa6934b29b474baad2697e29f1f920dcc77c8a0a088447624"),
            client_random=bytes.fromhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
            server_random=bytes.fromhex("707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f")),

            bytes.fromhex(
                "916abf9da55973e13614ae0a3f5d3f37b023ba129aee02cc9134338127cd7049781c8e19fc1eb2a7387ac06ae237344c"))

    def test_tls12_key_generation(self):
        self.assertEqual(kd.dev_tls_12_keys(
            master_secret=bytes.fromhex("916abf9da55973e13614ae0a3f5d3f37b023ba129aee02cc9134338127cd7049781c8e19fc1eb2a7387ac06ae237344c"),
            client_random=bytes.fromhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
            server_random=bytes.fromhex("707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f"),
            key_length=16,
            mac_length=20,
            key_block_length=104,
            cipher_algo=AES,
            use_aead=0,
            mac_function=SHA256),

            {
                "client_write_MAC_secret": bytes.fromhex("1b7d117c7d5f690bc263cae8ef60af0f1878acc2"),
                "server_write_MAC_secret":  bytes.fromhex("2ad8bdd8c601a617126f63540eb20906f781fad2"),
                "client_write_key": bytes.fromhex("f656d037b173ef3e11169f27231a84b6"),
                "server_write_key": bytes.fromhex("752a18e7a9fcb7cbcdd8f98dd8f769eb"),
                "client_write_IV":  bytes.fromhex("a0d2550c9238eebfef5c32251abb67d6"),
                "server_write_IV": bytes.fromhex("434528db4937d540d393135e06a11bb8"),
            })

    def test_tls13_key_generation(self):
        self.assertEqual(kd.dev_tls_10_11_keys(
            master_secret=bytes.fromhex(
                "de0388430b6540cc6719c520846372b8b07add09d7d4fb22894bc871cbe3679615b96e254928c271796734a99a71b96a"),
            server_random=bytes.fromhex("5ae72e31031a078d035e79a5dfeace288317e1cb33aa8525edfb0642f1b3925d"),
            client_random=bytes.fromhex("ad3a425b23e1fb2c50893f2ca8484baede685205f46238f573d37ae3297faa98"),
            key_length=24,
            mac_length=20,
            key_block_length=88,
            cipher_algo=TripleDES,
            use_aead=0),

            {
                "client_write_MAC_secret": bytes.fromhex("d3c122820fb226ab679e6913e52714aa2293c5c2"),
                "server_write_MAC_secret": bytes.fromhex("1fb0d84eebe0049a69d13d6fcdc6e3f4bb501667"),
                "client_write_key": bytes.fromhex("2d7afb026c41e24f987945b79c317b3b9adbc7e243fa5f51"),
                "server_write_key": bytes.fromhex("57d65d2c1c58d69270ff1d8af3374c0917ee5e618fb303f6"),
                "client_write_IV": bytes.fromhex("a688a99db4fa773d"),
                "server_write_IV": bytes.fromhex("006d9f3e58e97944")
            })

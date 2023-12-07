import logging

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand

from tlexport.cipher_suite_parser import split_cipher_suite
from tlexport.key_derivator import dev_tls_10_11_keys, dev_tls_12_keys
from tlexport.keylog_reader import Key
from tlexport.tlsversion import TlsVersion


class Epoch:
    def __init__(self, epoch_number, keys):
        self.epoch_number = epoch_number
        self.sequence_number_server = 0
        self.sequence_number_client = 0
        self.keys = keys
        self.server_secret = None
        self.client_secret = None


def make_info_dtls(label, key_length):
    labellen = len(label) + 6
    return key_length.to_bytes(2, 'big') + labellen.to_bytes(1, 'big') + b"dtls13" + label + b"\x00"


def dev_dtls_13_keys(key_length, secret_list, hash_fun: hashes.HashAlgorithm) -> list[Epoch]:
    key_info = make_info_dtls(b"key", key_length)
    iv_info = make_info_dtls(b"iv", 12)
    sn_info = make_info_dtls(b"sn", key_length)

    client_early_traffic_key = None
    client_early_traffic_iv = None
    client_early_traffic_sn = None
    server_early_traffic_key = None
    server_early_traffic_iv = None
    server_early_traffic_sn = None
    client_early_secret = None
    server_early_secret = None

    for secret in secret_list:
        if secret.label == "CLIENT_HANDSHAKE_TRAFFIC_SECRET":
            client_handshake_key = HKDFExpand(hash_fun, key_length, key_info).derive(bytes.fromhex(secret.value))
            client_handshake_iv = HKDFExpand(hash_fun, 12, iv_info).derive(bytes.fromhex(secret.value))
            client_handshake_sn = HKDFExpand(hash_fun, key_length, sn_info).derive(bytes.fromhex(secret.value))
            client_handshake_secret = bytes.fromhex(secret.value)

        elif secret.label == "SERVER_HANDSHAKE_TRAFFIC_SECRET":
            server_handshake_key = HKDFExpand(hash_fun, key_length, key_info).derive(bytes.fromhex(secret.value))
            server_handshake_iv = HKDFExpand(hash_fun, 12, iv_info).derive(bytes.fromhex(secret.value))
            server_handshake_sn = HKDFExpand(hash_fun, key_length, sn_info).derive(bytes.fromhex(secret.value))
            server_handshake_secret = bytes.fromhex(secret.value)

        elif secret.label == "CLIENT_TRAFFIC_SECRET_0":
            client_application_key = HKDFExpand(hash_fun, key_length, key_info).derive(bytes.fromhex(secret.value))
            client_application_iv = HKDFExpand(hash_fun, 12, iv_info).derive(bytes.fromhex(secret.value))
            client_application_sn = HKDFExpand(hash_fun, key_length, sn_info).derive(bytes.fromhex(secret.value))
            client_traffic_secret = bytes.fromhex(secret.value)

        elif secret.label == "SERVER_TRAFFIC_SECRET_0":
            server_application_key = HKDFExpand(hash_fun, key_length, key_info).derive(bytes.fromhex(secret.value))
            server_application_iv = HKDFExpand(hash_fun, 12, iv_info).derive(bytes.fromhex(secret.value))
            server_application_sn = HKDFExpand(hash_fun, key_length, sn_info).derive(bytes.fromhex(secret.value))
            server_traffic_secret = bytes.fromhex(secret.value)

        elif secret.label == "CLIENT_EARLY_TRAFFIC_SECRET":
            client_early_traffic_key = HKDFExpand(hash_fun, key_length, key_info).derive(
                bytes.fromhex(secret.value))
            client_early_traffic_iv = HKDFExpand(hash_fun, 12, iv_info).derive(bytes.fromhex(secret.value))
            client_early_traffic_sn = HKDFExpand(hash_fun, key_length, sn_info).derive(
                bytes.fromhex(secret.value))
            client_early_secret = bytes.fromhex(secret.value)

        elif secret.label == "SERVER_EARLY_TRAFFIC_SECRET":
            server_early_traffic_key = HKDFExpand(hash_fun, key_length, key_info).derive(
                bytes.fromhex(secret.value))
            server_early_traffic_iv = HKDFExpand(hash_fun, 12, iv_info).derive(bytes.fromhex(secret.value))
            server_early_traffic_sn = HKDFExpand(hash_fun, key_length, sn_info).derive(
                bytes.fromhex(secret.value))
            server_early_secret = bytes.fromhex(secret.value)

    logging_string = ""

    # Early Traffic
    epoch_1 = {
        "client_key": client_early_traffic_key,
        "client_iv": client_early_traffic_iv,
        "server_key": server_early_traffic_key,
        "server_iv": server_early_traffic_iv,
        "client_sn": client_early_traffic_sn,
        "server_sn": server_early_traffic_sn,
        "client_secret": client_early_secret,
        "server_secret": server_early_secret
    }
    for k, v in epoch_1.items():
        logging_string += f"{k}: {v.hex()}\n"
    # Handshake Traffic
    epoch_2 = {
        "client_key": client_handshake_key,
        "server_key": server_handshake_key,
        "client_iv": client_handshake_iv,
        "server_iv": server_handshake_iv,
        "client_sn": client_handshake_sn,
        "server_sn": server_handshake_sn,
        "client_secret": client_handshake_secret,
        "server_secret": server_handshake_secret
    }
    for k, v in epoch_2.items():
        logging_string += f"{k}: {v.hex()}\n"
    # Application Traffic
    epoch_3 = {
        "client_key": client_application_key,
        "server_key": server_application_key,
        "client_iv": client_application_iv,
        "server_iv": server_application_iv,
        "client_sn": client_application_sn,
        "server_sn": server_application_sn,
        "client_secret": client_traffic_secret,
        "server_secret": server_traffic_secret
    }
    for k, v in epoch_3.items():
        logging_string += f"{k}: {v.hex()}\n"

    logging.info(f"{logging_string}")
    epochs = [Epoch(0, None), Epoch(1, epoch_1), Epoch(2, epoch_2), Epoch(3, epoch_3)]
    return epochs


def derive_next_keys(old_epoch: Epoch, key_length, hash_fun: hashes.HashAlgorithm):
    old_epoch_client = old_epoch.keys["client_secret"]
    old_epoch_server = old_epoch.keys["server_secret"]

    info = make_info_dtls("traffic upd", key_length)
    key_info = make_info_dtls(b"key", key_length)
    iv_info = make_info_dtls(b"iv", 12)
    sn_info = make_info_dtls(b"sn", key_length)

    new_client_secret = HKDFExpand(hash_fun, hash_fun.digest_size, info).derive(old_epoch_client)
    new_server_secret = HKDFExpand(hash_fun, hash_fun.digest_size, info).derive(old_epoch_server)

    server_key = HKDFExpand(hash_fun, key_length, key_info).derive(new_server_secret)
    server_iv = HKDFExpand(hash_fun, 12, iv_info).derive(new_server_secret)
    server_sn = HKDFExpand(hash_fun, key_length, sn_info).derive(new_server_secret)
    server_secret = new_server_secret

    client_key = HKDFExpand(hash_fun, key_length, key_info).derive(new_client_secret)
    client_iv = HKDFExpand(hash_fun, 12, iv_info).derive(new_client_secret)
    client_sn = HKDFExpand(hash_fun, key_length, sn_info).derive(new_client_secret)
    client_secret = new_client_secret

    epoch = {
        "client_key": client_key,
        "server_key": server_key,
        "client_iv": client_iv,
        "server_iv": server_iv,
        "client_sn": client_sn,
        "server_sn": server_sn,
        "client_secret": client_secret,
        "server_secret": server_secret
    }

    return Epoch(old_epoch.epoch_number + 1, epoch)


class DtlsDecryptor:
    def __init__(self, keylog: list[Key], ciphersuite, tls_version, server_random, client_random):
        self.mac_algorithm = None
        self.key_length = None
        self.ciphersuite_parts = split_cipher_suite(ciphersuite)
        self.tls_version = tls_version

        self.client_epoch = 0
        self.server_epoch = 0

        self.epochs = [Epoch(0, None)]

        self.set_keys(keylog, server_random, client_random)

    def decrypt_partial_ciphertext(self, partial_epoch, partial_sequence_number, ciphertext):
        pass

    def decrypt_full_ciphertext(self, epoch, sequence_number, ciphertext):
        pass

    def set_keys(self, keylog: list[Key], server_random, client_random):
        if self.tls_version in [TlsVersion.TLS10, TlsVersion.TLS11]:
            master_secret = bytes.fromhex(keylog[0].value)
            key_length = self.ciphersuite_parts['KeyLength']
            mac_length = self.ciphersuite_parts["MAC"].digest_size
            cipher_algo = self.ciphersuite_parts["CryptoAlgo"][0]
            self.epochs.append(Epoch(1, dev_tls_10_11_keys(master_secret, server_random, client_random, key_length,
                                                           mac_length, 2 * key_length + 2 * mac_length, cipher_algo,
                                                           self.ciphersuite_parts["Mode"][1])))
        elif self.tls_version == TlsVersion.TLS12:
            master_secret = bytes.fromhex(keylog[0].value)
            key_length = self.ciphersuite_parts['KeyLength']
            mac_length = self.ciphersuite_parts["MAC"].digest_size
            cipher_algo = self.ciphersuite_parts["CryptoAlgo"][0]
            self.epochs.append(Epoch(1, dev_tls_12_keys(master_secret, server_random, client_random, key_length,
                                                        mac_length, 2 * key_length + 2 * mac_length, cipher_algo,
                                                        self.ciphersuite_parts["Mode"][1],
                                                        self.ciphersuite_parts["MAC"])))
        elif self.tls_version == TlsVersion.TLS13:
            key_length = self.ciphersuite_parts['KeyLength']
            mac_algorithm = self.ciphersuite_parts["MAC"]
            self.epochs.extend(dev_dtls_13_keys(key_length, keylog, mac_algorithm))
            self.key_length = key_length
            self.mac_algorithm = mac_algorithm

    def update_epoch(self):
        new_epoch = derive_next_keys(self.epochs[-1], self.key_length, self.mac_algorithm)
        self.epochs.append(new_epoch)

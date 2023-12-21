import logging

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand, HKDF
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers.algorithms import AES
from cryptography.hazmat.primitives.ciphers.modes import ECB


def dev_quic_keys(key_length, secret_list, hash_fun: hashes.HashAlgorithm):
    key_info = make_info(b"quic key", key_length)
    iv_info = make_info(b"quic iv", 12)
    hp_info = make_info(b"quic hp", key_length)

    client_early_traffic_key = None
    client_early_traffic_iv = None
    server_early_traffic_key = None
    server_early_traffic_iv = None
    client_early_traffic_hp = None
    server_early_traffic_hp = None

    for secret in secret_list:
        if secret.label == "CLIENT_HANDSHAKE_TRAFFIC_SECRET":
            client_handshake_key = HKDFExpand(hash_fun, key_length, key_info).derive(bytes.fromhex(secret.value))
            client_handshake_iv = HKDFExpand(hash_fun, 12, iv_info).derive(bytes.fromhex(secret.value))
            client_handshake_hp = HKDFExpand(hash_fun, key_length, hp_info).derive(bytes.fromhex(secret.value))

        elif secret.label == "SERVER_HANDSHAKE_TRAFFIC_SECRET":
            server_handshake_key = HKDFExpand(hash_fun, key_length, key_info).derive(bytes.fromhex(secret.value))
            server_handshake_iv = HKDFExpand(hash_fun, 12, iv_info).derive(bytes.fromhex(secret.value))
            server_handshake_hp = HKDFExpand(hash_fun, key_length, hp_info).derive(bytes.fromhex(secret.value))

        elif secret.label == "CLIENT_TRAFFIC_SECRET_0":
            client_application_key = HKDFExpand(hash_fun, key_length, key_info).derive(bytes.fromhex(secret.value))
            client_application_iv = HKDFExpand(hash_fun, 12, iv_info).derive(bytes.fromhex(secret.value))
            client_application_hp = HKDFExpand(hash_fun, key_length, hp_info).derive(bytes.fromhex(secret.value))

        elif secret.label == "SERVER_TRAFFIC_SECRET_0":
            server_application_key = HKDFExpand(hash_fun, key_length, key_info).derive(bytes.fromhex(secret.value))
            server_application_iv = HKDFExpand(hash_fun, 12, iv_info).derive(bytes.fromhex(secret.value))
            server_application_hp = HKDFExpand(hash_fun, key_length, hp_info).derive(bytes.fromhex(secret.value))

        elif secret.label == "CLIENT_EARLY_TRAFFIC_SECRET":
            client_early_traffic_key = HKDFExpand(hash_fun, key_length, key_info).derive(bytes.fromhex(secret.value))
            client_early_traffic_iv = HKDFExpand(hash_fun, 12, iv_info).derive(bytes.fromhex(secret.value))
            client_early_traffic_hp = HKDFExpand(hash_fun, key_length, hp_info).derive(bytes.fromhex(secret.value))

        elif secret.label == "SERVER_EARLY_TRAFFIC_SECRET":
            server_early_traffic_key = HKDFExpand(hash_fun, key_length, key_info).derive(bytes.fromhex(secret.value))
            server_early_traffic_iv = HKDFExpand(hash_fun, 12, iv_info).derive(bytes.fromhex(secret.value))
            server_early_traffic_hp = HKDFExpand(hash_fun, key_length, hp_info).derive(bytes.fromhex(secret.value))

    keys = {
        "client_handshake_key": client_handshake_key,
        "server_handshake_key": server_handshake_key,
        "client_handshake_iv": client_handshake_iv,
        "server_handshake_iv": server_handshake_iv,
        "client_handshake_hp": client_handshake_hp,
        "server_handshake_hp": server_handshake_hp,

        "client_application_key": client_application_key,
        "server_application_key": server_application_key,
        "client_application_iv": client_application_iv,
        "server_application_iv": server_application_iv,
        "client_application_hp": client_application_hp,
        "server_application_hp": server_application_hp,

        "client_early_key": client_early_traffic_key,
        "client_early_iv": client_early_traffic_iv,
        "server_early_key": server_early_traffic_key,
        "server_early_iv": server_early_traffic_iv,
        "client_early_hp": client_early_traffic_hp,
        "server_early_hp": server_early_traffic_hp
    }

    logging_string = ""
    for k in keys:
        if keys[k] is not None:
            logging_string += f"{k}: {keys[k].hex()}\n"

    logging.info(f"{logging_string}")

    return keys


def dev_initial_keys(connection_id: bytes):
    key_length = 16
    hp_key_length = 16
    hash_fun = SHA256()
    initial_salt = bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")

    initial_secret = HKDF(hash_fun, salt=initial_salt, length=32, info=None)._extract(connection_id)

    client_initial = HKDFExpand(hash_fun, 32, info=make_info(b"client in", 32)).derive(initial_secret)
    server_initial = HKDFExpand(hash_fun, 32, info=make_info(b"server in", 32)).derive(initial_secret)
    initial_keys = {
        "client_initial_key": HKDFExpand(hash_fun, key_length, make_info(b"quic key", key_length)).derive(
            client_initial),
        "client_initial_iv": HKDFExpand(hash_fun, 12, make_info(b"quic iv", 12)).derive(client_initial),
        "client_initial_hp": HKDFExpand(hash_fun, key_length, make_info(b"quic hp", hp_key_length)).derive(
            client_initial),
        "server_initial_key": HKDFExpand(hash_fun, key_length, make_info(b"quic key", key_length)).derive(
            server_initial),
        "server_initial_iv": HKDFExpand(hash_fun, 12, make_info(b"quic iv", 12)).derive(
            server_initial),
        "server_initial_hp": HKDFExpand(hash_fun, key_length, make_info(b"quic hp", hp_key_length)).derive(
            server_initial),
    }

    return initial_keys


def make_info(label, key_length):
    lable_len = len(label) + 6
    return key_length.to_bytes(2, 'big') + lable_len.to_bytes(1, 'big') + b"tls13 " + label + b"\x00"


def make_hp_mask(hp_key: bytes, sample: bytes) -> bytes:    # TODO: Add ChaCha20Poly1305 mask generation
    encryptor = Cipher(AES(hp_key), ECB()).encryptor()
    mask = encryptor.update(sample) + encryptor.finalize()
    return mask


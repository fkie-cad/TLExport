import logging

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand


def dev_quic_keys(key_length, hp_key_length, secret_list, hash_fun: hashes.HashAlgorithm):
    key_label = b"quic key"
    iv_label = b"quic iv"
    hp_label = b"quic hp"
    key_labellen = (14).to_bytes(1,'big')
    iv_labellen = (13).to_bytes(1, 'big')
    hp_labellen = iv_labellen
    key_info = key_length.to_bytes(2, 'big') + key_labellen + b"tls13 " + key_label + b"\x00"
    iv_info = (12).to_bytes(2, 'big') + iv_labellen + b"tls13 " + iv_label + b"\x00"
    hp_info = hp_key_length.to_bytes(2,'big') + hp_labellen + b"tls13 " + hp_label + b"\x00"

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
            client_handshake_hp = HKDFExpand(hash_fun, hp_key_length, hp_info).derive(bytes.fromhex(secret.value))

        elif secret.label == "SERVER_HANDSHAKE_TRAFFIC_SECRET":
            server_handshake_key = HKDFExpand(hash_fun, key_length, key_info).derive(bytes.fromhex(secret.value))
            server_handshake_iv = HKDFExpand(hash_fun, 12, iv_info).derive(bytes.fromhex(secret.value))
            server_handshake_hp = HKDFExpand(hash_fun, hp_key_length, hp_info).derive(bytes.fromhex(secret.value))

        elif secret.label == "CLIENT_TRAFFIC_SECRET_0":
            client_application_key = HKDFExpand(hash_fun, key_length, key_info).derive(bytes.fromhex(secret.value))
            client_application_iv = HKDFExpand(hash_fun, 12, iv_info).derive(bytes.fromhex(secret.value))
            client_application_hp = HKDFExpand(hash_fun, hp_key_length, hp_info).derive(bytes.fromhex(secret.value))

        elif secret.label == "SERVER_TRAFFIC_SECRET_0":
            server_application_key = HKDFExpand(hash_fun, key_length, key_info).derive(bytes.fromhex(secret.value))
            server_application_iv = HKDFExpand(hash_fun, 12, iv_info).derive(bytes.fromhex(secret.value))
            server_application_hp = HKDFExpand(hash_fun, hp_key_length, hp_info).derive(bytes.fromhex(secret.value))

        elif secret.label == "CLIENT_EARLY_TRAFFIC_SECRET":
            client_early_traffic_key = HKDFExpand(hash_fun, key_length, key_info).derive(bytes.fromhex(secret.value))
            client_early_traffic_iv = HKDFExpand(hash_fun, 12, iv_info).derive(bytes.fromhex(secret.value))
            client_early_traffic_hp = HKDFExpand(hash_fun, hp_key_length, hp_info).derive(bytes.fromhex(secret.value))

        elif secret.label == "SERVER_EARLY_TRAFFIC_SECRET":
            server_early_traffic_key = HKDFExpand(hash_fun, key_length, key_info).derive(bytes.fromhex(secret.value))
            server_early_traffic_iv = HKDFExpand(hash_fun, 12, iv_info).derive(bytes.fromhex(secret.value))
            server_early_traffic_hp = HKDFExpand(hash_fun, hp_key_length, hp_info).derive(bytes.fromhex(secret.value))



    keys = {
        "client_handshake_traffic_key": client_handshake_key,
        "server_handshake_traffic_key": server_handshake_key,
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

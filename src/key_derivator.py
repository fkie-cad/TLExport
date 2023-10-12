import logging
import math

from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand


def dev_ssl_30_keys(master_secret, server_random, client_random, key_length, mac_length, key_block_length, cipher_algo,
                    use_aead):
    iv_length = 4
    if cipher_algo in [algorithms.AES, algorithms.Camellia]:
        iv_length = 16
    elif cipher_algo == algorithms.TripleDES:
        iv_length = 8

    if use_aead:
        mac_length = 0

    key_block = prf_ssl_30(master_secret, client_random, server_random, key_block_length + 2 * iv_length, 0)

    keys = {
        "client_write_MAC_secret": key_block[0: mac_length],
        "server_write_MAC_secret": key_block[mac_length: 2 * mac_length],
        "client_write_key": key_block[2 * mac_length: 2 * mac_length + key_length],
        "server_write_key": key_block[2 * mac_length + key_length: 2 * mac_length + 2 * key_length],
        "client_write_IV": key_block[2 * mac_length + 2 * key_length: 2 * mac_length + 2 * key_length + iv_length],
        "server_write_IV": key_block[
                           2 * mac_length + 2 * key_length + iv_length: 2 * mac_length + 2 * key_length + 2 * iv_length]
    }

    logging_string = "Session Keys: "
    for k in keys:
        logging_string += f"{k}: {keys[k].hex()}\n"

    logging.info(f"{logging_string}")

    return keys


def dev_tls_10_11_keys(master_secret, server_random, client_random, key_length, mac_length, key_block_length,
                       cipher_algo, use_aead):
    iv_length = 4
    if cipher_algo in [algorithms.AES, algorithms.Camellia]:
        iv_length = 16
    elif cipher_algo == algorithms.TripleDES:
        iv_length = 8

    if use_aead:
        mac_length = 0

    key_block = prf_tls_10_11(master_secret, client_random, server_random, b"key expansion",
                              key_block_length + 2 * iv_length, 0)

    keys = {
        "client_write_MAC_secret": key_block[0: mac_length],
        "server_write_MAC_secret": key_block[mac_length: mac_length * 2],
        "client_write_key": key_block[mac_length * 2: mac_length * 2 + key_length],
        "server_write_key": key_block[mac_length * 2 + key_length: mac_length * 2 + key_length * 2],
        "client_write_IV": key_block[mac_length * 2 + key_length * 2: mac_length * 2 + key_length * 2 + iv_length],
        "server_write_IV": key_block[
                           mac_length * 2 + key_length * 2 + iv_length: mac_length * 2 + key_length * 2 + iv_length * 2]

    }

    logging_string = ""
    for k in keys:
        logging_string += f"{k}: {keys[k].hex()}\n"

    logging.info(f"{logging_string}")

    return keys


def dev_tls_12_keys(master_secret, client_random, server_random, key_length, mac_length, key_block_length, cipher_algo,
                    use_aead, mac_function):
    iv_length = 4
    if cipher_algo == ChaCha20Poly1305:
        iv_length = 12

    if cipher_algo in [algorithms.AES, algorithms.Camellia]:
        iv_length = 16

    if use_aead:
        mac_length = 0

    key_block = prf_tls_12(master_secret, client_random, server_random, b'key expansion',
                           key_block_length + 2 * iv_length, mac_function)

    keys = {
        "client_write_MAC_secret": key_block[0: mac_length],
        "server_write_MAC_secret": key_block[mac_length: mac_length * 2],
        "client_write_key": key_block[mac_length * 2: mac_length * 2 + key_length],
        "server_write_key": key_block[mac_length * 2 + key_length: mac_length * 2 + key_length * 2],
        "client_write_IV": key_block[mac_length * 2 + key_length * 2: mac_length * 2 + key_length * 2 + iv_length],
        "server_write_IV": key_block[
                           mac_length * 2 + key_length * 2 + iv_length: mac_length * 2 + key_length * 2 + 2 * iv_length]

    }

    logging_string = ""
    for k in keys:
        logging_string += f"{k}: {keys[k].hex()}\n"

    logging.info(f"{logging_string}")

    return keys


def dev_tls_13_keys(secret_list, key_length, hash_fun: hashes.HashAlgorithm):
    # key length dependent on algorithm iv size always 12
    key_length = int(key_length).to_bytes(2, 'big')
    iv_length = b'\x00\x0c'

    key_label = b'tls13 key'
    iv_label = b'tls13 iv'

    iv_label_len = b'\x08'
    key_label_len = b'\x09'

    iv_info = iv_length + iv_label_len + iv_label + b'\x00'
    key_info = key_length + key_label_len + key_label + b'\x00'

    # In case handshake secrets are not available
    client_handshake_key = None
    client_handshake_iv = None
    server_handshake_key = None
    server_handshake_iv = None

    for secret in secret_list:
        if secret.label == "CLIENT_HANDSHAKE_TRAFFIC_SECRET":
            client_handshake_key = HKDFExpand(hash_fun, int.from_bytes(key_length, 'big'), key_info).derive(
                bytes.fromhex(secret.value))
            client_handshake_iv = HKDFExpand(hash_fun, 12, iv_info).derive(bytes.fromhex(secret.value))

        elif secret.label == "SERVER_HANDSHAKE_TRAFFIC_SECRET":
            server_handshake_key = HKDFExpand(hash_fun, int.from_bytes(key_length, 'big'), key_info).derive(
                bytes.fromhex(secret.value))
            server_handshake_iv = HKDFExpand(hash_fun, 12, iv_info).derive(bytes.fromhex(secret.value))

        elif secret.label == "CLIENT_TRAFFIC_SECRET_0":
            client_application_key = HKDFExpand(hash_fun, int.from_bytes(key_length, 'big'), key_info).derive(
                bytes.fromhex(secret.value))
            client_application_iv = HKDFExpand(hash_fun, 12, iv_info).derive(bytes.fromhex(secret.value))

        elif secret.label == "SERVER_TRAFFIC_SECRET_0":
            server_application_key = HKDFExpand(hash_fun, int.from_bytes(key_length, 'big'), key_info).derive(
                bytes.fromhex(secret.value))
            server_application_iv = HKDFExpand(hash_fun, 12, iv_info).derive(bytes.fromhex(secret.value))

    keys = {
        "client_handshake_traffic_secret": client_handshake_key,
        "server_handshake_traffic_secret": server_handshake_key,
        "client_application_traffic_secret_0": client_application_key,
        "server_application_traffic_secret_0": server_application_key,
        "client_handshake_iv": client_handshake_iv,
        "server_handshake_iv": server_handshake_iv,
        "client_application_iv": client_application_iv,
        "server_application_iv": server_application_iv
    }

    logging_string = ""
    for k in keys:
        logging_string += f"{k}: {keys[k].hex()}\n"

    logging.info(f"{logging_string}")

    return keys


def gen_master_secret_ssl_30(pm_secret, client_random, server_random):
    master_secret = prf_ssl_30(pm_secret, client_random, server_random, 48, 1)
    logging.info(f"Master Secret: {master_secret}")
    return master_secret


def gen_master_secret_tls_10_11(pm_secret, client_random, server_random):
    master_secret = prf_tls_10_11(pm_secret, client_random, server_random, b'master secret', 48, 1)
    logging.info(f"Master Secret: {master_secret}")
    return master_secret


def gen_master_secret_tls_12(pm_secret, client_random, server_random):
    seed = b'master secret' + client_random + server_random

    a0 = seed

    h = hmac.HMAC(pm_secret, hashes.SHA256())
    h.update(a0)
    a1 = h.finalize()
    h = hmac.HMAC(pm_secret, hashes.SHA256())
    h.update(a1)
    a2 = h.finalize()

    h = hmac.HMAC(pm_secret, hashes.SHA256())
    h.update(a1 + seed)
    p1 = h.finalize()

    h = hmac.HMAC(pm_secret, hashes.SHA256())
    h.update(a2 + seed)
    p2 = h.finalize()

    master_secret = p1 + p2[:16]

    logging.info(f"Master Secret: {master_secret}")

    return master_secret


def prf_ssl_30(secret, client_random, server_random, length, non_key):
    key_block = b''
    sec_bits = 'ABCDEFGHIJ'
    counter = 1

    while len(key_block) < length:
        md5 = hashes.Hash(hashes.MD5())
        sha1 = hashes.Hash(hashes.SHA1())
        if non_key:
            sha1.update(bytes(counter * sec_bits[counter - 1], 'utf-8') + secret + client_random + server_random)
        else:
            sha1.update(bytes(counter * sec_bits[counter - 1], 'utf-8') + secret + server_random + client_random)

        a = sha1.finalize()
        md5.update(secret + a)
        key_block = key_block + md5.finalize()

        counter += 1

    return key_block[:length]


def prf_tls_10_11(secret, client_random, server_random, label, length, non_key):
    if non_key:
        seed = label + client_random + server_random
    else:
        seed = label + server_random + client_random

    l_s = len(secret)
    l_s1 = l_s2 = math.ceil(l_s / 2)
    s1 = secret[:l_s1]
    s2 = secret[l_s2:]

    a0 = seed

    p_md5 = b''
    md_5_count = 0

    while len(p_md5) < length:
        md_5_count += 1
        h1 = hmac.HMAC(s1, hashes.MD5())
        h1.update(a0)
        a1 = h1.finalize()

        h = hmac.HMAC(s1, hashes.MD5())
        h.update(a1 + seed)
        p_md5 = p_md5 + h.finalize()
        a0 = a1

    a0 = seed
    p_sha1 = b''
    sha_1_count = 0
    while len(p_sha1) < length:
        sha_1_count += 1
        h1 = hmac.HMAC(s2, hashes.SHA1())
        h1.update(a0)
        a1 = h1.finalize()

        h = hmac.HMAC(s2, hashes.SHA1())
        h.update(a1 + seed)
        p_sha1 = p_sha1 + h.finalize()
        a0 = a1

    secret_block = bytearray([b1 ^ b2 for b1, b2 in zip(p_md5, p_sha1)])

    return secret_block[:length]


def prf_tls_12(secret, client_random, server_random, label, length, mac_function):
    mac = hashes.SHA256

    if mac_function == hashes.SHA384:
        mac = hashes.SHA384

    seed = label + server_random + client_random

    a0 = seed
    secret_block = b''

    while len(secret_block) < length:
        h = hmac.HMAC(secret, mac())
        h.update(a0)

        a1 = h.finalize()

        h = hmac.HMAC(secret, mac())
        h.update(a1 + seed)
        secret_block = secret_block + h.finalize()
        a0 = a1

    return secret_block[:length]

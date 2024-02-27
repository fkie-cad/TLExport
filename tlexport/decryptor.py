import logging
import zlib
import warnings
from tlexport.tlsversion import TlsVersion
from tlexport.tlsrecord import TlsRecord

from enum import Enum
# Suppress the deprecation warning from the cryptography module.
with warnings.catch_warnings():
    warnings.simplefilter("ignore")
    from cryptography.hazmat.primitives.ciphers import Cipher
    from cryptography.hazmat.primitives.ciphers.algorithms import AES, TripleDES, Camellia, IDEA
    from cryptography.hazmat.primitives.ciphers.aead import AESCCM, AESGCM, ChaCha20Poly1305
    from cryptography.hazmat.primitives.ciphers.algorithms import ChaCha20
    from cryptography.hazmat.primitives.ciphers.algorithms import ARC4
    from cryptography.hazmat.primitives.ciphers.modes import CBC


class EncryptionType(Enum):
    Stream_Cipher = 0
    Block_Cipher = 1
    AEAD = 2
    Unknown = 3


class Decryptor:
    def __init__(self, bulk_alg, bulk_mode, mac_alg, keys, tls_version, key_length, mac_length, tag_length,
                 block_length, extensions, compression) -> None:

        self.bulk_alg = bulk_alg
        self.bulk_mode = bulk_mode
        self.mac_alg = mac_alg
        self.tls_version = tls_version
        self.key_length = key_length
        self.mac_length = mac_length
        self.tag_length = tag_length
        self.block_length = block_length
        self.compression_method = compression

        self.encrypt_then_mac = False
        if bytes.fromhex("0016") in extensions.keys():
            self.encrypt_then_mac = True
            logging.info("TLS-Extension 0x0016, using mac-then-encrypt")

        if self.tag_length is None:
            self.tag_length = 16
            logging.info("defaulting to Tag-Length")

        self.get_cipher_type()
        self.parse_keys(keys)

        self.client_seq = 0
        self.server_seq = 0

        if self.tls_version in [TlsVersion.TLS10, TlsVersion.SSL30]:
            self.last_block_server = self.server_iv
            self.last_block_client = self.client_iv

        if self.cipher_type == EncryptionType.Stream_Cipher and not self.bulk_alg == ChaCha20Poly1305:
            self.server_cipher = Cipher(self.bulk_alg(self.server_key), mode=None).decryptor()
            self.client_cipher = Cipher(self.bulk_alg(self.client_key), mode=None).decryptor()

        if self.compression_method == 1:
            self.s_decompressor = zlib.decompressobj(wbits=0)
            self.c_decompressor = zlib.decompressobj(wbits=0)

    def get_cipher_type(self):
        if self.bulk_alg in [AESCCM, AESGCM]:
            self.cipher_type = EncryptionType.AEAD
            logging.info("Using AEAD Cipher")
            return

        if self.bulk_alg in [AES, TripleDES, Camellia, IDEA]:
            self.cipher_type = EncryptionType.Block_Cipher
            logging.info("Using Block Cipher")
            return

        if self.bulk_alg in [ChaCha20, ChaCha20Poly1305, ARC4]:
            self.cipher_type = EncryptionType.Stream_Cipher
            logging.info("Using Stream Cipher")
            return

        logging.error("Cipher not implemented for decryption")
        self.cipher_type = EncryptionType.Unknown

    def parse_keys(self, keys):
        if self.tls_version == TlsVersion.TLS13:
            self.client_handshake_iv = keys["client_handshake_iv"]
            self.server_handshake_iv = keys["server_handshake_iv"]
            self.client_application_iv = keys["client_application_iv"]
            self.server_application_iv = keys["server_application_iv"]
            self.client_handshake_key = keys["client_handshake_traffic_secret"]
            self.server_handshake_key = keys["server_handshake_traffic_secret"]
            self.client_application_key = keys["client_application_traffic_secret_0"]
            self.server_application_key = keys["server_application_traffic_secret_0"]

            if keys["client_handshake_traffic_secret"] is None or keys[
                    "client_handshake_iv"] is None:  # If Handshake Secrets are not available
                self.client_handshake_key = keys["client_application_traffic_secret_0"]
                self.client_handshake_iv = keys["client_application_iv"]
                logging.warning("Missing Client Handshake Keys, "
                                "trying to decrypt with only application traffic secrets")
            if keys["server_handshake_traffic_secret"] is None or keys["server_handshake_iv"] is None:
                self.server_handshake_key = keys["server_application_traffic_secret_0"]
                self.server_handshake_iv = keys["server_application_iv"]
                logging.warning("Missing Server Handshake Keys, "
                                "trying to decrypt with only application traffic secrets")

            self.server_key = self.server_handshake_key
            self.client_key = self.client_handshake_key
            self.server_iv = self.server_handshake_iv
            self.client_iv = self.client_handshake_iv
        else:
            self.client_iv = keys["client_write_IV"]
            self.server_iv = keys["server_write_IV"]
            self.client_key = keys["client_write_key"]
            self.server_key = keys["server_write_key"]
            self.client_mac = keys["client_write_MAC_secret"]
            self.server_mac = keys["server_write_MAC_secret"]

    # AESGCM and CCM
    def decrypt_tls13_aead(self, record, isserver):
        logging.info("")
        logging.info("decrypting TLS 1.3 AEAD Record")

        record: TlsRecord
        associated_data = int.to_bytes(record.record_type, 1, 'big') + record.record_version + record.record_length

        logging.info(f"associated data: 0x{associated_data.hex()}")
        if isserver:
            key = self.server_key
            iv = self.server_iv
            seq = self.server_seq
            logging.info(f"decrypting as Server: Key: 0x{key.hex()}, "
                         f"Initialization Vector: 0x{iv.hex()} and Sequence Number: {seq}")
        else:
            key = self.client_key
            iv = self.client_iv
            seq = self.client_seq
            logging.info(f"decrypting as Client: Key: 0x{key.hex()}, "
                         f"Initialization Vector: 0x{iv.hex()} and Sequence Number: {seq}")

        nonce = byte_xor(iv, int(seq).to_bytes(8, 'big'))
        logging.info(f"generated Nonce: {nonce.hex()}")
        if self.bulk_alg == AESGCM:
            cipher = AESGCM(key)
            logging.info("algorithm: AESGCM")

        elif self.bulk_alg == AESCCM:
            cipher = AESCCM(key, self.tag_length)
            logging.info("algorithm: AESCCM")

        logging.info(f"ciphertext: {record.binary.hex()}")

        decrypted = cipher.decrypt(nonce, bytes(record.binary), associated_data)

        logging.info(f"plaintext: {decrypted}")

        if isserver:
            self.server_seq += 1

        else:
            self.client_seq += 1

        return decrypted

    def decrypt_tls13_stream_cipher(self, record, isserver):
        logging.info("")
        logging.info("decrypting TLS 1.3 Stream Cipher Record")
        logging.info("algorithm: ChaCha20")
        record: TlsRecord
        associated_data = int.to_bytes(record.record_type, 1, 'big') + record.record_version + record.record_length
        logging.info(f"associated data: 0x{associated_data.hex()}")
        if isserver:
            key = self.server_key
            iv = self.server_iv
            seq = self.server_seq
            logging.info(f"decrypting as Server: Key: 0x{key.hex()}, "
                         f"Initialization Vector: 0x{iv.hex()} and Sequence Number: {seq}")
        else:
            key = self.client_key
            iv = self.client_iv
            seq = self.client_seq
            logging.info(f"decrypting as Client: Key: 0x{key.hex()}, "
                         f"Initialization Vector: 0x{iv.hex()} and Sequence Number: {seq}")

        nonce = byte_xor(iv, int(seq).to_bytes(8, 'big'))
        logging.info(f"generated Nonce: {nonce.hex()}")
        cipher = ChaCha20Poly1305(key)

        logging.info(f"ciphertext: {record.binary.hex()}")

        decrypted = cipher.decrypt(nonce, bytes(record.binary), associated_data)

        logging.info(f"plaintext: {decrypted}")

        if isserver:
            self.server_seq += 1
        else:
            self.client_seq += 1

        return decrypted

    def decrypt_generic_stream_cipher(self, record, isserver):
        logging.info("")
        logging.info("decrypting stream cipher record")

        if isserver:
            cipher = self.server_cipher
            logging.info("decrypting as Server")
        else:
            cipher = self.client_cipher
            logging.info("decrypting as Client")
        logging.info(f"algorithm: {self.bulk_alg}, mode: {self.bulk_mode}")

        logging.info(f"ciphertext: {record.binary.hex()}")
        decrypted = cipher.update(bytes(record.binary))

        plaintext = decrypted[0:-self.mac_length]
        logging.info(f"decrypted with mac: {decrypted}")
        logging.info(f"plaintext: {plaintext}")
        return plaintext

    def decrypt_tls12_aead(self, record, isserver):
        logging.info("")
        logging.info("decrypting TLS 1.2 AEAD Record")
        ciphertext = record.binary
        logging.info(f"Ciphertext: {ciphertext}")
        if isserver:
            key = self.server_key
            iv = self.server_iv
            seq = self.server_seq
            logging.info(f"decrypting as Server: Key: 0x{key.hex()}, "
                         f"Initialization Vector: 0x{iv.hex()} and Sequence Number: {seq}")
        else:
            key = self.client_key
            iv = self.client_iv
            seq = self.client_seq
            logging.info(f"decrypting as Client: Key: 0x{key.hex()}, "
                         f"Initialization Vector: 0x{iv.hex()} and Sequence Number: {seq}")

        ciphertext_len = len(ciphertext) - 8 - self.tag_length
        associated_data = seq.to_bytes(8, 'big') + record.raw[:3] + ciphertext_len.to_bytes(2, 'big')
        logging.info(f"associated data: 0x{associated_data.hex()}")
        ciphertext = record.binary[8:]

        nonce = iv + record.binary[:8]
        logging.info(f"generated Nonce: {nonce.hex()}")

        if self.bulk_alg == AESGCM:
            cipher = AESGCM(key)
            logging.info("algorithm: AESGCM")
        elif self.bulk_alg == AESCCM:
            cipher = AESCCM(key, self.tag_length)
            logging.info("algorithm: AESCCM")

        logging.info(f"ciphertext: {record.binary.hex()}")
        decrypted = cipher.decrypt(nonce, bytes(ciphertext), associated_data)
        if isserver:
            self.server_seq += 1
        else:
            self.client_seq += 1

        if self.compression_method == 0x01:
            logging.info(f"compressed plaintext: {decrypted}")
            decrypted = self.inflate(decrypted, isserver)

        logging.info(f"plaintext: {decrypted}")

        return decrypted

    def decrypt_tls12_block_cipher(self, record, isserver):
        logging.info("")
        logging.info("decrypting block cipher Record for TLS 1.1 or TLS 1.2")
        if isserver:
            key = self.server_key
            logging.info(f"decrypting as server")
        else:
            key = self.client_key
            logging.info(f"decrypting as client")

        if self.bulk_alg == AES:
            cipher_alg = AES(key)
            block_size = 16
            logging.info(f"algorithm: AES")
        elif self.bulk_alg == TripleDES:
            cipher_alg = TripleDES(key)
            block_size = 8
            logging.info(f"algorithm: 3DES")
        elif self.bulk_alg == Camellia:
            cipher_alg = Camellia(key)
            block_size = 16
            logging.info(f"algorithm: Camellia")
        elif self.bulk_alg == IDEA:
            cipher_alg = IDEA(key)
            block_size = 8
            logging.info(f"algorithm: IDEA")
        iv = record.binary[:block_size]

        logging.info(f"Key: {key}, Initialization Vector: {iv}")

        ciphertext = record.binary[block_size:]
        logging.info(f"ciphertext: {ciphertext.hex()}")

        if self.encrypt_then_mac:
            ciphertext = ciphertext[:-self.mac_length]
            logging.info(f"ciphertext without mac: {ciphertext.hex()}")

        cipher = Cipher(cipher_alg, CBC(iv))
        decryptor = cipher.decryptor()

        decrypted = decryptor.update(ciphertext) + decryptor.finalize()
        logging.info(f"decrypted ciphertext with padding {decrypted}")

        padding_length = decrypted[-1]
        decrypted = decrypted[:-(padding_length + 1)]

        if not self.encrypt_then_mac:
            logging.info(f"decrypted ciphertext with mac, without padding: {ciphertext}")
            decrypted = decrypted[:-self.mac_length]


        if self.compression_method == 0x01:
            logging.info(f"compressed plaintext: {decrypted}")
            decrypted = self.inflate(decrypted, isserver)

        logging.info(f"plaintext: {decrypted}")
        return decrypted

    def decrypt_tls12_chacha20(self, record, isserver):
        logging.info("")
        logging.info("decrypting TLS 1.2 Stream Cipher Record")
        logging.info("algorithm: ChaCha20")
        if isserver:
            key = self.server_key
            iv = self.server_iv
            seq = self.server_seq
            logging.info(f"decrypting as Server: Key: 0x{key.hex()}, "
                         f"Initialization Vector: 0x{iv.hex()} and Sequence Number: {seq}")
        else:
            key = self.client_key
            iv = self.client_iv
            seq = self.client_seq
            logging.info(f"decrypting as Client: Key: 0x{key.hex()}, "
                         f"Initialization Vector: 0x{iv.hex()} and Sequence Number: {seq}")

        associated_data = seq.to_bytes(8, 'big') + record.record_type.to_bytes(1, 'big') + record.record_version + (
                len(record.binary) - 16).to_bytes(2, 'big')
        logging.info(f"associated data: {associated_data}")

        nonce = byte_xor(iv, int(seq).to_bytes(8, 'big'))
        logging.info(f"nonce: {nonce}")

        cipher = ChaCha20Poly1305(key)

        logging.info(f"ciphertext: {record.binary.hex()}")
        decrypted = cipher.decrypt(bytes(nonce), bytes(record.binary), associated_data)

        if isserver:
            self.server_seq += 1
        else:
            self.client_seq += 1

        if self.compression_method == 0x01:
            logging.info(f"compressed plaintext: {decrypted}")
            decrypted = self.inflate(decrypted, isserver)

        logging.info(f"plaintext: {decrypted}")

        return decrypted

    def decrypt_last_block_iv_cbc(self, record, isserver):
        logging.info("")
        logging.info("decrypting generic block cipher Record")
        logging.info(f"algorithm: {self.bulk_alg}, mode: {self.bulk_mode}")
        if isserver:
            key = self.server_key
            iv = self.last_block_server
            logging.info(f"decrypting as Server: Key: 0x{key.hex()}, "
                         f"Initialization Vector: 0x{iv.hex()}")
        else:
            key = self.client_key
            iv = self.last_block_client
            logging.info(f"decrypting as Client: Key: 0x{key.hex()}, "
                         f"Initialization Vector: 0x{iv.hex()}")

        cipher = Cipher(self.bulk_alg(key), CBC(iv))
        decryptor = cipher.decryptor()

        ciphertext = record.binary

        if self.encrypt_then_mac:
            logging.info(f"ciphertext with mac: {ciphertext}")
            ciphertext = ciphertext[:-self.mac_length]

        logging.info(f"ciphertext: {ciphertext}")

        decrypted = decryptor.update(ciphertext) + decryptor.finalize()
        logging.info(f"decrypted: {decrypted}")
        padding_len = decrypted[-1]

        plaintext = decrypted[:-(padding_len + 1)]

        logging.info(f"decrypted without padding: {plaintext}")

        if not self.encrypt_then_mac:
            plaintext = plaintext[:-self.mac_length]
        logging.info(f"plaintext: {plaintext}")
        if isserver:
            index = int(self.block_length / 8)
            self.last_block_server = ciphertext[-index:]
        else:
            index = int(self.block_length / 8)
            self.last_block_client = ciphertext[-index:]

        if self.compression_method == 0x01:
            logging.info(f"compressed plaintext: {plaintext}")
            plaintext = self.inflate(plaintext, isserver)

        logging.info(f"plaintext: {plaintext}")

        logging.info(f"last cipher block iv: {ciphertext[-index:]}")
        return plaintext

    def decrypt(self, record, isserver):
        # TLS 1.3 AEAD Cipher
        if self.tls_version == TlsVersion.TLS13 and self.cipher_type == EncryptionType.AEAD:
            return self.decrypt_tls13_aead(record, isserver)
        # TLS 1.3 Steam Cipher
        elif self.tls_version == TlsVersion.TLS13:
            return self.decrypt_tls13_stream_cipher(record, isserver)
        # TLS 1.2 CHACHA20
        elif self.tls_version == TlsVersion.TLS12 and self.bulk_alg == ChaCha20Poly1305:
            return self.decrypt_tls12_chacha20(record, isserver)
        # SSL 3.0 - TLS 1.2 Stream Cipher
        elif self.cipher_type == EncryptionType.Stream_Cipher:
            return self.decrypt_generic_stream_cipher(record, isserver)
        elif self.cipher_type == EncryptionType.AEAD:
            return self.decrypt_tls12_aead(record, isserver)
        elif self.cipher_type == EncryptionType.Block_Cipher and self.tls_version in [TlsVersion.TLS12,
                                                                                      TlsVersion.TLS11]:
            return self.decrypt_tls12_block_cipher(record, isserver)
        elif self.cipher_type == EncryptionType.Block_Cipher and self.tls_version in [TlsVersion.TLS10,
                                                                                      TlsVersion.SSL30]:
            return self.decrypt_last_block_iv_cbc(record, isserver)

    def update_keys(self, isserver):
        if isserver:
            logging.info("")
            logging.info("Updating keys from handshake keys to application keys for server")
            logging.info(f"Key: 0x{self.server_handshake_key.hex()} -> 0x{self.server_application_key.hex()}")
            logging.info(f"Iv: 0x{self.server_handshake_iv.hex()} -> 0x{self.server_application_iv.hex()}")
            self.server_key = self.server_application_key
            self.server_iv = self.server_application_iv
            self.server_seq = 0
        else:
            logging.info("")
            logging.info("Updating keys from handshake keys to application keys for client")
            logging.info(f"Key: 0x{self.client_handshake_key.hex()} -> 0x{self.client_application_key.hex()}")
            logging.info(f"Iv: 0x{self.client_handshake_iv.hex()} -> 0x{self.client_application_iv.hex()}")
            self.client_key = self.client_application_key
            self.client_iv = self.client_application_iv
            self.client_seq = 0

    def inflate(self, data, isserver):
        if isserver:
            decompressor = self.s_decompressor
        else:
            decompressor = self.c_decompressor

        inflated = decompressor.decompress(data)
        inflated += decompressor.flush()
        return inflated


def byte_xor(a, b):
    diff = len(a) - len(b)
    b_padded = bytes(diff) + b

    xor_out = bytearray(b'')

    for i in range(len(a)):
        xor_out.append(a[i] ^ b_padded[i])

    return xor_out




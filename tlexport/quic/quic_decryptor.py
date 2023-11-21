from cryptography.hazmat.primitives.ciphers.aead import AESCCM, AESGCM, ChaCha20Poly1305


class QuicDecryptor:
    def __init__(self, keys, bulk_cipher):
        self.server_key = keys[0]
        self.server_iv = keys[1]
        self.client_key = keys[2]
        self.client_iv = keys[3]

        self.server_bulk_cipher = bulk_cipher(self.server_key)
        self.client_bulk_cipher = bulk_cipher(self.client_key)

    # associated data: Quic Header from first byte up to and including the unprotected Packet Number
    def decrypt(self, ciphertext: bytes, packet_number: int, associated_data: bytes, isserver: bool):
        if isserver:
            decryptor = self.server_bulk_cipher
            iv = self.server_iv
        else:
            decryptor = self.client_bulk_cipher
            iv = self.client_iv

        packet_number = packet_number.to_bytes(12, 'big', signed=False)

        nonce = bytes([_a ^ _b for _a, _b in zip(packet_number, iv)])

        return decryptor.decrypt(nonce, ciphertext, associated_data)

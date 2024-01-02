import logging
from typing import Type, cast

import pylsqpack
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305, AESCCM
from cryptography.hazmat.primitives.hashes import SHA256, SHA384

from tlexport.keylog_reader import Key
from tlexport.packet import Packet
from tlexport.quic.quic_decryptor import QuicDecryptor
from tlexport.quic.quic_frame import Frame
from tlexport.quic.quic_key_generation import dev_quic_keys, dev_initial_keys
from tlexport.quic.quic_packet import QuicPacket, ShortQuicPacket, LongQuicPacket, QuicPacketType


class QuicSession:
    def __init__(self, packet: Packet, quic_packet: QuicPacket, server_ports, keylog: list[Key], portmap):
        self.keylog = keylog

        self.ipv6: bool = packet.ipv6_packet

        self.set_server_client_address(packet, server_ports)

        self.client_cids = []
        self.server_cids = []

        self.server_frame_buffer = []
        self.client_frame_buffer = []

        self.packet_buffer_quic = []
        self.packet_buffer_quic.append(quic_packet)

        secret_list = []

        self.epoch_client = 0
        self.epoch_server = 0

        self.output_buffer = []

        self.decryptors = {}
        self.keys: dict[str, bytes] = {}

        self.can_decrypt = True

        self.hash_fun = None
        self.cipher = None
        self.key_length = None

        self.early_traffic_keys = False

        self.application_data: list[list[bytes, Type[Frame], bool]] = []

        self.handle_packets()

    def decrypt(self):
        pass

    def decrypt_packet(self, quic_packet: type[QuicPacket]):
        decryptor: QuicDecryptor = None
        # decrypt 1-RTT
        if type(quic_packet) == ShortQuicPacket:
            quic_packet = cast(ShortQuicPacket, quic_packet)
            pass

        else:
            quic_packet = cast(LongQuicPacket, quic_packet)
            match quic_packet.packet_type:
                case QuicPacketType.INITIAL:
                    decryptor = self.decryptors["Initial"]
                case QuicPacketType.HANDSHAKE:
                    decryptor = self.decryptors["Handshake"]
                case QuicPacketType.RTT_O:
                    decryptor = self.decryptors["Early"]

            payload = decryptor.decrypt(quic_packet.payload, quic_packet.packet_num, )

    def handle_packets(self):
        for quic_packet in self.packet_buffer_quic:
            self.decrypt_packet(quic_packet)

    def set_server_client_address(self, packet,
                                  server_ports) -> bool:  # Returns True if packet is from server, else it returns False
        if packet.sport in server_ports:
            self.server_ip = packet.ip_src
            self.server_port = packet.sport
            self.server_mac_addr = packet.ethernet_src

            self.client_ip = packet.ip_dst
            self.client_port = packet.dport
            self.client_mac_addr = packet.ethernet_dst

            return True

        else:
            self.server_ip = packet.ip_dst
            self.server_port = packet.dport
            self.server_mac_addr = packet.ethernet_dst

            self.client_ip = packet.ip_src
            self.client_port = packet.sport
            self.client_mac_addr = packet.ethernet_src

            return False

    def match_cid(self, data: bytes) -> tuple | None:   # Returns (cid, 0) if cid is from client, (cid, 1) if cid is from server
        for cid in self.client_cids + self.server_cids:
            print(bytearray(data[1: len(cid) + 1]))
            if bytearray(data[1: len(cid) + 1]) == cid:    # Offset of 1 cause the dcid of a short header packet starts there
                if cid in self.client_cids:
                    return cid, 0
                elif cid in self.server_cids:
                    return cid, 1
                else:
                    return None  # CID is unknown/not found

    def matches_session_dgram(self, ip_src, ip_dst, sport, dport):

        if (ip_src == self.server_ip and sport == self.server_port
                and ip_dst == self.client_ip and dport == self.client_port):
            return True

        elif (ip_src == self.client_ip and sport == self.client_port
              and ip_dst == self.server_ip and dport == self.server_port):
            return True
        return False

    def matches_session_quic(self, cid):
        if cid in self.client_cids + self.server_cids:
            return True
        else:
            return False

    def set_initial_decryptor(self, dcid: bytes):
        keys: dict[str, bytes] = dev_initial_keys(dcid)

        dec_keys = [
            keys["server_initial_key"],
            keys["server_initial_iv"],
            keys["client_initial_key"],
            keys["client_initial_iv"]
        ]

        dec = QuicDecryptor(dec_keys, AESGCM)

        self.keys += keys
        self.decryptors["Initial"] = dec

    def set_tls_decryptors(self, client_random, ciphersuite: bytes):

        match ciphersuite:
            # TLS_AES_128_GCM_SHA256
            case b"\x13\x01":
                self.hash_fun = SHA256
                self.cipher = AESGCM
                self.key_length = 16

            # TLS_AES_256_GCM_SHA384
            case b"\x13\x02":
                self.hash_fun = SHA384
                self.cipher = AESGCM
                self.key_length = 32

            # TLS_CHACHA20_POLY1305_SHA256
            case b"\x13\x03":
                self.hash_fun = SHA256
                self.cipher = ChaCha20Poly1305
                self.key_length = 32

            # TLS_AES_128_CCM_SHA256
            case b"\x13\x04":
                self.hash_fun = SHA256
                self.cipher = AESCCM
                self.key_length = 16

            case _:
                logging.error(f"Unknown Ciphersuite: {ciphersuite.hex()}")
                self.can_decrypt = False
                return

        session_keys = []

        key: Key
        for key in self.keylog:
            if key.client_random == client_random:
                session_keys.append(key)

        keys = dev_quic_keys(self.key_length, session_keys, self.hash_fun())

        self.keys += keys
        try:
            self.decryptors["Handshake"] = QuicDecryptor(
                [keys["server_handshake_key"], keys["server_handshake_iv"], keys["client_handshake_key"],
                 keys["client_handshake_iv"]], self.cipher)
        except:
            self.can_decrypt = False
            logging.error("Missing Key Material")
            return

        try:
            self.decryptors["Application"] = [QuicDecryptor(
                [keys["server_application_key"], keys["server_application_iv"], keys["client_application_key"],
                 keys["client_application_iv"]], self.cipher)]
        except:
            self.can_decrypt = False
            logging.error("Missing Key Material")
            return

        try:
            self.decryptors["Early"] = QuicDecryptor(
                [keys["server_early_key"], keys["server_early_iv"], keys["client_early_key"],
                 keys["client_early_iv"]], self.cipher)
            self.early_traffic_keys = True
        except:
            logging.warning("No Early Traffic Secrets")

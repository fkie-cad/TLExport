import logging
from typing import Type, cast

from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305, AESCCM
from cryptography.hazmat.primitives.hashes import SHA256, SHA384

from tlexport.keylog_reader import Key
from tlexport.packet import Packet
from tlexport.quic.quic_decryptor import QuicDecryptor
from tlexport.quic.quic_frame import CryptoFrame, StreamFrame, NewConnectionIdFrame, ConnectionCloseFrame, Frame, \
    parse_frames
from tlexport.quic.quic_key_generation import dev_quic_keys, dev_initial_keys, key_update
from tlexport.quic.quic_packet import QuicPacket, ShortQuicPacket, LongQuicPacket, QuicPacketType
from tlexport.quic.quic_tls_parser import QuicTlsSession
from tlexport.quic.quic_dissector import get_quic_header_data

PACKET_TYPE_MAP = {
    QuicPacketType.INITIAL: (QuicPacketType.INITIAL,),
    QuicPacketType.HANDSHAKE: (QuicPacketType.HANDSHAKE,),
    QuicPacketType.RTT_O: (QuicPacketType.RTT_1, QuicPacketType.RTT_O),
    QuicPacketType.RTT_1: (QuicPacketType.RTT_1, QuicPacketType.RTT_O)
}


class QuicSession:
    def __init__(self, packet: Packet, server_ports, keylog: list[Key], portmap):
        self.keylog = keylog

        self.set_server_client_address(packet, server_ports)

        self.ipv6: bool = packet.ipv6_packet

        self.client_cids = set()
        self.server_cids = set()

        self.server_frame_buffer = []
        self.client_frame_buffer = []

        self.packet_buffer_quic = []

        self.epoch_client = 0
        self.epoch_server = 0

        self.last_key_phase_server = 0
        self.last_key_phase_client = 0

        self.decryptors = {}
        self.keys: dict[str, bytes] = {}

        self.can_decrypt = True

        self.hash_fun = None
        self.cipher = None
        self.key_length = None

        self.alpn = None

        self.early_traffic_keys = False

        self.tls_session = QuicTlsSession()

        self.application_data: list[list[bytes, Type[Frame], bool]] = []

        self.packet_number_server = None
        self.packet_number_client = None
        self.buffer_spaces_server = None
        self.buffer_spaces_client = None

        self.set_packet_number_spaces()

    # reset Quic Session Parameters, except output buffer and Socket Addresses
    def reset(self):
        self.client_cids = []
        self.server_cids = []

        self.server_frame_buffer = []
        self.client_frame_buffer = []

        self.packet_buffer_quic = []

        self.epoch_client = 0
        self.epoch_server = 0

        self.last_key_phase_server = 0
        self.last_key_phase_client = 0

        self.decryptors = {}
        self.keys: dict[str, bytes] = {}

        self.can_decrypt = True

        self.hash_fun = None
        self.cipher = None
        self.key_length = None

        self.alpn = None

        self.early_traffic_keys = False

        self.tls_session = QuicTlsSession()

        self.application_data: list[list[bytes, Type[Frame], bool]] = []

        self.packet_number_server: dict[tuple[QuicPacketType, QuicPacketType], int] = {}
        self.packet_number_client: dict[tuple[QuicPacketType, QuicPacketType], int] = {}
        self.buffer_spaces_server = {}
        self.buffer_spaces_client = {}

        self.set_packet_number_spaces()

    def decrypt(self):
        pass

    def set_packet_number_spaces(self):
        # RTT_1 and RTT_0 are in same packet_number space 12.3
        self.packet_number_server = {(QuicPacketType.INITIAL,): 0, (QuicPacketType.HANDSHAKE,): 0,
                                     (QuicPacketType.RTT_1, QuicPacketType.RTT_O): 0}
        self.packet_number_client = {(QuicPacketType.INITIAL,): 0, (QuicPacketType.HANDSHAKE,): 0,
                                     (QuicPacketType.RTT_1, QuicPacketType.RTT_O): 0}

        self.buffer_spaces_server = {(QuicPacketType.INITIAL,): [], (QuicPacketType.HANDSHAKE,): [],
                                     (QuicPacketType.RTT_1, QuicPacketType.RTT_O): []}
        self.buffer_spaces_client = {(QuicPacketType.INITIAL,): [], (QuicPacketType.HANDSHAKE,): [],
                                     (QuicPacketType.RTT_1, QuicPacketType.RTT_O): []}

    def handle_crypto_frame(self, frame: CryptoFrame):
        self.tls_session.update_session(frame)
        if self.tls_session.new_data:
            if self.tls_session.client_random is not None and self.tls_session.ciphersuite is not None:
                self.set_tls_decryptors(self.tls_session.client_random, self.tls_session.ciphersuite)
            self.alpn = self.tls_session.alpn
            self.tls_session.new_data = False

    def handle_frame(self, frame: Frame):
        isserver = frame.src_packet.isserver
        # CRYPTO, STREAM,  NEW_CONNECTION_ID, CONNECTION_CLOSE
        match frame:
            case CryptoFrame():
                frame = cast(CryptoFrame, frame)
                self.handle_crypto_frame(frame)

            case StreamFrame():
                self.output_buffer.append(frame)

            case NewConnectionIdFrame():
                frame = cast(NewConnectionIdFrame, frame)
                if isserver:
                    self.server_cids.add(frame.connection_id)
                else:
                    self.client_cids.add(frame.connection_id)
            case ConnectionCloseFrame():
                pass

    def check_key_epoch(self, key_phase_bit, isserver):
        if isserver:
            if self.last_key_phase_server != key_phase_bit:
                self.epoch_server += 1
                self.last_key_phase_server = key_phase_bit
        else:
            if self.last_key_phase_client != key_phase_bit:
                self.epoch_client += 1
                self.last_key_phase_client = key_phase_bit

        if self.epoch_client == len(self.decryptors["Application"]) or self.epoch_server == len(
                self.decryptors["Application"]):
            new_decryptor = key_update(self.decryptors["Application"][-1], self.hash_fun, self.key_length, self.cipher)
            self.decryptors["Application"].append(new_decryptor)

    def decrypt_packet(self, quic_packet: type[QuicPacket]):
        decryptor: QuicDecryptor
        if isinstance(quic_packet, ShortQuicPacket):
            quic_packet = cast(ShortQuicPacket, quic_packet)
            self.check_key_epoch(quic_packet.key_phase, quic_packet.isserver)

            if quic_packet.isserver:
                decryptor = self.decryptors["Application"][self.epoch_server]
            else:
                decryptor = self.decryptors["Application"][self.epoch_client]

        else:
            quic_packet = cast(LongQuicPacket, quic_packet)
            match quic_packet.packet_type:
                case QuicPacketType.INITIAL:
                    decryptor = self.decryptors["Initial"]
                case QuicPacketType.HANDSHAKE:
                    decryptor = self.decryptors["Handshake"]
                case QuicPacketType.RTT_O:
                    decryptor = self.decryptors["Early"]
        try:
            packet_number = self.get_full_packet_number(quic_packet)

            # payload = decryptor.decrypt(quic_packet.payload, packet_number, quic_packet, quic_packet.isserver)
            payload = b""

            frames = parse_frames(payload, quic_packet)

            for frame in frames:
                self.handle_frame(frame)

        except:
            logging.warning(f"Could not decrypt Quic Packet: {quic_packet.dcid}")

    def handle_packet(self, packet: Packet, dcid: bytes):
        if "Initial" not in self.decryptors.keys():
            self.set_initial_decryptor(dcid)

        # TODO extract QUIC-Packets
        quic_packets = get_quic_header_data(packet, False)

        self.handle_packets()

    def handle_packets(self):
        for quic_packet in self.packet_buffer_quic:
            if quic_packet.packet_type not in [QuicPacketType.RETRY, QuicPacketType.VERSION_NEG]:
                self.decrypt_packet(quic_packet)

            if quic_packet.packet_type == QuicPacketType.RETRY:
                self.tls_session = QuicTlsSession()
                self.decryptors = {}
                self.keys: dict[str, bytes] = {}

                self.hash_fun = None
                self.cipher = None
                self.key_length = None

                self.alpn = None

            if quic_packet.packet_type == QuicPacketType.INITIAL:
                if quic_packet.isserver:
                    self.server_cids.add(quic_packet.scid)
                    self.client_cids.add(quic_packet.dcid)
                else:
                    self.client_cids.add(quic_packet.scid)
                    self.server_cids.add(quic_packet.dcid)

    def set_server_client_address(self, packet, server_ports) -> bool:
        # Returns True if packet is from server, else it returns False
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

        self.keys.update(keys)
        self.decryptors["Initial"] = dec

    def get_full_packet_number(self, quic_packet: ShortQuicPacket | LongQuicPacket) -> int:
        if quic_packet.isserver:
            largest_pkn = self.packet_number_server[PACKET_TYPE_MAP[quic_packet.packet_type]]
        else:
            largest_pkn = self.packet_number_client[PACKET_TYPE_MAP[quic_packet.packet_type]]

        truncated_pkn = quic_packet.packet_num
        truncated_pkn_len = quic_packet.packet_num_len

        pkn_len_bits = truncated_pkn_len * 8

        expected_pkn = largest_pkn + 1
        pkn_window = 1 << pkn_len_bits
        pkn_hwindow = pkn_window / 2
        pkn_mask = pkn_window - 1

        candidate_pkn = (expected_pkn & ~pkn_mask) | truncated_pkn
        if candidate_pkn <= expected_pkn - pkn_hwindow and candidate_pkn < (1 << 62) - pkn_window:
            return candidate_pkn + pkn_window
        if candidate_pkn > expected_pkn + pkn_hwindow and candidate_pkn >= pkn_window:
            return candidate_pkn - pkn_window

        if candidate_pkn > largest_pkn:
            if quic_packet.isserver:
                self.packet_number_server[PACKET_TYPE_MAP[quic_packet.packet_type]] = candidate_pkn
            else:
                self.packet_number_client[PACKET_TYPE_MAP[quic_packet.packet_type]] = candidate_pkn

        return candidate_pkn

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

        self.keys.update(keys)
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
                 keys["client_application_iv"], keys["server_application_sec"], keys["client_application_sec"]],
                self.cipher)]
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

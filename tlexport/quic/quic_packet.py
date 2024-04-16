from enum import Enum


class QuicPacketType(Enum):
    INITIAL = 0x00
    RTT_O = 0x01
    RTT_1 = "RTT_1"
    HANDSHAKE = 0x02
    RETRY = 0x03

    VERSION_NEG = "VERSION_NEGOTIATION"


class QuicHeaderType(Enum):
    SHORT = 0x00
    LONG = 0x01

    VERSION_NEG = "VERSION_NEGOTIATION"


class QuicPacket:
    def __init__(self, header_type: QuicHeaderType, packet_type: QuicPacketType, isserver: bool, first_byte: bytes, ts: int):
        self.header_type = header_type
        self.packet_type = packet_type
        self.isserver = isserver
        self.first_byte = first_byte
        self.ts = ts


class LongQuicPacket(QuicPacket):
    def __init__(self, packet_type: QuicPacketType, version: bytes, dcid_len: bytes, dcid: bytes, scid_len: bytes,
                 scid: bytes, first_byte: bytes, ts: int,
                 packet_len: bytes = None, packet_len_bytes: bytes = None, packet_num: bytes = None, payload: bytes = None, token_len: int = None,
                 token_len_bytes: bytes = None, token: bytes = None,
                 retry_token: bytes = None, retry_integ_tag: bytes = None, isserver: bool = False, supported_version: bytes = None):

        super().__init__(QuicHeaderType.LONG, packet_type, isserver, first_byte, ts)
        self.version = version
        self.dcid_len = dcid_len
        self.dcid = dcid
        self.scid_len = scid_len
        self.scid = scid

        match packet_type:
            case QuicPacketType.INITIAL:
                self.token_len = token_len
                self.token_len_bytes = token_len_bytes
                self.token = token
                self.packet_len = packet_len
                self.packet_len_bytes = packet_len_bytes
                self.packet_num = packet_num
                self.payload = payload

            case QuicPacketType.HANDSHAKE | QuicPacketType.RTT_O:  # handshake and RTT-0 have same structure
                self.packet_len = packet_len
                self.packet_num = packet_num
                self.packet_len_bytes = packet_len_bytes
                self.payload = payload

            case QuicPacketType.RETRY:
                self.retry_token = retry_token
                self.retry_integ_tag = retry_integ_tag

            case QuicPacketType.VERSION_NEG:
                self.supported_version = supported_version


class ShortQuicPacket(QuicPacket):

    # init for 1-RTT Packet
    def __init__(self, packet_type: QuicPacketType, key_phase: int, dcid: bytes, packet_num: int, payload: bytes,
                 isserver: bool, first_byte: bytes, ts: int):
        super().__init__(QuicHeaderType.SHORT, packet_type, isserver, first_byte, ts)
        self.key_phase = key_phase
        self.dcid = dcid
        self.packet_num = packet_num
        self.payload = payload

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
    def __init__(self, header_type: QuicHeaderType, packet_type: QuicPacketType, isserver: bool):
        self.header_type = header_type
        self.packet_type = packet_type
        self.isserver = isserver


class LongQuicPacket(QuicPacket):
    def __init__(self, packet_type: QuicPacketType, version: int, dcid_len: int, dcid: bytes, scid_len: int, scid: bytes,
                 packet_len: int = None, packet_num: int = None, payload: bytes = None, token_len: int = None, token: bytes = None,
                 retry_token: bytes = None, retry_integ_tag: bytes = None, isserver: bool = False):

        super().__init__(QuicHeaderType.LONG, packet_type, isserver)
        self.version = version
        self.dcid_len = dcid_len
        self.dcid = dcid
        self.scid_len = scid_len
        self.scid = scid

        match packet_type:
            case QuicPacketType.INITIAL:
                self.token_len = token_len
                self.token = token
                self.packet_len = packet_len
                self.packet_num = packet_num
                self.payload = payload

            case [QuicPacketType.HANDSHAKE, QuicPacketType.RTT_O]:  # handshake and RTT-0 have same structure
                self.packet_len = packet_len
                self.packet_num = packet_num
                self.payload = payload

            case QuicPacketType.RETRY:
                self.retry_token = retry_token
                self.retry_integ_tag = retry_integ_tag


class ShortQuicPacket(QuicPacket):

    # init for 1-RTT Packet
    def __init__(self, packet_type: QuicPacketType, key_phase: int, dcid: bytes, packet_num: int, payload: bytes, isserver: bool):
        super().__init__(QuicHeaderType.SHORT, packet_type, isserver)
        self.key_phase = key_phase
        self.dcid = dcid
        self.packet_num = packet_num
        self.payload = payload


class VersionNegotiationPacket(QuicPacket):

    def __init__(self, supported_version: int):
        super().__init__(QuicHeaderType.VERSION_NEG, QuicPacketType.VERSION_NEG)
        self.supported_version = supported_version

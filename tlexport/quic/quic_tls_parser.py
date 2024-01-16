from tlexport.quic.quic_frame import CryptoFrame
from tlexport.quic.quic_packet import QuicPacketType


# the Quic Session shall create only one Quic TLS Session at a time,
# when a new Quic Session is registered the Quic TLS Session must be discarded
class QuicTlsSession:
    def __init__(self):
        self.ciphersuite = None
        self.client_random = None
        self.alpn = None
        self.tls_vers = None
        self.new_data = False

        self.server_offset = {QuicPacketType.INITIAL: 0, QuicPacketType.RTT_O: 0, QuicPacketType.RTT_1: 0, QuicPacketType.HANDSHAKE: 0}
        self.client_offset = {QuicPacketType.INITIAL: 0, QuicPacketType.RTT_O: 0, QuicPacketType.RTT_1: 0, QuicPacketType.HANDSHAKE: 0}

        self.server_frame_buffer: dict[QuicPacketType, list[CryptoFrame]] = {QuicPacketType.INITIAL: [], QuicPacketType.RTT_O: [], QuicPacketType.RTT_1: [], QuicPacketType.HANDSHAKE: []}
        self.client_frame_buffer: dict[QuicPacketType, list[CryptoFrame]] = {QuicPacketType.INITIAL: [], QuicPacketType.RTT_O: [], QuicPacketType.RTT_1: [], QuicPacketType.HANDSHAKE: []}

        self.server_buffer = {QuicPacketType.INITIAL: b"", QuicPacketType.RTT_O: b"", QuicPacketType.RTT_1: b"", QuicPacketType.HANDSHAKE: b""}
        self.client_buffer = {QuicPacketType.INITIAL: b"", QuicPacketType.RTT_O: b"", QuicPacketType.RTT_1: b"", QuicPacketType.HANDSHAKE: b""}

    def update_session(self, frame: CryptoFrame):
        if frame.src_packet.isserver:
            self.server_frame_buffer[frame.src_packet.packet_type].append(frame)
            self.server_frame_buffer[frame.src_packet.packet_type].sort(key=lambda x: x.offset)

            for crypto_frame in self.server_frame_buffer[frame.src_packet.packet_type]:
                if crypto_frame.offset == self.server_offset[frame.src_packet.packet_type]:
                    self.server_buffer[frame.src_packet.packet_type] += crypto_frame.crypto
                    self.server_offset[frame.src_packet.packet_type] += crypto_frame.crypto_length
                    self.server_frame_buffer[frame.src_packet.packet_type].remove(crypto_frame)

            self.handle_buffer(True)
        else:
            self.client_frame_buffer[frame.src_packet.packet_type].append(frame)
            self.client_frame_buffer[frame.src_packet.packet_type].sort(key=lambda x: x.offset)

            for crypto_frame in self.client_frame_buffer[frame.src_packet.packet_type]:
                if crypto_frame.offset == self.client_offset[frame.src_packet.packet_type]:
                    self.client_buffer[frame.src_packet.packet_type] += crypto_frame.crypto
                    self.client_offset[frame.src_packet.packet_type] += crypto_frame.crypto_length
                    self.client_frame_buffer[frame.src_packet.packet_type].remove(crypto_frame)

            self.handle_buffer(False)

    def handle_buffer(self, isserver):
        for quic_packet_type in [QuicPacketType.INITIAL, QuicPacketType.RTT_O, QuicPacketType.RTT_1, QuicPacketType.HANDSHAKE]:
            if isserver:
                buffer = self.server_buffer[quic_packet_type]
            else:
                buffer = self.client_buffer[quic_packet_type]

            while True:
                if len(buffer) <= 4:
                    break

                record_len = int.from_bytes(buffer[1:4], 'big', signed=False)

                if len(buffer) < 4 + record_len:
                    break
                self.handle_record(buffer[0], buffer[:4 + record_len])

                buffer = buffer[4 + record_len:]

                if isserver:
                    self.server_buffer[quic_packet_type] = buffer
                else:
                    self.client_buffer[quic_packet_type] = buffer

    def handle_client_hello(self, record):
        if len(record) < 38:
            return

        record = record[4:]
        self.tls_vers = record[:2]
        self.client_random = record[2:34]
        self.new_data = True

    def handle_server_hello(self, record):
        if len(record) < 44:
            return

        session_id_length = record[38]
        record = record[39 + session_id_length:]
        self.ciphersuite = record[:2]
        record = record[3:]

        self.get_extensions(record)
        self.new_data = True

    def handle_encrypted_extensions(self, record):
        if len(record) < 6:
            return

        self.get_extensions(record[4:])
        self.new_data = True

    def get_extensions(self, record):
        if len(record[2:]) != int.from_bytes(record[:2], 'big', signed=False):
            return
        record = record[2:]

        extensions = []
        while True:

            if len(record) < 4:
                break

            extension_type = record[:2]
            extension_length = int.from_bytes(record[2:4], 'big', signed=False)

            if len(record) < 4 + extension_length:
                break

            extension_body = record[4:4 + extension_length]

            extensions.append((extension_type, extension_length, extension_body))

            record = record[4 + extension_length:]

        for e_type, e_length, e_body in extensions:
            match int.from_bytes(e_type, "big", signed=False):
                case 43:
                    if e_length != 2:
                        continue
                    self.tls_vers = e_body
                case 16:
                    if e_length < 3:
                        continue
                    alpn_length = e_body[2]

                    if len(e_body) != 3 + alpn_length:
                        continue
                    self.alpn = e_body[3:3 + alpn_length]

    # Only Handshake Messages are carried in Crypto frames, alerts are Handled by QUIC
    def handle_record(self, record_type, record):
        match record_type:
            case 1:
                self.handle_client_hello(record)
            case 2:
                self.handle_server_hello(record)
            case 8:
                self.handle_encrypted_extensions(record)

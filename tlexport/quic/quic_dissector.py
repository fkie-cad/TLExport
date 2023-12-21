import struct

import dpkt
from enum import Enum
from tlexport.packet import Packet
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers.algorithms import AES
from cryptography.hazmat.primitives.ciphers.aead import AESCCM, AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.ciphers.modes import ECB
from cryptography.hazmat.primitives.hashes import SHA256
from tlexport.quic import quic_decode, quic_key_generation, quic_packet
from tlexport.quic.quic_packet import LongQuicPacket, ShortQuicPacket, QuicPacketType, QuicHeaderType


class QuicDissector:

    def __init__(self) -> None:
        self.follow_up_packet = 1
        self.packet_buf = []

    def get_quic_header_data(self, packet: Packet, isserver):

        self.isserver = isserver
        self.packet_buf = []
        self.follow_up_packet = 1

        datagram_data = packet.tls_data
        print(datagram_data.hex())

        try:
            while self.follow_up_packet:
                self.follow_up_packet = 0
                header_type = (datagram_data[0] & int('10000000', 2)) >> 7

                if all(b == b"\x00" for b in datagram_data):  # TODO: Maybe remove
                    return self.packet_buf

                match header_type:

                    case 0x01:  # if header is long header

                        fmt_string = "B4sB"  # First Byte, Version, DCID_Len
                        header_parts = struct.unpack_from(fmt_string, datagram_data)
                        version = int.from_bytes(header_parts[1], "big")
                        dcid_len = quic_decode.decode_variable_length_int(header_parts[2].to_bytes(1, "big"))
                        fmt_string = fmt_string + str(dcid_len) + "s"
                        header_parts = struct.unpack_from(fmt_string, datagram_data)
                        dcid = header_parts[3]
                        fmt_string = fmt_string + "s"

                        header_parts = struct.unpack_from(fmt_string, datagram_data)
                        scid_len = quic_decode.decode_variable_length_int((header_parts[4]))
                        fmt_string = fmt_string + str(scid_len) + "s"
                        header_parts = struct.unpack_from(fmt_string, datagram_data)
                        scid = header_parts[5]

                        print(f"DCID is {dcid.hex()} and SCID is {scid.hex()}")

                        pn_offset = 7 + len(dcid) + len(scid)

                        packet_type = (datagram_data[0] & int('00100000', 2)) >> 5

                        match packet_type:  # checks if packet type

                            case 0x00:  # Initial packet

                                header_parts = struct.unpack_from(fmt_string + "s", datagram_data)
                                token_len_len = quic_decode.get_variable_length_int_length(header_parts[-1])
                                fmt_string = fmt_string + str(token_len_len) + "s"
                                header_parts = struct.unpack_from(fmt_string, datagram_data)
                                token_len = quic_decode.decode_variable_length_int(header_parts[-1])
                                fmt_string = fmt_string + str(token_len) + "s"
                                header_parts = struct.unpack_from(fmt_string, datagram_data)
                                token = header_parts[-1]

                                packet_len_len = quic_decode.get_variable_length_int_length(
                                    struct.unpack_from(fmt_string + "s", datagram_data)[-1])
                                fmt_string = fmt_string + str(packet_len_len) + "s"
                                header_parts = struct.unpack_from(fmt_string, datagram_data)
                                packet_len = quic_decode.decode_variable_length_int(header_parts[-1])

                                pn_offset += packet_len_len + token_len_len + token_len
                                sample_offset = pn_offset + 4

                                sample = datagram_data[sample_offset: sample_offset + 16]

                                initial_keys = quic_key_generation.dev_initial_keys(dcid)

                                if self.isserver:
                                    hp_key = initial_keys["server_initial_hp"]
                                else:
                                    hp_key = initial_keys["client_initial_hp"]

                                decrypted_header = self.remove_header_protection(header_type=QuicHeaderType.LONG,
                                                                                 sample=sample,
                                                                                 first_packet_byte=header_parts[0],
                                                                                 hp_key=hp_key,
                                                                                 datagram_data=datagram_data,
                                                                                 pn_offset=pn_offset)

                                fmt_string += str(decrypted_header[-1]) + "s"
                                fmt_string += str(packet_len - decrypted_header[-1]) + "s"
                                header_parts = struct.unpack_from(fmt_string, datagram_data)
                                payload = header_parts[-1]
                                payload_len = len(payload)

                                total_packet_len = 1 + 4 + 1 + dcid_len + 1 + scid_len + token_len_len + token_len + packet_len_len + decrypted_header[-1] + payload_len

                                if len(datagram_data) > total_packet_len:
                                    datagram_data = datagram_data[total_packet_len:]
                                    self.follow_up_packet = 1

                                packet = LongQuicPacket(packet_type=QuicPacketType.INITIAL, version=version,
                                                        dcid_len=dcid_len, dcid=dcid, scid_len=scid_len, scid=scid,
                                                        token_len=token_len, token=token,
                                                        packet_len=packet_len, packet_num=decrypted_header[1],
                                                        payload=payload, isserver=self.isserver)

                                self.packet_buf.append(packet)

                            case 0x01 | 0x02:  # if packet is handshake or RTT-0

                                packet_len_len = quic_decode.get_variable_length_int_length(
                                    struct.unpack_from(fmt_string + "s", datagram_data)[-1])
                                fmt_string = fmt_string + str(packet_len_len) + "s"
                                header_parts = struct.unpack_from(fmt_string, datagram_data)
                                packet_len = quic_decode.decode_variable_length_int(header_parts[-1])

                                pn_offset += packet_len_len
                                sample_offset = pn_offset + 4

                                sample = datagram_data[sample_offset: sample_offset + 16]

                                initial_keys = quic_key_generation.dev_initial_keys(dcid)

                                if self.isserver:
                                    hp_key = initial_keys["server_initial_hp"]
                                else:
                                    hp_key = initial_keys["client_initial_hp"]

                                decrypted_header = self.remove_header_protection(header_type=QuicHeaderType.LONG,
                                                                                 sample=sample,
                                                                                 first_packet_byte=header_parts[0],
                                                                                 hp_key=hp_key,
                                                                                 datagram_data=datagram_data,
                                                                                 pn_offset=pn_offset)

                                fmt_string += str(decrypted_header[-1]) + "s"
                                fmt_string += str(packet_len - decrypted_header[-1]) + "s"
                                header_parts = struct.unpack_from(fmt_string, datagram_data)
                                payload = header_parts[-1]
                                payload_len = len(payload)

                                total_packet_len = 1 + 4 + 1 + dcid_len + 1 + scid_len + packet_len_len + decrypted_header[-1] + payload_len

                                if len(datagram_data) > total_packet_len:
                                    datagram_data = datagram_data[total_packet_len:]
                                    self.follow_up_packet = 1

                                packet = LongQuicPacket(packet_type=QuicPacketType.HANDSHAKE, version=version,
                                                        dcid_len=dcid_len, dcid=dcid, scid_len=scid_len, scid=scid,
                                                        packet_len=packet_len, packet_num=decrypted_header[1],
                                                        payload=payload, isserver=self.isserver)

                                self.packet_buf.append(packet)

                            case 0x03:  # if packet is retry
                                pass

                            case _:
                                continue

                    case 0:  # if header is short header
                        packet = quic_packet.ShortQuicPacket(packet_type=QuicPacketType.RTT_1,
                                                             dcid=datagram_data[2:23],
                                                             isserver=self.isserver,
                                                             packet_num=-1,
                                                             key_phase=-1,
                                                             payload=datagram_data)
                        self.packet_buf.append(packet)

                    case _:
                        continue

            return self.packet_buf

        except:
            return self.packet_buf

    def finish_short_header(self, cid: bytes, data: bytes, isserver):
        self.isserver = isserver
        fmt_string = "B" + str(len(cid))
        header_parts = struct.unpack_from(fmt_string, data)

        pn_offset = 1 + len(cid)
        sample_offset = pn_offset + 4
        sample = data[sample_offset:sample_offset + 16]

        initial_keys = quic_key_generation.dev_initial_keys(cid)

        if self.isserver:
            hp_key = initial_keys["server_initial_hp"]
        else:
            hp_key = initial_keys["client_initial_hp"]

        decrypted_header = self.remove_header_protection(header_type=QuicHeaderType.SHORT,
                                                         first_packet_byte=header_parts[0],
                                                         hp_key=hp_key,
                                                         sample=sample,
                                                         pn_offset=pn_offset,
                                                         datagram_data=data)

        fmt_string += str(decrypted_header[-1]) + "s"
        fmt_string += str(len(data) - (1 + len(cid) - decrypted_header[-1])) + "s"
        header_parts = struct.unpack_from(fmt_string, data)
        payload = header_parts[-1]
        keyphase = int(self.byte_and(header_parts[0], b"\x01"))

        packet = ShortQuicPacket(packet_type=QuicPacketType.RTT_1,
                                 dcid=header_parts[1],
                                 isserver=self.isserver,
                                 packet_num=header_parts[-2],
                                 key_phase=keyphase,
                                 payload=payload)

        return packet

    def remove_header_protection(self, header_type, sample, first_packet_byte, hp_key, datagram_data,
                                 pn_offset) -> tuple:
        mask = quic_key_generation.make_hp_mask(hp_key, sample)

        if header_type == quic_packet.QuicHeaderType.LONG:
            first_packet_byte = self.byte_xor(bytes([first_packet_byte]), self.byte_and(bytes([mask[0]]), b'\x0f'))
        else:
            first_packet_byte = self.byte_xor(bytes([first_packet_byte]), self.byte_and(bytes([mask[0]]), b'\x1f'))

        pn_len = quic_decode.decode_variable_length_int(
            self.byte_and(bytes([int.from_bytes(first_packet_byte, "big")]), b"\x03")) + 1

        packet_number_field = self.byte_xor(datagram_data[pn_offset:pn_offset + pn_len], mask[1: pn_len + 1])

        return first_packet_byte, packet_number_field, pn_len

    def byte_xor(self, byte1, byte2):
        result = b""
        for byte1, byte2 in zip(byte1, byte2):
            result += (bytes([byte1 ^ byte2]))
        return result

    def byte_and(self, byte1, byte2):
        result = b""
        for byte1, byte2 in zip(byte1, byte2):
            result += bytes([byte1 & byte2])
        return result

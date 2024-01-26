import struct

from tlexport.packet import Packet
from tlexport.quic.quic_decode import decode_variable_length_int, get_variable_length_int_length
from tlexport.quic.quic_key_generation import dev_quic_keys, make_hp_mask, dev_initial_keys
from tlexport.quic.quic_packet import QuicPacketType, QuicHeaderType
from tlexport.quic.quic_packet import LongQuicPacket, ShortQuicPacket, QuicPacketType, QuicHeaderType
from enum import Enum


class QuicVersion(Enum):
    UNKNOWN = 0
    V1 = 1
    V2 = 2


def byte_xor(byte1, byte2):
    result = b""
    for byte1, byte2 in zip(byte1, byte2):
        result += (bytes([byte1 ^ byte2]))
    return result


def byte_and(byte1, byte2):
    result = b""
    for byte1, byte2 in zip(byte1, byte2):
        result += bytes([byte1 & byte2])
    return result


def remove_header_protection(header_type, sample, first_packet_byte, hp_key, datagram_data,
                             pn_offset) -> tuple:
    mask = make_hp_mask(hp_key, sample)

    if header_type == QuicHeaderType.LONG:
        first_packet_byte = byte_xor(bytes([first_packet_byte]), byte_and(bytes([mask[0]]), b'\x0f'))
    else:
        first_packet_byte = byte_xor(bytes([first_packet_byte]), byte_and(bytes([mask[0]]), b'\x1f'))

    pn_len = decode_variable_length_int(
        byte_and(bytes([int.from_bytes(first_packet_byte, "big")]), b"\x03")) + 1

    packet_number_field = byte_xor(datagram_data[pn_offset:pn_offset + pn_len], mask[1: pn_len + 1])

    return first_packet_byte, packet_number_field, pn_len


def finish_short_header(cid: bytes, data: bytes, isserver):
    fmt_string = "B" + str(len(cid))
    header_parts = struct.unpack_from(fmt_string, data)

    pn_offset = 1 + len(cid)
    sample_offset = pn_offset + 4
    sample = data[sample_offset:sample_offset + 16]

    initial_keys = dev_initial_keys(cid)

    if isserver:
        hp_key = initial_keys["server_initial_hp"]
    else:
        hp_key = initial_keys["client_initial_hp"]

    decrypted_header = remove_header_protection(header_type=QuicHeaderType.SHORT,
                                                first_packet_byte=header_parts[0],
                                                hp_key=hp_key,
                                                sample=sample,
                                                pn_offset=pn_offset,
                                                datagram_data=data)

    fmt_string += str(decrypted_header[-1]) + "s"
    fmt_string += str(len(data) - (1 + len(cid) - decrypted_header[-1])) + "s"
    header_parts = struct.unpack_from(fmt_string, data)
    payload = header_parts[-1]
    keyphase = int(byte_and(header_parts[0], b"\x01"))

    packet = ShortQuicPacket(packet_type=QuicPacketType.RTT_1,
                             dcid=header_parts[1],
                             isserver=isserver,
                             packet_num=header_parts[-2],
                             key_phase=keyphase,
                             payload=payload)

    return packet


def get_quic_header_data(packet: Packet, isserver):
    packet_buf = []
    follow_up_packet = 1

    datagram_data = packet.tls_data
    print(datagram_data.hex())

    try:
        while follow_up_packet:
            follow_up_packet = 0
            header_type = (datagram_data[0] & int('10000000', 2)) >> 7

            if all(b == b"\x00" for b in datagram_data):  # TODO: Maybe remove
                return packet_buf

            match header_type:

                case 0x01:  # if header is long header

                    fmt_string = "B4sB"  # First Byte, Version, DCID_Len
                    header_parts = struct.unpack_from(fmt_string, datagram_data)
                    version = int.from_bytes(header_parts[1], "big")
                    dcid_len = decode_variable_length_int(header_parts[2].to_bytes(1, "big"))
                    fmt_string = fmt_string + str(dcid_len) + "s"
                    header_parts = struct.unpack_from(fmt_string, datagram_data)
                    dcid = header_parts[3]
                    fmt_string = fmt_string + "s"

                    header_parts = struct.unpack_from(fmt_string, datagram_data)
                    scid_len = decode_variable_length_int((header_parts[4]))
                    fmt_string = fmt_string + str(scid_len) + "s"
                    header_parts = struct.unpack_from(fmt_string, datagram_data)
                    scid = header_parts[5]

                    print(f"DCID is {dcid.hex()} and SCID is {scid.hex()}")

                    pn_offset = 7 + len(dcid) + len(scid)

                    packet_type = (datagram_data[0] & int('00100000', 2)) >> 5

                    match packet_type:  # checks if packet type

                        case 0x00:  # Initial packet

                            header_parts = struct.unpack_from(fmt_string + "s", datagram_data)
                            token_len_len = get_variable_length_int_length(header_parts[-1])
                            fmt_string = fmt_string + str(token_len_len) + "s"
                            header_parts = struct.unpack_from(fmt_string, datagram_data)
                            token_len = decode_variable_length_int(header_parts[-1])
                            fmt_string = fmt_string + str(token_len) + "s"
                            header_parts = struct.unpack_from(fmt_string, datagram_data)
                            token = header_parts[-1]

                            packet_len_len = get_variable_length_int_length(
                                struct.unpack_from(fmt_string + "s", datagram_data)[-1])
                            fmt_string = fmt_string + str(packet_len_len) + "s"
                            header_parts = struct.unpack_from(fmt_string, datagram_data)
                            packet_len = decode_variable_length_int(header_parts[-1])

                            pn_offset += packet_len_len + token_len_len + token_len
                            sample_offset = pn_offset + 4

                            sample = datagram_data[sample_offset: sample_offset + 16]

                            initial_keys = dev_initial_keys(dcid, version)

                            if isserver:
                                hp_key = initial_keys["server_initial_hp"]
                            else:
                                hp_key = initial_keys["client_initial_hp"]

                            decrypted_header = remove_header_protection(header_type=QuicHeaderType.LONG,
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

                            total_packet_len = 1 + 4 + 1 + dcid_len + 1 + scid_len + token_len_len + token_len + packet_len_len + \
                                               decrypted_header[-1] + payload_len

                            if len(datagram_data) > total_packet_len:
                                datagram_data = datagram_data[total_packet_len:]
                                follow_up_packet = 1

                            packet = LongQuicPacket(packet_type=QuicPacketType.INITIAL, version=version,
                                                    dcid_len=dcid_len, dcid=dcid, scid_len=scid_len, scid=scid,
                                                    token_len=token_len, token=token,
                                                    packet_len=packet_len, packet_num=decrypted_header[1],
                                                    payload=payload, isserver=isserver)

                            packet_buf.append(packet)

                        case 0x01 | 0x02:  # if packet is handshake or RTT-0

                            packet_len_len = get_variable_length_int_length(
                                struct.unpack_from(fmt_string + "s", datagram_data)[-1])
                            fmt_string = fmt_string + str(packet_len_len) + "s"
                            header_parts = struct.unpack_from(fmt_string, datagram_data)
                            packet_len = decode_variable_length_int(header_parts[-1])

                            pn_offset += packet_len_len
                            sample_offset = pn_offset + 4

                            sample = datagram_data[sample_offset: sample_offset + 16]

                            initial_keys = dev_initial_keys(dcid)

                            if isserver:
                                hp_key = initial_keys["server_initial_hp"]
                            else:
                                hp_key = initial_keys["client_initial_hp"]

                            decrypted_header = remove_header_protection(header_type=QuicHeaderType.LONG,
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

                            total_packet_len = 1 + 4 + 1 + dcid_len + 1 + scid_len + packet_len_len + \
                                               decrypted_header[-1] + payload_len

                            if len(datagram_data) > total_packet_len:
                                datagram_data = datagram_data[total_packet_len:]
                                follow_up_packet = 1

                            packet = LongQuicPacket(packet_type=QuicPacketType.HANDSHAKE, version=version,
                                                    dcid_len=dcid_len, dcid=dcid, scid_len=scid_len, scid=scid,
                                                    packet_len=packet_len, packet_num=decrypted_header[1],
                                                    payload=payload, isserver=isserver)

                            packet_buf.append(packet)

                        case 0x03:  # if packet is retry
                            pass

                        case _:
                            continue

                case 0:  # if header is short header
                    packet = ShortQuicPacket(packet_type=QuicPacketType.RTT_1,
                                                         dcid=datagram_data[2:23],
                                                         isserver=isserver,
                                                         packet_num=-1,
                                                         key_phase=-1,
                                                         payload=datagram_data)
                    packet_buf.append(packet)

                case _:
                    continue

        return packet_buf

    except:
        return packet_buf


def get_header_type(payload: bytes):
    if payload[0] >> 7 & 1 == 1:
        return QuicHeaderType.LONG
    else:
        return QuicHeaderType.SHORT

import struct

from tlexport.packet import Packet
from tlexport.quic.quic_decode import decode_variable_length_int, get_variable_length_int_length, QuicVersion
from tlexport.quic.quic_key_generation import dev_quic_keys, make_hp_mask, dev_initial_keys, make_chacha_hp_mask
from tlexport.quic.quic_packet import QuicPacketType, QuicHeaderType
from tlexport.quic.quic_packet import LongQuicPacket, ShortQuicPacket, QuicPacketType, QuicHeaderType
from enum import Enum


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


def get_header_type(datagram_data: bytes):
    if datagram_data[0] >> 7 & 1 == 1:
        return QuicHeaderType.LONG
    else:
        return QuicHeaderType.SHORT

def get_packet_type(datagram_data: bytes):
    packet_type = (datagram_data[0] & int('00100000', 2)) >> 5
    match packet_type:
        case 0x00:
            return QuicPacketType.INITIAL
        case 0x01 | 0x02:
            return QuicPacketType.HANDSHAKE
        case 0x03:
            return QuicPacketType.RETRY
        case _:
            return None


def remove_header_protection(header_type, sample, first_packet_byte, hp_key, datagram_data,
                             pn_offset, ciphersuite: bytes) -> tuple:

    if ciphersuite == b'\x13\x03':
        mask = make_chacha_hp_mask(hp_key, sample)
    else:
        mask = make_hp_mask(hp_key, sample)

    if header_type == QuicHeaderType.LONG:
        first_packet_byte = byte_xor(bytes([first_packet_byte]), byte_and(bytes([mask[0]]), bytes.fromhex("0f")))
    else:
        first_packet_byte = byte_xor(bytes([first_packet_byte]), byte_and(bytes([mask[0]]), bytes.fromhex("1f")))

    pn_len = decode_variable_length_int(
        byte_and(bytes([int.from_bytes(first_packet_byte, "big")]), b"\x03")) + 1

    packet_number_field = byte_xor(datagram_data[pn_offset:pn_offset + pn_len], mask[1: pn_len + 1])

    return first_packet_byte, packet_number_field, pn_len


def extract_quic_packet(in_packet: Packet, isserver, guessed_dcid: bytes = None, keys: {} = None, ciphersuite: bytes = None):
    packet_buf = []

    datagram_data = in_packet.tls_data
    #print(datagram_data.hex())
    #datagram_data = bytes.fromhex("cf000000010008f067a5502a4262b5004075c0d95a482cd0991cd25b0aac406a5816b6394100f37a1c69797554780bb38cc5a99f5ede4cf73c3ec2493a1839b3dbcba3f6ea46c5b7684df3548e7ddeb9c3bf9c73cc3f3bded74b562bfb19fb84022f8ef4cdd93795d77d06edbb7aaf2f58891850abbdca3d20398c276456cbc42158407dd074ee")

    try:

        header_type = get_header_type(datagram_data)

        if all(b == b"\x00" for b in datagram_data):    # If we have a zero-padding at the end
            in_packet.tls_data = b""
            return packet_buf, in_packet

        match header_type:

            case QuicHeaderType.LONG:  # if header is long header

                fmt_string = "B4sB"  # First Byte, Version, DCID_Len
                header_parts = struct.unpack_from(fmt_string, datagram_data)
                version = header_parts[1]
                dcid_len = header_parts[2]
                fmt_string = fmt_string + str(dcid_len) + "s"
                dcid_len = dcid_len.to_bytes(1, "big")
                header_parts = struct.unpack_from(fmt_string, datagram_data)
                dcid = header_parts[3]
                fmt_string = fmt_string + "s"

                header_parts = struct.unpack_from(fmt_string, datagram_data)
                scid_len = decode_variable_length_int((header_parts[4]))
                fmt_string = fmt_string + str(scid_len) + "s"
                scid_len = scid_len.to_bytes(1, "big")
                header_parts = struct.unpack_from(fmt_string, datagram_data)
                scid = header_parts[5]

                pn_offset = 7 + len(dcid) + len(scid)

                packet_type = get_packet_type(datagram_data=datagram_data)

                match packet_type:  # checks if packet type

                    case QuicPacketType.INITIAL:  # Initial packet

                        header_parts = struct.unpack_from(fmt_string + "s", datagram_data)
                        token_len_len = get_variable_length_int_length(header_parts[-1])
                        fmt_string = fmt_string + str(token_len_len) + "s"
                        header_parts = struct.unpack_from(fmt_string, datagram_data)
                        token_len_bytes = header_parts[-1]
                        token_len = decode_variable_length_int(header_parts[-1])
                        fmt_string = fmt_string + str(token_len) + "s"
                        header_parts = struct.unpack_from(fmt_string, datagram_data)
                        token = header_parts[-1]

                        packet_len_len = get_variable_length_int_length(
                            struct.unpack_from(fmt_string + "s", datagram_data)[-1])
                        fmt_string = fmt_string + str(packet_len_len) + "s"
                        header_parts = struct.unpack_from(fmt_string, datagram_data)
                        packet_len = decode_variable_length_int(header_parts[-1]).to_bytes(packet_len_len, "big")
                        packet_len_bytes = header_parts[-1]

                        pn_offset += packet_len_len + token_len_len + token_len
                        sample_offset = pn_offset + 4

                        sample = datagram_data[sample_offset: sample_offset + 16]

                        if isserver:
                            hp_key = keys['server_initial_hp']
                        else:
                            hp_key = keys['client_initial_hp']

                        decrypted_header = remove_header_protection(header_type=QuicHeaderType.LONG,
                                                                    sample=sample,
                                                                    first_packet_byte=header_parts[0],
                                                                    hp_key=hp_key,
                                                                    datagram_data=datagram_data,
                                                                    pn_offset=pn_offset, ciphersuite=None)

                        fmt_string += str(decrypted_header[-1]) + "s"
                        fmt_string += str(int.from_bytes(packet_len, "big") - decrypted_header[-1]) + "s"
                        header_parts = struct.unpack_from(fmt_string, datagram_data)
                        payload = header_parts[-1]
                        payload_len = len(payload)

                        total_packet_len = 1 + 4 + 1 + int.from_bytes(dcid_len, "big") + 1 + int.from_bytes(scid_len, "big") + token_len_len + token_len + packet_len_len + \
                                           decrypted_header[-1] + payload_len

                        packet = LongQuicPacket(packet_type=QuicPacketType.INITIAL, version=version,
                                                dcid_len=dcid_len, dcid=dcid, scid_len=scid_len, scid=scid,
                                                token_len=token_len, token_len_bytes=token_len_bytes, token=token,
                                                packet_len=packet_len, packet_len_bytes=packet_len_bytes, packet_num=decrypted_header[1],
                                                payload=payload, isserver=isserver, first_byte=decrypted_header[0], ts=in_packet.timestamp)

                        packet_buf.append(packet)

                    case QuicPacketType.HANDSHAKE:  # if packet is handshake or RTT-0

                        packet_len_len = get_variable_length_int_length(
                            struct.unpack_from(fmt_string + "s", datagram_data)[-1])
                        fmt_string = fmt_string + str(packet_len_len) + "s"
                        header_parts = struct.unpack_from(fmt_string, datagram_data)
                        packet_len = decode_variable_length_int(header_parts[-1]).to_bytes(packet_len_len, "big")
                        packet_len_bytes = header_parts[-1]

                        pn_offset += packet_len_len
                        sample_offset = pn_offset + 4

                        sample = datagram_data[sample_offset: sample_offset + 16]
                        print("Sample: " + sample.hex())

                        if isserver:
                            hp_key = keys["server_handshake_hp"]
                        else:
                            hp_key = keys["client_handshake_hp"]

                        decrypted_header = remove_header_protection(header_type=QuicHeaderType.LONG,
                                                                    sample=sample,
                                                                    first_packet_byte=header_parts[0],
                                                                    hp_key=hp_key,
                                                                    datagram_data=datagram_data,
                                                                    pn_offset=pn_offset, ciphersuite=ciphersuite)

                        fmt_string += str(decrypted_header[-1]) + "s"
                        fmt_string += str(int.from_bytes(packet_len, "big") - decrypted_header[-1]) + "s"
                        header_parts = struct.unpack_from(fmt_string, datagram_data)
                        payload = header_parts[-1]
                        payload_len = len(payload)

                        total_packet_len = 1 + 4 + 1 + int.from_bytes(dcid_len, "big") + 1 + int.from_bytes(scid_len, "big") + packet_len_len + \
                                           decrypted_header[-1] + payload_len

                        packet = LongQuicPacket(packet_type=QuicPacketType.HANDSHAKE, version=version,
                                                dcid_len=dcid_len, dcid=dcid, scid_len=scid_len, scid=scid,
                                                packet_len=packet_len, packet_num=decrypted_header[1],
                                                payload=payload, isserver=isserver, first_byte=decrypted_header[0],
                                                packet_len_bytes=packet_len_bytes, ts=in_packet.timestamp)

                        packet_buf.append(packet)

                    case QuicPacketType.RETRY:  # if packet is retry
                        pass

                    case _:
                        pass

            case QuicHeaderType.SHORT:  # if header is short header
                fmt_string = "B" + str(len(guessed_dcid)) + "s"
                header_parts = struct.unpack_from(fmt_string, datagram_data)

                pn_offset = 1 + len(guessed_dcid)
                sample_offset = pn_offset + 4
                sample = datagram_data[sample_offset:sample_offset + 16]

                if isserver:
                    hp_key = keys["server_application_hp"]
                else:
                    hp_key = keys["client_application_hp"]

                decrypted_header = remove_header_protection(header_type=QuicHeaderType.SHORT,
                                                            first_packet_byte=header_parts[0],
                                                            hp_key=hp_key,
                                                            sample=sample,
                                                            pn_offset=pn_offset,
                                                            datagram_data=datagram_data, ciphersuite=ciphersuite)

                fmt_string += str(decrypted_header[-1]) + "s"
                fmt_string += str(len(datagram_data) - (1 + len(guessed_dcid) + decrypted_header[-1])) + "s"
                header_parts = struct.unpack_from(fmt_string, datagram_data)
                payload = header_parts[-1]
                key_phase = decrypted_header[0][0] >> 2 & 1

                total_packet_len = 1 + len(guessed_dcid) + decrypted_header[-1] + len(payload)

                packet = ShortQuicPacket(packet_type=QuicPacketType.RTT_1,
                                         dcid=guessed_dcid,
                                         isserver=isserver,
                                         packet_num=decrypted_header[1],
                                         key_phase=key_phase,
                                         payload=payload,
                                         first_byte=decrypted_header[0],
                                         ts=in_packet.timestamp)

                packet_buf.append(packet)
            case _:
                pass
        in_packet.tls_data = datagram_data[total_packet_len:]
        return packet_buf, in_packet

    except Exception as e:
        print(e)
        in_packet.tls_data = b""
        return packet_buf, in_packet




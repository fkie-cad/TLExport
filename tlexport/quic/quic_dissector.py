import struct

from tlexport.packet import Packet
from tlexport.quic.quic_decode import decode_variable_length_int, get_variable_length_int_length, QuicVersion
from tlexport.quic.quic_key_generation import dev_quic_keys, make_hp_mask, dev_initial_keys
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


def get_header_type(payload: bytes):
    if payload[0] >> 7 & 1 == 1:
        return QuicHeaderType.LONG
    else:
        return QuicHeaderType.SHORT


def remove_header_protection(header_type, sample, first_packet_byte, hp_key, datagram_data,
                             pn_offset) -> tuple:
    mask = make_hp_mask(hp_key, sample)

    if header_type == QuicHeaderType.LONG:
        first_packet_byte = byte_xor(bytes([first_packet_byte]), byte_and(bytes([mask[0]]), bytes.fromhex("0f")))
    else:
        first_packet_byte = byte_xor(bytes([first_packet_byte]), byte_and(bytes([mask[0]]), bytes.fromhex("1f")))

    pn_len = decode_variable_length_int(
        byte_and(bytes([int.from_bytes(first_packet_byte, "big")]), b"\x03")) + 1

    packet_number_field = byte_xor(datagram_data[pn_offset:pn_offset + pn_len], mask[1: pn_len + 1])

    print(int.from_bytes(packet_number_field, "little"))
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


def get_quic_header_data(in_packet: Packet, isserver, connection_ids, keys):
    packet_buf = []


    datagram_data = in_packet.tls_data
    #print(datagram_data.hex())
    #datagram_data = bytes.fromhex("c000000001088394c8f03e5157080000449e7b9aec34d1b1c98dd7689fb8ec11d242b123dc9bd8bab936b47d92ec356c0bab7df5976d27cd449f63300099f3991c260ec4c60d17b31f8429157bb35a1282a643a8d2262cad67500cadb8e7378c8eb7539ec4d4905fed1bee1fc8aafba17c750e2c7ace01e6005f80fcb7df621230c83711b39343fa028cea7f7fb5ff89eac2308249a02252155e2347b63d58c5457afd84d05dfffdb20392844ae812154682e9cf012f9021a6f0be17ddd0c2084dce25ff9b06cde535d0f920a2db1bf362c23e596d11a4f5a6cf3948838a3aec4e15daf8500a6ef69ec4e3feb6b1d98e610ac8b7ec3faf6ad760b7bad1db4ba3485e8a94dc250ae3fdb41ed15fb6a8e5eba0fc3dd60bc8e30c5c4287e53805db059ae0648db2f64264ed5e39be2e20d82df566da8dd5998ccabdae053060ae6c7b4378e846d29f37ed7b4ea9ec5d82e7961b7f25a9323851f681d582363aa5f89937f5a67258bf63ad6f1a0b1d96dbd4faddfcefc5266ba6611722395c906556be52afe3f565636ad1b17d508b73d8743eeb524be22b3dcbc2c7468d54119c7468449a13d8e3b95811a198f3491de3e7fe942b330407abf82a4ed7c1b311663ac69890f4157015853d91e923037c227a33cdd5ec281ca3f79c44546b9d90ca00f064c99e3dd97911d39fe9c5d0b23a229a234cb36186c4819e8b9c5927726632291d6a418211cc2962e20fe47feb3edf330f2c603a9d48c0fcb5699dbfe5896425c5bac4aee82e57a85aaf4e2513e4f05796b07ba2ee47d80506f8d2c25e50fd14de71e6c418559302f939b0e1abd576f279c4b2e0feb85c1f28ff18f58891ffef132eef2fa09346aee33c28eb130ff28f5b766953334113211996d20011a198e3fc433f9f2541010ae17c1bf202580f6047472fb36857fe843b19f5984009ddc324044e847a4f4a0ab34f719595de37252d6235365e9b84392b061085349d73203a4a13e96f5432ec0fd4a1ee65accdd5e3904df54c1da510b0ff20dcc0c77fcb2c0e0eb605cb0504db87632cf3d8b4dae6e705769d1de354270123cb11450efc60ac47683d7b8d0f811365565fd98c4c8eb936bcab8d069fc33bd801b03adea2e1fbc5aa463d08ca19896d2bf59a071b851e6c239052172f296bfb5e72404790a2181014f3b94a4e97d117b438130368cc39dbb2d198065ae3986547926cd2162f40a29f0c3c8745c0f50fba3852e566d44575c29d39a03f0cda721984b6f440591f355e12d439ff150aab7613499dbd49adabc8676eef023b15b65bfc5ca06948109f23f350db82123535eb8a7433bdabcb909271a6ecbcb58b936a88cd4e8f2e6ff5800175f113253d8fa9ca8885c2f552e657dc603f252e1a8e308f76f0be79e2fb8f5d5fbbe2e30ecadd220723c8c0aea8078cdfcb3868263ff8f0940054da48781893a7e49ad5aff4af300cd804a6b6279ab3ff3afb64491c85194aab760d58a606654f9f4400e8b38591356fbf6425aca26dc85244259ff2b19c41b9f96f3ca9ec1dde434da7d2d392b905ddf3d1f9af93d1af5950bd493f5aa731b4056df31bd267b6b90a079831aaf579be0a39013137aac6d404f518cfd46840647e78bfe706ca4cf5e9c5453e9f7cfd2b8b4c8d169a44e55c88d4a9a7f9474241e221af44860018ab0856972e194cd934")

    try:

        header_type = (datagram_data[0] & int('10000000', 2)) >> 7

        if all(b == b"\x00" for b in datagram_data):
            in_packet.tls_data = b""
            return packet_buf, in_packet

        match header_type:

            case 0x01:  # if header is long header

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

                print(f"DCID is {dcid.hex()} and SCID is {scid.hex()}")

                pn_offset = 7 + len(dcid) + len(scid)

                packet_type = (datagram_data[0] & int('00100000', 2)) >> 5

                match packet_type:  # checks if packet type

                    case 0x00:  # Initial packet

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
                                                                    pn_offset=pn_offset)

                        fmt_string += str(decrypted_header[-1]) + "s"
                        fmt_string += str(int.from_bytes(packet_len, "big") - decrypted_header[-1]) + "s"
                        header_parts = struct.unpack_from(fmt_string, datagram_data)
                        payload = header_parts[-1]
                        payload_len = len(payload)

                        total_packet_len = 1 + 4 + 1 + int.from_bytes(dcid_len, "big") + 1 + int.from_bytes(scid_len, "big") + token_len_len + token_len + packet_len_len + \
                                           decrypted_header[-1] + payload_len

                        if len(datagram_data) > total_packet_len:
                            datagram_data = datagram_data[total_packet_len:]
                            follow_up_packet = 1

                        packet = LongQuicPacket(packet_type=QuicPacketType.INITIAL, version=version,
                                                dcid_len=dcid_len, dcid=dcid, scid_len=scid_len, scid=scid,
                                                token_len=token_len, token_len_bytes=token_len_bytes, token=token,
                                                packet_len=packet_len, packet_len_bytes=packet_len_bytes, packet_num=decrypted_header[1],
                                                payload=payload, isserver=isserver, first_byte=decrypted_header[0])

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

                        total_packet_len = 1 + 4 + 1 + dcid_len + 1 + scid_len + packet_len_len + \
                                           decrypted_header[-1] + payload_len

                        if len(datagram_data) > total_packet_len:
                            datagram_data = datagram_data[total_packet_len:]
                            follow_up_packet = 1

                        packet = LongQuicPacket(packet_type=QuicPacketType.HANDSHAKE, version=version,
                                                dcid_len=dcid_len, dcid=dcid, scid_len=scid_len, scid=scid,
                                                packet_len=packet_len, packet_num=decrypted_header[1],
                                                payload=payload, isserver=isserver, first_byte=header_parts[2])

                        packet_buf.append(packet)

                    case 0x03:  # if packet is retry
                        pass

                    case _:
                        pass

            case 0:  # if header is short header
                packet = ShortQuicPacket(packet_type=QuicPacketType.RTT_1,
                                         dcid=datagram_data[2:23],
                                         isserver=isserver,
                                         packet_num=-1,
                                         key_phase=-1,
                                         payload=datagram_data,
                                         first_byte=header_parts[2])
                packet_buf.append(packet)

            case _:
                pass
        in_packet.tls_data = datagram_data[total_packet_len:]
        return packet_buf, in_packet

    except Exception as e:
        print(e)
        in_packet.tls_data = b""
        return packet_buf, in_packet




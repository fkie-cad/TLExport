import copy
import logging

from tlexport.packet import Packet


def ones_complement_checksum(byte_arr: bytearray) -> bytearray:
    checksum_arr = copy.deepcopy(byte_arr)

    # pad to multiples of 16 Bit
    if len(checksum_arr) % 2 != 0:
        checksum_arr.extend(b'\x00')

    checksum = 0
    # Sum up all 16-Bit Chunks
    for i in range(0, len(checksum_arr), 2):
        checksum += int.from_bytes(checksum_arr[i:i + 2], "big")

    # short checksum to 16 Bit
    while checksum > 65536:
        first = checksum >> 16
        last = checksum & 0xFFFF
        checksum = first + last

    # ones complement of checksum
    out_arr = bytearray(checksum.to_bytes(2, byteorder='big'))
    for i in range(2):
        out_arr[i] = ~out_arr[i] + 256

    return out_arr


def calculate_checksum_tcp(packet: Packet):
    logging.info("")
    logging.info("TCP Checksum")
    pseudo_header = bytearray(b'')

    # IPv4
    if not packet.ipv6_packet:
        pseudo_header.extend(packet.ip_src)
        pseudo_header.extend(packet.ip_dst)
        pseudo_header.extend(b'\x00')
        pseudo_header.extend(packet.ip.p.to_bytes(1, 'big'))
        pseudo_header.extend(len(packet.tcp).to_bytes(2, 'big'))

    # IPv6
    if packet.ipv6_packet:
        pseudo_header.extend(packet.ip_src)
        pseudo_header.extend(packet.ip_dst)
        pseudo_header.extend(len(packet.tcp).to_bytes(4, 'big'))
        pseudo_header.extend(b'\x00\x00\x00')
        pseudo_header.extend(packet.ip.nxt.to_bytes(1, 'big'))

    # TCP Body
    tcp_data = bytearray(bytes(packet.tcp))
    tcp_data[16:18] = bytearray(b'\x00\x00')
    logging.info(f"pseudo header: 0x{pseudo_header.hex()}")
    logging.info(f"tcp data: 0x{tcp_data.hex()}")

    pseudo_header.extend(tcp_data)

    calculated_checksum = ones_complement_checksum(pseudo_header)
    packet_checksum = packet.tcp.sum.to_bytes(2, 'big')

    logging.info(f"expected checksum: 0x{calculated_checksum.hex()}, packet checksum: 0x{packet_checksum.hex()}")

    return calculated_checksum == packet_checksum

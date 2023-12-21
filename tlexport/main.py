import os
import sys

import dpkt
import argparse
import logging

from tlexport.packet import Packet
import tlexport.keylog_reader as keylog_reader
from tlexport.dpkt_dsb import Reader
from tlexport.session import Session
from tlexport.checksums import calculate_checksum_tcp, calculate_checksum_udp
from tlexport.log import set_logger
from tlexport.quic.quic_packet import  QuicHeaderType
from tlexport.quic.quic_session import QuicSession
from tlexport.quic.quic_dissector import QuicDissector

server_ports = [443, 44330]
keylog = []
sessions = []
quic_sessions = []
quic_diss = QuicDissector()

def arg_parser_init():
    parser = argparse.ArgumentParser(description="Adding Decryption Secret Block Support to Zeek")
    parser.add_argument("-p", "--serverports", help="additional ports to test for TLS-Connections", nargs="+",
                        default=[443])
    parser.add_argument("-i", "--infile", help="path of input file",
                        default="/home/jannis/Documents/Programming/github/TLExport/tlexport/pcaps_und_keylogs/quic_pcaps/only_quic.pcapng")
    parser.add_argument("-o", "--outfile", help="path of output file", default="out.pcapng")
    parser.add_argument("-s", "--sslkeylog", help="path to sslkeylogfile",
                        default="/home/jannis/Documents/Programming/github/TLExport/tlexport/pcaps_und_keylogs/quic_pcaps/dtls_cid_change.log")
    # default False due to checksum offloading producing wrong checksums in Packet Capture
    parser.add_argument("-c", "--checksumTest", help="enable for checking tcp Checksums",
                        action=argparse.BooleanOptionalAction, default=False)
    parser.add_argument("-l", "--pcaplegacy", help="enable flag if infile is in the pcap format",
                        action=argparse.BooleanOptionalAction)
    parser.add_argument("-m", "--mapports",
                        help="map TLS-Ports to specific output ports, use this option when using more than one "
                             "serverport <serverport:outputport>",
                        nargs="+",
                        default=["443:8080"])
    parser.add_argument("-d", "--debug",
                        help="enable logger and set log-level, log levels are INFO, WARNING and ERROR",
                        default="INFO")

    parser.add_argument("-f", "--filter",
                        help="filter log messages by file, add files you want to filter", nargs="+")

    return parser.parse_args()


def get_port_map(parser):
    port_map = {}
    i: str
    for i in parser.mapports:
        split = i.split(":")
        server_port = int(split[0])
        output_port = int(split[1])
        port_map[server_port] = output_port

    return port_map


def handle_packet(packet: Packet, keylog, sessions: list[Session], portmap):
    for session in sessions:
        if session.matches_session(packet):
            session.handle_packet(packet)
            return

    if packet.dport in server_ports or packet.sport in server_ports:
        sessions.append(Session(packet, server_ports, keylog, portmap))


def handle_quic_packet(packet, keylog, quic_sessions: list[QuicSession], portmap):

    quic_packets = quic_diss.get_quic_header_data(packet=packet, isserver=False)    # if there is no session for this packet, we assume it is an inital from the client

    for quic_session in quic_sessions:

        isserver = quic_session.set_server_client_address(packet, server_ports)
        quic_packets = quic_diss.get_quic_header_data(packet=packet, isserver=isserver)

        if quic_session.matches_session_dgram(ip_src=packet.ip_src, ip_dst=packet.ip_dst, sport=packet.sport, dport=packet.dport):  # check if packet in session, based on port and ip
            for quic_packet in quic_packets:
                if quic_packet.header_type != QuicHeaderType.SHORT:  # Short header packets haven't been fully dissected at this point, so we first ignore them
                    quic_session.packet_buffer_quic.append(quic_packet)

                    if isserver:
                        if bytearray(quic_packet.scid) not in quic_session.server_cids:
                            quic_session.server_cids.append(bytearray(quic_packet.scid))
                        if bytearray(quic_packet.dcid) not in quic_session.client_cids:
                            quic_session.client_cids.append(bytearray(quic_packet.dcid))

                    else:
                        if bytearray(quic_packet.dcid) not in quic_session.server_cids:
                            quic_session.server_cids.append(bytearray(quic_packet.dcid))
                        if bytearray(quic_packet.scid) not in quic_session.client_cids:
                            quic_session.client_cids.append(bytearray(quic_packet.scid))
                    quic_packets.remove(quic_packet)
            return

        for quic_packet in quic_packets:
            if quic_packet.header_type == QuicHeaderType.SHORT:  # Short header packtes haven't been fully dissected at this point, so we have to further analyse their contents here

                cid_found = quic_session.match_cid(bytearray(quic_packet.payload))

                if cid_found is not None:
                    quic_packet = quic_diss.finish_short_header(cid=cid_found[0], data=quic_packet.payload, isserver=cid_found[1])
                    quic_session.packet_buffer_quic.append(quic_packet)
                    quic_packets.remove(quic_packet)
                    continue

            elif quic_packet.header_type != QuicHeaderType.SHORT and (quic_session.matches_session_quic(quic_packet.dcid) or quic_session.matches_session_quic(quic_packet.scid)):    # check if packet in session, based on CIDs from QUIC
                quic_session.packet_buffer_quic.append(quic_packet)
                quic_packets.remove(quic_packet)
                continue

    if (packet.dport in server_ports or packet.sport in server_ports) and len(quic_packets) > 0:  # TODO: Change
        for quic_packet in quic_packets:
            if quic_packet.header_type != QuicHeaderType.SHORT:
                new_session = QuicSession(packet=packet, quic_packet=quic_packets, server_ports=server_ports, keylog=keylog, portmap=portmap)
                new_session.packet_buffer_quic.extend(quic_packets)
                quic_sessions.append(new_session)


def run():
    args = arg_parser_init()
    portmap = get_port_map(args)

    set_logger(args)

    logging.info(f"Arguments: {args}")
    logging.info(f"Mapping Ports: {portmap}")

    server_ports.extend([int(x) for x in args.serverports])
    logging.info(f"Checking for TLS Traffic on these ports: {server_ports}")

    if args.sslkeylog is not None:
        keylog.extend(keylog_reader.read_keylog_from_file(args.sslkeylog))

    file = open(args.infile, "rb")

    if args.pcaplegacy:
        pcap_reader = dpkt.pcap.Reader(file)
    else:
        pcap_reader = Reader(file)

    for ts, buf in pcap_reader:
        packet = Packet(buf, ts)

        if ts == -1:
            keylog.extend(keylog_reader.get_keys_from_string(buf.decode('ascii')))
            continue

        if packet.tcp_packet:
            if len(packet.tls_data) == 0:
                continue

            if not args.checksumTest:
                checksum_test = True
            else:
                checksum_test = calculate_checksum_tcp(packet)

            if not checksum_test:
                logging.info("")
                logging.info(f"bad checksum discarded Packet {packet.get_params()}")
                logging.info("")
            if packet.tcp_packet and checksum_test:
                handle_packet(packet, keylog, sessions, portmap)

        elif packet.udp_packet:
            if len(packet.tls_data) == 0:
                continue

            if not args.checksumTest:
                checksum_test = True
            else:
                checksum_test = calculate_checksum_udp(packet)

            if not checksum_test:
                logging.info("")
                logging.info(f"bad checksum discarded Packet {packet.get_params()}")
                logging.info("")
                continue

            # using fixed bit for differentiating between QUIC and D-TLS (Second bit of first Byte is always 1 in QUIC)
            if ((int(packet.tls_data[0]) & 0x40) >> 6) == 1:
                # QUIC Packet
                handle_quic_packet(packet, keylog, quic_sessions, portmap)

            else:
                # D-TLS Packet
                pass

    file.close()
    all_decrypted_sessions = []
    for session in sessions:
        all_decrypted_sessions.extend(session.decrypt())

    for quic_session in quic_sessions:
        quic_session.decrypt()

    file = open(args.outfile, "wb")

    writer = dpkt.pcapng.Writer(file)

    for buf, ts in all_decrypted_sessions:
        writer.writepkt(bytes(buf), ts)

    file.close()


if __name__ == "__main__":
    run()

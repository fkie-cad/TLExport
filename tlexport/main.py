import argparse
import logging

import dpkt

import tlexport.keylog_reader as keylog_reader
from tlexport.checksums import calculate_checksum_tcp, calculate_checksum_udp
from tlexport.dpkt_dsb import Reader
from tlexport.log import set_logger
from tlexport.packet import Packet
from tlexport.quic.quic_dissector import get_header_type
from tlexport.quic.quic_packet import QuicHeaderType
from tlexport.quic.quic_session import QuicSession
from tlexport.session import Session
from tlexport.quic.quic_decode import QuicVersion

server_ports = [443, 44330]
keylog = []
sessions = []
quic_sessions = []


def arg_parser_init():
    parser = argparse.ArgumentParser(description="Adding Decryption Secret Block Support to Zeek")
    parser.add_argument("-p", "--serverports", help="additional ports to test for TLS-Connections", nargs="+",
                        default=[443])
    parser.add_argument("-i", "--infile", help="path of input file",
                        default="pcaps_und_keylogs/quic_pcaps/all_ciphersuites.pcapng")
    parser.add_argument("-o", "--outfile", help="path of output file", default="out.pcapng")
    parser.add_argument("-s", "--sslkeylog", help="path to sslkeylogfile",
                        default="pcaps_und_keylogs/quic_pcaps/all_ciphersuites.log")
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
    parser.add_argument("-g", "--greasy", help="ignore dtls, due to changes in the QUIC fixed bit, RFC 9287",
                        action=argparse.BooleanOptionalAction, default=False)

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


def handle_quic_packet(packet: Packet, keylog, quic_sessions: list[QuicSession], portmap):
    packet_payload = packet.tls_data
    header_type = get_header_type(packet_payload)

    quic_version = QuicVersion.UNKNOWN

    if header_type == QuicHeaderType.LONG:
        dcid_len = packet_payload[5]
        dcid = packet_payload[6: 6 + dcid_len]
        quic_vers_num = int.from_bytes(packet_payload[1:5], "big", signed=False)
        match quic_vers_num:
            case 1:
                quic_version = QuicVersion.V1
            case 2:
                quic_version = QuicVersion.V2
            case _:
                quic_version = QuicVersion.UNKNOWN

    for session in quic_sessions:
        # first try matching connection IDs
        if QuicHeaderType.LONG:
            if dcid in session.client_cids or dcid in session.server_cids:
                session.handle_packet(packet, dcid, quic_version)
                return
        else:
            # match by checking all known cid lengths for session
            for cid in session.client_cids | session.server_cids:
                if cid == packet_payload[1:1 + len(cid)]:
                    session.handle_packet(packet, dcid, quic_version)
                    return

        # check matching ip address and port for zero length cids
        if session.matches_session_dgram(packet.ip_src, packet.ip_dst, packet.sport, packet.dport):
            session.handle_packet(packet, dcid, quic_version)
            return

    if header_type != QuicHeaderType.SHORT:
        new_session = QuicSession(packet, server_ports, keylog, portmap)
        quic_sessions.append(new_session)
        new_session.handle_packet(packet, dcid, quic_version)


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
            if ((int(packet.tls_data[0]) & 0x40) >> 6) == 1 or args.greasy:
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

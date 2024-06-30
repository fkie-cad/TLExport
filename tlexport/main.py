#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import dpkt
import argparse
import logging

from .packet import Packet
from . import keylog_reader
from .dpkt_dsb import Reader
from .session import Session
from .checksums import calculate_checksum_tcp, calculate_checksum_udp
from .log import set_logger
from .about import __version__
from .quic.quic_dissector import get_header_type
from .quic.quic_packet import QuicHeaderType
from .quic.quic_session import QuicSession
from .quic.quic_decode import QuicVersion



server_ports = [443, 44330]
keylog = []
sessions = []
quic_sessions = []

class MapPortsAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        keep_original_ports = False  # If -m is used, we don't keep original ports
        if values:
            setattr(namespace, self.dest, values)
        else:
            # -m used without parameters, use default value
            setattr(namespace, self.dest, ["443:8080"])
        setattr(namespace, 'keep_original_ports', keep_original_ports)


def arg_parser_init():
    parser = argparse.ArgumentParser(description="TLExport - GENERATING DECRYPTED TLS PCAPS")

    parser.add_argument("-p", "--serverports", help="additional ports to test for TLS-Connections", nargs="+",
                        default=[443])
    parser.add_argument("-i", "--infile", help="path of input file",
                        default="tlexport/pcaps_und_keylogs/quic_pcaps/aes_gcm_128.pcapng")
    parser.add_argument("-o", "--outfile", help="path of output file", default="out.pcapng")
    parser.add_argument("-s", "--sslkeylog", help="path to sslkeylogfile",
                        default="tlexport/pcaps_und_keylogs/quic_pcaps/all_ciphersuites.log")
    # default False due to checksum offloading producing wrong checksums in Packet Capture
    parser.add_argument("-c", "--checksumTest", help="enable for checking tcp Checksums",
                        action=argparse.BooleanOptionalAction, default=False)
    parser.add_argument("-l", "--pcaplegacy", help="enable flag if infile is in the pcap format",
                        action=argparse.BooleanOptionalAction)
    parser.add_argument("-m", "--mapports",
                    action=MapPortsAction,
                    nargs='*',
                    default=argparse.SUPPRESS,  # Avoid setting mapports if not used
                    help="map TLS-Ports to specific output ports, use this option when using more than one "
                         "serverport <serverport:outputport>")
    parser.add_argument("-d", "--debug", nargs='?', const="INFO", default="ERROR",
                        help="Set the logging level (DEBUG, INFO, WARNING, ERROR)")

    parser.add_argument("-f", "--filter",
                        help="filter log messages by file, add files you want to filter", nargs="+")
    parser.add_argument('--version', action='version',version='TLExport v{version}'.format(version=__version__))
    parser.add_argument("-g", "--greasy", help="ignore dtls, due to changes in the QUIC fixed bit, RFC 9287",
                        action=argparse.BooleanOptionalAction, default=False)
    parser.add_argument("-a", "--metadata", help="export metadata (e.g. TLS-Handshake data), this could be useful for some packet analyzers like Wireshark or Zeek", 
                        action=argparse.BooleanOptionalAction, default=False)
    parser.set_defaults(keep_original_ports=True)


    return parser.parse_args()


def get_port_map(parser: argparse.Namespace):
    """Gets ports from given arguments

        :param parser: Namespace from *argparse* module
        :type parser: argparse.Namespace

        :return: directory containing how server ports are mapped to the output ports
        :rtype: dict
    """
    port_map: dict = {}
    i: str

    if 'mapports' not in parser or parser.mapports is None:
        return port_map

    for i in parser.mapports:
        i = i.replace(",", "") # if somebody is using a "," as seperator
        split = i.split(":")
        server_port = int(split[0])
        output_port = int(split[1])
        port_map[server_port] = output_port

    return port_map



def handle_packet(packet: Packet, args, keylog: bytes, sessions: list[Session], portmap: dict, keep_original_ports: bool, exp_meta: bool):
    """Matches packet to it's corresponding session, and initiates the handling of that packet in that session. Only used for *TLS over TCP* (NOT for QUIC, DTLS, etc.)

        :param packet: packet that is handled
        :param keylog: the secrets from the SSLKEYLOGFILE **AND** decryption secret blocks containing the connection secrets
        :type packet: Packet
        :type keylog: bytes
        :param sessions: list of all sessions that are currently handled
        :type sessions: list[Session]
        :param portmap: directory containing how server ports are mapped to the output ports
        :type portmap: dict
    """

    for session in sessions:
        if session.matches_session(packet):
            session.handle_packet(packet)
            return

    # if no matching session is found, a new one is created
    if packet.dport in server_ports or packet.sport in server_ports:
        sessions.append(Session(packet, server_ports, keylog, portmap, keep_original_ports, exp_meta))
        #sessions.append(Session(packet, server_ports, keylog, portmap, exp_meta))


def handle_quic_packet(packet: Packet, keylog, quic_sessions: list[QuicSession], portmap):
    """Matches packet to a session containg QUIC traffic, and initiates the handling of that packet in that session.
        Only used QUIC traffic

        :param packet: packet that is handled
        :type packet: Packet
        :param keylog: the secrets from the SSLKEYLOGFILE **AND** decryption secret blocks containing the connection secrets
        :type keylog: bytes
        :param quic_sessions: list of all quic sessions that are currently handled
        :type quic_sessions: list[Session]
        :param portmap: directory containing how server ports are mapped to the output ports
        :type portmap: dict
    """
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
        if header_type == QuicHeaderType.LONG:
            if dcid in session.client_cids or dcid in session.server_cids:
                session.handle_packet(packet, dcid, quic_version)
                return
        else:
            # match by checking all known cid lengths for session
            for cid in session.client_cids | session.server_cids:
                if cid == packet_payload[1:1 + len(cid)]:
                    session.handle_packet(packet, cid, quic_version)
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
    """Starts the program"""
    args = arg_parser_init()
    keep_original_ports = args.keep_original_ports
    portmap = get_port_map(args)

    set_logger(args)

    logging.debug(f"Arguments: {args}")
    logging.info(f"Mapping Ports: {portmap}")

    server_ports.extend([int(x) for x in args.serverports])
    

    metadata: bool = args.metadata

    if args.sslkeylog is not None:
        print(f"[*] Using keys from SSLKEYLOG: {args.sslkeylog}")
        keylog.extend(keylog_reader.read_keylog_from_file(args.sslkeylog))
    else:
        print("[*] Using keys from DSB")

    file = open(args.infile, "rb")

    if args.pcaplegacy:
        pcap_reader = dpkt.pcap.Reader(file)
    else:
        pcap_reader = Reader(file)
    
 
    print(f"[*] Checking for TLS traffic on these ports: {server_ports}")

    for ts, buf in pcap_reader:
        packet = Packet(buf, ts)

        if ts == -1:
            keylog.extend(keylog_reader.get_keys_from_string(buf.decode('ascii')))  # adds secrets from decryption secret block to keylog
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
                handle_packet(packet, args, keylog, sessions, portmap, keep_original_ports, exp_meta=metadata)


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

            # using fixed bit for differentiating between QUIC and D-TLS (For further information take a look at RFC 9287)
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
        all_decrypted_sessions.extend(quic_session.build_output(metadata))

    file = open(args.outfile, "wb")

    writer = dpkt.pcapng.Writer(file, snaplen=20000)

    for buf, ts in all_decrypted_sessions:
        writer.writepkt(bytes(buf), ts)

    file.close()
    print(f"[*] written decrypted PCAP to {args.outfile}")
    print("[*] Thx for using TLExport. Have a nice day!")


if __name__ == "__main__":
    run()

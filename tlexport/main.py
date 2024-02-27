#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import dpkt
import argparse
import logging

from .packet import Packet
from . import keylog_reader
from .dpkt_dsb import Reader
from .session import Session
from .checksums import calculate_checksum_tcp
from .log import set_logger
from .__init__ import __version__

server_ports = [443]
keylog = []
sessions = []


def arg_parser_init():
    parser = argparse.ArgumentParser(description="TLExport - GENERATING DECRYPTED TLS PCAPS")
    parser.add_argument("-p", "--serverports", help="additional ports to test for TLS-Connections", nargs="+",
                        default=[443])
    parser.add_argument("-i", "--infile", help="path of input file",
                        default="in.pcapng")
    parser.add_argument("-o", "--outfile", help="path of output file", default="out.pcapng")
    parser.add_argument("-s", "--sslkeylog", help="path to sslkeylogfile")
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
    parser.add_argument("-d", "--debug", nargs='?', const="INFO", default="ERROR",
                        help="Set the logging level (DEBUG, INFO, WARNING, ERROR)")

    parser.add_argument("-f", "--filter",
                        help="filter log messages by file, add files you want to filter", nargs="+")
    parser.add_argument('--version', action='version',version='TLExport v{version}'.format(version=__version__))

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


def handle_packet(packet: Packet, args, keylog, sessions: list[Session], portmap):
    for session in sessions:
        if session.matches_session(packet):
            session.handle_packet(packet)
            return

    if packet.dport in server_ports or packet.sport in server_ports:
        sessions.append(Session(packet, server_ports, keylog, portmap))


def run():

    args = arg_parser_init()
    portmap = get_port_map(args)

    set_logger(args)

    logging.debug(f"Arguments: {args}")
    logging.info(f"Mapping Ports: {portmap}")

    server_ports.extend([int(x) for x in args.serverports])
    


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

    
    print(f"[*] Checking for TLS Traffic on these ports: {server_ports}")

    for ts, buf in pcap_reader:
        packet = Packet(buf, ts)

        if ts == -1:
            keylog.extend(keylog_reader.get_keys_from_string(buf.decode('ascii')))
            continue

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
        if packet.tls_packet and checksum_test:
            handle_packet(packet, args, keylog, sessions, portmap)

    file.close()
    all_decrypted_sessions = []
    for session in sessions:
        all_decrypted_sessions.extend(session.decrypt())

    file = open(args.outfile, "wb")

    writer = dpkt.pcapng.Writer(file)

    for buf, ts in all_decrypted_sessions:
        writer.writepkt(bytes(buf), ts)

    file.close()
    print(f"[*] written decrypted PCAP to {args.outfile}")
    print("[*] Thx for using TLExport. Have a nice day!")


if __name__ == "__main__":
    run()

import logging
# suppress scapy warning message when importing the module
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.packet import Raw
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP
from tlexport.tlsrecord import TlsRecord
from math import floor


class OutputBuilder:
    def __init__(self, decrypted_records, server_ip, client_ip, server_port, client_port, server_mac_addr,
                 client_mac_addr, portmap) -> None:
        self.decrypted_records = decrypted_records
        self.server_ip = '.'.join(f'{c}' for c in server_ip)
        self.client_ip = '.'.join(f'{c}' for c in client_ip)
        self.server_port = server_port
        self.client_port = client_port
        self.default_port = 8080
        self.server_mac_addr = server_mac_addr
        self.client_mac_addr = client_mac_addr
        self.out = []

        self.server_seq = 1
        self.client_seq = 1

        if self.server_port in portmap.keys():
            self.server_port = portmap[self.server_port]
        else:
            self.server_port = self.default_port

    def build(self):
        self.no_application_records = True

        for record in self.decrypted_records:
            if record is not None:
                self.no_application_records = False

        if self.no_application_records:
            return []

        self.decrypted_records: list[TlsRecord]
        record: (str, TlsRecord, bool)

        self.conn_reset = True

        for record in self.decrypted_records:
            if record is None:
                self.conn_reset = True
                self.server_seq = 1
                self.client_seq = 1
                continue

            if self.conn_reset:
                self.ts_zero = record[1].metadata[0].timestamp
                self.build_ack_handshake()
                self.conn_reset = False

            decrypted = record[0]
            ts = []
            for packet in record[1].metadata:
                ts.append(packet.timestamp)

            if record[2]:
                self.build_server_packet(decrypted, ts)
            else:
                self.build_client_packet(decrypted, ts)
        return self.out

    # due to the size difference between plaintext and ciphertext new Syn/Ack values starting at 0 are used.
    # timestamps for the TCP Handshake are equal to the timestamp of the first TLS-Record
    def build_ack_handshake(self):
        syn = Ether(src=self.client_mac_addr, dst=self.server_mac_addr) / IP(src=self.client_ip,
                                                                             dst=self.server_ip) / TCP(
            dport=self.server_port, sport=self.client_port, flags='S', seq=0, ack=0)
        syn_ack = Ether(src=self.server_mac_addr, dst=self.client_mac_addr) / IP(src=self.server_ip,
                                                                                 dst=self.client_ip) / TCP(
            dport=self.client_port, sport=self.server_port, flags='SA', seq=0, ack=1)
        ack = Ether(src=self.client_mac_addr, dst=self.server_mac_addr) / IP(src=self.client_ip,
                                                                             dst=self.server_ip) / TCP(
            dport=self.server_port, sport=self.client_port, flags='A', seq=1, ack=1)

        self.out.extend([(syn, self.ts_zero), (syn_ack, self.ts_zero), (ack, self.ts_zero)])

    def build_server_packet(self, decrypted, ts):
        record_len = len(decrypted)
        packet_count = len(ts)
        part_len = floor(record_len / packet_count)
        parts = []
        last_len = 0
        for i in range(0, packet_count - 1):
            parts.append(decrypted[i * part_len: i * part_len + part_len])
            last_len = i * part_len + part_len

        if last_len < record_len:
            parts.append(decrypted[last_len:])
        for i in range(0, len(parts)):
            packet = Ether(src=self.server_mac_addr, dst=self.client_mac_addr) / IP(src=self.server_ip,
                                                                                    dst=self.client_ip) / TCP(
                dport=self.client_port, sport=self.server_port, flags='PA', seq=self.server_seq,
                ack=self.client_seq) / Raw(parts[i])
            self.server_seq += len(parts[i])
            packet_ack = Ether(src=self.client_mac_addr, dst=self.server_mac_addr) / IP(src=self.client_ip,
                                                                                        dst=self.server_ip) / TCP(
                dport=self.server_port, sport=self.client_port, flags='A', seq=self.client_seq, ack=self.server_seq)
            self.out.append((packet, ts[i]))
            self.out.append((packet_ack, ts[i]))

    def build_client_packet(self, decrypted, ts):
        record_len = len(decrypted)
        packet_count = len(ts)
        part_len = floor(record_len / packet_count)
        parts = []
        last_len = 0
        for i in range(0, packet_count - 1):
            parts.append(decrypted[i * part_len: i * part_len + part_len])
            last_len = i * part_len + part_len

        if last_len < record_len:
            parts.append(decrypted[last_len:])

        for i in range(0, len(parts)):
            packet = Ether(src=self.client_mac_addr, dst=self.server_mac_addr) / IP(src=self.client_ip,
                                                                                    dst=self.server_ip) / TCP(
                dport=self.server_port, sport=self.client_port, flags='PA', seq=self.client_seq,
                ack=self.server_seq) / Raw(parts[i])
            self.client_seq += len(parts[i])
            packet_ack = Ether(src=self.server_mac_addr, dst=self.client_mac_addr) / IP(src=self.server_ip,
                                                                                        dst=self.client_ip) / TCP(
                dport=self.client_port, sport=self.server_port, flags='A', seq=self.server_seq, ack=self.client_seq)
            self.out.append((packet, ts[i]))
            self.out.append((packet_ack, ts[i]))

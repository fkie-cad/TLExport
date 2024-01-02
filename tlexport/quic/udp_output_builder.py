from scapy.packet import Raw
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP, UDP
from typing import Type
from tlexport.quic.quic_frame import Frame

class UdpOutputBuilder:
    def __init__(self, decrypted_records: list[list[bytes, Type[Frame], bool]], server_ip, client_ip, server_port, client_port, server_mac_addr,
                 client_mac_addr, portmap):
        self.decrypted_records = decrypted_records
        self.server_ip = '.'.join(f'{c}' for c in server_ip)
        self.client_ip = '.'.join(f'{c}' for c in client_ip)

        self.server_port = server_port
        self.client_port = client_port
        self.portmap = portmap
        self.default_port = 8080
        self.server_mac_addr = server_mac_addr
        self.client_mac_addr = client_mac_addr
        self.out = []

        if self.server_port in portmap.keys():
            self.server_port = portmap[self.server_port]
        else:
            self.server_port = self.default_port

    def build(self):
        for record in self.decrypted_records:
            # TODO: get ts from associated packets
            ts = None
            isserver = record[2]
            if isserver:
                packet = Ether(src=self.server_mac_addr, dst=self.client_mac_addr) / IP(src=self.server_ip, dst=self.client_ip) / UDP(sport=self.server_port, dport=self.client_port) / Raw(record[0])
            else:
                packet = Ether(dst=self.server_mac_addr, src=self.client_mac_addr) / IP(dst=self.server_ip, src=self.client_ip) / UDP(dport=self.server_port, sport=self.client_port) / Raw(record[0])

            self.out.append((packet, ts))



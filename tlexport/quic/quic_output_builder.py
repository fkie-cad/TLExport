from tlexport.quic.quic_frame import Frame
from typing import Dict
from scapy.packet import Raw
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP

class QUICOutputbuilder:
    def __init__(self, decrypted_traffic, server_ip, client_ip, server_port, client_port, server_mac_address, client_mac_address, portmap):
        self.decrypted_traffic: Dict[int, list] = decrypted_traffic
        self.server_ip = '.'.join(f'{c}' for c in server_ip)
        self.client_ip = '.'.join(f'{c}' for c in client_ip)
        self.server_port = server_port
        self.client_port = client_port
        self.default_port = 8080
        self.server_mac_address = server_mac_address
        self.client_mac_address = client_mac_address
        self.out = []

        if self.server_port in portmap.keys():
            self.server_port = portmap[self.server_port]
        else:
            self.server_port = self.default_port

    def build(self, metadata: bool):
        pn = self.decrypted_traffic[0].src_packet.packet_num
        ts = self.decrypted_traffic[0].src_packet.ts
        isserver = self.decrypted_traffic[0].src_packet.isserver
        packets = bytearray()
        for frame in self.decrypted_traffic:

            if frame.frame_type == 0x06 and metadata:
                data = frame.crypto
            elif frame.frame_type == 0xfe and metadata:
                data = frame.supported_version
            elif frame.frame_type in [0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f]:
                data = frame.stream_data
            else:
                continue

            if frame.src_packet.packet_num == pn:
                packets.extend(data)
                continue
            else:   # if packets number changes
                if frame.src_packet.ts == ts:   # if same ts => same datagram
                    pn = frame.src_packet.packet_num
                    packets.extend(data)
                    continue
                else:   # if not same ts => different datagram
                    if isserver:
                        packet = Ether(src=self.server_mac_address, dst=self.client_mac_address) / IP(src=self.server_ip,
                                                                                                dst=self.client_ip) / UDP(
                            dport=self.client_port, sport=self.server_port) / Raw(bytes(packets))

                    else:
                        packet = Ether(src=self.client_mac_address, dst=self.server_mac_address) / IP(src=self.client_ip,
                                                                                                dst=self.server_ip) / UDP(
                            dport=self.server_port, sport=self.client_port) / Raw(bytes(packets))

                    self.out.append((packet, ts))

                    pn = frame.src_packet.packet_num
                    ts = frame.src_packet.ts
                    isserver = self.decrypted_traffic[0].src_packet.isserver
                    packets = bytearray()
                    packets.extend(data)

        if isserver:
            packet = Ether(src=self.server_mac_address, dst=self.client_mac_address) / IP(src=self.server_ip,
                                                                                            dst=self.client_ip) / UDP(
                dport=self.client_port, sport=self.server_port) / Raw(bytes(packets))

        else:
            packet = Ether(src=self.client_mac_address, dst=self.server_mac_address) / IP(src=self.client_ip,
                                                                                            dst=self.server_ip) / UDP(
                dport=self.server_port, sport=self.client_port) / Raw(bytes(packets))

        self.out.append((packet, ts))

        return self.out
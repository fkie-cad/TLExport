from tlexport.packet import Packet
from tlexport.keylog_reader import Key
from tlexport.quic.quic_key_generation import dev_quic_keys, dev_initial_keys
from cryptography.hazmat.primitives.hashes import SHA256
import pylsqpack
from tlexport.key_derivator import dev_tls_13_keys


class QuicSession:
    def __init__(self, packet: Packet, server_ports, keylog: list[Key], portmap):
        self.keylog = keylog

        self.ipv6 = packet.ipv6_packet

        self.set_server_client_address(packet, server_ports)

        self.packet_buffer = []
        self.packet_buffer.append(packet)

        self.server_decoder = pylsqpack.Decoder(4096, 16)
        self.client_decoder = pylsqpack.Decoder(4096, 16)
        secret_list = []

        self.client_initial_packets = []
        self.client_0_rtt_packets = []
        self.client_handshake_packets = []
        self.client_1_rtt_packets = []
        self.client_retry_packets = []

        self.server_initial_packets = []
        self.server_0_rtt_packets = []
        self.server_handshake_packets = []
        self.server_1_rtt_packets = []
        self.server_retry_packets = []



    def decrypt(self):
        for packet in self.packet_buffer:
            pass


    def set_server_client_address(self, packet, server_ports):
        if packet.sport in server_ports:
            self.server_ip = packet.ip_src
            self.server_port = packet.sport
            self.server_mac_addr = packet.ethernet_src

            self.client_ip = packet.ip_dst
            self.client_port = packet.dport
            self.client_mac_addr = packet.ethernet_dst

        else:
            self.server_ip = packet.ip_dst
            self.server_port = packet.dport
            self.server_mac_addr = packet.ethernet_dst

            self.client_ip = packet.ip_src
            self.client_port = packet.sport
            self.client_mac_addr = packet.ethernet_src

    def matches_session(self, packet: Packet):
        if (packet.ip_src == self.server_ip and packet.sport == self.server_port
                and packet.ip_dst == self.client_ip and packet.dport == self.client_port):
            return True
        elif (packet.ip_src == self.client_ip and packet.sport == self.client_port
              and packet.ip_dst == self.server_ip and packet.dport == self.server_port):
            return True
        return False

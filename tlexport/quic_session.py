from tlexport.packet import Packet


class QuicSession:
    def __init__(self, packet: Packet, server_ports, keylog, portmap):
        self.keylog = keylog

        self.ipv6 = packet.ipv6_packet

        self.set_server_client_address(packet, server_ports)

        self.packet_buffer = []
        self.packet_buffer.append(packet)

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

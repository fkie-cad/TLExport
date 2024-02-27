import dpkt
from ipaddress import IPv6Address, IPv4Address

# data class for network packets and metadata
class Packet:
    def __init__(self, packet, timestamp) -> None:
        self.timestamp = timestamp
        self.binary = packet

        self.ethernet = dpkt.ethernet.Ethernet(self.binary)

        self.tls_packet = True

        if not (isinstance(self.ethernet.data, dpkt.ip.IP) or isinstance(self.ethernet.data, dpkt.ip6.IP6)):
            self.tls_packet = False
            return

        if isinstance(self.ethernet.data, dpkt.ip6.IP6):
            self.ipv6_packet = True
        else:
            self.ipv6_packet = False

        self.ip = self.ethernet.data

        if not isinstance(self.ip.data, dpkt.tcp.TCP):
            self.tls_packet = False
            self.tls_data = b''
            return

        self.tcp = self.ip.data

        self.ethernet_src = self.ethernet.src
        self.ethernet_dst = self.ethernet.dst

        self.ip_src = self.ip.src
        self.ip_dst = self.ip.dst

        self.seq = self.tcp.seq
        self.ack = self.tcp.ack

        self.sport = self.tcp.sport
        self.dport = self.tcp.dport

        self.tls_data = self.tcp.data

    def get_params(self):
        if not self.ipv6_packet:
            src_address = IPv4Address(self.ip_src)
            dst_address = IPv4Address(self.ip_dst)
        else:
            src_address = IPv6Address(self.ip_src)
            dst_address = IPv6Address(self.ip_dst)



        return (f"source: {src_address} {self.sport}, "
                f"destination: {dst_address} {self.dport}, "
                f"sequence number: {self.seq}")
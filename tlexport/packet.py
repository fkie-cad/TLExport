import dpkt
from ipaddress import IPv6Address, IPv4Address


class Packet:
    """This class serves as a wrapper class for simplifying handling network packets and their metadata."""
    def __init__(self, binary: bytes, timestamp: float) -> None:
        """
            :param binary: packet data in bytes extracted by dpkt
            :type binary: bytes
            :param timestamp: timestamp of packet extracted by dpkt
            :type timestamp: float
        """
        self.timestamp = timestamp
        self.binary = binary

        self.ethernet = dpkt.ethernet.Ethernet(self.binary)

        self.tcp_packet = True
        self.udp_packet = False

        if not (isinstance(self.ethernet.data, dpkt.ip.IP) or isinstance(self.ethernet.data, dpkt.ip6.IP6)):
            self.tcp_packet = False
            return

        if isinstance(self.ethernet.data, dpkt.ip6.IP6):
            self.ipv6_packet = True
        else:
            self.ipv6_packet = False

        self.ip = self.ethernet.data

        self.ethernet_src = self.ethernet.src
        self.ethernet_dst = self.ethernet.dst

        self.ip_src = self.ip.src
        self.ip_dst = self.ip.dst

        if isinstance(self.ip.data, dpkt.tcp.TCP):
            self.tcp = self.ip.data
            self.seq = self.tcp.seq
            self.ack = self.tcp.ack

            self.sport = self.tcp.sport
            self.dport = self.tcp.dport

            self.tls_data = self.tcp.data

            return

        self.tcp_packet = False

        if isinstance(self.ip.data, dpkt.udp.UDP):
            self.udp = self.ip.data
            self.sport = self.udp.sport
            self.dport = self.udp.dport

            self.tls_data = self.udp.data

            self.udp_packet = True
            return

    def get_params(self):
        if not self.ipv6_packet:
            src_address = IPv4Address(self.ip_src)
            dst_address = IPv4Address(self.ip_dst)
        else:
            src_address = IPv6Address(self.ip_src)
            dst_address = IPv6Address(self.ip_dst)

        if self.tcp_packet:
            return (f"source: {src_address} {self.sport}, "
                    f"destination: {dst_address} {self.dport}, "
                    f"sequence number: {self.seq}, timestamp: {self.timestamp}")

        else:
            return (f"source: {src_address} {self.sport}, "
                    f"destination: {dst_address} {self.dport}, "
                    f"timestamp: {self.timestamp}")

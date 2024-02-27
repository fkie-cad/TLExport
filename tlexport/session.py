import logging
import warnings

from tlexport.packet import Packet
from tlexport.tlsrecord import TlsRecord
from tlexport.tlsversion import TlsVersion
import tlexport.key_derivator as key_derivator
import tlexport.cipher_suite_parser as cipher_suite_parser
from tlexport.decryptor import Decryptor
from tlexport.output_builder import OutputBuilder

from ipaddress import IPv6Address, IPv4Address

# Suppress the deprecation warning from the cryptography module.
with warnings.catch_warnings():
    warnings.simplefilter("ignore")
    from cryptography.hazmat.primitives.ciphers.algorithms import AES, TripleDES, IDEA, Camellia
    from cryptography.hazmat.primitives.ciphers.aead import AESCCM, AESGCM


class Session:
    def __init__(self, packet: Packet, server_ports, keylog, portmap) -> None:
        self.start_packet = packet
        self.keylog = keylog

        self.set_client_and_server_ports(packet, server_ports)

        self.server_tls_records = []
        self.client_tls_records = []
        self.server_packet_buffer = []
        self.client_packet_buffer = []
        self.packet_buffer = []

        self.server_counter = 0
        self.client_counter = 0

        self.seen_packets_server = []
        self.seen_packets_client = []

        self.can_decrypt = False
        self.client_hello_seen = False

        self.server_cipher_change = False
        self.client_cipher_change = False

        self.decryptor: Decryptor
        self.decryptor = None

        self.handle_packet(packet)

        self.application_traffic = []

        self.portmap = portmap

    # search SSLKEYLOG for session log data
    def find_session_secrets(self):
        is_handshake_secret = 0  # Only for TLS 1.3
        secrets = []
        for secret in self.keylog:
            if secret.client_random.lower() == self.client_random.hex().lower():
                if secret.label == "CLIENT_HANDSHAKE_TRAFFIC_SECRET":
                    is_handshake_secret += 1
                elif secret.label == "SERVER_HANDSHAKE_TRAFFIC_SECRET":
                    is_handshake_secret += 2
                secrets.append(secret)

        if is_handshake_secret < 2 and self.tls_version == TlsVersion.TLS13:
            logging.warning(f"Missing CLIENT_HANDSHAKE_TRAFFIC_SECRET")
        elif is_handshake_secret < 3 and self.tls_version == TlsVersion.TLS13:
            logging.warning(f"Missing SERVER_HANDSHAKE_TRAFFIC_SECRET")
        elif is_handshake_secret == 3 and self.tls_version == TlsVersion.TLS13:
            logging.warning(f"Missing CLIENT_HANDSHAKE_TRAFFIC_SECRET and SERVER_HANDSHAKE_TRAFFIC_SECRET")

        logging_string = "SSLKEYLOGFILE Content: "
        for secret in secrets:
            logging_string += f"{secret.label}: {secret.value}"
        logging.info(logging_string)

        return secrets

    # generate session keys from SSLKEYLOG
    def generate_keys(self, tls_version, server_cipher_suite, client_random, server_random):
        cipher_suite = cipher_suite_parser.split_cipher_suite(bytes(server_cipher_suite))

        if cipher_suite is None:
            self.can_decrypt = False
            return

        key_length = cipher_suite["KeyLength"]
        mac_length = cipher_suite["MAC"].digest_size

        secret_list = self.find_session_secrets()

        if len(secret_list) == 0:
            logging.error(f"Missing Secrets\n"
                          f"Server IP: {self.binary_to_ip(self.server_ip)}\n"
                          f"Server Port: {self.server_port}\n"
                          f"Client IP: {self.binary_to_ip(self.client_ip)}\n"
                          f"Client Port: {self.client_port}")
            self.can_decrypt = False
            return

        try:
            secret = secret_list[0]
        except IndexError:
            logging.error(f"Missing Secrets\n"
                          f"Server IP: {self.binary_to_ip(self.server_ip)}\n"
                          f"Server Port: {self.server_port}\n"
                          f"Client IP: {self.binary_to_ip(self.client_ip)}\n"
                          f"Client Port: {self.client_port}")
            self.can_decrypt = False
            return

        match tls_version:
            case TlsVersion.TLS13:
                keys = key_derivator.dev_tls_13_keys(secret_list, key_length, cipher_suite["MAC"]())

            case TlsVersion.TLS12:
                if secret.label == "CLIENT_RANDOM":
                    keys = key_derivator.dev_tls_12_keys(bytes.fromhex(secret.value), client_random, server_random,
                                                         key_length, mac_length, 2 * key_length + 2 * mac_length,
                                                         cipher_suite["CryptoAlgo"][0],
                                                         cipher_suite["Mode"][1], cipher_suite["MAC"])
                elif secret.label == "RSA":
                    master_secret = key_derivator.gen_master_secret_tls_12(bytes.fromhex(secret.value), client_random,
                                                                           server_random)
                    keys = key_derivator.dev_tls_12_keys(master_secret, client_random, server_random, key_length,
                                                         mac_length, 2 * key_length + 2 * mac_length,
                                                         cipher_suite["CryptoAlgo"][0],
                                                         cipher_suite["Mode"][1], cipher_suite["MAC"])

            case TlsVersion.TLS10 | TlsVersion.TLS11:
                if secret.label == "CLIENT_RANDOM":
                    keys = key_derivator.dev_tls_10_11_keys(bytes.fromhex(secret.value), server_random, client_random,
                                                            key_length, mac_length, 2 * key_length + 2 * mac_length,
                                                            cipher_suite["CryptoAlgo"][0], cipher_suite["Mode"][1])
                elif secret.label == "RSA":
                    master_secret = key_derivator.gen_master_secret_tls_10_11(bytes.fromhex(secret.value),
                                                                              client_random, server_random)
                    keys = key_derivator.dev_tls_10_11_keys(master_secret, client_random, server_random, key_length,
                                                            mac_length, 2 * key_length + 2 * mac_length,
                                                            cipher_suite["CryptoAlgo"][0], cipher_suite["Mode"][1])

            case TlsVersion.SSL30:
                if secret.label == "CLIENT_RANDOM":
                    keys = key_derivator.dev_ssl_30_keys(bytes.fromhex(secret.value), server_random, client_random,
                                                         key_length, mac_length, 2 * key_length + 2 * mac_length,
                                                         cipher_suite["CryptoAlgo"][0], cipher_suite["CryptoAlgo"][1])
                elif secret.label == "RSA":
                    master_secret = key_derivator.gen_master_secret_ssl_30(bytes.fromhex(secret.value), client_random,
                                                                           server_random)
                    keys = key_derivator.dev_ssl_30_keys(master_secret, client_random, server_random, key_length,
                                                         mac_length, 2 * key_length + 2 * mac_length,
                                                         cipher_suite["CryptoAlgo"][0], cipher_suite["CryptoAlgo"][1])

        # get block size
        block_size = 0
        algo = cipher_suite["CryptoAlgo"][0]
        if algo in [AES, AESCCM, AESGCM, Camellia]:
            block_size = 128
        elif algo in [TripleDES, IDEA]:
            block_size = 64

        self.decryptor = Decryptor(cipher_suite["CryptoAlgo"][0], cipher_suite["Mode"][0], cipher_suite["MAC"], keys,
                                   self.tls_version, cipher_suite["KeyLength"], cipher_suite["MAC"].digest_size,
                                   cipher_suite["TagLength"], block_size, self.extensions, self.compression_method)

    # gets the session metadata from first session packet
    def set_client_and_server_ports(self, packet: Packet, server_ports):
        self.ipv6 = packet.ipv6_packet

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

    # checks if packet is in session
    def matches_session(self, packet: Packet):
        if (packet.ip_src == self.server_ip and packet.sport == self.server_port
                and packet.ip_dst == self.client_ip and packet.dport == self.client_port):
            return True
        elif (packet.ip_src == self.client_ip and packet.sport == self.client_port
              and packet.ip_dst == self.server_ip and packet.dport == self.server_port):
            return True
        return False

    # add packet to session, if packet is not a duplicate, splitting into server and client packets
    def handle_packet(self, packet: Packet):
        sequence = packet.seq

        if packet.ip_src == self.server_ip and packet.sport == self.server_port:
            if sequence in self.seen_packets_server:
                return

            self.seen_packets_server.append(sequence)

            self.packet_buffer.append(packet)

        else:
            if sequence in self.seen_packets_client:
                return

            self.seen_packets_client.append(sequence)

            self.packet_buffer.append(packet)

    def decrypt(self):
        print(f"[*] Decrypting session: [{self.binary_to_ip(self.server_ip)}:{self.server_port}-{self.binary_to_ip(self.client_ip)}:{self.client_port}]\n")
        logging.info(f"\n---------------------------------------------------------------------\n"
                     f"Decrypting session:\n"
                     f"Server IP: {self.binary_to_ip(self.server_ip)}\n"
                     f"Server Port: {self.server_port}\n"
                     f"Client IP: {self.binary_to_ip(self.client_ip)}\n"
                     f"Client Port: {self.client_port}"
                     f"\n---------------------------------------------------------------------\n")
        self.get_tls_records()
        self.builder = OutputBuilder(self.application_traffic, self.server_ip, self.client_ip, self.server_port,
                                     self.client_port, self.server_mac_addr, self.client_mac_addr, self.portmap)
        return self.builder.build()

    def handle_tls_handshake_record(self, record: TlsRecord, isserver):
        if self.server_cipher_change or self.client_cipher_change:
            try:
                self.handle_handshake_finished(record, isserver)
            except Exception as e:
                logging.warning(f"Could not decrypt Record: Handshake finished")
            return

        match record.binary[0]:
            # client Hello
            case 0x01:
                self.handle_tls_client_hello(record)
            case 0x02:
                self.handle_tls_server_hello(record)
            # ignore the others for now (in TLS 1.3 in application Records)
            case _:
                try:
                    self.handle_handshake_finished(record, isserver)
                except Exception as e:
                    logging.warning(f"Could not decrypt Record: Handshake finished")

    def handle_handshake_finished(self, record, isserver):
        if self.decryptor is None:
            logging.warning(f"Could not decrypt Record: Handshake finished")
            return
        if self.server_cipher_change and isserver and self.can_decrypt:
            _plaintext = self.decryptor.decrypt(record, isserver)

        if self.client_cipher_change and not isserver and self.can_decrypt:
            _plaintext = self.decryptor.decrypt(record, isserver)

    def handle_tls_client_hello(self, record: TlsRecord):
        self.can_decrypt = False
        self.server_cipher_change = False
        self.client_cipher_change = False
        self.client_random = record.binary[6:38]
        logging.info(f"Client Random: {self.client_random.hex()}")
        self.client_hello_seen = True

    def handle_tls_server_hello(self, record: TlsRecord):
        if self.client_hello_seen:
            self.can_decrypt = True

        self.server_random = record.binary[6: 38]
        logging.info(f"Server Random: {self.server_random.hex()}")

        index = 38
        session_id_length = record.binary[index]
        index += session_id_length + 1

        self.ciphersuite = record.binary[index: index + 2]

        self.compression_method = record.binary[index + 2]

        extensions_length = int.from_bytes(record.binary[index + 3: index + 5], 'big')
        extensions_bin = record.binary[index + 5: index + 5 + extensions_length]

        self.extensions = {}

        extensions_index = 0
        while extensions_index < extensions_length:
            extension_length = int.from_bytes(extensions_bin[extensions_index + 2: extensions_index + 4], 'big')
            self.extensions[bytes(extensions_bin[extensions_index:extensions_index + 2])] \
                = extensions_bin[extensions_index + 4: extensions_index + 4 + extension_length]
            extensions_index += extension_length + 4
        is_tls13 = False
        if self.extensions.get(bytes.fromhex("002b")) == bytearray.fromhex("0304"):
            is_tls13 = True

        match int.from_bytes(record.record_version, 'big'):
            case 0x0300:
                self.tls_version = TlsVersion.SSL30
            case 0x0302:
                self.tls_version = TlsVersion.TLS11
            case _:
                if int.from_bytes(record.binary[4:6], 'big') == 0x0301:
                    self.tls_version = TlsVersion.TLS10
                elif int.from_bytes(record.binary[4:6], 'big') == 0x0303:
                    if is_tls13:
                        self.tls_version = TlsVersion.TLS13
                    else:
                        self.tls_version = TlsVersion.TLS12
                else:
                    self.can_decrypt = False
        self.generate_keys(self.tls_version, self.ciphersuite, self.client_random, self.server_random)

    def handle_alert(self, alert_level):
        # Closing Connection as every error leads to immediate termination of connection
        if alert_level == 0x1 and self.tls_version != TlsVersion.TLS13:
            return
        self.can_decrypt = False
        self.client_hello_seen = False

    def handle_decrypted_handshake_record(self, plaintext, isserver):
        index = 0
        while index < len(plaintext):
            handshake_type = plaintext[index]
            length = int.from_bytes(plaintext[index + 1:index + 4], 'big')

            if handshake_type == 20:
                self.decryptor.update_keys(isserver)

            index += length + 4

    def handle_tls_13_application_record(self, record: TlsRecord, isserver):
        try:
            plaintext = self.decryptor.decrypt(record, isserver)
            subrecord_type = plaintext[-1:]
            if subrecord_type == b'\x16':
                self.handle_decrypted_handshake_record(plaintext[:-1], isserver)
                return
            if subrecord_type == b'\x17':
                self.application_traffic.append((plaintext[:-1], record, isserver))
            if subrecord_type == 21:
                self.handle_alert(record.binary[0])
        except Exception as e:
            logging.warning(f"Could not decrypt Record: {self.tls_version} Application Record")

    def handle_tls_application_record(self, record: TlsRecord, isserver):
        try:
            plaintext = self.decryptor.decrypt(record, isserver)

            self.application_traffic.append((plaintext, record, isserver))
        except Exception as e:
            logging.warning(f"Could not decrypt Record: TLS Application Record")

    # consumes and handles a TLS_Record
    def handle_tls_record(self, record: TlsRecord, isserver):
        logging.info("")
        logging.info(f"Record Type: {record.record_type}")
        logging.info(f"Binary: {record.raw.hex()}")
        match record.record_type:
            # Handshake Record
            case 0x16:
                self.handle_tls_handshake_record(record, isserver)
                self.application_traffic.append(None)

            case 0x17:
                if self.decryptor is None:
                    logging.warning(f"Could not decrypt Record: Decryptor is None")
                if self.can_decrypt and self.decryptor is not None:
                    match self.tls_version:
                        case TlsVersion.TLS13:
                            self.handle_tls_13_application_record(record, isserver)
                        case TlsVersion.TLS12 | TlsVersion.TLS11 | TlsVersion.TLS10 | TlsVersion.SSL30:
                            self.handle_tls_application_record(record, isserver)

                        case _:
                            logging.error(f"Unkown TLS Version\n"
                                          f"Server IP: {self.binary_to_ip(self.server_ip)}\n"
                                          f"Server Port: {self.server_port}\n"
                                          f"Client IP: {self.binary_to_ip(self.client_ip)}\n"
                                          f"Client Port: {self.client_port}")
                            self.can_decrypt = False
                            pass

            # Alert Record
            case 0x15:
                self.handle_alert(record.binary[0])
                self.application_traffic.append(None)

            case 0x14:
                if isserver:
                    self.server_cipher_change = True
                else:
                    self.client_cipher_change = True

    def binary_to_ip(self, ip_addr):
        if self.ipv6:
            return IPv6Address(ip_addr)
        else:
            return IPv4Address(ip_addr)

    # extracts TLS_Records from packet buffers
    def get_tls_records(self):
        packet: Packet
        for packet in self.packet_buffer:
            if packet.ip_src == self.server_ip and packet.sport == self.server_port:
                self.server_packet_buffer.append(packet)
                self.extract_server_buf()

                for record in self.server_tls_records:
                    self.handle_tls_record(record, True)

                self.server_tls_records.clear()
            else:
                self.client_packet_buffer.append(packet)
                self.extract_client_buf()

                for record in self.client_tls_records:
                    self.handle_tls_record(record, False)

                self.client_tls_records.clear()

    # extracts packets from session which together contain complete TLS_Records
    def extract_server_buf(self):
        self.server_counter += 1
        self.server_packet_buffer.sort(key=lambda x: x.seq)

        for i in range(0, len(self.server_packet_buffer) - 1):
            if self.server_packet_buffer[i].seq + len(self.server_packet_buffer[i].tls_data) != \
                    self.server_packet_buffer[i + 1].seq:
                # need more packets (missing packets)
                return

        index = 0
        packet_ranges = []
        total_packet_len = 0
        packet_data = bytearray(b'')

        for i in self.server_packet_buffer:
            packet_len = len(i.tls_data)
            packet_ranges.append((total_packet_len, total_packet_len + packet_len, i))
            total_packet_len += packet_len
            packet_data.extend(i.tls_data)

        while True:
            if total_packet_len - index == 0:
                need_data = False
                break
            if total_packet_len - index < 5:
                need_data = True
                break

            record_len = packet_data[index + 3: index + 5]
            record_len = int.from_bytes(record_len, 'big') + 5

            index += record_len

        if not need_data:
            index = 0
            while index != total_packet_len:
                metadata = []
                record_len = packet_data[index + 3: index + 5]
                record_len = int.from_bytes(record_len, 'big') + 5
                for packet_range in packet_ranges:
                    if index < packet_range[1] and index + record_len > packet_range[0]:
                        metadata.append(packet_range[2])

                binary = packet_data[index:index + record_len]

                tls_record = TlsRecord(binary, metadata, True)
                self.server_tls_records.append(tls_record)

                index += record_len
            self.server_packet_buffer.clear()

    # extracts packets from session which together contain complete TLS_Records
    def extract_client_buf(self):
        self.client_counter += 1
        self.client_packet_buffer.sort(key=lambda x: x.seq)

        for i in range(0, len(self.client_packet_buffer) - 1):
            if self.client_packet_buffer[i].seq + len(self.client_packet_buffer[i].tls_data) != \
                    self.client_packet_buffer[i + 1].seq:
                # need more packets (missing packets)
                return

        index = 0
        packet_ranges = []
        total_packet_len = 0
        packet_data = bytearray(b'')

        for i in self.client_packet_buffer:
            packet_len = len(i.tls_data)
            packet_ranges.append((total_packet_len, total_packet_len + packet_len, i))
            total_packet_len += packet_len
            packet_data.extend(i.tls_data)

        while True:
            if total_packet_len - index == 0:
                need_data = False
                break
            if total_packet_len - index < 5:
                need_data = True
                break

            record_len = packet_data[index + 3: index + 5]
            record_len = int.from_bytes(record_len, 'big') + 5

            index += record_len

        if not need_data:
            index = 0
            while index != total_packet_len:
                metadata = []
                record_len = packet_data[index + 3: index + 5]
                record_len = int.from_bytes(record_len, 'big') + 5
                for packet_range in packet_ranges:
                    if index < packet_range[1] and index + record_len > packet_range[0]:
                        metadata.append(packet_range[2])

                binary = packet_data[index:index + record_len]

                tls_record = TlsRecord(binary, metadata, True)
                self.client_tls_records.append(tls_record)

                index += record_len
            self.client_packet_buffer.clear()

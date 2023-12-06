from typing import Type


class DtlsRecord:
    pass


class UnifiedHeaderRecord(DtlsRecord):
    def __init__(self, record_bytes: bytes, connection_id_length: int):
        # last two bits of epoch
        # TODO: decrypt record number
        self.epoch_last_bits = record_bytes[0] & 2
        length_exists = bool(record_bytes[0] >> 2 & 1)
        sequence_number_length = 2 if record_bytes[0] >> 3 & 1 else 1
        connection_id_present = bool(record_bytes[0] >> 4 & 1)
        print(self.epoch_last_bits, length_exists, sequence_number_length, connection_id_present)
        self.connection_id = None
        index = 1

        if connection_id_present:
            self.connection_id = record_bytes[index:index + connection_id_length]
            index += connection_id_length

        self.sequence_number = record_bytes[index:index + sequence_number_length]
        index += sequence_number_length

        if length_exists:
            self.payload_length = int.from_bytes(record_bytes[index:index + 2], 'big', signed=False)
            index += 2
            self.record_length = index + self.payload_length
            self.payload = record_bytes[index: self.record_length]
        else:
            self.record_length = len(record_bytes)
            self.payload_length = self.record_length - index
            self.payload = record_bytes[index:]


class PlaintextRecord(DtlsRecord):
    def __init__(self, record_bytes):
        self.content_type = record_bytes[0]

        # for legacy reasons
        self.protocol_version = record_bytes[1:2]
        self.epoch = record_bytes[2:4]
        self.sequence_number = record_bytes[4:10]
        self.payload_length = int.from_bytes(record_bytes[11:13], 'big', signed=False)
        self.payload = record_bytes[12:12 + self.payload_length]
        self.record_length = 13 + self.payload_length


class AlertRecord(PlaintextRecord):
    def __init__(self, record_bytes: bytes):
        super().__init__(record_bytes)


class CidEnhancedCiphertextRecord(DtlsRecord):
    def __init__(self, record_bytes, connection_id_length):
        self.content_type = record_bytes[0]

        # for legacy reasons
        self.protocol_version = record_bytes[1:2]
        self.epoch = record_bytes[2:4]
        self.sequence_number = record_bytes[4:10]
        self.connection_id = record_bytes[10: 10 + connection_id_length]
        index = 10 + connection_id_length
        self.payload_length = int.from_bytes(record_bytes[index:index + 2], 'big', signed=False)
        index += 2
        self.payload = record_bytes[index:index + self.payload_length]
        self.record_length = index + self.payload_length


class AckRecord(PlaintextRecord):
    def __init__(self, record_bytes):
        super().__init__(record_bytes)


class ApplicationDataRecord(PlaintextRecord):
    def __init__(self, record_bytes):
        super().__init__(record_bytes)


class ClientHelloRecord(PlaintextRecord):
    def __init__(self, record_bytes):
        super().__init__(record_bytes)
        self.handshake_type = 0x01

        self.handshake_length = int.from_bytes(record_bytes[14: 17], "big", signed=False)

        self.message_seq = int.from_bytes(record_bytes[17: 19], "big", signed=False)
        self.fragment_offset = int.from_bytes(record_bytes[19: 22], "big", signed=False)
        self.fragment_length = int.from_bytes(record_bytes[22:25], "big", signed=False)
        self.handshake_message = record_bytes[25: 25 + self.fragment_length]

        self.legacy_version = self.handshake_message[0:2]
        self.client_random = self.handshake_message[2:34]


class ServerHelloRecord(PlaintextRecord):
    def __init__(self, record_bytes):
        super().__init__(record_bytes)
        self.handshake_type = 0x02

        self.handshake_length = int.from_bytes(record_bytes[14: 17], "big", signed=False)

        self.message_seq = int.from_bytes(record_bytes[17: 19], "big", signed=False)
        self.fragment_offset = int.from_bytes(record_bytes[19: 22], "big", signed=False)
        self.fragment_length = int.from_bytes(record_bytes[22:25], "big", signed=False)
        self.handshake_message = record_bytes[25: 25 + self.fragment_length]

        self.legacy_version = self.handshake_message[0:2]
        self.dtls_version = b""
        for i in range(len(self.legacy_version)):
            self.dtls_version = self.dtls_version + (self.legacy_version[i] ^ 0xff).to_bytes(1, 'big', signed=False)
        self.dtls_version_inverted = self.legacy_version

        print(self.dtls_version)

        self.client_random = self.handshake_message[2:34]
        self.session_id_length = self.handshake_message[34]
        print(self.session_id_length)

        self.session_id = self.handshake_message[35:35 + self.session_id_length]
        index = 35 + self.session_id_length
        self.cipher_suite = self.handshake_message[index: index + 2]
        self.compression_method = self.handshake_message[index + 2: index + 3]
        self.extension_body = self.handshake_message[index + 3:]

        self.get_extensions(self.extension_body)
        self.encrypt_then_mac = False

    def get_extensions(self, record):
        if len(record[2:]) != int.from_bytes(record[:2], 'big', signed=False):
            return
        record = record[2:]

        extensions = []
        while True:

            if len(record) < 4:
                break

            extension_type = record[:2]
            extension_length = int.from_bytes(record[2:4], 'big', signed=False)

            if len(record) < 4 + extension_length:
                break

            extension_body = record[4:4 + extension_length]

            extensions.append((extension_type, extension_length, extension_body))

            record = record[4 + extension_length:]

        for e_type, e_length, e_body in extensions:
            match int.from_bytes(e_type, "big", signed=False):
                # TODO add cid extension, which is not supported by about all tls libraries
                case 43:
                    if e_length != 2:
                        continue
                    self.dtls_version_inverted = e_body
                    self.dtls_version = b""
                    for i in range(len(self.legacy_version)):
                        self.dtls_version = self.dtls_version + (self.legacy_version[i] ^ 0xff).to_bytes(1, 'big',
                                                                                                         signed=False)
                    print("DTLS VERS", self.dtls_version, self.dtls_version_inverted)
                case 22:
                    self.encrypt_then_mac = True


def extract_records(record_bytes: bytes, connection_id_length: int):
    records: list[DtlsRecord] = []
    for i in range(len(record_bytes)):
        if len(record_bytes) == 0:
            break

        record, record_length = extract_record(record_bytes, connection_id_length)
        records.append(record)
        record_bytes = record_bytes[record_length:]

    return records


# warning multiplexing can occur only Content Type 19 - 64 is dtls
def extract_record(record_bytes: bytes, connection_id_length: int) -> (Type[DtlsRecord], bytes):
    # TODO decryption

    # unified Header
    if (record_bytes[0] >> 5) == 1:
        record = UnifiedHeaderRecord(record_bytes, connection_id_length)

    # Dtls plaintext structure
    else:
        match record_bytes[0]:
            # change cipher spec, not needed
            case 20:
                record = PlaintextRecord(record_bytes)

            # alert record
            case 21:
                record = AlertRecord(record_bytes)

            # handshake record, Server and Client Hello needed
            # TODO: Key Update, Connection IDs
            case 22:
                print(record_bytes[13])
                # TODO add CID Extension parsing
                # client hello
                if record_bytes[13] == 1:
                    record = ClientHelloRecord(record_bytes)

                # server hello
                elif record_bytes[13] == 2:
                    record = ServerHelloRecord(record_bytes)

                else:
                    record = PlaintextRecord(record_bytes)

            # application record
            case 23:
                record = ApplicationDataRecord(record_bytes)

            # heartbeat record
            case 24:
                record = PlaintextRecord(record_bytes)

            # tls1.2 cid record
            case 25:
                record = CidEnhancedCiphertextRecord

            # ack record
            case 26:
                record = AckRecord(record_bytes)

    return record, record.record_length

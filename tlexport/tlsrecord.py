from tlexport.packet import Packet


# data class for better handling of tls records
class TlsRecord:
    def __init__(self, binary, metadata: list[Packet], isserver) -> None:
        self.binary = binary[5:]
        self.record_type = binary[0]
        self.record_version = binary[1:3]
        self.record_length = binary[3:5]
        self.metadata = metadata
        self.isserver = isserver

        self.raw = binary

from enum import Enum


class KeyType(Enum):
    RSA = 1
    CLIENT_RANDOM = 2
    CLIENT_EARLY_TRAFFIC_SECRET = 3
    CLIENT_HANDSHAKE_TRAFFIC_SECRET = 4
    SERVER_HANDSHAKE_TRAFFIC_SECRET = 5
    CLIENT_TRAFFIC_SECRET_0 = 6
    SERVER_TRAFFIC_SECRET_0 = 7
    EARLY_EXPORTER_SECRET = 8
    EXPORTER_SECRET = 9
    NONE = 0


class Key:
    def __init__(self, sec_string: str) -> None:
        [ktype, cl_rand, sec] = sec_string.split(" ")
        self.key_type = self.get_key_type(ktype)
        self.client_random = bytes.fromhex(cl_rand)
        self.secret = bytes.fromhex(sec)

    def get_key_type(self, ktype):
        if ktype == "RSA":
            return KeyType.RSA
        elif ktype == "CLIENT_RANDOM":
            return KeyType.CLIENT_RANDOM
        elif ktype == "CLIENT_EARLY_TRAFFIC_SECRET":
            return KeyType.CLIENT_EARLY_TRAFFIC_SECRET
        elif ktype == "CLIENT_HANDSHAKE_TRAFFIC_SECRET":
            return KeyType.CLIENT_HANDSHAKE_TRAFFIC_SECRET
        elif ktype == "SERVER_HANDSHAKE_TRAFFIC_SECRET":
            return KeyType.SERVER_HANDSHAKE_TRAFFIC_SECRET
        elif ktype == "CLIENT_TRAFFIC_SECRET_0":
            return KeyType.CLIENT_TRAFFIC_SECRET_0
        elif ktype == "SERVER_TRAFFIC_SECRET_0":
            return KeyType.SERVER_TRAFFIC_SECRET_0
        elif ktype == "EARLY_EXPORTER_SECRET":
            return KeyType.EARLY_EXPORTER_SECRET
        elif ktype == "EXPORTER_SECRET":
            return KeyType.EXPORTER_SECRET
        else:
            return KeyType.NONE

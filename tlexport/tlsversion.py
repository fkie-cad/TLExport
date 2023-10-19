from enum import Enum


class TlsVersion(Enum):
    SSL30 = 0x0300
    TLS10 = 0x0301
    TLS11 = 0x0302
    TLS12 = 0x0303
    TLS13 = 0x0304
    UNDEFINED = 0x00

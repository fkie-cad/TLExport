
import logging
import warnings

# Suppress the deprecation warning from the cryptography module.
with warnings.catch_warnings():
    warnings.simplefilter("ignore")
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers import modes
    from cryptography.hazmat.primitives.ciphers.algorithms import AES, TripleDES, Camellia, IDEA, ARC4, ChaCha20
    from cryptography.hazmat.primitives.ciphers import aead

cipher_suites = {
    # The following 5 cipher suites are the only cipher suites supported by TLSv1.3
    b'\x13\x02': 'TLS_AES_256_GCM_SHA384',
    b'\x13\x03': 'TLS_CHACHA20_POLY1305_SHA256',
    b'\x13\x01': 'TLS_AES_128_GCM_SHA256',
    b'\x13\x04': 'TLS_AES_128_CCM_SHA256',
    b'\x13\x05': 'TLS_AES_128_CCM_8_SHA256',

    # The following cipher suites are other cipher suites recommended by the IANA (Date: September 2023)
    b'\xD0\x05': 'TLS_ECDHE_PSK_WITH_AES_128_CCM_SHA256',
    b'\xD0\x02': 'TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384',
    b'\xD0\x01': 'TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256',
    b'\xCC\xAD': 'TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256',
    b'\xCC\xAC': 'TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256',
    b'\xCC\xAA': 'TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256',
    b'\xCC\xA9': 'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256',
    b'\xCC\xA8': 'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256',
    b'\xC0\xA7': 'TLS_DHE_PSK_WITH_AES_256_CCM',
    b'\xC0\xA6': 'TLS_DHE_PSK_WITH_AES_128_CCM',
    b'\xC0\x9F': 'TLS_DHE_RSA_WITH_AES_256_CCM',
    b'\xC0\x9E': 'TLS_DHE_RSA_WITH_AES_128_CCM',
    b'\xC0\x30': 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
    b'\xC0\x2F': 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
    b'\xC0\x2B': 'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',
    b'\xC0\x2C': 'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384',
    b'\x00\xAA': 'TLS_DHE_PSK_WITH_AES_128_GCM_SHA256',
    b'\x00\xAB': 'TLS_DHE_PSK_WITH_AES_256_GCM_SHA384',
    b'\x00\x9E': 'TLS_DHE_RSA_WITH_AES_128_GCM_SHA256',
    b'\x00\x9F': 'TLS_DHE_RSA_WITH_AES_256_GCM_SHA384',

    # All following cipher suites are cipher suites that are DEPRECATED and NOT RECOMMENDED by the IANA except 'TLS_AES_128_CCM_8_SHA256'

    # Deprecated cipher suites using CAMELLIA
    b'\xC0\x9B': 'TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384',
    b'\xC0\x9A': 'TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256',
    b'\xC0\x99': 'TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384',
    b'\xC0\x98': 'TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256',
    b'\xC0\x97': 'TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384',
    b'\xC0\x96': 'TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256',
    b'\xC0\x95': 'TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384',
    b'\xC0\x94': 'TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256',

    # b'\xC0\x93': 'TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384',
    # b'\xC0\x92': 'TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256',
    # b'\xC0\x91': 'TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384',
    # b'\xC0\x90': 'TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256',
    # b'\xC0\x8F': 'TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384',
    # b'\xC0\x8E': 'TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256',
    # b'\xC0\x8D': 'TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384',
    # b'\xC0\x8C': 'TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256',
    # b'\xC0\x8B': 'TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384',
    # b'\xC0\x8A': 'TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256',
    # b'\xC0\x89': 'TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384',
    # b'\xC0\x88': 'TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256',
    # b'\xC0\x87': 'TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384',
    # b'\xC0\x86': 'TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256',
    # b'\xC0\x85': 'TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384',
    # b'\xC0\x84': 'TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256',
    # b'\xC0\x83': 'TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384',
    # b'\xC0\x82': 'TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256',
    # b'\xC0\x81': 'TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384',
    # b'\xC0\x80': 'TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256',
    # b'\xC0\x7F': 'TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384',
    # b'\xC0\x7E': 'TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256',
    # b'\xC0\x7D': 'TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384',
    # b'\xC0\x7C': 'TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256',
    # b'\xC0\x7B': 'TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384',
    # b'\xC0\x7A': 'TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256',

    b'\xC0\x79': 'TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384',
    b'\xC0\x78': 'TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256',
    b'\xC0\x77': 'TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384',
    b'\xC0\x76': 'TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256',
    b'\xC0\x75': 'TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384',
    b'\xC0\x74': 'TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256',
    b'\xC0\x73': 'TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384',
    b'\xC0\x72': 'TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256',
    b'\x00\xC5': 'TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256',
    b'\x00\xC4': 'TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256',
    b'\x00\xC3': 'TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256',
    b'\x00\xC2': 'TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256',
    b'\x00\xC1': 'TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256',
    b'\x00\xC0': 'TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256',
    b'\x00\xBF': 'TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256',
    b'\x00\xBE': 'TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256',
    b'\x00\xBD': 'TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256',
    b'\x00\xBC': 'TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256',
    b'\x00\xBB': 'TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256',
    b'\x00\xBA': 'TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256',
    b'\x00\x89': 'TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA',
    b'\x00\x88': 'TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA',
    b'\x00\x87': 'TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA',
    b'\x00\x86': 'TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA',
    b'\x00\x85': 'TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA',
    b'\x00\x84': 'TLS_RSA_WITH_CAMELLIA_256_CBC_SHA',
    b'\x00\x46': 'TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA',
    b'\x00\x45': 'TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA',
    b'\x00\x44': 'TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA',
    b'\x00\x43': 'TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA',
    b'\x00\x42': 'TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA',
    b'\x00\x41': 'TLS_RSA_WITH_CAMELLIA_128_CBC_SHA',

    # Deprecated cipher suites using RC4
    b'\xC0\x33': 'TLS_ECDHE_PSK_WITH_RC4_128_SHA',
    b'\xC0\x16': 'TLS_ECDH_anon_WITH_RC4_128_SHA',
    b'\xC0\x11': 'TLS_ECDHE_RSA_WITH_RC4_128_SHA',
    b'\xC0\x0C': 'TLS_ECDH_RSA_WITH_RC4_128_SHA',
    b'\xC0\x07': 'TLS_ECDHE_ECDSA_WITH_RC4_128_SHA',
    b'\xC0\x02': 'TLS_ECDH_ECDSA_WITH_RC4_128_SHA',
    b'\x00\x92': 'TLS_RSA_PSK_WITH_RC4_128_SHA',
    b'\x00\x8E': 'TLS_DHE_PSK_WITH_RC4_128_SHA',
    b'\x00\x8A': 'TLS_PSK_WITH_RC4_128_SHA',
    b'\x00\x24': 'TLS_KRB5_WITH_RC4_128_MD5',
    b'\x00\x20': 'TLS_KRB5_WITH_RC4_128_SHA',
    b'\x00\x18': 'TLS_DH_anon_WITH_RC4_128_MD5',
    b'\x00\x05': 'TLS_RSA_WITH_RC4_128_SHA',
    b'\x00\x04': 'TLS_RSA_WITH_RC4_128_MD5',

    # Deprecated cipher suites using 3DES (Triple-DES)
    b'\xC0\x34': 'TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA',
    b'\xC0\x1C': 'TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA',
    b'\xC0\x1B': 'TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA',
    b'\xC0\x1A': 'TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA',
    b'\xC0\x17': 'TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA',
    b'\xC0\x12': 'TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA',
    b'\xC0\x0D': 'TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA',
    b'\xC0\x08': 'TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA',
    b'\xC0\x03': 'TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA',
    b'\x00\x93': 'TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA',
    b'\x00\x8F': 'TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA',
    b'\x00\x8B': 'TLS_PSK_WITH_3DES_EDE_CBC_SHA',
    b'\x00\x23': 'TLS_KRB5_WITH_3DES_EDE_CBC_MD5',
    b'\x00\x1F': 'TLS_KRB5_WITH_3DES_EDE_CBC_SHA',
    b'\x00\x1B': 'TLS_DH_anon_WITH_3DES_EDE_CBC_SHA',
    b'\x00\x16': 'TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA',
    b'\x00\x13': 'TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA',
    b'\x00\x10': 'TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA',
    b'\x00\x0D': 'TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA',
    b'\x00\x0A': 'TLS_RSA_WITH_3DES_EDE_CBC_SHA',

    # Deprecated cipher suites using ChaCha20
    b'\xCC\xAE': 'TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256',
    b'\xCC\xAB': 'TLS_PSK_WITH_CHACHA20_POLY1305_SHA256',

    # Deprecated cipher suites using AES
    b'\xD0\x03': 'TLS_ECDHE_PSK_WITH_AES_128_CCM_8_SHA256',
    b'\xC0\xB3': 'TLS_ECCPWD_WITH_AES_256_CCM_SHA384',
    b'\xC0\xB2': 'TLS_ECCPWD_WITH_AES_128_CCM_SHA256',
    b'\xC0\xB1': 'TLS_ECCPWD_WITH_AES_256_GCM_SHA384',
    b'\xC0\xB0': 'TLS_ECCPWD_WITH_AES_128_GCM_SHA256',
    b'\xC0\xAF': 'TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8',
    b'\xC0\xAE': 'TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8',
    b'\xC0\xAD': 'TLS_ECDHE_ECDSA_WITH_AES_256_CCM',
    b'\xC0\xAC': 'TLS_ECDHE_ECDSA_WITH_AES_128_CCM',
    b'\xC0\xAB': 'TLS_PSK_DHE_WITH_AES_256_CCM_8',
    b'\xC0\xAA': 'TLS_PSK_DHE_WITH_AES_128_CCM_8',
    b'\xC0\xA9': 'TLS_PSK_WITH_AES_256_CCM_8',
    b'\xC0\xA8': 'TLS_PSK_WITH_AES_128_CCM_8',
    b'\xC0\xA5': 'TLS_PSK_WITH_AES_256_CCM',
    b'\xC0\xA4': 'TLS_PSK_WITH_AES_128_CCM',
    b'\xC0\xA3': 'TLS_DHE_RSA_WITH_AES_256_CCM_8',
    b'\xC0\xA2': 'TLS_DHE_RSA_WITH_AES_128_CCM_8',
    b'\xC0\xA1': 'TLS_RSA_WITH_AES_256_CCM_8',
    b'\xC0\xA0': 'TLS_RSA_WITH_AES_128_CCM_8',
    b'\xC0\x9D': 'TLS_RSA_WITH_AES_256_CCM',
    b'\xC0\x9C': 'TLS_RSA_WITH_AES_128_CCM',
    b'\xC0\x38': 'TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384',
    b'\xC0\x37': 'TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256',
    b'\xC0\x36': 'TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA',
    b'\xC0\x35': 'TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA',
    b'\xC0\x32': 'TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384',
    b'\xC0\x31': 'TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256',
    b'\xC0\x2E': 'TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384',
    b'\xC0\x2D': 'TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256',
    b'\xC0\x2A': 'TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384',
    b'\xC0\x29': 'TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256',
    b'\xC0\x28': 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384',
    b'\xC0\x27': 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256',
    b'\xC0\x26': 'TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384',
    b'\xC0\x25': 'TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256',
    b'\xC0\x24': 'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384',
    b'\xC0\x23': 'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256',
    b'\xC0\x22': 'TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA',
    b'\xC0\x21': 'TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA',
    b'\xC0\x20': 'TLS_SRP_SHA_WITH_AES_256_CBC_SHA',
    b'\xC0\x1F': 'TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA',
    b'\xC0\x1E': 'TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA',
    b'\xC0\x1D': 'TLS_SRP_SHA_WITH_AES_128_CBC_SHA',
    b'\xC0\x19': 'TLS_ECDH_anon_WITH_AES_256_CBC_SHA',
    b'\xC0\x18': 'TLS_ECDH_anon_WITH_AES_128_CBC_SHA',
    b'\xC0\x14': 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA',
    b'\xC0\x13': 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA',
    b'\xC0\x0F': 'TLS_ECDH_RSA_WITH_AES_256_CBC_SHA',
    b'\xC0\x0E': 'TLS_ECDH_RSA_WITH_AES_128_CBC_SHA',
    b'\xC0\x0A': 'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA',
    b'\xC0\x09': 'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA',
    b'\xC0\x05': 'TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA',
    b'\xC0\x04': 'TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA',
    b'\x00\xB7': 'TLS_RSA_PSK_WITH_AES_256_CBC_SHA384',
    b'\x00\xB6': 'TLS_RSA_PSK_WITH_AES_128_CBC_SHA256',
    b'\x00\xB3': 'TLS_DHE_PSK_WITH_AES_256_CBC_SHA384',
    b'\x00\xB2': 'TLS_DHE_PSK_WITH_AES_128_CBC_SHA256',
    b'\x00\xAF': 'TLS_PSK_WITH_AES_256_CBC_SHA384',
    b'\x00\xAE': 'TLS_PSK_WITH_AES_128_CBC_SHA256',
    b'\x00\xAD': 'TLS_RSA_PSK_WITH_AES_256_GCM_SHA384',
    b'\x00\xAC': 'TLS_RSA_PSK_WITH_AES_128_GCM_SHA256',
    b'\x00\xA9': 'TLS_PSK_WITH_AES_256_GCM_SHA384',
    b'\x00\xA8': 'TLS_PSK_WITH_AES_128_GCM_SHA256',
    b'\x00\xA7': 'TLS_DH_anon_WITH_AES_256_GCM_SHA384',
    b'\x00\xA6': 'TLS_DH_anon_WITH_AES_128_GCM_SHA256',
    b'\x00\xA5': 'TLS_DH_DSS_WITH_AES_256_GCM_SHA384',
    b'\x00\xA4': 'TLS_DH_DSS_WITH_AES_128_GCM_SHA256',
    b'\x00\xA3': 'TLS_DHE_DSS_WITH_AES_256_GCM_SHA384',
    b'\x00\xA2': 'TLS_DHE_DSS_WITH_AES_128_GCM_SHA256',
    b'\x00\xA1': 'TLS_DH_RSA_WITH_AES_256_GCM_SHA384',
    b'\x00\xA0': 'TLS_DH_RSA_WITH_AES_128_GCM_SHA256',
    b'\x00\x9D': 'TLS_RSA_WITH_AES_256_GCM_SHA384',
    b'\x00\x9C': 'TLS_RSA_WITH_AES_128_GCM_SHA256',
    b'\x00\x95': 'TLS_RSA_PSK_WITH_AES_256_CBC_SHA',
    b'\x00\x94': 'TLS_RSA_PSK_WITH_AES_128_CBC_SHA',
    b'\x00\x91': 'TLS_DHE_PSK_WITH_AES_256_CBC_SHA',
    b'\x00\x90': 'TLS_DHE_PSK_WITH_AES_128_CBC_SHA',
    b'\x00\x8D': 'TLS_PSK_WITH_AES_256_CBC_SHA',
    b'\x00\x8C': 'TLS_PSK_WITH_AES_128_CBC_SHA',
    b'\x00\x6D': 'TLS_DH_anon_WITH_AES_256_CBC_SHA256',
    b'\x00\x6C': 'TLS_DH_anon_WITH_AES_128_CBC_SHA256',
    b'\x00\x6B': 'TLS_DHE_RSA_WITH_AES_256_CBC_SHA256',
    b'\x00\x6A': 'TLS_DHE_DSS_WITH_AES_256_CBC_SHA256',
    b'\x00\x69': 'TLS_DH_RSA_WITH_AES_256_CBC_SHA256',
    b'\x00\x68': 'TLS_DH_DSS_WITH_AES_256_CBC_SHA256',
    b'\x00\x67': 'TLS_DHE_RSA_WITH_AES_128_CBC_SHA256',
    b'\x00\x40': 'TLS_DHE_DSS_WITH_AES_128_CBC_SHA256',
    b'\x00\x3F': 'TLS_DH_RSA_WITH_AES_128_CBC_SHA256',
    b'\x00\x3E': 'TLS_DH_DSS_WITH_AES_128_CBC_SHA256',
    b'\x00\x3D': 'TLS_RSA_WITH_AES_256_CBC_SHA256',
    b'\x00\x3C': 'TLS_RSA_WITH_AES_128_CBC_SHA256',
    b'\x00\x3A': 'TLS_DH_anon_WITH_AES_256_CBC_SHA',
    b'\x00\x39': 'TLS_DHE_RSA_WITH_AES_256_CBC_SHA',
    b'\x00\x38': 'TLS_DHE_DSS_WITH_AES_256_CBC_SHA',
    b'\x00\x37': 'TLS_DH_RSA_WITH_AES_256_CBC_SHA',
    b'\x00\x36': 'TLS_DH_DSS_WITH_AES_256_CBC_SHA',
    b'\x00\x35': 'TLS_RSA_WITH_AES_256_CBC_SHA',
    b'\x00\x34': 'TLS_DH_anon_WITH_AES_128_CBC_SHA',
    b'\x00\x33': 'TLS_DHE_RSA_WITH_AES_128_CBC_SHA',
    b'\x00\x32': 'TLS_DHE_DSS_WITH_AES_128_CBC_SHA',
    b'\x00\x31': 'TLS_DH_RSA_WITH_AES_128_CBC_SHA',
    b'\x00\x30': 'TLS_DH_DSS_WITH_AES_128_CBC_SHA',
    b'\x00\x2F': 'TLS_RSA_WITH_AES_128_CBC_SHA',
    b'\x00\x07': 'TLS_RSA_WITH_IDEA_CBC_SHA',
    b'\x00\x25': 'TLS_KRB5_WITH_IDEA_CBC_MD5',
    b'\x00\x21': 'TLS_KRB5_WITH_IDEA_CBC_SHA'

}

cipher_suite_parts = {

    "CryptoAlgo": {
        "AES": (AES, 0),
        "3DES": (TripleDES, 0),
        "CHACHA20": (aead.ChaCha20Poly1305, 1),
        "RC4": (ARC4, 0),
        "CAMELLIA": (Camellia, 0),
        "IDEA": (IDEA,0),

        "GCM": (aead.AESGCM, 1),
        "CCM": (aead.AESCCM, 1)

    },

    "Mode": {
        "CBC": (modes.CBC, 0),  # Tuple[0] is the mode and Tuple[1] is 1 if mode uses AEAD, else it is 0
        "CFB": (modes.CFB, 0),
        "CTR": (modes.CTR, 0),
        "GCM": (modes.GCM, 1),
        "CCM": (aead.AESCCM, 1),
        "POLY1305": (aead.ChaCha20Poly1305, 1)
    },

    "KeyLength": {
        "IDEA": 16,
        "AES_128": 16,
        "AES_256": 32,
        "CAMELLIA_128": 16,
        "CAMELLIA_256": 32,
        "CHACHA20": 32,
        "RC4_128": 16,
        "3DES": 24
    },

    "MAC": {
        "SHA256": hashes.SHA256,
        "SHA384": hashes.SHA384,
        "SHA": hashes.SHA1,
        "MD5": hashes.MD5
    },

    "TagLength": {
        "_8": 8
    }
}


def split_cipher_suite(suite_id):
    try:
        suite_string = cipher_suites[suite_id]
    except KeyError:
        logging.error(f"Cipher suite with value '{suite_id.hex()}' not supported")
        return

    added_part = 0
    cipher_suite = {}

    for part in cipher_suite_parts:
        for p in cipher_suite_parts[part]:
            if p in suite_string:
                cipher_suite.update({part: cipher_suite_parts[part][p]})
                added_part = 1
                break
        if not added_part:
            if part == "TagLength":  # if no tag-length is explicitly given, the tag-length is set to 16 bit
                cipher_suite.update({part: 16})
            else:
                cipher_suite.update({part: (None, 0)})
        added_part = 0

    if cipher_suite["CryptoAlgo"] == (AES,
                                      0):  # if cipher suite uses AES, check if mode is AEAD, so the correct classes from 'cryptography'-module are used
        if "GCM" in suite_string:
            cipher_suite.update({"CryptoAlgo": (aead.AESGCM, 1)})
        elif "CCM" in suite_string:
            cipher_suite.update({"CryptoAlgo": (aead.AESCCM, 1)})

    if cipher_suite["MAC"] == (None, 0):
        cipher_suite["MAC"] = hashes.SHA256

    return cipher_suite

import logging
import warnings

# Suppress the deprecation warning from the cryptography module.
with warnings.catch_warnings():
    warnings.simplefilter("ignore")
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers import modes
    from cryptography.hazmat.primitives.ciphers.algorithms import AES, ChaCha20
    from cryptography.hazmat.primitives.ciphers import aead
    from cryptography.hazmat.decrepit.ciphers import modes as decrepit_modes
    from cryptography.hazmat.decrepit.ciphers.algorithms import (
        Camellia,
        TripleDES,
        IDEA,
        ARC4,
    )


cipher_suites = {
    # The following 5 cipher suites are the only cipher suites supported by TLSv1.3
    b"\x13\x02": "TLS_AES_256_GCM_SHA384",
    b"\x13\x03": "TLS_CHACHA20_POLY1305_SHA256",
    b"\x13\x01": "TLS_AES_128_GCM_SHA256",
    b"\x13\x04": "TLS_AES_128_CCM_SHA256",
    b"\x13\x05": "TLS_AES_128_CCM_8_SHA256",
    # The following cipher suites are other cipher suites recommended by the IANA (Date: September 2023)
    b"\xd0\x05": "TLS_ECDHE_PSK_WITH_AES_128_CCM_SHA256",
    b"\xd0\x02": "TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384",
    b"\xd0\x01": "TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256",
    b"\xcc\xad": "TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256",
    b"\xcc\xac": "TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256",
    b"\xcc\xaa": "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    b"\xcc\xa9": "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
    b"\xcc\xa8": "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    b"\xc0\xa7": "TLS_DHE_PSK_WITH_AES_256_CCM",
    b"\xc0\xa6": "TLS_DHE_PSK_WITH_AES_128_CCM",
    b"\xc0\x9f": "TLS_DHE_RSA_WITH_AES_256_CCM",
    b"\xc0\x9e": "TLS_DHE_RSA_WITH_AES_128_CCM",
    b"\xc0\x30": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    b"\xc0\x2f": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    b"\xc0\x2b": "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    b"\xc0\x2c": "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    b"\x00\xaa": "TLS_DHE_PSK_WITH_AES_128_GCM_SHA256",
    b"\x00\xab": "TLS_DHE_PSK_WITH_AES_256_GCM_SHA384",
    b"\x00\x9e": "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
    b"\x00\x9f": "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
    # All following cipher suites are cipher suites that are DEPRECATED and NOT RECOMMENDED by the IANA except 'TLS_AES_128_CCM_8_SHA256'
    # Deprecated cipher suites using CAMELLIA
    b"\xc0\x9b": "TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384",
    b"\xc0\x9a": "TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256",
    b"\xc0\x99": "TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384",
    b"\xc0\x98": "TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256",
    b"\xc0\x97": "TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384",
    b"\xc0\x96": "TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256",
    b"\xc0\x95": "TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384",
    b"\xc0\x94": "TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256",
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
    b"\xc0\x79": "TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384",
    b"\xc0\x78": "TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256",
    b"\xc0\x77": "TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384",
    b"\xc0\x76": "TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256",
    b"\xc0\x75": "TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384",
    b"\xc0\x74": "TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256",
    b"\xc0\x73": "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384",
    b"\xc0\x72": "TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256",
    b"\x00\xc5": "TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256",
    b"\x00\xc4": "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256",
    b"\x00\xc3": "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256",
    b"\x00\xc2": "TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256",
    b"\x00\xc1": "TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256",
    b"\x00\xc0": "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256",
    b"\x00\xbf": "TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256",
    b"\x00\xbe": "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256",
    b"\x00\xbd": "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256",
    b"\x00\xbc": "TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256",
    b"\x00\xbb": "TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256",
    b"\x00\xba": "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256",
    b"\x00\x89": "TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA",
    b"\x00\x88": "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA",
    b"\x00\x87": "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA",
    b"\x00\x86": "TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA",
    b"\x00\x85": "TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA",
    b"\x00\x84": "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA",
    b"\x00\x46": "TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA",
    b"\x00\x45": "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA",
    b"\x00\x44": "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA",
    b"\x00\x43": "TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA",
    b"\x00\x42": "TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA",
    b"\x00\x41": "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA",
    # Deprecated cipher suites using RC4
    b"\xc0\x33": "TLS_ECDHE_PSK_WITH_RC4_128_SHA",
    b"\xc0\x16": "TLS_ECDH_anon_WITH_RC4_128_SHA",
    b"\xc0\x11": "TLS_ECDHE_RSA_WITH_RC4_128_SHA",
    b"\xc0\x0c": "TLS_ECDH_RSA_WITH_RC4_128_SHA",
    b"\xc0\x07": "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",
    b"\xc0\x02": "TLS_ECDH_ECDSA_WITH_RC4_128_SHA",
    b"\x00\x92": "TLS_RSA_PSK_WITH_RC4_128_SHA",
    b"\x00\x8e": "TLS_DHE_PSK_WITH_RC4_128_SHA",
    b"\x00\x8a": "TLS_PSK_WITH_RC4_128_SHA",
    b"\x00\x24": "TLS_KRB5_WITH_RC4_128_MD5",
    b"\x00\x20": "TLS_KRB5_WITH_RC4_128_SHA",
    b"\x00\x18": "TLS_DH_anon_WITH_RC4_128_MD5",
    b"\x00\x05": "TLS_RSA_WITH_RC4_128_SHA",
    b"\x00\x04": "TLS_RSA_WITH_RC4_128_MD5",
    # Deprecated cipher suites using 3DES (Triple-DES)
    b"\xc0\x34": "TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA",
    b"\xc0\x1c": "TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA",
    b"\xc0\x1b": "TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA",
    b"\xc0\x1a": "TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA",
    b"\xc0\x17": "TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA",
    b"\xc0\x12": "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
    b"\xc0\x0d": "TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA",
    b"\xc0\x08": "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA",
    b"\xc0\x03": "TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA",
    b"\x00\x93": "TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA",
    b"\x00\x8f": "TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA",
    b"\x00\x8b": "TLS_PSK_WITH_3DES_EDE_CBC_SHA",
    b"\x00\x23": "TLS_KRB5_WITH_3DES_EDE_CBC_MD5",
    b"\x00\x1f": "TLS_KRB5_WITH_3DES_EDE_CBC_SHA",
    b"\x00\x1b": "TLS_DH_anon_WITH_3DES_EDE_CBC_SHA",
    b"\x00\x16": "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA",
    b"\x00\x13": "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA",
    b"\x00\x10": "TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA",
    b"\x00\x0d": "TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA",
    b"\x00\x0a": "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
    # Deprecated cipher suites using ChaCha20
    b"\xcc\xae": "TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256",
    b"\xcc\xab": "TLS_PSK_WITH_CHACHA20_POLY1305_SHA256",
    # Deprecated cipher suites using AES
    b"\xd0\x03": "TLS_ECDHE_PSK_WITH_AES_128_CCM_8_SHA256",
    b"\xc0\xb3": "TLS_ECCPWD_WITH_AES_256_CCM_SHA384",
    b"\xc0\xb2": "TLS_ECCPWD_WITH_AES_128_CCM_SHA256",
    b"\xc0\xb1": "TLS_ECCPWD_WITH_AES_256_GCM_SHA384",
    b"\xc0\xb0": "TLS_ECCPWD_WITH_AES_128_GCM_SHA256",
    b"\xc0\xaf": "TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8",
    b"\xc0\xae": "TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8",
    b"\xc0\xad": "TLS_ECDHE_ECDSA_WITH_AES_256_CCM",
    b"\xc0\xac": "TLS_ECDHE_ECDSA_WITH_AES_128_CCM",
    b"\xc0\xab": "TLS_PSK_DHE_WITH_AES_256_CCM_8",
    b"\xc0\xaa": "TLS_PSK_DHE_WITH_AES_128_CCM_8",
    b"\xc0\xa9": "TLS_PSK_WITH_AES_256_CCM_8",
    b"\xc0\xa8": "TLS_PSK_WITH_AES_128_CCM_8",
    b"\xc0\xa5": "TLS_PSK_WITH_AES_256_CCM",
    b"\xc0\xa4": "TLS_PSK_WITH_AES_128_CCM",
    b"\xc0\xa3": "TLS_DHE_RSA_WITH_AES_256_CCM_8",
    b"\xc0\xa2": "TLS_DHE_RSA_WITH_AES_128_CCM_8",
    b"\xc0\xa1": "TLS_RSA_WITH_AES_256_CCM_8",
    b"\xc0\xa0": "TLS_RSA_WITH_AES_128_CCM_8",
    b"\xc0\x9d": "TLS_RSA_WITH_AES_256_CCM",
    b"\xc0\x9c": "TLS_RSA_WITH_AES_128_CCM",
    b"\xc0\x38": "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384",
    b"\xc0\x37": "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256",
    b"\xc0\x36": "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA",
    b"\xc0\x35": "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA",
    b"\xc0\x32": "TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384",
    b"\xc0\x31": "TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256",
    b"\xc0\x2e": "TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384",
    b"\xc0\x2d": "TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256",
    b"\xc0\x2a": "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384",
    b"\xc0\x29": "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256",
    b"\xc0\x28": "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
    b"\xc0\x27": "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
    b"\xc0\x26": "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384",
    b"\xc0\x25": "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256",
    b"\xc0\x24": "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
    b"\xc0\x23": "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
    b"\xc0\x22": "TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA",
    b"\xc0\x21": "TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA",
    b"\xc0\x20": "TLS_SRP_SHA_WITH_AES_256_CBC_SHA",
    b"\xc0\x1f": "TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA",
    b"\xc0\x1e": "TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA",
    b"\xc0\x1d": "TLS_SRP_SHA_WITH_AES_128_CBC_SHA",
    b"\xc0\x19": "TLS_ECDH_anon_WITH_AES_256_CBC_SHA",
    b"\xc0\x18": "TLS_ECDH_anon_WITH_AES_128_CBC_SHA",
    b"\xc0\x14": "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
    b"\xc0\x13": "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
    b"\xc0\x0f": "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA",
    b"\xc0\x0e": "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA",
    b"\xc0\x0a": "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
    b"\xc0\x09": "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
    b"\xc0\x05": "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA",
    b"\xc0\x04": "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA",
    b"\x00\xb7": "TLS_RSA_PSK_WITH_AES_256_CBC_SHA384",
    b"\x00\xb6": "TLS_RSA_PSK_WITH_AES_128_CBC_SHA256",
    b"\x00\xb3": "TLS_DHE_PSK_WITH_AES_256_CBC_SHA384",
    b"\x00\xb2": "TLS_DHE_PSK_WITH_AES_128_CBC_SHA256",
    b"\x00\xaf": "TLS_PSK_WITH_AES_256_CBC_SHA384",
    b"\x00\xae": "TLS_PSK_WITH_AES_128_CBC_SHA256",
    b"\x00\xad": "TLS_RSA_PSK_WITH_AES_256_GCM_SHA384",
    b"\x00\xac": "TLS_RSA_PSK_WITH_AES_128_GCM_SHA256",
    b"\x00\xa9": "TLS_PSK_WITH_AES_256_GCM_SHA384",
    b"\x00\xa8": "TLS_PSK_WITH_AES_128_GCM_SHA256",
    b"\x00\xa7": "TLS_DH_anon_WITH_AES_256_GCM_SHA384",
    b"\x00\xa6": "TLS_DH_anon_WITH_AES_128_GCM_SHA256",
    b"\x00\xa5": "TLS_DH_DSS_WITH_AES_256_GCM_SHA384",
    b"\x00\xa4": "TLS_DH_DSS_WITH_AES_128_GCM_SHA256",
    b"\x00\xa3": "TLS_DHE_DSS_WITH_AES_256_GCM_SHA384",
    b"\x00\xa2": "TLS_DHE_DSS_WITH_AES_128_GCM_SHA256",
    b"\x00\xa1": "TLS_DH_RSA_WITH_AES_256_GCM_SHA384",
    b"\x00\xa0": "TLS_DH_RSA_WITH_AES_128_GCM_SHA256",
    b"\x00\x9d": "TLS_RSA_WITH_AES_256_GCM_SHA384",
    b"\x00\x9c": "TLS_RSA_WITH_AES_128_GCM_SHA256",
    b"\x00\x95": "TLS_RSA_PSK_WITH_AES_256_CBC_SHA",
    b"\x00\x94": "TLS_RSA_PSK_WITH_AES_128_CBC_SHA",
    b"\x00\x91": "TLS_DHE_PSK_WITH_AES_256_CBC_SHA",
    b"\x00\x90": "TLS_DHE_PSK_WITH_AES_128_CBC_SHA",
    b"\x00\x8d": "TLS_PSK_WITH_AES_256_CBC_SHA",
    b"\x00\x8c": "TLS_PSK_WITH_AES_128_CBC_SHA",
    b"\x00\x6d": "TLS_DH_anon_WITH_AES_256_CBC_SHA256",
    b"\x00\x6c": "TLS_DH_anon_WITH_AES_128_CBC_SHA256",
    b"\x00\x6b": "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
    b"\x00\x6a": "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256",
    b"\x00\x69": "TLS_DH_RSA_WITH_AES_256_CBC_SHA256",
    b"\x00\x68": "TLS_DH_DSS_WITH_AES_256_CBC_SHA256",
    b"\x00\x67": "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
    b"\x00\x40": "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256",
    b"\x00\x3f": "TLS_DH_RSA_WITH_AES_128_CBC_SHA256",
    b"\x00\x3e": "TLS_DH_DSS_WITH_AES_128_CBC_SHA256",
    b"\x00\x3d": "TLS_RSA_WITH_AES_256_CBC_SHA256",
    b"\x00\x3c": "TLS_RSA_WITH_AES_128_CBC_SHA256",
    b"\x00\x3a": "TLS_DH_anon_WITH_AES_256_CBC_SHA",
    b"\x00\x39": "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
    b"\x00\x38": "TLS_DHE_DSS_WITH_AES_256_CBC_SHA",
    b"\x00\x37": "TLS_DH_RSA_WITH_AES_256_CBC_SHA",
    b"\x00\x36": "TLS_DH_DSS_WITH_AES_256_CBC_SHA",
    b"\x00\x35": "TLS_RSA_WITH_AES_256_CBC_SHA",
    b"\x00\x34": "TLS_DH_anon_WITH_AES_128_CBC_SHA",
    b"\x00\x33": "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
    b"\x00\x32": "TLS_DHE_DSS_WITH_AES_128_CBC_SHA",
    b"\x00\x31": "TLS_DH_RSA_WITH_AES_128_CBC_SHA",
    b"\x00\x30": "TLS_DH_DSS_WITH_AES_128_CBC_SHA",
    b"\x00\x2f": "TLS_RSA_WITH_AES_128_CBC_SHA",
    b"\x00\x07": "TLS_RSA_WITH_IDEA_CBC_SHA",
    b"\x00\x25": "TLS_KRB5_WITH_IDEA_CBC_MD5",
    b"\x00\x21": "TLS_KRB5_WITH_IDEA_CBC_SHA",
}

cipher_suite_parts = {
    "CryptoAlgo": {
        "AES": (AES, 0),
        "3DES": (TripleDES, 0),
        "CHACHA20": (aead.ChaCha20Poly1305, 1),
        "RC4": (ARC4, 0),
        "CAMELLIA": (Camellia, 0),
        "IDEA": (IDEA, 0),
        "GCM": (aead.AESGCM, 1),
        "CCM": (aead.AESCCM, 1),
    },
    "Mode": {
        "CBC": (
            modes.CBC,
            0,
        ),  # Tuple[0] is the mode and Tuple[1] is 1 if mode uses AEAD, else it is 0
        "CFB": (decrepit_modes.CFB, 0),
        "CTR": (modes.CTR, 0),
        "GCM": (modes.GCM, 1),
        "CCM": (aead.AESCCM, 1),
        "POLY1305": (aead.ChaCha20Poly1305, 1),
    },
    "KeyLength": {
        "IDEA": 16,
        "AES_128": 16,
        "AES_256": 32,
        "CAMELLIA_128": 16,
        "CAMELLIA_256": 32,
        "CHACHA20": 32,
        "RC4_128": 16,
        "3DES": 24,
    },
    "MAC": {
        "SHA256": hashes.SHA256,
        "SHA384": hashes.SHA384,
        "SHA": hashes.SHA1,
        "MD5": hashes.MD5,
    },
    "TagLength": {"_8": 8},
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
            if (
                part == "TagLength"
            ):  # if no tag-length is explicitly given, the tag-length is set to 16 bit
                cipher_suite.update({part: 16})
            else:
                cipher_suite.update({part: (None, 0)})
        added_part = 0

    if (
        cipher_suite["CryptoAlgo"]
        == (
            AES,
            0,
        )
    ):  # if cipher suite uses AES, check if mode is AEAD, so the correct classes from 'cryptography'-module are used
        if "GCM" in suite_string:
            cipher_suite.update({"CryptoAlgo": (aead.AESGCM, 1)})
        elif "CCM" in suite_string:
            cipher_suite.update({"CryptoAlgo": (aead.AESCCM, 1)})

    if cipher_suite["MAC"] == (None, 0):
        cipher_suite["MAC"] = hashes.SHA256

    return cipher_suite

<p align="center">
    <img src="https://raw.githubusercontent.com/fkie-cad/TLExport/main/logo.svg" alt="TLExport logo" width="75%" height="75%"/>
</p>


# TLExport
![version](https://img.shields.io/badge/version-0.5-blue) [![PyPi](https://badge.fury.io/py/TLExport.svg)](https://pypi.org/project/tlexport)

TLExport (TLE) is a tool for decrypting TLS-Traffic and exporting the 
traffic into unencrypted TCP/UDP traffic. The goal is to provide support to network analysis tools, 
which have no or limited support for TLS decryption.

This project is inspired by [Wiresharks] built in TLS Decryption, which does not support the extraction 
of decrypted traffic into pcap files.

## Installation

Installation is simply a matter of `pip3 install tlexport`. This will give you the `tlexport` command. You can update an existing `tlexport` installation with `pip3 install --upgrade tlexport`.

Alternatively just clone the repository and execute the `main.py` file of the src module.


## Usage

TLE requires sslkeylogs to decrypt the traffic.
They can be passed in a keylogfile:<br>
```tlexport -i in.pcapng -o out.pcapng -s sslkeylog.log```

or within the pcap file as a decryption secret block:<br>
```$ tlexport -i in.pcapng -o out.pcapng```

You can specify the ports on which TLS-Traffic is to be decrypted (default: 443):<br>
```$ tlexport -i in.pcapng -o out.pcapng -p 443 -p 8443```

and which ports to map the TLS-Traffic to (default 443:8080):<br>
```$ tlexport -i in.pcapng -o out.pcapng -p 443 -p 8443 -m```
```$ tlexport -i in.pcapng -o out.pcapng -p 443 -p 8443 -m 443:8081 444:8088```

By default (when no `m`-parameter is provided) the orignal port will be used.

Ensuring, that only packets with correct checksums are decrypted<br> 
(Warning: Often the checksums are incorrect on linux due to checksum offload)<br>
```$ tlexport -i in.pcapng -o out.pcapng -c```

The program also supports old pcap files:<br>
```$ tlexport -i in.pcapng -o out.pcapng -l -s sslkeylog.log```

## Dependencies

A Python Version of 3.10 or above is required [4]

Install the python packages:
- cryptography    [1]
- dpkt                  [2] 
- scapy [3]

```pip install cryptography dpkt scapy```

## Supported Versions and Algorithms

In the following we list the supported TLS versions as well as the supported algorithms.

### Versions:
- Secure Socket Layer 3.0
- Transport Layer Security 1.0-1.3
### Algorithms:
- Block Ciphers: AES-CBC, Camellia-CBC, 3DES-CBC, IDEA (Untested / no out of the box support by cryptography [#2])
- AEAD Ciphers: AES-GCM, AES-CCM, AES-CCM-8, CHACHA20-POLY1305
- Stream Ciphers: RC4
- Compression: Zlib/Deflate (Untested)
### soon(tm)
- QUIC
- D-TLS

## Support
If you have any suggestions, questions, or bug reports, please create an issue in the Issue Tracker.

[1]: https://pypi.org/project/cryptography/
[2]: https://pypi.org/project/dpkt/
[3]: https://pypi.org/project/scapy/
[4]: https://www.python.org/
[Wiresharks]: https://www.wireshark.org/
[#2]: https://github.com/fkie-cad/TLExport/issues/2


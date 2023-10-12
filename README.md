# Transport Layer Export
Transport Layer Export (TLE) is a tool for decrypting TLS-Traffic and exporting the 
traffic into unencrypted TCP/UDP traffic. The goal is to provide support to network analysis tools, 
which have no or limited support for TLS decryption.

This project is inspired by [Wiresharks] build in TLS Decryption, which does not support the extraction 
of decrypted traffic into pcap files.

## Installation
Clone the github project and execute the main.py file of the src module

## Usage
TLE requires sslkeylogs to decrypt the traffic.
They can be passed in a keylogfile:<br>
```python3 main.py -i in.pcapng -o out.pcapng -s sslkeylog.log```

or within the pcap file as a decryption secret block:<br>
```$ python3 main.py -i in.pcapng -o out.pcapng```

You can specify the ports on which TLS-Traffic is to be decrypted (default: 443):<br>
```$ python3 main.py -i in.pcapng -o out.pcapng -p 443 -p 8443```

and which ports to map the TLS-Traffic to (default 443:8080):<br>
```$ python3 main.py -i in.pcapng -o out.pcapng -p 443 -p 8443 -m 443:8080 -m 8443:8090```

Ensuring, that only packets with correct checksums are decrypted<br> 
(Warning: Often the checksums are incorrect on linux due to checksum offload)<br>
```$ python3 main.py -i in.pcapng -o out.pcapng -c```

The program also supports old pcap files:<br>
```$ python3 main.py -i in.pcapng -o out.pcapng -l -s sslkeylog.log```

## Dependencies
A Python Version of 3.10 or above is required [4]

Install the python packages:
- cryptography    [1]
- dpkt                  [2] 
- scapy [3]

```pip install cryptography dpkt scapy```

## Supported Versions and Algorithms
### Versions:
- Secure Socket Layer 3.0
- Transport Layer Security 1.0-1.3
### Algorithms:
- Block Ciphers: AES-CBC, Camellia-CBC, 3DES-CBC
- AEAD Ciphers: AES-GCM, AES-CCM, CHACHA20-POLY1305
- Stream Ciphers: RC4
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

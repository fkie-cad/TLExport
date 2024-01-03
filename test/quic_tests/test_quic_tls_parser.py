from unittest import TestCase
from tlexport.quic.quic_tls_parser import QuicTlsSession
from tlexport.quic.quic_frame import CryptoFrame
from tlexport.quic.quic_packet import QuicPacket, QuicHeaderType, QuicPacketType


class TestQuicTlsParser(TestCase):
    def setUp(self):
        self.quic_tls_session = QuicTlsSession()
        self.quic_tls_session_2 = QuicTlsSession()

        self.initial_packet_client = QuicPacket(QuicHeaderType.LONG, QuicPacketType.INITIAL, False)
        self.initial_packet_server = QuicPacket(QuicHeaderType.LONG, QuicPacketType.INITIAL, True)

        self.handshake_packet_client = QuicPacket(QuicHeaderType.LONG, QuicPacketType.HANDSHAKE, False)
        self.handshake_packet_server = QuicPacket(QuicHeaderType.LONG, QuicPacketType.HANDSHAKE, True)

        self.rtt_1_packet_client = QuicPacket(QuicHeaderType.SHORT, QuicPacketType.RTT_1, False)
        self.rtt_1_packet_server = QuicPacket(QuicHeaderType.SHORT, QuicPacketType.RTT_1, True)

        self.rtt_0_packet_client = QuicPacket(QuicHeaderType.SHORT, QuicPacketType.RTT_O, False)
        self.rtt_0_packet_server = QuicPacket(QuicHeaderType.SHORT, QuicPacketType.RTT_O, True)

    def test_client_hello(self):
        client_hello = bytes.fromhex(
            "06004224010002200303baa39ecf56d1d50e2626737a5254c8e0ce1b97dd576ff9030637626c6bd5f2fc0000081301130213031304010001efffa5003f0f11f48b4afc4a98ec1e372ee23d5eb7b79638050480600000070480600000040480f00000090240640104800075300e01076ab200110800000001000000010039003f0f11f48b4afc4a98ec1e372ee23d5eb7b79638050480600000070480600000040480f00000090240640104800075300e01076ab20011080000000100000001fe0d00d40000010001e30020be6ea58a46f137aba63894dac652151e1444fd5be3424b5fa4234703d97d446500aa5048a9e3367548056e58647b1267ef63b77b9326d52973ac299474220bf04a8d084f564d06c988ca2723489f913071b5fe1a492fefb8127bbc4734104a1ca91fb56cfdff7502bdfe79945978751a65b570bfc88a48f59ad98293653b60a567a32493d51d9e8071d279fa30b81e16cda0f2b5b8e1740588d917a5eb2f05ea1672de54fdce629b643b57db28430d36eb4aaabe390bb3de5f22cdbb50e601ed349fef596da25d7166122895002d0003020001003300260024001d002086256c8e19e0e7add482405897504693eeb3c856629d5c116becabe1163b1808002b0003020304000d002400220603050304030203080708080806080b0805080a0804080906010501040103010201001600000000000e000c0000096c6f63616c686f7374001000050003026833000a000a0008001d00170018001900230000")
        frame = CryptoFrame(client_hello, self.initial_packet_client)
        self.quic_tls_session.update_session(frame)
        self.assertEqual(self.quic_tls_session.client_random,
                         b"\xba\xa3\x9e\xcf\x56\xd1\xd5\x0e\x26\x26\x73\x7a\x52\x54\xc8\xe0\xce\x1b\x97\xdd\x57\x6f\xf9\x03\x06\x37\x62\x6c\x6b\xd5\xf2\xfc")
        self.assertEqual(self.quic_tls_session.server_hello_seen, False)

    def test_server_hello(self):
        server_hello = b"\x06\x00\x40\x5a\x02\x00\x00\x56\x03\x03\x79\xf0\xd4\x71\x26\x23" \
                       b"\xe6\x55\x05\x6a\x6f\x10\x00\x05\x11\x0e\x4c\x17\x63\x10\xce\x45" \
                       b"\x24\xa7\xca\x2e\x4d\x31\xf5\x38\x36\x69\x00\x13\x01\x00\x00\x2e" \
                       b"\x00\x33\x00\x24\x00\x1d\x00\x20\x1a\xb1\x2a\x7d\x49\x3a\x07\xda" \
                       b"\xd0\x39\x4b\x59\xcd\x21\x18\x78\xb2\x4e\x5e\xf9\xb0\x6d\xc9\xb7" \
                       b"\xbd\x55\xef\x39\xaa\xa4\x4e\x0a\x00\x2b\x00\x02\x03\x04"

        frame = CryptoFrame(server_hello, self.initial_packet_server)
        self.quic_tls_session.update_session(frame)
        self.assertEqual(self.quic_tls_session.server_hello_seen, True)
        self.assertEqual(self.quic_tls_session.alpn, None)
        self.assertEqual(self.quic_tls_session.ciphersuite, b"\x13\x01")
        self.assertEqual(self.quic_tls_session.tls_vers, b"\x03\x04")

    def test_handshake_messages(self):
        handshake_msg = bytes.fromhex("060043ba080000780076003900690012d901c5d91b6c9e1049eb426a64b621f1797f021037ec51176eb41a9e7e0e669685d3fb550f1278b002327c363d06d8fda4f13e3240da7046060480040000070480040000040480100000080240640901030104800075300e01076ab200110800000001000000010010000500030268330b0003a00000039c000397308203933082027ba00302010202146a95f37e73b552b1705f0ebfcdce7f1f99a05821300d06092a864886f70d01010b05003059310b30090603550406130241553113301106035504080c0a536f6d652d53746174653121301f060355040a0c18496e7465726e6574205769646769747320507479204c74643112301006035504030c096c6f63616c686f7374301e170d3233313232313131303732325a170d3234313232303131303732325a3059310b30090603550406130241553113301106035504080c0a536f6d652d53746174653121301f060355040a0c18496e7465726e6574205769646769747320507479204c74643112301006035504030c096c6f63616c686f737430820122300d06092a864886f70d01010105000382010f003082010a0282010100e48e6d6c21c0fca9810817b31ee083f7cedc98f5b9cd1f038e4b4df756abcc261f66f131902a8c031615fd5411a917f656f893d649cd604daa73bd00fdd764fe3c6c1cc347e66ffb6c0714abf0f4b9cdf24d7d7d5b2596556f45e81672a565425cd64db8815f66c6529ae6f59eacc5cfeb969523332c94193fc6f4731b25fa4d355bbd2fac165b418c021992991f2e22c93eb7bcf25dfdbf4b47b17e7386f96716dae9681ce5e086f1d1c2f09deeaa87f518d47a2f540b44319b6e078ae4253c523267c1ee5cd123dec22a9055f50bccff6e401d4c59780b3ee2cb26131c5d5e9243f069fa60875aa3a907d2a3d6242e82e2d0d3928f191a4bad3fe33f5427530203010001a3533051301d0603551d0e0416041426e46d370ddf57c69be4f3b9a85d0aa32021a316301f0603551d2304183016801426e46d370ddf57c69be4f3b9a85d0aa32021a316300f0603551d130101ff040530030101ff300d06092a864886f70d01010b05000382010100771e8ba50a264cc9ad131e9479b51eab889ac05aa00ab3662cc6200860a9c4ee3245f53a9137298bbefdc01529ee17725e0efeb614af8dbb478499b4feedb7a4c7380aba5b8d5705c8c1ab1da1a3bd99c50a41cd060dadeb654589bc06d98db2dfb787a985e8e18b8484c9730a2c87e62299c6b7981afc26a54a4997d651d669cfab9616ea50d2028dc486885574c5beb5ba7bf4cad8473ca5477bbc")
        frame = CryptoFrame(handshake_msg, self.handshake_packet_server)
        self.quic_tls_session.update_session(frame)
        self.assertEqual(self.quic_tls_session.alpn, b"h3")

    def test_out_of_order(self):
        certificate = bytes.fromhex("0643ba419218046f2a8f27b524c8627833f09024aefa19a3ebf10909ba7ec1fa5c25b435c90f6c5edd3cc80bea12f88fef76a0897aa3cf26fec64fc73bc252c278b40b6e3c44d6153b5523a2fd3f8b77de56bb8f4f0a906f8e7414a8703cf758d441e8de0b0d58acb800000f0001040804010001b2ca8c8ebdb34c3ee8e7dcf178d1902e749d018b359193811ddb213db8972ad8cf70ea94c955082a9a84fc0198418bce654017519ae698f8753ececdd55eb8c58515c05263bc618a09092021b8b26c793059582bd321f25b085aca04d771ebed3b300900a251c3ccd3525dafd38794428ec1b4197ceb8034e7774497816f34be70bce97e775a7cc928ba6a52b44f349d91b3d14840db60a76670c311c52aa2686c026fbb5c4424afc8d862bc786c59659e173765cb03685a00296f1f6bdd10b478f6672d1cd8c94d164cd72b63e5b683e3bf1c39f7cf5439c6a92d600bd58f16a021a8efec2cc04a0524d833eeec6ec026e5f6cb5b2e708ae4683a942f27fb14000020b12aeea7d1c736b65f9b6d35c52fc846a8145edbcf3df07ec2376cee596b9b7b")
        handshake_msg = bytes.fromhex("060043ba080000780076003900690012d901c5d91b6c9e1049eb426a64b621f1797f021037ec51176eb41a9e7e0e669685d3fb550f1278b002327c363d06d8fda4f13e3240da7046060480040000070480040000040480100000080240640901030104800075300e01076ab200110800000001000000010010000500030268330b0003a00000039c000397308203933082027ba00302010202146a95f37e73b552b1705f0ebfcdce7f1f99a05821300d06092a864886f70d01010b05003059310b30090603550406130241553113301106035504080c0a536f6d652d53746174653121301f060355040a0c18496e7465726e6574205769646769747320507479204c74643112301006035504030c096c6f63616c686f7374301e170d3233313232313131303732325a170d3234313232303131303732325a3059310b30090603550406130241553113301106035504080c0a536f6d652d53746174653121301f060355040a0c18496e7465726e6574205769646769747320507479204c74643112301006035504030c096c6f63616c686f737430820122300d06092a864886f70d01010105000382010f003082010a0282010100e48e6d6c21c0fca9810817b31ee083f7cedc98f5b9cd1f038e4b4df756abcc261f66f131902a8c031615fd5411a917f656f893d649cd604daa73bd00fdd764fe3c6c1cc347e66ffb6c0714abf0f4b9cdf24d7d7d5b2596556f45e81672a565425cd64db8815f66c6529ae6f59eacc5cfeb969523332c94193fc6f4731b25fa4d355bbd2fac165b418c021992991f2e22c93eb7bcf25dfdbf4b47b17e7386f96716dae9681ce5e086f1d1c2f09deeaa87f518d47a2f540b44319b6e078ae4253c523267c1ee5cd123dec22a9055f50bccff6e401d4c59780b3ee2cb26131c5d5e9243f069fa60875aa3a907d2a3d6242e82e2d0d3928f191a4bad3fe33f5427530203010001a3533051301d0603551d0e0416041426e46d370ddf57c69be4f3b9a85d0aa32021a316301f0603551d2304183016801426e46d370ddf57c69be4f3b9a85d0aa32021a316300f0603551d130101ff040530030101ff300d06092a864886f70d01010b05000382010100771e8ba50a264cc9ad131e9479b51eab889ac05aa00ab3662cc6200860a9c4ee3245f53a9137298bbefdc01529ee17725e0efeb614af8dbb478499b4feedb7a4c7380aba5b8d5705c8c1ab1da1a3bd99c50a41cd060dadeb654589bc06d98db2dfb787a985e8e18b8484c9730a2c87e62299c6b7981afc26a54a4997d651d669cfab9616ea50d2028dc486885574c5beb5ba7bf4cad8473ca5477bbc")

        certificate_frame = CryptoFrame(certificate, self.handshake_packet_server)
        message_frame = CryptoFrame(handshake_msg, self.handshake_packet_server)
        self.quic_tls_session_2.update_session(certificate_frame)
        self.quic_tls_session_2.update_session(message_frame)

        self.assertEqual(self.quic_tls_session_2.alpn, b"h3")


from unittest import TestCase
import tlexport.quic.quic_frame as frames
from tlexport.quic.quic_packet import QuicPacket, QuicPacketType, QuicHeaderType


class TestQuicFrameGeneration(TestCase):
    def setUp(self):
        self.quic_packet = QuicPacket(QuicHeaderType.LONG, QuicPacketType.HANDSHAKE, False, first_byte=None, ts=0)

    def test_ping_and_padding(self):
        parsed_frames = frames.parse_frames(bytes.fromhex("010000"), self.quic_packet)

        self.assertEqual(type(parsed_frames[0]), frames.PingFrame)
        self.assertEqual(parsed_frames[1].length, 2)

    def test_crypto_frame(self):
        parsed_frames = frames.parse_frames(bytes.fromhex(
            "0200414800000600405a020000560303b7be3c8d397996b7264f25fe5f624f4ac37e901a5acd517d408972a6ddb1cda800130100002e00330024001d0020813355ac9760c2dc4e7df93de0d5d9c120f58f38a381706c73d6177705e24a3c002b00020304") + bytes.fromhex(
            "0000000000010001"), self.quic_packet)

        ack_frame: frames.AckFrame = parsed_frames[0]
        self.assertEqual(0, ack_frame.largest_acknowledged)
        self.assertEqual(328, ack_frame.ack_delay)
        self.assertEqual(0, ack_frame.range_count)
        self.assertEqual(0, ack_frame.first_ack_range)
        crypto_frame: frames.CryptoFrame = parsed_frames[1]
        self.assertEqual(0, crypto_frame.offset)
        self.assertEqual(90, crypto_frame.crypto_length)
        self.assertEqual(crypto_frame.crypto, bytes.fromhex(
            "020000560303b7be3c8d397996b7264f25fe5f624f4ac37e901a5acd517d408972a6ddb1cda800130100002e00330024001d0020813355ac9760c2dc4e7df93de0d5d9c120f58f38a381706c73d6177705e24a3c002b00020304"))

        parsed_frames = frames.parse_frames(bytes.fromhex(
            "064995450f413048931bbfb7f6e0450221e0964217cfd92b6556340726040da8fd7dca2eefea487c374d3f009f83dfef75842e79575cfc576e1a96fffc8c9aa699be25d97f962c06f7112a028080eb63183c504987e58aca5f192b59968100a0fb51dbca770b0bc9964fef7049c75c6d20fd99b4b4e2ca2e77fd2ddc0bb66b130c8c192b179698b9f08bf6a027bbb6e38d518fbdaec79bb1899d0203010001a38201803082017c300e0603551d0f0101ff040403020186301d0603551d250416301406082b0601050507030106082b0601050507030230120603551d130101ff040830060101ff020100301d0603551d0e041604148a747faf85cdee95cd3d9cd0e24614f371351d27301f0603551d23041830168014e4af2b26711a2b4827852f52662ceff08913713e306806082b06010505070101045c305a302606082b06010505073001861a687474703a2f2f6f6373702e706b692e676f6f672f6774737231303006082b060105050730028624687474703a2f2f706b692e676f6f672f7265706f2f63657274732f67747372312e64657230340603551d1f042d302b3029a027a0258623687474703a2f2f63726c2e706b692e676f6f672f67747372312f67747372312e63726c30570603551d200450304e3038060a2b06010401d679020503302a302806082b06010505070201161c68747470733a2f2f706b692e676f6f672f7265706f7369746f72792f3008060667810c0102013008060667810c010202300d06092a864886f70d01010b05000382020100897dac205c0c3cbe9aa857951bb4aefaaba57271b43695fddf4011034cc24614bb1424abf0507122dbadc46e7fcff16a6fc8831bd8ce895f876c87b8a90ca39ba162949395df5bae66190b02969efcb5e710693e7acb46495f46e141b1d7984d653400801a3f4f9f6c7f4900815341a4922182821af1a3445b2a5012134dc15336f34208af54fa8e77531b6438271709bd58c91b7c392d5bf3ced4ed97db1403bf0953241fc20c04799826f261f15352fd428c1b662b3f15a1bbfff69be3819a01067189352824dde1bdeb192de148cb3d598351b474c69d7cc6b1865bafcc34c4d3ccd481119500a1f4122201fab48371af8cb78c7324ac3753c200903f11fe5ced3694103bbd29aee2c73a623b6c63d980bf5971ac6327b94c17a0daf67315bf2ade8ff3a56c32813303d08651719934ba938d5db55158f7b293e801f659be719bfd4d28cecf6dc716dcf7d1d6469ba7ca6be9770ffda0b61b23831d101ad9090084e044d3a27523b33486f620b0a45e101de05246009db10f1f217051f59add06fc55f42b0e3377c34b42c2f17713fc738094eb1fbb373fce022a66b0731d32a5326c32b08ee0c423ff5b7d4d6570ac2b9b3dcedbe06d8e3280be969f9263bc97bb5db9f4e1715e2ae4ef0322b18a653a8fc09365d485cd0f0f5b83591647162d9c243ac880a62614859bf6379bac6ff9c5c30651f3e27fc5b110ba51f4dd0000000566308205623082044aa003020102021077bd0d6cdb36f91aea210fc4f058d30d300d06092a864886f70d01010b05003057310b300906035504061302424531193017060355040a1310476c6f62616c5369676e206e762d73613110300e060355040b1307526f6f74204341311b301906035504031312476c6f62616c5369676e20526f6f74204341301e170d3230303631393030303034325a170d3238303132383030303034325a3047310b300906035504061302555331223020060355040a1319476f6f676c65205472757374205365727669636573204c"), self.quic_packet)
        crypto_frame: frames.CryptoFrame = parsed_frames[0]
        self.assertEqual(2453, crypto_frame.offset)
        self.assertEqual(1295, crypto_frame.crypto_length)
        self.assertEqual(crypto_frame.crypto, bytes.fromhex(
            "413048931bbfb7f6e0450221e0964217cfd92b6556340726040da8fd7dca2eefea487c374d3f009f83dfef75842e79575cfc576e1a96fffc8c9aa699be25d97f962c06f7112a028080eb63183c504987e58aca5f192b59968100a0fb51dbca770b0bc9964fef7049c75c6d20fd99b4b4e2ca2e77fd2ddc0bb66b130c8c192b179698b9f08bf6a027bbb6e38d518fbdaec79bb1899d0203010001a38201803082017c300e0603551d0f0101ff040403020186301d0603551d250416301406082b0601050507030106082b0601050507030230120603551d130101ff040830060101ff020100301d0603551d0e041604148a747faf85cdee95cd3d9cd0e24614f371351d27301f0603551d23041830168014e4af2b26711a2b4827852f52662ceff08913713e306806082b06010505070101045c305a302606082b06010505073001861a687474703a2f2f6f6373702e706b692e676f6f672f6774737231303006082b060105050730028624687474703a2f2f706b692e676f6f672f7265706f2f63657274732f67747372312e64657230340603551d1f042d302b3029a027a0258623687474703a2f2f63726c2e706b692e676f6f672f67747372312f67747372312e63726c30570603551d200450304e3038060a2b06010401d679020503302a302806082b06010505070201161c68747470733a2f2f706b692e676f6f672f7265706f7369746f72792f3008060667810c0102013008060667810c010202300d06092a864886f70d01010b05000382020100897dac205c0c3cbe9aa857951bb4aefaaba57271b43695fddf4011034cc24614bb1424abf0507122dbadc46e7fcff16a6fc8831bd8ce895f876c87b8a90ca39ba162949395df5bae66190b02969efcb5e710693e7acb46495f46e141b1d7984d653400801a3f4f9f6c7f4900815341a4922182821af1a3445b2a5012134dc15336f34208af54fa8e77531b6438271709bd58c91b7c392d5bf3ced4ed97db1403bf0953241fc20c04799826f261f15352fd428c1b662b3f15a1bbfff69be3819a01067189352824dde1bdeb192de148cb3d598351b474c69d7cc6b1865bafcc34c4d3ccd481119500a1f4122201fab48371af8cb78c7324ac3753c200903f11fe5ced3694103bbd29aee2c73a623b6c63d980bf5971ac6327b94c17a0daf67315bf2ade8ff3a56c32813303d08651719934ba938d5db55158f7b293e801f659be719bfd4d28cecf6dc716dcf7d1d6469ba7ca6be9770ffda0b61b23831d101ad9090084e044d3a27523b33486f620b0a45e101de05246009db10f1f217051f59add06fc55f42b0e3377c34b42c2f17713fc738094eb1fbb373fce022a66b0731d32a5326c32b08ee0c423ff5b7d4d6570ac2b9b3dcedbe06d8e3280be969f9263bc97bb5db9f4e1715e2ae4ef0322b18a653a8fc09365d485cd0f0f5b83591647162d9c243ac880a62614859bf6379bac6ff9c5c30651f3e27fc5b110ba51f4dd0000000566308205623082044aa003020102021077bd0d6cdb36f91aea210fc4f058d30d300d06092a864886f70d01010b05003057310b300906035504061302424531193017060355040a1310476c6f62616c5369676e206e762d73613110300e060355040b1307526f6f74204341311b301906035504031312476c6f62616c5369676e20526f6f74204341301e170d3230303631393030303034325a170d3238303132383030303034325a3047310b300906035504061302555331223020060355040a1319476f6f676c65205472757374205365727669636573204c"))

    def test_stream_frame(self):
        parsed_frames = frames.parse_frames(bytes.fromhex(
            "080300041f018001000006800100000740640801c00000044fc25e00c0000000997dd1d8c0000000af79f09b02e68e"), self.quic_packet)
        stream_frame: frames.StreamFrame = parsed_frames[0]
        self.assertEqual(stream_frame.stream_id, 3)
        self.assertEqual(stream_frame.fin, False)
        self.assertEqual(stream_frame.off, False)
        self.assertEqual(stream_frame.len, False)
        self.assertEqual(stream_frame.data_length, 45)
        self.assertEqual(stream_frame.server_initiated, True)
        self.assertEqual(stream_frame.stream_unidirectional, True)
        self.assertEqual(stream_frame.length, 47)

        parsed_frames = frames.parse_frames(bytes.fromhex(
            "0b0040a101409e0684d1d75098b2c696596454b35336572af742f31cf3505ee690a75c87a751896262d45b0692c42035105f50b4d07f66a281b0dae053fafc087ed4ce6aadf2a7979c89c6bed4b3bdc0882b83fb531149d4ec0801000200a984d61653f960220ae05f0e93352398ac0fb9a5fa352398ac782c75fd7cb1f35f398b2d4b70ddf45abefb4005dbdf115d929d29ad171863c78f0bfa3da9b632ae43d2c71213140e0605405f66aec31ec327d783b606bf661d095ad4164f98b2c696596454b35336572af742f31cf3505ee690a75c87a76a4148b4a549275a42a13f84352398bf6a4148b4a549275a93c85f85a8eb10f6236a4148b4a549275906497f872587421641925f"), self.quic_packet)
        stream_frame: frames.StreamFrame = parsed_frames[0]
        self.assertEqual(stream_frame.stream_id, 0)
        self.assertEqual(stream_frame.fin, True)
        self.assertEqual(stream_frame.off, False)
        self.assertEqual(stream_frame.len, True)
        self.assertEqual(stream_frame.data_length, 161)
        self.assertEqual(stream_frame.server_initiated, False)
        self.assertEqual(stream_frame.stream_unidirectional, False)
        self.assertEqual(stream_frame.length, 165)

        stream_frame: frames.StreamFrame = parsed_frames[1]
        self.assertEqual(stream_frame.stream_id, 6)
        self.assertEqual(stream_frame.fin, False)
        self.assertEqual(stream_frame.off, True)
        self.assertEqual(stream_frame.len, True)
        self.assertEqual(stream_frame.data_length, 95)
        self.assertEqual(stream_frame.server_initiated, False)
        self.assertEqual(stream_frame.stream_unidirectional, True)
        self.assertEqual(stream_frame.length, 100)

    def test_handshake_done_packet(self):
        parsed_frames = frames.parse_frames(bytes.fromhex(
            "1e0740410095028230a8f84f9402b7e252734ad7cc45d4e291c4909931164d2c15d769c0504390b2198dc477ba147f7184c67ab5e27f69667733df75fd6bb8ff8d8ca0273b18010008e01f26872f1ff3d8f60b2d543c097238b39865dd3e7b5880"), self.quic_packet)
        self.assertEqual(0x1e, parsed_frames[0].frame_type)
        self.assertEqual(1, parsed_frames[0].length)
        token_frame: frames.NewTokenFrame = parsed_frames[1]
        self.assertEqual(65, token_frame.token_length)
        self.assertEqual(bytes.fromhex(
            "0095028230a8f84f9402b7e252734ad7cc45d4e291c4909931164d2c15d769c0504390b2198dc477ba147f7184c67ab5e27f69667733df75fd6bb8ff8d8ca0273b"),
            token_frame.token)
        new_connection_id_frame: frames.NewConnectionIdFrame = parsed_frames[2]
        self.assertEqual(1, new_connection_id_frame.sequence_number)
        self.assertEqual(0, new_connection_id_frame.retire_prior_to)
        self.assertEqual(8, new_connection_id_frame.connection_id_length)
        self.assertEqual(bytes.fromhex("e01f26872f1ff3d8"), new_connection_id_frame.connection_id)
        self.assertEqual(bytes.fromhex("f60b2d543c097238b39865dd3e7b5880"),
                         new_connection_id_frame.stateless_reset_token)

    def test_datagram_frame(self):
        parsed_frames = frames.parse_frames(bytes.fromhex(
            "310454657374"),
            self.quic_packet)
        datagram_frames: frames.DatagramFrame = parsed_frames[0]
        self.assertEqual(datagram_frames.length, 6)
        self.assertEqual(datagram_frames.payload, b"Test")

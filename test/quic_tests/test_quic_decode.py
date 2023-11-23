from unittest import TestCase
from tlexport.quic.quic_decode import decode_variable_length_int, get_variable_length_int_length


class TestVariableLengthInt(TestCase):
    def test_decode_variable_length_int(self):
        self.assertEqual(0, decode_variable_length_int(b"\x00"))
        self.assertEqual(63, decode_variable_length_int(b"\x3F"))
        self.assertEqual(4611686018427387903, decode_variable_length_int(b"\xff\xff\xff\xff\xff\xff\xff\xff"))
        self.assertEqual(151288809941952652, decode_variable_length_int(bytes.fromhex("c2197c5eff14e88c")))
        self.assertEqual(494878333, decode_variable_length_int(bytes.fromhex("9d7f3e7d")))
        self.assertEqual(15293, decode_variable_length_int(bytes.fromhex("7bbd")))
        self.assertEqual(37, decode_variable_length_int(bytes.fromhex("25")))
        self.assertEqual(37, decode_variable_length_int(bytes.fromhex("80000025")))


    def test_get_variable_length_int_length(self):
        self.assertEqual(1, get_variable_length_int_length(b"\x3F"))
        self.assertEqual(2, get_variable_length_int_length(b"\x60"))
        self.assertEqual(4, get_variable_length_int_length(b"\xA0"))
        self.assertEqual(8, get_variable_length_int_length(b"\xff"))




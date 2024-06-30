from enum import Enum


def decode_variable_length_int(variable_integer: bytes) -> int:
    v = variable_integer[0]
    prefix = v >> 6
    length = 1 << prefix

    v = v & 0x3f
    for i in range(1, length):
        v = (v << 8) + variable_integer[i]

    return v


def get_variable_length_int_length(first_byte_of_variable_int: bytes) -> int:
    v = first_byte_of_variable_int[0]
    prefix = v >> 6
    length = 1 << prefix

    return length


class QuicVersion(Enum):
    UNKNOWN = 0
    V1 = 1
    V2 = 2

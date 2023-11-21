from tlexport.quic.quic_decode import get_variable_length_int_length, decode_variable_length_int


def parse_frames(payload: bytes):
    payload = bytearray(payload)

    frames = []
    keys = frame_type.keys()
    while len(payload) != 0:
        key = 0x00
        for k in keys:
            if payload[0] in k:
                key = k
        frame = frame_type[key](payload)

        frames.append(frame)
        frame_length = frame.length

        payload = payload[frame_length:]

    return frames


class Frame:
    def __init__(self, _payload):
        pass


class PaddingFrame(Frame):
    frame_type = 0x00
    length = 0x01


class PingFrame(Frame):
    frame_type = 0x01
    length = 1


class AckFrame:
    def __init__(self, payload):
        self.frame_type = payload[0]
        self.length = 1

        self.length += get_variable_length_int_length(payload[1:2])
        self.largest_acknowledged = decode_variable_length_int(payload[1:self.length])
        index = self.length

        self.length += get_variable_length_int_length(payload[index:index + 1])
        self.ack_delay = decode_variable_length_int(payload[index:self.length])
        index = self.length

        self.length += get_variable_length_int_length(payload[index:index + 1])
        self.range_count = decode_variable_length_int(payload[index:self.length])
        index = self.length

        self.length += get_variable_length_int_length(payload[index:index + 1])
        self.first_ack_range = decode_variable_length_int(payload[index:self.length])
        index = self.length

        self.ack_ranges = []
        for i in range(0, self.range_count):
            self.length += get_variable_length_int_length(payload[index:index + 1])
            gap = decode_variable_length_int(payload[index:self.length])
            index = self.length
            self.length += get_variable_length_int_length(payload[index:index + 1])
            ack_range_length = decode_variable_length_int(payload[index:self.length])
            index = self.length

            self.ack_ranges.append((gap, ack_range_length))

        if self.frame_type == 0x03:
            self.length += get_variable_length_int_length(payload[index:index + 1])
            self.ect_0_count = decode_variable_length_int(payload[index:self.length])
            index = self.length

            self.length += get_variable_length_int_length(payload[index:index + 1])
            self.ect_1_count = decode_variable_length_int(payload[index:self.length])
            index = self.length

            self.length += get_variable_length_int_length(payload[index:index + 1])
            self.ect_ce_count = decode_variable_length_int(payload[index:self.length])


class ResetStreamFrame:
    frame_type = 0x04

    def __init__(self, payload):
        self.length = 1

        self.length += get_variable_length_int_length(payload[1:2])
        self.stream_id = decode_variable_length_int(payload[1:self.length])
        index = self.length

        self.length += get_variable_length_int_length(payload[index:index + 1])
        self.application_protocol_error_code = decode_variable_length_int(payload[index:self.length])
        index = self.length

        self.length += get_variable_length_int_length(payload[index:index + 1])
        self.final_size = decode_variable_length_int(payload[index:self.length])


class StopSendingFrame:
    frame_type = 0x05

    def __init__(self, payload):
        self.length = 1

        self.length += get_variable_length_int_length(payload[1:2])
        self.stream_id = decode_variable_length_int(payload[1:self.length])
        index = self.length

        self.length += get_variable_length_int_length(payload[index:index + 1])
        self.application_protocol_error_code = decode_variable_length_int(payload[index:self.length])


class CryptoFrame:
    frame_type = 0x06

    def __init__(self, payload):
        self.length = 1

        self.length += get_variable_length_int_length(payload[1:2])
        self.offset = decode_variable_length_int(payload[1:self.length])
        index = self.length

        self.length += get_variable_length_int_length(payload[index:index + 1])
        self.crypto_length = decode_variable_length_int(payload[index:self.length])
        index = self.length

        self.length += self.crypto_length
        self.crypto = payload[index: self.length]


class NewTokenFrame:
    frame_type = 0x07

    def __init__(self, payload):
        self.length = 1

        self.length += get_variable_length_int_length(payload[1:2])
        self.token_length = decode_variable_length_int(payload[1:self.length])
        index = self.length

        self.length += self.token_length
        self.token = payload[index: self.length]


class StreamFrame:
    def __init__(self, payload):
        self.frame_type = payload[0]
        self.fin = bool(self.frame_type & 1)
        self.len = bool((self.frame_type >> 1) & 1)
        self.off = bool((self.frame_type >> 2) & 1)

        self.length = 1
        self.length += get_variable_length_int_length(payload[1:2])
        self.stream_id = decode_variable_length_int(payload[1:self.length])

        self.server_initiated = bool(self.stream_id & 1)
        self.stream_type = bool((self.stream_id >> 1) & 1)

        index = self.length

        self.stream_data = None

        if self.off:
            self.length += get_variable_length_int_length(payload[index:index + 1])
            self.offset = decode_variable_length_int(payload[index:self.length])
            index = self.length
        else:
            self.offset = 0

        if self.len:
            self.length += get_variable_length_int_length(payload[index:index + 1])
            self.data_length = decode_variable_length_int(payload[index:self.length])
            index = self.length
            self.length += self.data_length
        else:
            self.length = len(payload)
            self.data_length = len(payload) - index

        self.stream_data = payload[index:self.length]


class MaxDataFrame:
    frame_type = 0x10

    def __init__(self, payload):
        self.length = 1
        self.length += get_variable_length_int_length(payload[1:2])
        self.maximum_data = decode_variable_length_int(payload[1:self.length])


class MaxStreamDataFrame:
    frame_type = 0x11

    def __init__(self, payload):
        self.length = 1
        self.length += get_variable_length_int_length(payload[1:2])
        self.stream_id = decode_variable_length_int(payload[1:self.length])
        index = self.length

        self.length += get_variable_length_int_length(payload[index: index + 1])
        self.maximum_stream_data = decode_variable_length_int(payload[index: self.length])


class MaxStreamsFrame:
    def __init__(self, payload):
        self.frame_type = payload[0]

        self.length = 1
        self.length += get_variable_length_int_length(payload[1:2])
        self.maximum_streams = decode_variable_length_int(payload[1:self.length])


class DataBlockedFrame:
    frame_type = 0x14

    def __init__(self, payload):
        self.length = 1
        self.length += get_variable_length_int_length(payload[1:2])
        self.maximum_data = decode_variable_length_int(payload[1:self.length])


class StreamDataBlockedFrame:
    frame_type = 0x15

    def __init__(self, payload):
        self.length = 1
        self.length += get_variable_length_int_length(payload[1:2])
        self.stream_id = decode_variable_length_int(payload[1:self.length])
        index = self.length

        self.length += get_variable_length_int_length(payload[index: index + 1])
        self.maximum_stream_data = decode_variable_length_int(payload[index: self.length])


class StreamsBlockedFrame:
    def __init__(self, payload):
        self.frame_type = payload[0]

        self.length = 1
        self.length += get_variable_length_int_length(payload[1:2])
        self.maximum_streams = decode_variable_length_int(payload[1:self.length])


class NewConnectionIdFrame:
    frame_type = 0x18

    def __init__(self, payload):
        self.length = 1
        self.length += get_variable_length_int_length(payload[1:2])
        self.sequence_number = decode_variable_length_int(payload[1:self.length])
        index = self.length

        self.length += get_variable_length_int_length(payload[index: index + 1])
        self.retire_prior_to = decode_variable_length_int(payload[index: self.length])

        self.connection_id_length = payload[self.length]
        self.length += 1

        self.connection_id = payload[self.length: self.length + self.connection_id_length]
        self.length += self.connection_id_length

        self.stateless_reset_token = payload[self.length: self.length + 16]
        self.length += 16


class RetireConnectionIdFrame:
    frame_type = 0x19

    def __init__(self, payload):
        self.length = 1
        self.length += get_variable_length_int_length(payload[1:2])
        self.sequence_number = decode_variable_length_int(payload[1:self.length])


class PathChallengeFrame:
    frame_type = 0x1a
    length = 9

    def __init__(self, payload):
        self.data = payload[1:9]


class PathResponseFrame:
    frame_type = 0x1b
    length = 9

    def __init__(self, payload):
        self.data = payload[1:9]


class ConnectionCloseFrame:
    def __init__(self, payload):
        self.frame_type = payload[0]

        self.length = 1
        self.length += get_variable_length_int_length(payload[1:2])
        self.error_code = decode_variable_length_int(payload[1:self.length])
        index = self.length

        if self.frame_type == 0x1c:
            self.length += get_variable_length_int_length(payload[index + index + 1])
            self.close_frame_type = decode_variable_length_int(payload[index:self.length])
            index = self.length

        self.length += get_variable_length_int_length(payload[index: index + 1])
        self.reason_phrase_length = decode_variable_length_int(payload[index: self.length])
        index = self.length

        self.length += self.reason_phrase_length
        self.reason_phrase = payload[index: self.length]


class HandshakeDoneFrame(Frame):
    frame_type = 0x1e
    length = 1


frame_type = {
    (0x00,): PaddingFrame,
    (0x01,): PingFrame,
    (0x02,): AckFrame,
    (0x03,): AckFrame,
    (0x04,): ResetStreamFrame,
    (0x05,): StopSendingFrame,
    (0x06,): CryptoFrame,
    (0x07,): NewTokenFrame,
    (0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f): StreamFrame,
    (0x10,): MaxDataFrame,
    (0x11,): MaxStreamDataFrame,
    (0x12, 0x13): MaxStreamsFrame,
    (0x14,): DataBlockedFrame,
    (0x15,): StreamDataBlockedFrame,
    (0x16, 0x17): StreamsBlockedFrame,
    (0x18,): NewConnectionIdFrame,
    (0x19,): RetireConnectionIdFrame,
    (0x1a,): PathChallengeFrame,
    (0x1b,): PathResponseFrame,
    (0x1c, 0x1d): ConnectionCloseFrame,
    (0x1e,): HandshakeDoneFrame
}

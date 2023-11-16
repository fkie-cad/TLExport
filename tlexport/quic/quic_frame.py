from tlexport.quic.quic_decode import get_variable_length_int_length, decode_variable_length_int


def parse_frames(payload: bytes):
    payload = bytearray(payload)

    frames = []
    while len(payload) != 0:
        frame = frame_type[payload[0]](payload)

        frames.append(frame)
        frame_length = frame.get_length()

        payload = payload[frame_length:]

    return frames


class PaddingFrame:
    frame_type = 0x00
    length = 0x01

    def __init__(self, payload):
        payload = payload[1:]

    def get_length(self):
        return 0x01


class PingFrame:
    frame_type = 0x01

    def __init__(self, payload):
        payload = payload[1:]

    def get_length(self):
        return 0x01


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

    def get_length(self):
        return self.length


frame_type = {
    0x00: PaddingFrame,
    0x01: PingFrame,
    0x02: AckFrame,
    0x03: AckFrame
}

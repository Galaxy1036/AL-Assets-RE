import struct

from io import BufferedReader, BytesIO


class BinaryReader(BufferedReader):
    def __init__(self, data):
        super().__init__(BytesIO(data))

    def read_byte(self):
        return int.from_bytes(self.read(1), 'little')

    def read_short(self):
        return int.from_bytes(self.read(2), 'little')

    def read_float16(self):
        return struct.unpack('<e', self.read(2))[0]  # binary16

    def read_int24(self):
        return int.from_bytes(self.read(3), 'little')

    def read_int(self):
        return int.from_bytes(self.read(4), 'little')

    def read_string(self):
        string = []

        while True:
            char = self.read(1)

            if char != b'\x00':
                string.append(char)

            else:
                break

        return b''.join(string).decode('utf-8')

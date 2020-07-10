from io import BytesIO


class BinaryWriter(BytesIO):

    def __init__(self):
        super().__init__()

    def write_int(self, value):
        self.write(value.to_bytes(4, 'little'))

    def write_string(self, value):
        self.write(value + b'\x00')  # Null terminated string

    @property
    def buffer(self):
        return self.getvalue()

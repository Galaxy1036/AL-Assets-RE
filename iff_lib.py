from reader import BinaryReader


class IffObject:
    def __init__(self, data):
        self.root = None
        self.reader = BinaryReader(data)
        self.parse()

    def parse(self):
        magic = self.reader.read(4).decode('utf-8')

        if magic in ('PIFF', 'IFF2'):
            block_size = self.reader.read_int24()
            block_type = self.reader.read_byte()
            block_tag = self.reader.read(4).decode('utf-8')

            if block_type == 0x46:
                if block_tag == 'ROOT':
                    self.root = Form(block_tag, self.reader.read(block_size))

                else:
                    raise ValueError('Root form must have the ROOT tag')

            elif block_type == 0x43:
                raise ValueError('Chunk not allowed at iff root')

            else:
                raise TypeError('Unknown block type: {}'.format(hex(block_tag)))

        else:
            raise TypeError('Invalid IFF magic: {}, expected PIFF or IFF2'.format(magic))

    def get_root_form(self):
        return self.root


class Form:
    def __init__(self, tag, data):
        self.tag = tag
        self.forms = []
        self.chunks = []

        self.reader = BinaryReader(data)
        self.parse()

    def parse(self):
        while self.reader.peek():
            block_size = self.reader.read_int24()
            block_type = self.reader.read_byte()
            block_tag = self.reader.read(4).decode('utf-8')

            if block_type == 0x46:
                self.forms.append(Form(block_tag, self.reader.read(block_size)))

            elif block_type == 0x43:
                self.chunks.append(Chunk(block_tag, self.reader.read(block_size)))

            else:
                raise TypeError('Unknown block type: {}'.format(hex(block_tag)))

    def get_form(self, form_tag):
        """ Return the first found form with the matching tag. If none where found return None """

        for form in self.forms:
            if form.tag == form_tag:
                return form

        return None

    def get_forms(self, form_tag):
        """ Return all found forms with the matching tag. If none where found return an empty list """
        forms = []

        for form in self.forms:
            if form.tag == form_tag:
                forms.append(form)

        return forms

    def get_chunk(self, chunk_tag):
        """ Return the first found chunk with the matching tag. If none where found return None """

        for chunk in self.chunks:
            if chunk.tag == chunk_tag:
                return chunk

        return None

    def get_chunks(self, chunk_tag):
        """ Return all found chunks with the matching tag. If none where found return an empty list """
        chunks = []

        for chunk in self.chunks:
            if chunk.tag == chunk_tag:
                chunks.append(chunk)

        return chunks


class Chunk:
    def __init__(self, tag, data):
        self.tag = tag
        self.data = data

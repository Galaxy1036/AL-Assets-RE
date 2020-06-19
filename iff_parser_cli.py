import os
import sys
import argparse

from reader import BinaryReader


def parse_iff_block(reader):
    while reader.peek():
        block_size = reader.read_int24()
        block_type = reader.read_byte()
        block_tag = reader.read(4).decode('utf-8')

        if block_type == 0x46:  # 0x46 = 'F' => 'FORM'
            print('[*] Found form with tag {}, length: {}'.format(block_tag, block_size))
            parse_iff_block(BinaryReader(reader.read(block_size)))

        elif block_type == 0x43:  # 0x43 = 'C' => 'CHUNK'
            print('[*] Found chunk with tag {}, length: {}'.format(block_tag, block_size))

            print(reader.read(block_size))

        else:
            sys.exit('[x] Unknown block type found: {}'.format(hex(block_type)))


def parse_iff(reader):
    file_magic = reader.read(4).decode('utf-8')

    if file_magic in ('PIFF', 'IFF2'):
        parse_iff_block(reader)

    else:
        print('[*] Wrong file magic: {}'.format(file_magic))


if __name__ == '__main__':
    parser = parser = argparse.ArgumentParser(description='A little tool used to iff file structure from Arcane Legends game')
    parser.add_argument('files', help='IFF files to parse', nargs='+')

    args = parser.parse_args()

    for file in args.files:
        if os.path.isfile(file):
            with open(file, 'rb') as f:
                parse_iff(BinaryReader(f.read()))

        else:
            print('[*] Cannot find {}'.format(file))

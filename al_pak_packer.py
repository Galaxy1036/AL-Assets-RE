import os
import sys
import math
import brotli
import argparse

from utils import crc32c
from writer import BinaryWriter


def pack_files(input_folder, compression_quality):
    writer = BinaryWriter()
    filenames_writer = BinaryWriter()

    input_files = [os.path.join(path + '\\', name) for path, subdirs, files in os.walk(input_folder) for name in files]

    print('[*] Starting to compress {} files'.format(len(input_files)))

    writer.write(b'0006')  # PAK Version
    writer.write_int(len(input_files))

    print('[*] Computing filenames crc32c values')

    files = {}

    for file in input_files:
        filename = '/'.join(file.split('\\')[1:]).split('\\')[0].encode('utf-8')
        filename_crc32c = crc32c(filename)

        if filename_crc32c not in files:
            files[filename_crc32c] = {
                'filepath': file,
                'filename': filename
            }

        else:
            sys.exit('[x] Filename crc32c collision between file {} and file {}'.format(files[filename_crc32c], filename))

    print('[*] Writing files info')

    full_data = BinaryWriter()

    for filename_crc in sorted(files):
        filepath = files[filename_crc]['filepath']
        filename = files[filename_crc]['filename']

        with open(filepath, 'rb') as f:
            file_data = f.read()

        writer.write_int(filename_crc)
        writer.write_int(filenames_writer.tell())
        writer.write_int(full_data.tell())
        writer.write_int(len(file_data))

        filenames_writer.write_string(filename)
        full_data.write(file_data)

    print('[*] Finished writing file info')

    filenames_table = filenames_writer.buffer
    compressed_filenames_table = brotli.compress(filenames_table, quality=compression_quality)

    writer.write_int(len(compressed_filenames_table))
    writer.write_int(len(filenames_table))

    if len(filenames_table) > len(compressed_filenames_table):
        writer.write(compressed_filenames_table)
        print('[*] Finished writing filename table, status: compressed')

    else:
        writer.write(filenames_table)
        print('[*] Finished writing filename table, status: not compressed')

    writer.write_int(0x10000)  # Block Size

    full_data = full_data.buffer
    data_chunks = []

    print('[*] Total data size: {}'.format(len(full_data)))

    for i in range(math.ceil(len(full_data) / 0x10000)):
        block = full_data[i * 0x10000: (i + 1) * 0x10000]
        data_chunks.append(block)

    print('[*] Finished splitting block, amount of data chunk: {}'.format(len(data_chunks)))

    compressed_chunks = []

    for chunk in data_chunks:
        compressed = brotli.compress(chunk, quality=compression_quality)

        if len(chunk) > len(compressed):
            compressed_chunks.append(compressed)

        else:
            compressed_chunks.append(chunk)

    print('[*] Finished compressing block')

    blocks_count = len(compressed_chunks) + 1

    writer.write_int(len(full_data))

    compressed_block_offset = writer.tell() + 4 * blocks_count

    for chunk in compressed_chunks:
        writer.write_int(compressed_block_offset)

        compressed_block_offset += len(chunk)

    writer.write_int(compressed_block_offset)  # Last offset

    print('[*] Finished writing block offsets')

    for chunk in compressed_chunks:
        writer.write(chunk)

    print('[*] Finished writing compressed chunks')

    pak_data = writer.buffer

    writer.write(b'CRC0')
    writer.write_int(crc32c(pak_data))
    writer.write_int(len(pak_data))

    print('[*] Finished writing CRC end block')

    with open('{}.pak'.format(input_folder), 'wb') as f:
        f.write(writer.buffer)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='A little tool used to create .pak archive')
    parser.add_argument('folder', help='Folder to compress files from')
    parser.add_argument(
        '-q', '--quality',
        help='''Compression quality to use to compress data chunks, the bigger you set it to the longer it will take to compress.
                Value should be between 0 and 11. Default one is 1''',
        default=1, type=int
    )

    args = parser.parse_args()

    if 11 >= args.quality >= 0:
        if os.path.isdir(args.folder):
            pack_files(args.folder, args.quality)

        else:
            print('[x] Cannot locate the input folder')

    else:
        print('[x] Invalid quality value. Should be between 0 and 11')

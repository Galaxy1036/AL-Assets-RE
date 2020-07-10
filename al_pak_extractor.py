import os
import sys
import brotli
import argparse

from utils import crc32c
from reader import BinaryReader


def extract_ressources(data, output_directory, verbose_mode):
    files = []
    reader = BinaryReader(data)

    file_magic = reader.read_int()

    if file_magic == 0x36303030:
        files_count = reader.read_int()

        print('[*] File version: {}, files count: {}'.format(hex(file_magic), files_count))

        crc_block = data[-12:]

        crc_tag = crc_block[0:4]

        if crc_tag == b'CRC0':
            pak_crc = int.from_bytes(crc_block[4:8], 'little')
            pak_size = int.from_bytes(crc_block[8:12], 'little')

            if pak_size != len(data[:-12]):
                sys.exit('[x] Mismatching size between the real one and the specified one in the crc end block, aborting...')

            if pak_crc != crc32c(data[:-12]):
                sys.exit('[x] Mismatching crc, maybe your data are corrupted, aborting...')

        else:
            sys.exit('[x] Cannot find CRC end block, aborting...')

        for _ in range(files_count):
            files.append({
                'filename_crc32c': reader.read_int(),
                'filename_offset': reader.read_int(),
                'file_data_offset': reader.read_int(),
                'file_size': reader.read_int()
            })

        filenames_table_compressed_size = reader.read_int()
        filenames_table_uncompressed_size = reader.read_int()

        if filenames_table_uncompressed_size > filenames_table_compressed_size:
            print('[*] Filenames table is compressed, decompressing ...')

            try:
                filenames_table = brotli.decompress(reader.read(filenames_table_compressed_size))
                print('[*] Successfully decompress filenames table using Brotli compression, total length: {}'.format(filenames_table_uncompressed_size))

            except:
                sys.exit('[x] Failed to decompress filenames table')

        else:
            print('[*] Filenames table is not compressed, total length: {}'.format(filenames_table_uncompressed_size))
            filenames_table = reader.read(filenames_table_uncompressed_size)

        filenames = BinaryReader(filenames_table)

        uncompressed_block_size = reader.read_int()
        total_uncompressed_data_size = reader.read_int()

        block_count = ((total_uncompressed_data_size + uncompressed_block_size - 1) // uncompressed_block_size) + 1

        print('[*] Amount of data block: {}, uncompressed block size: {}, total data size: {}'.format(
            block_count,
            uncompressed_block_size,
            total_uncompressed_data_size)
        )

        block_offsets = []

        for _ in range(block_count):
            block_offsets.append(reader.read_int())

        data = []

        for index, block_offset in enumerate(block_offsets[:-1]):  # Last offset is simply the end of the decompressed data
            compressed_block_size = block_offsets[index + 1] - block_offset

            reader.seek(block_offset)

            if uncompressed_block_size > compressed_block_size:
                if verbose_mode:
                    print('[*] Decompressing pak block at offset {}, compressed size: {}'.format(hex(block_offset), compressed_block_size))

                try:
                    data.append(brotli.decompress(reader.read(compressed_block_size)))

                except:
                    sys.exit('[x] Failed to decompress pak block data at offset: {}'.format(hex(block_offset)))

            else:
                data.append(reader.read(compressed_block_size))

        data = b''.join(data)

        if len(data) != total_uncompressed_data_size:
            sys.exit('[x] Total uncompressed size doesn\'t match the expected one !')

        for file_info in files:
            filenames.seek(file_info['filename_offset'])

            filename = filenames.read_string()

            if crc32c(filename.encode('utf-8')) != file_info['filename_crc32c']:
                sys.exit('[x] Filename {} doesn\'t match the expected crc32c'.format(filename))

            file_data = data[file_info['file_data_offset']: file_info['file_data_offset'] + file_info['file_size']]

            if verbose_mode:
                print('[*] Extracting file: {}, file size: {}'.format(filename, file_info['file_size']))

            output_path = '{}/{}'.format(output_directory, filename)

            os.makedirs(os.path.dirname(output_path), exist_ok=True)

            with open(output_path, 'wb') as f:
                f.write(file_data)

        print('[*] Successfully extracted {} files !'.format(files_count))

    elif file_magic == 0x35303030:
        print('[x] Unsupported .pak version: 0x35303030')

    else:
        print('[x] Unknown .pak version: {}'.format(hex(file_magic)))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='A little tool used to extract ressources from Arcane legends .pak archives')
    parser.add_argument('files', help='.pak archives to extract ressources from', nargs='+')
    parser.add_argument('-v', '--verbose', help='Enable extra information logging', action='store_true')

    args = parser.parse_args()

    for file in args.files:
        if file.endswith('.pak'):
            if os.path.isfile(file):
                with open(file, 'rb') as f:
                    extract_ressources(f.read(), os.path.splitext(file)[0], args.verbose)

            else:
                print('[*] Cannot find {}'.format(file))

        else:
            print('[*] Your file isn\'t a .pak archive')

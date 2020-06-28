import os
import sys
import brotli
import argparse

from reader import BinaryReader


def extract_ressources(reader, output_directory, verbose_mode):
    files = {}

    file_magic = reader.read_int()

    # TODO: verify the file CRC (crc is at the end of the file ), they use crc32c not crc32

    if file_magic == 0x36303030:
        files_count = reader.read_int()

        print('[*] File version: {}, files count: {}'.format(hex(file_magic), files_count))

        for i in range(files_count):
            reader.read_int()  # Unknown value, seems to grow at each iteration

            file_id = reader.read_int()
            file_offset = reader.read_int()
            file_size = reader.read_int()

            files[file_id] = {
                'offset': file_offset,
                'size': file_size
            }

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

        filenames = [name.decode('utf-8') for name in filenames_table.split(b'\x00')]  # They use null char terminator

        uncompressed_block_size = reader.read_int()
        block_count = ((reader.read_int() + uncompressed_block_size - 1) // uncompressed_block_size) + 1

        print('[*] Amount of data block: {}, uncompressed block size: {}'.format(block_count, uncompressed_block_size))

        block_offsets = []

        for i in range(block_count):
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
        sorted_files_id = sorted(files)

        for i in range(files_count):
            filename = filenames[i]
            file_info = files[sorted_files_id[i]]

            file_data = data[file_info['offset']: file_info['offset'] + file_info['size']]

            if verbose_mode:
                print('[*] Extracting file: {}, file size: {}'.format(filename, file_info['size']))

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
                    extract_ressources(BinaryReader(f.read()), os.path.splitext(file)[0], args.verbose)

            else:
                print('[*] Cannot find {}'.format(file))

        else:
            print('[*] Your file isn\'t a .pak archive')

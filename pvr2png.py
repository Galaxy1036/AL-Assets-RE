import os
import sys
import argparse
import etcpack

from PIL import Image
from reader import BinaryReader


class PixelType:
    RGBA8888 = b'rgba\x08\x08\x08\x08'
    RGBA4444 = b'rgba\x04\x04\x04\x04'
    RGB565 = b'rgb\x00\x05\x06\x05\x00'
    L8 = b'l\x00\x00\x00\x08\x00\x00\x00'
    A8 = b'a\x00\x00\x00\x08\x00\x00\x00'
    RGBA5551 = b'rgba\x05\x05\x05\x01'
    LA88 = b'la\x00\x00\x08\x08\x00\x00'


pixels_type_size = {
    PixelType.RGBA8888: 4,
    PixelType.RGBA4444: 2,
    PixelType.RGB565: 2,
    PixelType.L8: 1,
    PixelType.RGBA5551: 2,
    PixelType.A8: 1,
    PixelType.LA88: 2,
}


def convert_pixels(pixel, pixel_type):
    if pixel_type == PixelType.RGBA8888:
        return ((pixel >> 24), ((pixel >> 16) & 0xFF),
                ((pixel >> 8) & 0xFF), (pixel & 0xFF))

    elif pixel_type == PixelType.RGBA4444:
        return (((pixel >> 12) & 0xF) << 4, ((pixel >> 8) & 0xF) << 4,
                ((pixel >> 4) & 0xF) << 4, ((pixel >> 0) & 0xF) << 4)

    elif pixel_type == PixelType.RGB565:
        return (((pixel >> 11) & 0x1F) << 3, ((pixel >> 5) & 0x3F) << 2, (pixel & 0x1F) << 3)

    elif pixel_type == PixelType.RGBA5551:
        return (((pixel >> 11) & 0x1F) << 3, ((pixel >> 6) & 0x1F) << 3,
                ((pixel >> 1) & 0x1F) << 3, ((pixel) & 0xFF) << 7)

    elif pixel_type == PixelType.LA88:  # Right one, dunno why alpha channel is encoded first
        return (pixel & 0xFF), (pixel & 0xFF), (pixel & 0xFF), (pixel >> 8)

    elif pixel_type == PixelType.L8:
        return pixel, pixel, pixel

    elif pixel_type == PixelType.A8:  # TEST, seems fine
        return 0, 0, 0, pixel


def extract_textures(reader, filename):
    file_magic = reader.read_int()

    if file_magic == 0x3525650:
        reader.read(4)  # flags

        pixel_format = reader.read(8)

        reader.read(8)  # Colour space & channel type

        height = reader.read_int()
        width = reader.read_int()

        reader.read(4)  # Depth

        num_surfaces = reader.read_int()
        num_faces = reader.read_int()
        mipmap_count = reader.read_int()

        if (num_surfaces, num_faces, mipmap_count) != (1, 1, 1):
            sys.exit('[*] Got more than than one surface, faces or mipmap: {}, {}, {}'.format(num_surfaces, num_faces, mipmap_count))

        metadata_size = reader.read_int()

        reader.read(metadata_size)

        if pixel_format in pixels_type_size or pixel_format == b'\x06\x00\x00\x00\x00\x00\x00\x00':
            if pixel_format == b'\x06\x00\x00\x00\x00\x00\x00\x00':
                image = Image.frombytes('RGB', (width, height), reader.read(), 'etc2', (0, ))

            else:
                image = Image.new('RGBA', (width, height))

                pixels = []
                pixel_size = pixels_type_size[pixel_format]

                for _ in range(height):
                    for _ in range(width):
                        pixel = int.from_bytes(reader.read(pixel_size), 'little')
                        pixels.append(convert_pixels(pixel, pixel_format))

                image.putdata(pixels)

            output_name = '{}.png'.format(os.path.splitext(filename)[0])
            image.save(output_name, 'PNG')

            print('[*] Successfully extracted {} with pixelformat {}'.format(output_name, pixel_format))

        else:
            print('[*] Unknown pixel format: {}'.format(pixel_format))

    else:
        print('[*] Wrong PVR magic header, expected PVR\x03')


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='A small script used to extract textures as .png from .pvr files')
    parser.add_argument('files', help='.pvr files to extract textures from', nargs='+')

    args = parser.parse_args()

    for file in args.files:
        with open(file, 'rb') as f:
            print('[*] Extracting textures from {}'.format(file))
            extract_textures(BinaryReader(f.read()), file)

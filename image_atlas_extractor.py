import os
import argparse

from PIL import Image
from iff_lib import IffObject
from reader import BinaryReader


def extract_info(iff_object, texture):
    iff_root = iff_object.get_root_form()

    imat_form = iff_root.get_form('IMAT')

    if imat_form is not None:
        imat_data = imat_form.get_chunk('0004')

        if imat_data is not None:
            imat_reader = BinaryReader(imat_data.data)

            unknown_count = imat_reader.read_int()

            print('[*] Unknown count value: {}'.format(unknown_count))

            while len(imat_data.data) - imat_reader.tell() >= 2:
                imat_reader.read_byte()  # unknown

                imat_reader.read_string()  # atlas tag

                ouput_name = imat_reader.read_string()

                # 4 unknown short
                for i in range(4):
                    imat_reader.read_short()

                upper_left_x = imat_reader.read_short()
                upper_left_y = imat_reader.read_short()
                sprite_width = imat_reader.read_short()
                sprite_height = imat_reader.read_short()

                sprite = texture.crop((
                    upper_left_x,
                    upper_left_y,
                    upper_left_x + sprite_width,
                    upper_left_y + sprite_height
                ))

                os.makedirs(os.path.dirname(ouput_name), exist_ok=True)

                sprite.save(ouput_name, 'PNG')

                print('[*] Succesfully extracted {}'.format(ouput_name))

        else:
            print('[*] Your file contain an IMAT form without data (0004 chunk)')

    else:
        print('[*] Your file doesn\'t contain any IMAT form')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='A little tool used to extract info from .iat files used by Arcane Legends')
    parser.add_argument('file', help='.iat file to extract info from')
    parser.add_argument('-t', '--texture', help='.png texture to extract part from')

    args = parser.parse_args()

    if args.file.endswith('.iat'):
        if os.path.isfile(args.file):
            if args.texture.endswith('.png'):
                if os.path.isfile(args.texture):
                    with open(args.file, 'rb') as f:
                        extract_info(IffObject(f.read()), Image.open(args.texture))

                else:
                    print('[*] Cannot find {}'.format(args.texture))

            else:
                print('[*] Your texture file isn\'t a .png file')

        else:
            print('[*] Cannot find {}'.format(args.file))

    else:
        print('[*] Your file isn\'t a .iat file')

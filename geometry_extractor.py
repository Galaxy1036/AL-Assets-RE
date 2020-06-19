import os
import sys
import argparse
import numpy as np
import collada

from iff_lib import IffObject
from reader import BinaryReader


def extract_models(iff_object, filename):
    iff_root = iff_object.get_root_form()

    # Maybe they can contains multiple GEOM, dunno
    geometry = iff_root.get_form('GEOM')

    if geometry is not None:
        geometry_data = geometry.get_form('0000')

        if geometry_data is not None:
            primitives = geometry_data.get_forms('PRIM')

            if primitives:
                geometry_nodes = []
                
                model = collada.Collada()

                contributor = collada.asset.Contributor()

                contributor.author = 'GaLaXy1036'
                contributor.authoring_tool = 'Arcane Legends Models Ripper'
                contributor.comments = 'no sharing allowed'
                contributor.save()

                model.assetInfo.contributors.append(contributor)

                model.assetInfo.unitmeter = 0.01
                model.assetInfo.unitname = 'centimeter'

                model.assetInfo.upaxis = collada.asset.UP_AXIS.Y_UP

                for index, primitive in enumerate(primitives):
                    primitive_data = primitive.get_form('0002')

                    if primitive_data is not None:
                        vertices_data = primitive_data.get_chunk('VRTX')
                        indices_data = primitive_data.get_chunk('INDX')

                        if vertices_data is not None and indices_data is not None:
                            object_name = 'object-{}'.format(index)

                            vertices = []
                            indices = []
                            normals = []
                            # colors = []
                            texcoords = []

                            vertices_reader = BinaryReader(vertices_data.data)
                            indices_reader = BinaryReader(indices_data.data)
                            
                            vertices_count = vertices_reader.read_int()

                            for _ in range(vertices_count):
                                for _ in range(3):
                                    vertices.append(vertices_reader.read_float16())  # x, y, z coordinates

                                for _ in range(3):
                                    normals.append(vertices_reader.read_float16())  # Maybe normals (x, y, z)

                                vertices_reader.read_int()  # always 0xFFFFFFFF (maybe vertices color R, G, B, A)

                                # for _ in range(4):
                                #     colors.append(vertices_reader.read_byte())

                                for _ in range(2):
                                    texcoords.append(vertices_reader.read_float16() * 4096.0)  # Maybe texture coordinates (s, t)
                                    # multiplied by 4096 in the lib (0x1000)

                            # print(texcoords)
                            # print(normals)

                            indices_count = indices_reader.read_int()

                            for _ in range(indices_count):
                                indice = indices_reader.read_short()

                                for _ in range(2):
                                    indices.append(indice)

                            sources = [
                                collada.source.FloatSource('{}-mesh-positions'.format(object_name), np.array(vertices), ('X', 'Y', 'Z')),
                                # collada.source.FloatSource('{}-mesh-normals'.format(object_name), np.array(indices), ('X', 'Y', 'Z')),
                                # collada.source.FloatSource('{}-mesh-colors'.format(object_name), np.array(colors), ('R', 'G', 'B', 'A')),
                                # collada.source.FloatSource('{}-mesh-map'.format(object_name), np.array(texcoords), ('S', 'T'))
                            ]

                            geom = collada.geometry.Geometry(model, '{}-mesh'.format(object_name), object_name, sources)

                            input_list = collada.source.InputList()

                            input_list.addInput(0, 'VERTEX', '#{}-mesh-positions'.format(object_name))
                            # input_list.addInput(1, 'NORMAL', '#{}-mesh-normals'.format(object_name))
                            # input_list.addInput(2, 'COLOR', '#{}-mesh-colors'.format(object_name), set='0')
                            # input_list.addInput(2, 'TEXCOORD', '#{}-mesh-map'.format(object_name), set='0')

                            triset = geom.createTriangleSet(np.array(indices), input_list, 'group-{}'.format(index))
                            geom.primitives.append(triset)

                            model.geometries.append(geom)
                            geomnode = collada.scene.GeometryNode(geom)
                            node = collada.scene.Node(object_name + '-GaLaXy1036', children=[geomnode])
                            geometry_nodes.append(node)

                        else:
                            print('[*] The given .geo file contains primitive data without vertices (VRTX) or indices (INDX) chunks')

                    else:
                        print('[*] The given .geo file contains a primitive ({}) without data (0002) form'.format(index))

                scene = collada.scene.Scene("Scene", geometry_nodes)

                model.scenes.append(scene)
                model.scene = scene

                save_model(filename, model)

            else:
                print('[*] The given .geo file has GEOM data but doesn\'t contains any primitives')

        else:
            print('[*] The given .geo file GEOM form doesn\'t contains data (0000 form)')

    else:
        print('[*] The given .geo file do not contains any GEOM form')


def save_model(filename, model):
    output_path = '{0}/{0}_model.dae'.format(filename)

    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    model.write(output_path)

    print('[*] Successfully extracted 3d models as .dae file')

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='A little tool used to extract 3d models from .geo files used by Arcane Legends')
    parser.add_argument('files', help='.geo files to extract models from', nargs='+')

    args = parser.parse_args()

    for file in args.files:
        if file.endswith('.geo'):
            if os.path.isfile(file):
                with open(file, 'rb') as f:
                    extract_models(IffObject(f.read()), os.path.splitext(file)[0])

            else:
                print('[*] Cannot find {}'.format(file))

        else:
            print('[*] Your file isn\'t a .geo file')

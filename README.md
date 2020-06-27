# AL-Assets-RE
 An attempt to reverse engine assets used by Arcane Legends

## Information
Arcane Legends is a Mobile & Browser MMORPG game, the game actually has it's own game engine. Since almost all files have a custom format the goal of this repository was to reverse-engine thoses files & try to to extract ressources from it.

The game use a custom .pak format as files archive. You can use `al_pak_extractor.py` to extract files from thoses archives.

**Notice**: You can grab the main .pak in the game apk, the pak is named `android000.png`. Additional .pak can be grabbed out of your device cache if you are rooted.

## Files

Once extracted you may notice than approximatively 90-95 % use a custom format. In fact Arcane Legends use IFF file format based on forms & chunks of data. You can easily get an overview of the IFF structure by using `iff_parser_cli.py`. To directly deal with the forms & chunks in your code just use the `iff_lib.py` methods

For further explanations about the files formats look at the following links

| File Type | Format |
| -----| ------------- |
| PAK files | [PAK files format](https://github.com/Galaxy1036/AL-Assets-RE/wiki) |
| IFF files | [IFF files format](https://github.com/Galaxy1036/AL-Assets-RE/wiki) |
| Others files | [Others files formats](https://github.com/Galaxy1036/AL-Assets-RE/wiki) |

## Scripts list
- `geometry_extractor.py`: allow you to extract 3d models from .geo files
- `image_atlas_extractor.py`: allow you to extract sprites from image atlas
- `pvr2png.py`: allow you to extract textures as .png files from .pvr files. **Note:** The script isn't 100% done, it currently only support a few pixel types (enough to support all games textures tho) & extracting textures as .png can also be done via PVRTexTool

## About the reverse engineering
I'm not gonna detail how i reversed thoses assets format. For static reverse engineering i used IDA to look at the compiled library. About dynamic reverse engineering i used [Frida](https://frida.re/), scripts used can be found in the `dev_scripts` folder

## Contact me
Do you have any questions or bugs to report? Feel free to contact me at @GaLaXy1036#1601 on Discord!

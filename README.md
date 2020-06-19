# AL-Assets-RE
 An attempt to reverse engine assets used by Arcane Legends Mobile & Browser MMORPG game

## Information
The game actually use a custom .pak format as files archive. Use `al_pak_extractor.py` to extract files from thoses archives.

**Notice**: You can grab the main .pak in the game apk, the pak is named `android000.png`. Additional .pak can be grabbed out of your device cache if you are rooted.

Once extracted you may notice than approximatively 90-95 % use a custom format. In fact Arcane Legends use IFF format based on form & chunk of data. You can easily get an overview of the IFF structure by using `iff_parser_cli.py`. To directly deal with the forms & chunks in your code just use the `iff_lib.py` methods

## Files

### Geo files
.geo files are files that contains the models used by the game, you can find them in the `geometry` folder extracted from .pak. To extract models use `geometry_extractor.py`
 

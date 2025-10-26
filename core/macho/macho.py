from core.constants import MAGIC_64, MAGIC_FAT


# todo integrate LIEF here

def is_macho_file(file_path):
    with open(file_path, 'rb') as f:
        magic = int.from_bytes(f.read(4))
        return magic in MAGIC_64 or magic in MAGIC_FAT

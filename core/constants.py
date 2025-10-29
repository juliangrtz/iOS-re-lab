VERSION = "1.1"

# https://opensource.apple.com/source/cctools/cctools-795/include/mach-o/loader.h
# MAGIC_32 = [0xFEEDFACE, 0xCEFAEDFE]
MAGIC_64 = [0xFEEDFACF, 0xCFFAEDFE]
MAGIC_FAT = [0xBEBAFECA, 0xCAFEBABE]


from struct import pack

class Uint8:
    """
    an unsigned byte
    """
    def __init__(self, value):
        self.value = value

    def __repr__(self):
        return "{}(0x{:0{width}x})" \
               .format(self.__class__.__name__, self.value, width=len(self)*2)

    def __len__(self):
        return 1

    def to_bytes(self):
        return pack('>B', self.value)

class Uint16(Uint8):
    """
    uint8 uint24[3];
    """
    def __len__(self):
        return 2

    def to_bytes(self):
        return pack('>H', self.value)

class Uint24(Uint8):
    """
    uint8 uint24[3];
    """
    def __len__(self):
        return 3

    def to_bytes(self):
        return pack('>BH', self.value >> 16, self.value & 0xffff)

class Uint32(Uint8):
    """
    uint8 uint32[4];
    """
    def __len__(self):
        return 4

    def to_bytes(self):
        return pack('>I', self.value)

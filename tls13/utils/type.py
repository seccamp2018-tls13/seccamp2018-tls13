
from struct import pack

class Uint8:
    """
    an unsigned byte
    """
    def __init__(self, value):
        assert type(value) is int
        self.value = value

    def __repr__(self):
        return "{}(0x{:0{width}x})" \
               .format(self.__class__.__name__, self.value, width=len(self)*2)

    def __len__(self):
        return 1

    # HACK: __eq__ メソッドを実装すると，辞書使用時の型エラーの
    #       「TypeError: unhashable type: Uint8」
    #       が発生するので，__hash__ メソッドを作ってエラーを回避する．
    #       より厳密に書く場合は，self.value を書き換え不可能（immutable）にする必要がある．
    #       https://stackoverflow.com/questions/4996815/ways-to-make-a-class-immutable-in-python
    def __hash__(self):
        return hash((self.value,))

    def __eq__(self, other):
        return self.value == other.value

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

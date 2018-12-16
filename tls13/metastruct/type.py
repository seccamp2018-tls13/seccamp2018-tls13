
__all__ = ['Uint', 'Uint8', 'Uint16', 'Uint24', 'Uint32', 'Type']

from struct import pack

class Uint:
    def __init__(self, value):
        assert type(value) is int
        assert self.__class__ != Uint  # Uint is abstract class
        self.value = value

    def __repr__(self):
        return "{}(0x{:0{width}x})" \
               .format(self.__class__.__name__, self.value, width=len(self)*2)

    def __len__(self):
        return self.__class__._size

    def __int__(self):
        return self.value

    def __hash__(self):
        return hash((self.value,)) # 辞書型の値はイミュータブルにしないといけない

    def __eq__(self, other):
        return hasattr(other, 'value') and self.value == other.value

    @staticmethod
    def size(size):
        return Uint.get_type(size)

    @staticmethod
    def get_type(size):
        if size == 1: return Uint8
        if size == 2: return Uint16
        if size == 3: return Uint24
        if size == 4: return Uint32
        raise NotImplementedError()


class Uint8(Uint):
    """an unsigned byte"""
    _size = 1
    def to_bytes(self):
        return pack('>B', self.value)


class Uint16(Uint):
    """ uint8 uint24[2]; """
    _size = 2
    def to_bytes(self):
        return pack('>H', self.value)


class Uint24(Uint):
    """ uint8 uint24[3]; """
    _size = 3
    def to_bytes(self):
        return pack('>BH', self.value >> 16, self.value & 0xffff)


class Uint32(Uint):
    """ uint8 uint32[4]; """
    _size = 4
    def to_bytes(self):
        return pack('>I', self.value)


class Type:
    # 全てのTLSの定数群（enum）はTypeクラスを継承する。
    #
    # このクラスはTLSで使われる定数群に label() と values() というメソッドを追加する。
    # 例えば HandshakeType に label() が追加されると次のように定数から定数名を取得できる。
    #     HandshakeType.label(Uint16(1)) # => 'client_hello'
    # また、 HandshakeType に values() が追加されると次のように
    # ある値が定数群の中に含まれているか確認することができる。
    #     self.msg_type in HandshakeType.values() # => True or False

    @classmethod
    def label(cls, value):
        if not hasattr(cls, '_labels'):
            cls._labels = dict((v,k) for k,v in cls.__dict__.items()
                                     if not k.startswith('_'))
        return cls._labels[value]

    @classmethod
    def values(cls):
        if not hasattr(cls, '_values'):
            UintN = Uint.get_type(cls._size)
            cls._values = set(v for k,v in cls.__dict__.items()
                                if type(v) == UintN)
        return cls._values

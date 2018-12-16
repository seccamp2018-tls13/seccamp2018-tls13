
__all__ = ['Reader', 'Writer']

from typing import List

from .type import Uint, Type


class ReaderParseError(Exception):
    pass


class Reader:
    """
    Byte string reader
    """
    def __init__(self, data):
        self.bytes = data
        self.index = 0

    def get(self, type, length_t=None) -> int or Uint:
        from .metastruct import Listof, Struct

        if isinstance(type, int):
            return self.get_int(type)

        if isinstance(type, Listof):
            elem_len = type.subtype._size
            length_len = length_t._size
            fun = lambda x: x
            # Listof(Type) のときはリストの要素を UintN に変換する
            if issubclass(type.subtype, (Uint, Type)):
                fun = Uint.get_type(type.subtype._size)
            return [fun(x) for x in self.get_var_list(elem_len, length_len)]

        if issubclass(type, Uint):
            return self.get_uint(type)

        if issubclass(type, (bytes, Struct)):
            if hasattr(type, '_size'):
                return self.get_fix_bytes(type._size)
            if length_t:
                return self.get_var_bytes(length_t._size)
            return self.get_rest()

        raise NotImplementedError()

    def get_int(self, length) -> int:
        """
        Read a single big-endian integer value in 'length' bytes.
        """
        if self.index + length > len(self.bytes):
            raise ReaderParseError()
        x = 0
        for _ in range(length):
            x <<= 8
            x |= self.bytes[self.index]
            self.index += 1
        return x

    def get_uint(self, uint) -> Uint:
        length = uint._size
        x = self.get_int(length)
        return uint(x)

    def get_fix_bytes(self, bytes_length) -> bytearray:
        """
        Read a string of bytes encoded in 'bytes_length' bytes.
        """
        if self.index + bytes_length > len(self.bytes):
            raise ReaderParseError()
        bytes = self.bytes[self.index : self.index+bytes_length]
        self.index += bytes_length
        return bytes

    def get_var_bytes(self, length_length) -> bytearray:
        """
        Read a variable length string with a fixed length.
        """
        bytes_length = self.get(length_length)
        return self.get_fix_bytes(bytes_length)

    def get_fix_list(self, elem_length, list_length) -> List[int]:
        """
        Read a list of static length with same-sized ints.
        """
        l = [0] * list_length
        for x in range(list_length):
            l[x] = self.get(elem_length)
        return l

    def get_var_list(self, elem_length, length_length) -> List[int]:
        """
        Read a variable length list of same-sized integers.
        """
        list_length = self.get(length_length)
        if list_length % elem_length != 0:
            raise SyntaxError()
        list_length = list_length // elem_length
        l = [0] * list_length
        for x in range(list_length):
            l[x] = self.get(elem_length)
        return l

    def get_uint_var_list(self, elem, length_length):
        uint = elem
        elem_length = uint._size
        assert issubclass(uint, Uint)
        return [uint(x) for x in self.get_var_list(elem_length, length_length)]

    def get_rest(self):
        """
        Read a rest of the data.
        """
        rest_bytes = self.bytes[self.index:]
        self.index = len(self.bytes)
        return rest_bytes

    def get_rest_length(self):
        return len(self.bytes) - self.index



class Writer:
    """
    Byte string writer
    """
    def __init__(self):
        self.bytes = bytearray(0)

    def _get_bytes(self, obj):
        if hasattr(obj, 'to_bytes') and callable(obj.to_bytes):
            return obj.to_bytes()
        else:
            return obj

    def add_bytes(self, obj, length_t=None):
        """
        バイト列をバッファに追加するメソッド．
        バッファは self.bytes のことを指す．
        引数 obj に .to_bytes() メソッドがあれば，それを呼び出してバイト列に変換してから追加する．
        引数 length_t は長さの型を表す．Uint8, Uint16 などの型が与えられたときは，
        バイト列の長さを求めて Uint16 なら2byteのバイト列にし，それをバイト列の前に追加する．

        例えば，追加するバイト列が b'abcdef' で，長さの型が Uint16 のとき，
        最終的に追加されるバイト列は次のようになる．
            b'\x00\x06abcdef'
        """
        if length_t:
            self.bytes += length_t(len(obj)).to_bytes()
        self.bytes += self._get_bytes(obj)

    def add_list(self, a_list, length_t):
        """
        リストをバッファに追加するメソッド．
        バッファは self.bytes のことを指す．
        リストの要素は全て .to_bytes() メソッドを持っていることを前提とする．
        引数 length_t は長さの型を表す．Uint8, Uint16 などの型が与えられたときは，
        バイト列の長さを求めて Uint16 なら2byteのバイト列にし，それをバイト列の前に追加する．

        例えば，追加するリストが [Uint16(0x0304), Uint16(0x0303), Uint16(0x0302)] で，
        長さの型が Uint16 のとき，最終的に追加されるバイト列は次のようになる．
            b'\x00\x06\x03\x04\x03\x03\x03\x02'
        """
        self.bytes += length_t(sum(map(len, a_list))).to_bytes()
        self.bytes += b''.join(x.to_bytes() for x in a_list)

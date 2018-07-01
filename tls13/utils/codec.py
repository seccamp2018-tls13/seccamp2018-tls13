
from typing import List

class Reader:
    def __init__(self, data):
        self.bytes = data
        self.index = 0

    def get(self, length) -> int:
        """
        Read a single big-endian integer value in 'length' bytes.
        """
        if self.index + length > len(self.bytes):
            raise RuntimeError()
        x = 0
        for _ in range(length):
            x <<= 8
            x |= self.bytes[self.index]
            self.index += 1
        return x

    def get_fix_bytes(self, bytes_length) -> bytearray:
        """
        Read a string of bytes encoded in 'bytes_length' bytes.
        """
        if self.index + bytes_length > len(self.bytes):
            raise RuntimeError()
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

    def get_rest(self):
        """
        Read a rest of the data.
        """
        rest_bytes = self.bytes[self.index:]
        self.index = len(self.bytes)
        return rest_bytes

    def get_rest_length(self):
        return len(self.bytes) - self.index

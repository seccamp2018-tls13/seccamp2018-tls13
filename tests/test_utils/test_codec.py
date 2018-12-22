
import unittest

from tls13.metastruct.codec import Reader
from tls13.metastruct.type import *

class ReaderTest(unittest.TestCase):

    def test_get(self):
        data = bytearray.fromhex('deadbeef' * 3)
        reader = Reader(data)
        self.assertTrue(isinstance(reader.get(1), int))
        self.assertTrue(isinstance(reader.get(4), int))
        self.assertTrue(isinstance(reader.get(Uint8), Uint))
        self.assertTrue(isinstance(reader.get(Uint32), Uint))

    def test_get_int(self):
        data = bytearray.fromhex('deadbeef')
        reader = Reader(data)
        self.assertEqual(0xde, reader.get_int(1))
        self.assertEqual(0xad, reader.get_int(1))
        self.assertEqual(0xbeef, reader.get_int(2))
        self.assertRaises(Exception, lambda: reader.get_int(1))

    def test_get_uint(self):
        data = bytearray.fromhex('deadbeef')
        reader = Reader(data)
        self.assertEqual(Uint8(0xde), reader.get_uint(Uint8))
        self.assertEqual(Uint8(0xad), reader.get_uint(Uint8))
        self.assertEqual(Uint16(0xbeef), reader.get_uint(Uint16))
        self.assertRaises(Exception, lambda: reader.get_uint(Uint8))

    def test_get_fix_bytes(self):
        data = bytearray.fromhex('deadbeef')
        reader = Reader(data)
        self.assertEqual(b'\xde\xad', reader.get_fix_bytes(2))
        self.assertEqual(b'\xbe\xef', reader.get_fix_bytes(2))
        self.assertRaises(Exception, lambda: reader.get_fix_bytes(1))

    def test_get_var_bytes(self):
        data = bytearray.fromhex('04deadbeef02cafe')
        reader = Reader(data)
        self.assertEqual(b'\xde\xad\xbe\xef', reader.get_var_bytes(1))
        self.assertEqual(b'\xca\xfe', reader.get_var_bytes(1))
        self.assertRaises(Exception, lambda: reader.get_var_bytes(1))

    def test_get_var_bytes__1byte(self):
        data = bytearray.fromhex('04deadbeef00000000')
        reader = Reader(data)
        self.assertEqual(b'\xde\xad\xbe\xef', reader.get_var_bytes(1))

    def test_get_var_bytes__2bytes(self):
        data = bytearray.fromhex('0004deadbeef00000000')
        reader = Reader(data)
        self.assertEqual(b'\xde\xad\xbe\xef', reader.get_var_bytes(2))

    def test_get_fix_list__elem_length_1byte(self):
        data = bytearray.fromhex('000300050007000b')
        reader = Reader(data)
        self.assertEqual(
            [0x00, 0x03, 0x00, 0x05, 0x00, 0x07, 0x00, 0x0b],
            reader.get_fix_list(elem_length=1, list_length=8))

    def test_get_fix_list__elem_length_2bytes(self):
        data = bytearray.fromhex('000300050007000b')
        reader = Reader(data)
        self.assertEqual(
            [0x0003, 0x0005, 0x0007, 0x000b],
            reader.get_fix_list(elem_length=2, list_length=4))

    def test_get_var_list__length_length_1byte(self):
        data = bytearray.fromhex('08000300050007000b')
        reader = Reader(data)
        self.assertEqual(
            [0x0003, 0x0005, 0x0007, 0x000b],
            reader.get_var_list(elem_length=2, length_length=1))

    def test_get_var_list__length_length_2byte(self):
        data = bytearray.fromhex('0008000300050007000b')
        reader = Reader(data)
        self.assertEqual(
            [0x0003, 0x0005, 0x0007, 0x000b],
            reader.get_var_list(elem_length=2, length_length=2))

    def test_get_uint_var_list(self):
        data = bytearray.fromhex('08000300050007000b')
        reader = Reader(data)
        self.assertEqual(
            [Uint16(0x0003), Uint16(0x0005), Uint16(0x0007), Uint16(0x000b)],
            reader.get_uint_var_list(elem=Uint16, length_length=1))

    def test_get_rest(self):
        reader = Reader(bytearray.fromhex('deadbeef'))
        self.assertEqual(b'\xde\xad\xbe\xef', reader.get_rest())

        reader = Reader(bytearray.fromhex('deadbeef'))
        reader.get(3)
        self.assertEqual(b'\xef', reader.get_rest())

    def test_get_rest_length(self):
        reader = Reader(bytearray.fromhex('deadbeef'))
        self.assertEqual(4, reader.get_rest_length())

        reader.get(3)
        self.assertEqual(1, reader.get_rest_length())

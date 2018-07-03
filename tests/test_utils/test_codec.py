
import unittest

from tls13.utils.codec import Reader

class ReaderTest(unittest.TestCase):

    def test_get(self):
        data = bytearray.fromhex('deadbeef')
        reader = Reader(data)
        self.assertEqual(0xde, reader.get(1))
        self.assertEqual(0xad, reader.get(1))
        self.assertEqual(0xbeef, reader.get(2))
        self.assertRaises(Exception, lambda: reader.get(1))

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

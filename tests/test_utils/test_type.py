
import unittest

from tls13.utils.type import Uint8, Uint16, Uint24, Uint32


class Uint8Test(unittest.TestCase):

    def test_to_bytes(self):
        self.assertEqual(b'\x00', Uint8(0).to_bytes())
        self.assertEqual(b'\x1d', Uint8(29).to_bytes())
        self.assertEqual(b'\xff', Uint8(255).to_bytes())
        self.assertRaises(Exception, lambda: Uint8(256).to_bytes())
        self.assertRaises(Exception, lambda: Uint8(-1).to_bytes())


class Uint16Test(unittest.TestCase):

    def test_to_bytes(self):
        self.assertEqual(b'\x00\x1d', Uint16(29).to_bytes())
        self.assertEqual(b'\xff\xff', Uint16(2**16 - 1).to_bytes())
        self.assertRaises(Exception, lambda: Uint16(2**16).to_bytes())
        self.assertRaises(Exception, lambda: Uint16(-1).to_bytes())


class Uint24Test(unittest.TestCase):

    def test_to_bytes(self):
        self.assertEqual(b'\x00\x00\x1d', Uint24(29).to_bytes())
        self.assertEqual(b'\xff\xff\xff', Uint24(2**24 - 1).to_bytes())
        self.assertRaises(Exception, lambda: Uint24(2**24).to_bytes())
        self.assertRaises(Exception, lambda: Uint24(-1).to_bytes())


class Uint32Test(unittest.TestCase):

    def test_to_bytes(self):
        self.assertEqual(b'\x00\x00\x00\x1d', Uint32(29).to_bytes())
        self.assertEqual(b'\xff\xff\xff\xff', Uint32(2**32 - 1).to_bytes())
        self.assertRaises(Exception, lambda: Uint32(2**32).to_bytes())
        self.assertRaises(Exception, lambda: Uint32(-1).to_bytes())

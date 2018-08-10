
import unittest
import binascii

from tls13.utils.encryption.Cipher import RC4

class RC4Test(unittest.TestCase):

    def setUp(self):
        self.plain = b"The quick brown fox jumps over the lazy dog"
        self.plain2 = b"The quick brown fox jumps over the lazy dog"[::-1]
        self.key = binascii.unhexlify(
            '4cb0aa43afc90d99919b0cad160a26fe976285570d0eefea3884cca9a5366705')
        self.key2 = binascii.unhexlify(
            '200731a6dea4df66c7c6ffbef7e495c84d4c08f6e3c85be1e37c87d26de077c4')

    def test_enc_dec(self):
        rc4 = RC4(self.key)
        enc = rc4.encrypt(self.plain)
        dec = rc4.decrypt(enc)
        self.assertEqual(self.plain, dec) 

    def test_enc_dec__diff_keys(self):
        rc4_1 = RC4(self.key)
        rc4_2 = RC4(self.key2)
        enc = rc4_1.encrypt(self.plain)
        dec = rc4_2.decrypt(enc)
        self.assertNotEqual(self.plain, dec)

    def test_mac(self):
        rc4 = RC4(self.key)
        enc, mac = rc4.encrypt_with_mac(self.plain)
        enc2, mac2 = rc4.encrypt_with_mac(self.plain2)
        self.assertNotEqual(enc, enc2)
        self.assertNotEqual(mac, mac2)

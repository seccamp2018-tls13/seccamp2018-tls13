
import unittest
import binascii

from tls13.utils.encryption.Cipher import Chacha20Poly1305

class Chacha20Poly1305Test(unittest.TestCase):

    def setUp(self):
        self.plain = (b"The quick brown fox jumps over the lazy dog"*2)[:64]
        # chacha20.encrypt内でのpaddingをやめたので強制的に64bytes長へ
        self.key = binascii.unhexlify(
            '4cb0aa43afc90d99919b0cad160a26fe976285570d0eefea3884cca9a5366705')
        self.key2 = binascii.unhexlify(
            '200731a6dea4df66c7c6ffbef7e495c84d4c08f6e3c85be1e37c87d26de077c4')
        self.nonce = binascii.unhexlify(
            '1b1589a4aa99de2b51267ad8bee329d3eb672e88bda24b31f29ad8405dfe2e1c')
        self.nonce2 = binascii.unhexlify(
            '5c2bd761df1669f08b26ddb6ef7139e09e898d48593591da89d0357095de0e5c')
        self.auth_data = binascii.unhexlify(
            'd761d8b26ddb629ad8405ef713e09e89e4584d4c08f6e3c850b2f29ad8405976')
        self.auth_data2 = binascii.unhexlify(
            '26cb24b3db2329df29ad0d0eedeadbeef7dda2c850b2f59ef715126789a4efea')

    def test_enc_dec(self):
        polychacha = Chacha20Poly1305(self.key, self.nonce)
        enc = polychacha.encrypt(self.plain)
        dec = polychacha.decrypt(enc)
        self.assertEqual(self.plain, dec)

    def test_enc_dec__diff_keys(self):
        polychacha = Chacha20Poly1305(self.key, self.nonce)
        polychacha2 = Chacha20Poly1305(self.key2, self.nonce)
        enc = polychacha.encrypt(self.plain)
        dec = polychacha2.decrypt(enc)
        self.assertNotEqual(self.plain, dec)

    def test_enc_dec__diff_nonce(self):
        polychacha = Chacha20Poly1305(self.key, self.nonce)
        polychacha2 = Chacha20Poly1305(self.key, self.nonce2)
        enc = polychacha.encrypt(self.plain)
        dec = polychacha2.decrypt(enc)
        self.assertNotEqual(self.plain, dec)

    def test_aead(self):
        polychacha = Chacha20Poly1305(self.key, self.nonce)
        enc, tag = polychacha.chacha20_aead_encrypt(self.auth_data, self.plain)
        enc2, tag2 = polychacha.chacha20_aead_encrypt(self.auth_data2, self.plain)
        self.assertEqual(enc, enc2)
        self.assertNotEqual(tag, tag2)

    def test_aead_enc_dec(self):
        polychacha = Chacha20Poly1305(self.key, self.nonce)
        ciphertext = polychacha.aead_encrypt(self.auth_data, self.plain)
        plaintext = polychacha.aead_decrypt(self.auth_data, ciphertext)
        self.assertEqual(self.plain, plaintext)

    def test_aead_enc_dec__diff_auth(self):
        polychacha = Chacha20Poly1305(self.key, self.nonce)
        ciphertext = polychacha.aead_encrypt(self.auth_data, self.plain)
        plaintext = polychacha.aead_decrypt(self.auth_data2, ciphertext)
        self.assertTrue(plaintext is None)

    def test_idempotence(self):
        import os
        m = os.urandom(64*2)
        polychacha = Chacha20Poly1305(self.key, self.nonce)
        c = polychacha.aead_encrypt(self.auth_data, m)
        self.assertEqual(m, 
                polychacha.aead_decrypt(self.auth_data, c))
        self.assertEqual(m, 
                polychacha.aead_decrypt(self.auth_data, 
                    polychacha.aead_encrypt(self.auth_data, m)))

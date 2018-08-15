
import unittest
import binascii

from tls13.utils.encryption.Cipher import Chacha20Poly1305, make_array
from tls13.utils.encryption.chacha20poly1305 import chacha20

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

    def test_chacha20_block_function(self):
        key = binascii.unhexlify(
            '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f')
        nonce = binascii.unhexlify(
            '000000090000004a00000000')

        key   = make_array(key, 4, to_int=True)
        nonce = make_array(nonce, 4, to_int=True)

        plain_blocks = [0x0] * 16

        c, state = chacha20(plain_blocks, key, nonce, cnt=1)

        expected = [
            0xe4e7f110, 0x15593bd1, 0x1fdd0f50, 0xc47120a3,
            0xc7f4d1c7, 0x0368c033, 0x9aaa2204, 0x4e6cd4c3,
            0x466482d2, 0x09aa9f07, 0x05d7c214, 0xa2028bd9,
            0xd19c12b5, 0xb94e16de, 0xe883d0cb, 0x4e3c50a2,
        ]
        actual = state
        self.assertEqual(expected, actual)

    # https://tools.ietf.org/html/rfc7539#section-2.5.2
    def test_poly1305(self):
        key = binascii.unhexlify(
            '85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b')
        s = int('0103808afb0db2fd4abff6af4149f51b', 16)
        r = int('85d6be7857556d337f4452fe42d506a8', 16)
        message = b'Cryptographic Forum Research Group'

        expected_tag = binascii.unhexlify('a8061dc1305136c6c22b8baf0c0127a9')

        polychacha = Chacha20Poly1305(key, self.nonce)
        tag = polychacha.poly1305_mac(message, (s,r))

        self.assertEqual(expected_tag, tag)

    # https://tools.ietf.org/html/rfc7539#section-2.6.2
    def test_vector_for_POLY1305_key_generation(self):
        key = binascii.unhexlify(
            '808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f')
        nonce = binascii.unhexlify(
            '000000000001020304050607')
        polychacha = Chacha20Poly1305(key, nonce)

        s, r = polychacha.poly1305_key_gen()
        expected_r = 0x8ad5a08b905f81cc815040274ab29471
        expected_s = 0xa833b637e3fd0da508dbb8e2fdd1a646
        self.assertEqual(r, expected_r)
        self.assertEqual(s, expected_s)

    # https://tools.ietf.org/html/rfc7539#section-2.8.2
    def test_Vector_for_AEAD_CHACHA20_POLY1305(self):
        plaintext = \
        b'Ladies and Gentl' + \
        b'emen of the clas' + \
        b"s of '99: If I c" + \
        b'ould offer you o' + \
        b'nly one tip for ' + \
        b'the future, suns' + \
        b'creen would be i' + \
        b't.'
        aad = binascii.unhexlify('50515253c0c1c2c3c4c5c6c7')
        key = binascii.unhexlify(''.join('''
            80 81 82 83 84 85 86 87 88 89 8a 8b 8c 8d 8e 8f
            90 91 92 93 94 95 96 97 98 99 9a 9b 9c 9d 9e 9f
        '''.split()))
        nonce = binascii.unhexlify('070000004041424344454647')
        
        polychacha = Chacha20Poly1305(key, nonce)
        s, r = polychacha.poly1305_key_gen()
        self.assertEqual(r, 0x7bac2b252db447af09b67a55a4e95584)
        self.assertEqual(s, 0x0ae1d6731075d9eb2a9375783ed553ff)

        c = polychacha.encrypt(plaintext + bytearray(64 - len(plaintext) % 64))

        expected_c = binascii.unhexlify("".join("""
            d3 1a 8d 34 64 8e 60 db 7b 86 af bc 53 ef 7e c2
            a4 ad ed 51 29 6e 08 fe a9 e2 b5 a7 36 ee 62 d6
            3d be a4 5e 8c a9 67 12 82 fa fb 69 da 92 72 8b
            1a 71 de 0a 9e 06 0b 29 05 d6 a5 b6 7e cd 3b 36
            92 dd bd 7f 2d 77 8b 8c 98 03 ae e3 28 09 1b 58 
            fa b3 24 e4 fa d6 75 94 55 85 80 8b 48 31 d7 bc
            3f f4 de f0 8e 4b 7a 9d e5 76 d2 65 86 ce c6 4b
            61 16
        """.split()))
        self.assertEqual(c[:len(plaintext)], expected_c[:len(plaintext)])
        

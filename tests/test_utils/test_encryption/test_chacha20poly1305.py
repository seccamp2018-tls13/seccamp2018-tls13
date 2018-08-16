
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
        nonce = make_array(self.nonce, 4, to_int=True)
        enc = polychacha.encrypt(self.plain, nonce)
        dec = polychacha.decrypt(enc, nonce)
        self.assertEqual(self.plain, dec)

    def test_enc_dec__diff_keys(self):
        polychacha = Chacha20Poly1305(self.key, self.nonce)
        polychacha2 = Chacha20Poly1305(self.key2, self.nonce)
        nonce = make_array(self.nonce, 4, to_int=True)
        nonce2 = make_array(self.nonce2, 4, to_int=True)
        enc = polychacha.encrypt(self.plain, nonce)
        dec = polychacha2.decrypt(enc, nonce2)
        self.assertNotEqual(self.plain, dec)

    def test_enc_dec__diff_nonce(self):
        polychacha = Chacha20Poly1305(self.key, self.nonce)
        polychacha2 = Chacha20Poly1305(self.key, self.nonce2)
        nonce = make_array(self.nonce, 4, to_int=True)
        nonce2 = make_array(self.nonce2, 4, to_int=True)
        enc = polychacha.encrypt(self.plain, nonce)
        dec = polychacha2.decrypt(enc, nonce2)
        self.assertNotEqual(self.plain, dec)

    def test_aead(self):
        polychacha = Chacha20Poly1305(self.key, self.nonce)
        nonce = make_array(self.nonce, 4, to_int=True)
        enc, tag = polychacha.chacha20_aead_encrypt(self.auth_data, self.plain, nonce)
        enc2, tag2 = polychacha.chacha20_aead_encrypt(self.auth_data2, self.plain, nonce)
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
    def test_vector_for_POLY1305_key_generation1(self):
        key = binascii.unhexlify(
            '808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f')
        nonce = binascii.unhexlify(
            '000000000001020304050607')
        polychacha = Chacha20Poly1305(key, nonce)

        s, r = polychacha.poly1305_key_gen(make_array(nonce, 4, to_int=True))
        expected_r = 0x8ad5a08b905f81cc815040274ab29471
        expected_s = 0xa833b637e3fd0da508dbb8e2fdd1a646
        self.assertEqual(r, expected_r)
        self.assertEqual(s, expected_s)

    # https://tools.ietf.org/html/rfc7539#appendix-A.4
    def test_vector_for_POLY1305_key_generation2(self):
        key = binascii.unhexlify(
            '00000000000000000000000000000000'*2)
        nonce = binascii.unhexlify(
            '000000000000000000000000')
        polychacha = Chacha20Poly1305(key, nonce)

        s, r = polychacha.poly1305_key_gen(make_array(nonce, 4, to_int=True))
        expected_r = 0x76b8e0ada0f13d90405d6ae55386bd28
        expected_s = 0xbdd219b8a08ded1aa836efcc8b770dc7

        self.assertEqual(s, expected_s)
        self.assertEqual(r, expected_r)

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
        nonce = make_array(nonce, 4, to_int=True)
        s, r = polychacha.poly1305_key_gen(nonce)
        self.assertEqual(r, 0x7bac2b252db447af09b67a55a4e95584)
        self.assertEqual(s, 0x0ae1d6731075d9eb2a9375783ed553ff)

        c = polychacha.encrypt(plaintext, nonce)

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

        self.assertEqual(len(c), len(expected_c))
        self.assertEqual(c, expected_c)
        
    # https://tools.ietf.org/html/rfc7539#section-2.4.2
    def test_vector_for_chacha20(self):
        plaintext = \
        b'Ladies and Gentl' + \
        b'emen of the clas' + \
        b"s of '99: If I c" + \
        b'ould offer you o' + \
        b'nly one tip for ' + \
        b'the future, suns' + \
        b'creen would be i' + \
        b't.'
 
        key = binascii.unhexlify(
            '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f')
        nonce = binascii.unhexlify(
            '000000000000004a00000000')

        polychacha = Chacha20Poly1305(key, nonce)
        nonce = make_array(nonce, 4, to_int=True)
        c = polychacha.encrypt(plaintext, nonce)

        expected_c = binascii.unhexlify(''.join("""
            6e 2e 35 9a 25 68 f9 80 41 ba 07 28 dd 0d 69 81
            e9 7e 7a ec 1d 43 60 c2 0a 27 af cc fd 9f ae 0b
            f9 1b 65 c5 52 47 33 ab 8f 59 3d ab cd 62 b3 57
            16 39 d6 24 e6 51 52 ab 8f 53 0c 35 9f 08 61 d8
            07 ca 0d bf 50 0d 6a 61 56 a3 8e 08 8a 22 b6 5e
            52 bc 51 4d 16 cc f8 06 81 8c e9 1a b7 79 37 36
            5a f9 0b bf 74 a3 5b e6 b4 0b 8e ed f2 78 5e 42
            87 4d
        """.split()))
        self.assertEqual(c, expected_c)

    # https://tools.ietf.org/html/rfc7539#appendix-A.3
    def test_vector_poly(self):
        otk = (0, 0)
        text = b'\x00'*64

        polychacha = Chacha20Poly1305(key=b'\x00'*32, nonce=b'\x00'*12)
        tag = polychacha.poly1305_mac(text, otk)
        self.assertEqual(tag, b'\x00')

    def test_vector_poly2(self):
        r = 0
        s = 0x36e5f6b5c5e06070f0efca96227a863e
        otk = (s, r)

        text = binascii.unhexlify(''.join("""
            41 6e 79 20 73 75 62 6d 69 73 73 69 6f 6e 20 74
            6f 20 74 68 65 20 49 45 54 46 20 69 6e 74 65 6e
            64 65 64 20 62 79 20 74 68 65 20 43 6f 6e 74 72
            69 62 75 74 6f 72 20 66 6f 72 20 70 75 62 6c 69
            63 61 74 69 6f 6e 20 61 73 20 61 6c 6c 20 6f 72
            20 70 61 72 74 20 6f 66 20 61 6e 20 49 45 54 46
            20 49 6e 74 65 72 6e 65 74 2d 44 72 61 66 74 20
            6f 72 20 52 46 43 20 61 6e 64 20 61 6e 79 20 73
            74 61 74 65 6d 65 6e 74 20 6d 61 64 65 20 77 69
            74 68 69 6e 20 74 68 65 20 63 6f 6e 74 65 78 74
            20 6f 66 20 61 6e 20 49 45 54 46 20 61 63 74 69
            76 69 74 79 20 69 73 20 63 6f 6e 73 69 64 65 72
            65 64 20 61 6e 20 22 49 45 54 46 20 43 6f 6e 74
            72 69 62 75 74 69 6f 6e 22 2e 20 53 75 63 68 20
            73 74 61 74 65 6d 65 6e 74 73 20 69 6e 63 6c 75
            64 65 20 6f 72 61 6c 20 73 74 61 74 65 6d 65 6e
            74 73 20 69 6e 20 49 45 54 46 20 73 65 73 73 69
            6f 6e 73 2c 20 61 73 20 77 65 6c 6c 20 61 73 20
            77 72 69 74 74 65 6e 20 61 6e 64 20 65 6c 65 63
            74 72 6f 6e 69 63 20 63 6f 6d 6d 75 6e 69 63 61
            74 69 6f 6e 73 20 6d 61 64 65 20 61 74 20 61 6e
            79 20 74 69 6d 65 20 6f 72 20 70 6c 61 63 65 2c
            20 77 68 69 63 68 20 61 72 65 20 61 64 64 72 65
            73 73 65 64 20 74 6f
        """.split()))

        polychacha = Chacha20Poly1305(key=b'\x00'*32, nonce=b'\x00'*12)
        tag = polychacha.poly1305_mac(text, otk)
        expected_tag = binascii.unhexlify(
            '36e5f6b5c5e06070f0efca96227a863e')
        self.assertEqual(tag, expected_tag)

    def test_vector_poly3(self):
        r = 0x36e5f6b5c5e06070f0efca96227a863e
        s = 0
        otk = (s, r)
        text = binascii.unhexlify(''.join("""
            41 6e 79 20 73 75 62 6d 69 73 73 69 6f 6e 20 74
            6f 20 74 68 65 20 49 45 54 46 20 69 6e 74 65 6e
            64 65 64 20 62 79 20 74 68 65 20 43 6f 6e 74 72
            69 62 75 74 6f 72 20 66 6f 72 20 70 75 62 6c 69
            63 61 74 69 6f 6e 20 61 73 20 61 6c 6c 20 6f 72
            20 70 61 72 74 20 6f 66 20 61 6e 20 49 45 54 46
            20 49 6e 74 65 72 6e 65 74 2d 44 72 61 66 74 20
            6f 72 20 52 46 43 20 61 6e 64 20 61 6e 79 20 73
            74 61 74 65 6d 65 6e 74 20 6d 61 64 65 20 77 69
            74 68 69 6e 20 74 68 65 20 63 6f 6e 74 65 78 74
            20 6f 66 20 61 6e 20 49 45 54 46 20 61 63 74 69
            76 69 74 79 20 69 73 20 63 6f 6e 73 69 64 65 72
            65 64 20 61 6e 20 22 49 45 54 46 20 43 6f 6e 74
            72 69 62 75 74 69 6f 6e 22 2e 20 53 75 63 68 20
            73 74 61 74 65 6d 65 6e 74 73 20 69 6e 63 6c 75
            64 65 20 6f 72 61 6c 20 73 74 61 74 65 6d 65 6e
            74 73 20 69 6e 20 49 45 54 46 20 73 65 73 73 69
            6f 6e 73 2c 20 61 73 20 77 65 6c 6c 20 61 73 20
            77 72 69 74 74 65 6e 20 61 6e 64 20 65 6c 65 63
            74 72 6f 6e 69 63 20 63 6f 6d 6d 75 6e 69 63 61
            74 69 6f 6e 73 20 6d 61 64 65 20 61 74 20 61 6e
            79 20 74 69 6d 65 20 6f 72 20 70 6c 61 63 65 2c
            20 77 68 69 63 68 20 61 72 65 20 61 64 64 72 65
            73 73 65 64 20 74 6f
        """.split()))

        polychacha = Chacha20Poly1305(key=b'\x00'*32, nonce=b'\x00'*12)
        tag = polychacha.poly1305_mac(text, otk)
        expected_tag = binascii.unhexlify(
            'f3477e7cd95417af89a6b8794c310cf0') 
        self.assertEqual(tag, expected_tag)

    def test_vector_poly4(self):
        r = 0x1c9240a5eb55d38af333888604f6b5f0
        s = 0x473917c1402b80099dca5cbc207075c0
        otk = (s, r)

        text = binascii.unhexlify(''.join("""
            27 54 77 61 73 20 62 72 69 6c 6c 69 67 2c 20 61
            6e 64 20 74 68 65 20 73 6c 69 74 68 79 20 74 6f
            76 65 73 0a 44 69 64 20 67 79 72 65 20 61 6e 64
            20 67 69 6d 62 6c 65 20 69 6e 20 74 68 65 20 77
            61 62 65 3a 0a 41 6c 6c 20 6d 69 6d 73 79 20 77
            65 72 65 20 74 68 65 20 62 6f 72 6f 67 6f 76 65
            73 2c 0a 41 6e 64 20 74 68 65 20 6d 6f 6d 65 20
            72 61 74 68 73 20 6f 75 74 67 72 61 62 65 2e
        """.split()))

        polychacha = Chacha20Poly1305(key=b'\x00'*32, nonce=b'\x00'*12)
        tag = polychacha.poly1305_mac(text, otk)
        expected_tag = binascii.unhexlify(
            '4541669a7eaaee61e708dc7cbcc5eb62') 
        self.assertEqual(tag, expected_tag)

    def test_chacha_poly_aead_final(self):
        key = binascii.unhexlify(''.join("""
        1c 92 40 a5 eb 55 d3 8a f3 33 88 86 04 f6 b5 f0
        47 39 17 c1 40 2b 80 09 9d ca 5c bc 20 70 75 c0
        """.split()))
        nonce = binascii.unhexlify(
            '000000000102030405060708')
        aad = binascii.unhexlify(
            'f33388860000000000004e91')

        polychacha = Chacha20Poly1305(key, nonce)
        s, r = polychacha.poly1305_key_gen(make_array(nonce, 4, to_int=True))
        otk = (s, r)

        self.assertEqual(r, 0xbdf04aa95ce4de8995b14bb6a18fecaf)
        self.assertEqual(s, 0x26478f50c054f563dbc0a21e261572aa)

        message = binascii.unhexlify(''.join("""
            f3 33 88 86 00 00 00 00 00 00 4e 91 00 00 00 00
            64 a0 86 15 75 86 1a f4 60 f0 62 c7 9b e6 43 bd
            5e 80 5c fd 34 5c f3 89 f1 08 67 0a c7 6c 8c b2
            4c 6c fc 18 75 5d 43 ee a0 9e e9 4e 38 2d 26 b0
            bd b7 b7 3c 32 1b 01 00 d4 f0 3b 7f 35 58 94 cf
            33 2f 83 0e 71 0b 97 ce 98 c8 a8 4a bd 0b 94 81
            14 ad 17 6e 00 8d 33 bd 60 f9 82 b1 ff 37 c8 55
            97 97 a0 6e f4 f0 ef 61 c1 86 32 4e 2b 35 06 38
            36 06 90 7b 6a 7c 02 b0 f9 f6 15 7b 53 c8 67 e4
            b9 16 6c 76 7b 80 4d 46 a5 9b 52 16 cd e7 a4 e9
            90 40 c5 a4 04 33 22 5e e2 82 a1 b0 a0 6c 52 3e
            af 45 34 d7 f8 3f a1 15 5b 00 47 71 8c bc 54 6a
            0d 07 2b 04 b3 56 4e ea 1b 42 22 73 f5 48 27 1a
            0b b2 31 60 53 fa 76 99 19 55 eb d6 31 59 43 4e
            ce bb 4e 46 6d ae 5a 10 73 a6 72 76 27 09 7a 10
            49 e6 17 d9 1d 36 10 94 fa 68 f0 ff 77 98 71 30
            30 5b ea ba 2e da 04 df 99 7b 71 4d 6c 6f 2c 29
            a6 ad 5c b4 02 2b 02 70 9b 00 00 00 00 00 00 00
            0c 00 00 00 00 00 00 00 09 01 00 00 00 00 00 00
        """.split()))
        tag = polychacha.poly1305_mac(message, otk) 
        expected_tag = binascii.unhexlify(
            'eead9d67890cbb22392336fea1851f38')
        self.assertEqual(tag, expected_tag)

        ciphertext = binascii.unhexlify(''.join("""
            64 a0 86 15 75 86 1a f4 60 f0 62 c7 9b e6 43 bd
            5e 80 5c fd 34 5c f3 89 f1 08 67 0a c7 6c 8c b2
            4c 6c fc 18 75 5d 43 ee a0 9e e9 4e 38 2d 26 b0
            bd b7 b7 3c 32 1b 01 00 d4 f0 3b 7f 35 58 94 cf
            33 2f 83 0e 71 0b 97 ce 98 c8 a8 4a bd 0b 94 81
            14 ad 17 6e 00 8d 33 bd 60 f9 82 b1 ff 37 c8 55
            97 97 a0 6e f4 f0 ef 61 c1 86 32 4e 2b 35 06 38
            36 06 90 7b 6a 7c 02 b0 f9 f6 15 7b 53 c8 67 e4
            b9 16 6c 76 7b 80 4d 46 a5 9b 52 16 cd e7 a4 e9
            90 40 c5 a4 04 33 22 5e e2 82 a1 b0 a0 6c 52 3e
            af 45 34 d7 f8 3f a1 15 5b 00 47 71 8c bc 54 6a
            0d 07 2b 04 b3 56 4e ea 1b 42 22 73 f5 48 27 1a
            0b b2 31 60 53 fa 76 99 19 55 eb d6 31 59 43 4e
            ce bb 4e 46 6d ae 5a 10 73 a6 72 76 27 09 7a 10
            49 e6 17 d9 1d 36 10 94 fa 68 f0 ff 77 98 71 30
            30 5b ea ba 2e da 04 df 99 7b 71 4d 6c 6f 2c 29
            a6 ad 5c b4 02 2b 02 70 9b
        """.split()))

        decrypt_text = polychacha.decrypt(ciphertext, make_array(nonce, 4, to_int=True))
        print("[*] DEC TEXT :", decrypt_text)

        expectd_plain = binascii.unhexlify(''.join("""
            49 6e 74 65 72 6e 65 74 2d 44 72 61 66 74 73 20
            61 72 65 20 64 72 61 66 74 20 64 6f 63 75 6d 65
            6e 74 73 20 76 61 6c 69 64 20 66 6f 72 20 61 20
            6d 61 78 69 6d 75 6d 20 6f 66 20 73 69 78 20 6d
            6f 6e 74 68 73 20 61 6e 64 20 6d 61 79 20 62 65
            20 75 70 64 61 74 65 64 2c 20 72 65 70 6c 61 63
            65 64 2c 20 6f 72 20 6f 62 73 6f 6c 65 74 65 64
            20 62 79 20 6f 74 68 65 72 20 64 6f 63 75 6d 65
            6e 74 73 20 61 74 20 61 6e 79 20 74 69 6d 65 2e
            20 49 74 20 69 73 20 69 6e 61 70 70 72 6f 70 72
            69 61 74 65 20 74 6f 20 75 73 65 20 49 6e 74 65
            72 6e 65 74 2d 44 72 61 66 74 73 20 61 73 20 72
            65 66 65 72 65 6e 63 65 20 6d 61 74 65 72 69 61
            6c 20 6f 72 20 74 6f 20 63 69 74 65 20 74 68 65
            6d 20 6f 74 68 65 72 20 74 68 61 6e 20 61 73 20
            2f e2 80 9c 77 6f 72 6b 20 69 6e 20 70 72 6f 67
            72 65 73 73 2e 2f e2 80 9d
        """.split()))
        self.assertEqual(decrypt_text, expectd_plain)

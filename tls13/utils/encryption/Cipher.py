import binascii
import hashlib
from .chacha20poly1305 import *

from Crypto.Util.number import bytes_to_long, long_to_bytes

## NOTE : 今後のためにファイル分けとかも考えた方が良さそう?
##          chacha20poly1305だけならまだ大丈夫かも

## NOTE : Cipherを継承したそれぞれのアルゴリズムでの
##        AEAD(MAC)の生成関数の名前を統一した方が良さそう

def make_array(text, n_bytes=16, to_int=False):
    if to_int:
        return [bytes_to_long(text[i:i+n_bytes]) for i in range(0, len(text), n_bytes)]
    else:
        return [text[i:i+n_bytes] for i in range(0, len(text), n_bytes)]

def concatenate_bytes(array:list) -> bytes:
    con_bytes = b"".join(map(long_to_bytes, array))
    return con_bytes

class Cipher:
    
    def __init__(self, key):
        self.key = key
        # self.key_size 

    def encrypt(self, plaintext):
        assert len(plaintext) % 16 == 0
        raise ValueError("Input strings must be a multiple of 16 in length")

        # ENCRYPTO()

    def decrypt(self, ciphertext):
        assert len(ciphertext) % 16 == 0
        raise ValueError("Input strings must be a multiple of 16 in length")

        # DECRYPTO()


class Chacha20Poly1305(Cipher):
    key_size = 32
    nonce_size = 12
    # keyとnonceをHKDFで生成するときに
    # HKDF_expand_label(Master Secret, b"key", b"", Chacha20Poly1305.key_size)
    # のようにできるようにしておく

    def __init__(self, key, nonce):
        #super(Chacha20Poly1305, self).__init__(key)
        self.key = make_array(key, 4, to_int=True)      # 32 [bytes] = 4 [bytes] * 8 [block]
        self.nonce = make_array(nonce, 4, to_int=True)  # 12 [bytes] = 4 [bytes] * 3 [block]

    def encrypt(self, plaintext):
        if len(plaintext) % 64 != 0:
            plaintext = plaintext + bytearray(64 - len(plaintext) % 64)

        array64s = make_array(plaintext, 64, to_int=False)

        cipher = bytearray(0)
        for cnt, array64 in enumerate(array64s, 1):
            plain_blocks = []
            for block in make_array(array64 , 4, to_int=True):
                plain_blocks.append(block)

            c, state = chacha20(plain_blocks, self.key, self.nonce, cnt=cnt)
            for _c in c:
                hex_c = hex(_c)[2:]
                if len(hex_c) != 8:
                    hex_c = '0' * (8-len(hex_c)) + hex_c
                dt = binascii.unhexlify(hex_c)
                cipher += dt

        return cipher

    def decrypt(self, ciphertext):
        if len(ciphertext) % 64 != 0:
            raise ValueError("Input strings must be a multipul of 64 in length")

        array64s = make_array(ciphertext, 64, to_int=False)

        plain = bytearray(0)
        for cnt, array64 in enumerate(array64s, 1):
            cipher_blocks = []
            for block in make_array(array64 , 4, to_int=True):
                cipher_blocks.append(block)

            c, state = chacha20(cipher_blocks, self.key, self.nonce, cnt=cnt)
            for _c in c:
                hex_c = hex(_c)[2:]
                if len(hex_c) != 8:
                    hex_c = '0' * (8-len(hex_c)) + hex_c
                dt = binascii.unhexlify(hex_c)
                plain += dt

        plain = plain.rstrip(b'\x00') # remove \x00 padding
        return  plain

    def poly1305_mac(self, message, otk):
        s, r = otk

        if len(message) % 16 != 0:
            message += bytearray(16 - len(message) % 16)

        # 16 [bytes] に区切って 1 [byte] (\x01) を付加
        coefs_messages = make_array(message, 16, to_int=False)
        for idx in range(len(coefs_messages)):
            coefs_messages[idx] += b'\x01'

        coefs_messages = list(map(bytes_to_long, coefs_messages))
        auth = poly1305(coefs_messages, s, r)
        return long_to_bytes(auth)

    def poly1305_key_gen(self):
        _, state = chacha20(b"\x00"*16, self.key, self.nonce, cnt=0)
        least16bytes = state[8:]
        s = least16bytes[:4]
        r = least16bytes[4:]

        concate_s = concatenate_bytes(s)
        concate_r = concatenate_bytes(r)

        s = bytes_to_long(concate_s)
        r = bytes_to_long(concate_r)

        return s, r

    def chacha20_aead_encrypt(self, aad, plaintext):
        """
        chacha20_aead_encrypt(aad, key, iv, constant, plaintext):
            nonce = constant | iv
            otk = poly1305_key_gen(key, nonce)
            ciphertext = chacha20_encrypt(key, 1, nonce, plaintext)
            mac_data = aad | pad16(aad)
            mac_data |= ciphertext | pad16(ciphertext)
            mac_data |= num_to_4_le_bytes(aad.length)
            mac_data |= num_to_4_le_bytes(ciphertext.length)
            tag = poly1305_mac(mac_data, otk)
            return (ciphertext, tag)
        """
        otk = self.poly1305_key_gen()
        ciphertext = self.encrypt(plaintext)

        mac_data = aad
        if len(mac_data) % 16 != 0:
            mac_data += bytearray(16 - len(mac_data) % 16)
        mac_data += ciphertext
        mac_data += bytearray(len(aad) + len(ciphertext))

        tag = self.poly1305_mac(mac_data, otk)
        return ciphertext, tag

# http://inaz2.hatenablog.com/entry/2013/11/30/233649
#
class RC4(Cipher):
    """
    USAGE:
        key = HKDF_expand_label(secret, b'key', b'', Cipher.RC4.key_size)
        rc4 = Cipher.RC4(key=key)

        cipher, tag = rc4.encrypt_with_mac(plain)
    """
    key_size = 32

    def __init__(self, key):
        self.key = key

    def KSA(self):
        S = [i for i in range(256)]
        j = 0
        for i in range(256):
            j = (j + S[i] + self.key[i % len(self.key)]) % 256
            S[i], S[j] = S[j], S[i]
        return S

    def PRGA(self, S):
        i, j = 0, 0
        while True:
            i = (i + 1) % 256
            j = (j + S[i]) % 256
            S[i], S[j] = S[j], S[i]
            K = S[(S[i] + S[j]) % 256]
            yield K

    def encrypt(self, plaintext):
        S = self.KSA()
        gen = self.PRGA(S)
        ciphertext = bytearray(c ^ n for c, n in zip(plaintext, gen))
        return ciphertext

    def decrypt(self, ciphertext):
        return self.encrypt(ciphertext)

    def gen_mac(self, auth_data):
        hash_ = hashlib.sha256(self.key + auth_data).digest()
        return hash_

    def encrypt_with_mac(self, plaintext):
        ciphertext = self.encrypt(plaintext)
        mac = bytearray(self.gen_mac(plaintext))

        return ciphertext, mac

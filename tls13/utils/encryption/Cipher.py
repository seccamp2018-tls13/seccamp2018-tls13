import binascii
from chacha20poly1305 import *

from Crypto.Util.number import bytes_to_long, long_to_bytes

## NOTE : 今後のためにファイル分けとかも考えた方が良さそう? 
##          chacha20poly1305だけならまだ大丈夫かも

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

    def encrypt(self, plaintext):
        assert len(plaintext) % 16 == 0
        raise ValueError("Input strings must be a multiple of 16 in length")

        # ENCRYPTO()

    def decrypt(self, ciphertext):
        assert len(ciphertext) % 16 == 0
        raise ValueError("Input strings must be a multiple of 16 in length")

        # DECRYPTO()

class Chacha20Poly1305(Cipher):

    def __init__(self, key, nonce):
        #super(Chacha20Poly1305, self).__init__(key)
        self.key = make_array(key, 4, to_int=True)      # 32 [bytes] = 4 [bytes] * 8 [block]
        self.nonce = make_array(nonce, 4, to_int=True)  # 12 [bytes] = 4 [bytes] * 3 [block]

    def encrypt(self, plaintext):
        if len(plaintext) % 64 != 0:
            raise ValueError("Input strings must be a multipul of 64 in length")

        ## 1. 64 [bytes] ごとに区切る
        ## 2. さらに 64 [bytes] = 4 [bytes] * 16 [block] に区切る

        # 1
        array64s = make_array(plaintext, 64, to_int=False)

        #cipher = b''
        cipher = bytearray(0)
        for cnt, array64 in enumerate(array64s, 1):
            # 2
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

        #plain = b''
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

        return  plain

    def authenticate(self):
        _, state = chacha20(b"\x00"*16, self.key, self.nonce, cnt=0)
        least16bytes = state[8:]
        s = least16bytes[:4]
        r = least16bytes[4:]

        concate_r = concatenate_bytes(r)
        concate_s = concatenate_bytes(s)

        return concate_s, concate_r


import binascii
import hashlib
import struct
import math
from .chacha20poly1305 import *

from Crypto.Util.number import bytes_to_long, long_to_bytes

## NOTE : 今後のためにファイル分けとかも考えた方が良さそう?
##          chacha20poly1305だけならまだ大丈夫かも

## NOTE : Cipherを継承したそれぞれのアルゴリズムでの
##        AEAD(MAC)の生成関数の名前を統一した方が良さそう

def make_array(text, n_bytes=16, to_int=False):
    if to_int:
        # Little endian
        return [bytes_to_long(text[i:i+n_bytes][::-1]) for i in range(0, len(text), n_bytes)]
    else:
        return [text[i:i+n_bytes] for i in range(0, len(text), n_bytes)]

def concatenate_bytes(array:list) -> bytes:
    con_bytes = b"".join(map(long_to_bytes, array))
    return con_bytes

class Cipher:

    seq_number = 0

    def __init__(self, key, nonce):
        self.key_raw = key
        self.nonce_raw = nonce
        self.seq_number = 0

    def encrypt(self, plaintext):
        assert len(plaintext) % 16 == 0
        raise ValueError("Input strings must be a multiple of 16 in length")

        # ENCRYPTO()

    def decrypt(self, ciphertext):
        assert len(ciphertext) % 16 == 0
        raise ValueError("Input strings must be a multiple of 16 in length")

        # DECRYPTO()

    @staticmethod
    def pad16(data):
        """Return padding for the Associated Authenticated Data"""
        if len(data) % 16 == 0: return bytearray(0)
        return bytearray(16 - (len(data) % 16))

    @staticmethod
    def ct_compare_digest(a, b):
        """Compares if string like objects are equal. Constant time."""
        # この関数は a == b の結果を返すが、
        # 内容に基づく短絡的な振る舞いを避けることで、タイミング分析を防ぐ
        if len(a) != len(b): return False
        result = 0
        for x, y in zip(a, b):
            result |= x ^ y
        return result == 0


class Chacha20Poly1305(Cipher):
    key_size = 32
    nonce_size = 12
    # keyとnonceをHKDFで生成するときに
    # HKDF_expand_label(Master Secret, b"key", b"", Chacha20Poly1305.key_size)
    # のようにできるようにしておく

    def __init__(self, key, nonce):
        super(Chacha20Poly1305, self).__init__(key, nonce)
        # self.key: 32 [bytes] = 4 [bytes] * 8 [block]
        # self.iv:  12 [bytes] = 4 [bytes] * 3 [block]
        self.key = make_array(key, 4, to_int=True)
        self.iv = make_array(nonce, 4, to_int=True)

    def encrypt(self, plaintext, nonce):
        print("[+] key", self.key_raw.hex(), self.key)
        print("[+] nonce", self.nonce_raw.hex(), nonce)

        counter = 1
        #encrypted_message = bytearray(0)
        encrypted_message = b''
        for j in range(0, math.floor(len(plaintext)//64)):
            key_stream = chacha20( self.key, nonce, cnt=counter+j)
            block = plaintext[(j*64):(j*64+64)]
            key_stream = b''.join(map(lambda x:struct.pack('I', x), key_stream))

            print("[+] block :", block)
            print("[+] key_stream :", key_stream)

            # encrypted_message +=  block ^ key_stream
            encrypted_message += bytes([
                x ^ y for x, y in zip(block, key_stream)])

        if len(plaintext) % 64 != 0:
            j = math.floor(len(plaintext)//64)
            key_stream = chacha20(self.key, nonce, cnt=counter+j)
            key_stream = b''.join(map(lambda x:struct.pack('I', x), key_stream))
            block = plaintext[(j*64):len(plaintext)]

            # encrypted_message += (block^key_stream)[0..len(plaintext)%64]
            encrypted_message += bytes([
                x ^ y for x, y in zip(block, key_stream)])

        return encrypted_message

    def decrypt(self, ciphertext, nonce):
        counter = 1
        #decrypted_message = bytearray(0)
        decrypted_message = b''
        for j in range(0, math.floor(len(ciphertext)//64)):
            key_stream = chacha20(self.key, nonce, cnt=counter+j)
            block = ciphertext[(j*64):(j*64+64)]
            key_stream = b''.join(map(lambda x:struct.pack('I', x), key_stream))

            print("[+] block :", block)
            print("[+] key_stream :", key_stream)

            # decrypted_message +=  block ^ key_stream
            decrypted_message += bytes([
                x ^ y for x, y in zip(block, key_stream)])

        if len(ciphertext) % 64 != 0:
            j = math.floor(len(ciphertext)//64)
            key_stream = chacha20(self.key, nonce, cnt=counter+j)
            key_stream = b''.join(map(lambda x:struct.pack('I', x), key_stream))
            block = ciphertext[(j*64):len(ciphertext)]

            # decrypted_message += (block^key_stream)[0..len(plaintext)%64]
            decrypted_message += bytes([
                x ^ y for x, y in zip(block, key_stream)])

        return decrypted_message

    def poly1305_mac(self, message, otk):

        def cramp(r):
            return r & 0x0ffffffc0ffffffc0ffffffc0fffffff


        def le_num(n : int):
            dt = hex(n)[2:].encode()
            if len(dt) % 2 != 0:
                dt = b'0' + dt
            dt = b"".join([dt[i:i+2] for i in range(len(dt)-2, -1, -2)])
            return int(dt, 16)

        s, r = otk

        # 16 [bytes] に区切って 1 [byte] (\x01) を付加
        coefs_messages = make_array(message, 16, to_int=False)
        for idx in range(len(coefs_messages)):
            coefs_messages[idx] += b'\x01'
            coefs_messages[idx] = int(coefs_messages[idx][::-1].hex(), 16)

        # r -> リトルエンディアンにした後 cramp(r)
        # s -> リトルエンディアン
        r = le_num(r)
        r = cramp(r)
        s = le_num(s)

        print("[+] Poly1305 r :", hex(r))
        print("[+] Poly1305 s :", hex(s))

        p = 2**130 - 5
        accumulator = 0
        for i, Ci in enumerate(coefs_messages, 1):
            accumulator = ((Ci + accumulator) % p ) * r % p
            print("[+] Ci, ACC :", hex(Ci), hex(accumulator))

        print("[+] ACC + S :\t\t", hex(accumulator + s)[2:])
        accumulator = (accumulator + s) % 2**128
        print("[+] TAG(REVERSED) :\t ", long_to_bytes(accumulator).hex())
        print("[+] TAG :\t\t ", long_to_bytes(accumulator)[::-1].hex())
        return long_to_bytes(accumulator)[::-1]


    def poly1305_key_gen(self, nonce):
        state = chacha20(self.key, nonce, cnt=0)
        r = state[0:4]
        s = state[4:8]

        r = b''.join(map(lambda x: struct.pack("<I", x), r))
        s = b''.join(map(lambda x: struct.pack("<I", x), s))

        s = bytes_to_long(s)
        r = bytes_to_long(r)

        return s, r

    def chacha20_aead_encrypt(self, aad, plaintext, nonce):
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
        otk = self.poly1305_key_gen(nonce)
        ciphertext = self.encrypt(plaintext, nonce)

        mac_data = aad + self.pad16(aad)
        mac_data += ciphertext + self.pad16(ciphertext)
        mac_data += struct.pack("<Q", len(aad))
        mac_data += struct.pack("<Q", len(ciphertext))

        tag = self.poly1305_mac(mac_data, otk)
        return ciphertext, tag

    # [Mako 8/11]
    # AEAD-Encrypt と AEAD-Decrypt の追加
    # https://tools.ietf.org/html/draft-ietf-tls-tls13-26#page-84
    # AEADなアルゴリズムを実装するクラスは全て aead_encrypt と aead_decrypt という
    # メソッドを持つようにして、インターフェースを統一したい。

    def aead_encrypt(self, aad, plaintext):
        """
        Encrypts and authenticates plaintext using nonce and data. Returns the
        ciphertext, consisting of the encrypted plaintext and tag concatenated.
        """
        print("self.iv:", self.iv)
        nonce = self.get_nonce()
        nonce = make_array(nonce, 4, to_int=True)
        print("nonce:", nonce)

        ciphertext, tag = self.chacha20_aead_encrypt(aad, plaintext, nonce)
        return ciphertext + tag

    def aead_decrypt(self, aad, ciphertext):
        """
        Decrypts and authenticates ciphertext using nonce and aad. If the
        tag is valid, the plaintext is returned. If the tag is invalid,
        returns None.
        """
        import struct

        # if len(self.nonce) != 12:
        #     raise ValueError("Nonce must be 96 bit long")
        print("[+] ciphertext : ", ciphertext)
        if len(ciphertext) < 16:
            return None

        print("self.iv:", self.iv)
        nonce = self.get_nonce()
        nonce = make_array(nonce, 4, to_int=True)
        print("nonce:", nonce)

        expected_tag = ciphertext[-16:]
        ciphertext = ciphertext[:-16]

        otk = self.poly1305_key_gen(nonce)
        mac_data = aad + self.pad16(aad)
        mac_data += ciphertext + self.pad16(ciphertext)
        mac_data += struct.pack("<Q", len(aad))
        mac_data += struct.pack("<Q", len(ciphertext))
        tag = self.poly1305_mac(mac_data, otk)

        if not self.ct_compare_digest(tag, expected_tag):
            return None

        return self.decrypt(ciphertext, nonce)

    def get_nonce(self):
        print("seq_number:", self.seq_number)
        # res = self.iv
        iv = b''.join(map(lambda x: struct.pack("<I", x), self.iv))

        iv_len = len(iv)
        seq = long_to_bytes(self.seq_number)
        seq = seq.rjust(iv_len, b'\x00')
        print('iv: ', iv.hex())
        print('seq:', seq.hex())
        res = b''.join(map(lambda x: bytearray([x[0] ^ x[1]]), zip(iv, seq)))
        print("res:", res.hex())

        self.seq_number += 1
        return res


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

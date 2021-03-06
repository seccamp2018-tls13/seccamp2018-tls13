import binascii
import random
from Crypto.Util.number import bytes_to_long, long_to_bytes

def plus(x, y):
    return (x + y) & 0xffffffff
    #return (x + y) % 2^32

def lrotate(x, n):
    l = (x << n) & 0xffffffff
    r = (x >> (32-n)) & 0xffffffff
    return l + r

def QuarterRound(a, b, c, d):
    a = plus(a, b); d ^= a; d = lrotate(d, 16)
    c = plus(c, d); b ^= c; b = lrotate(b, 12)
    a = plus(a, b); d ^= a; d = lrotate(d, 8)
    c = plus(c, d); b ^= c; b = lrotate(b, 7)
    return a, b, c, d

def chacha20(key, nonce, cnt=0):
    """
        const : 4 [byte] * 4 [block]
        key   : 4 [byte] * 8 [block]
        nonce : 4 [byte] * 3 [block]
        count : 4 [byte] * 1 [block]

        TOTAL : 4 [byte] * 16 [block]
    """

    ## initialize ##
    const = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]
    count = [0 + cnt]
    state = const + key + count + nonce
    state_orig = list(state)
    # print(state)

    for _ in range(10):
        # Columns
        state[0], state[4], state[8], state[12] = QuarterRound(state[0], state[4], state[8], state[12])
        state[1], state[5], state[9], state[13] = QuarterRound(state[1], state[5], state[9], state[13])
        state[2], state[6], state[10], state[14] = QuarterRound(state[2], state[6], state[10], state[14])
        state[3], state[7], state[11], state[15] = QuarterRound(state[3], state[7], state[11], state[15])

        # Diagonal
        state[0], state[5], state[10], state[15] = QuarterRound(state[0], state[5], state[10], state[15])
        state[1], state[6], state[11], state[12] = QuarterRound(state[1], state[6], state[11], state[12])
        state[2], state[7], state[8], state[13] = QuarterRound(state[2], state[7], state[8], state[13])
        state[3], state[4], state[9], state[14] = QuarterRound(state[3], state[4], state[9], state[14])

    state = list(map(lambda x: plus(x[0], x[1]), zip(state, state_orig)))
    # print("="*16)
    # print(b''.join(map(lambda x: long_to_bytes(x)[::-1].ljust(4, b'\x00'), text)).hex())

    # print(b''.join(map(lambda x: long_to_bytes(x)[::-1].ljust(4, b'\x00'), results)).hex())
    # print("="*16)

    return state

# NOTE : chacha20の引数textは暗号化するメッセージを64bytesごとに区切ったもの(足りない部分は0パディング)
#        呼び出し側で区切ってあげる?
#        Crypto.Cipher.AESでは16 * n bytesになっていれば問題ないので, クラス化して CIPHER_CLASS.encrypt(key, text)
#        みたいな感じにしてencrypt内で16bytesに区切って暗号化
#
# TODO : Nonceの生成. NonceはTLSのシーケンス番号(8 [byte])に0パディングして12 [byte]長にしてから
#        Master Secret によって生成される12 [byte]のWriteIVとXORをとって生成.

import binascii
import random

bytes_to_int = lambda x:int(binascii.hexlify(x), 16)
str_to_int = lambda x:int(binascii.hexlify(x.encode()), 16)

def make_array(s:bytes):
    return [ s[16*i:16*(i+1)] for i in range((len(s)+15)//16) ]

def make_coef(array):
    r = []
    for s in array:
        s = (s << 8) + 1
        len_s = len(bin(s)[2:])
        if len_s < 136:
            s <<= (136-len_s)
        r.append(s)
    return r

def poly1305(coefs, s, r):
    """

        chacha20のカウンタ0でのstateの下位32 [byte]のうち
        s : 上位 16 [byte]
        r : 下位 16 [byte]
    """
    MOD = 2**130 - 5
    x = 0
    for i, Ci in enumerate(coefs[::-1], 1):
        x += (Ci % MOD)*pow(r, i, MOD) % MOD
    
    return (x + s) & 0xffffffffffffffffffffffffffffffff


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

def chacha20(text, key, nonce, cnt=0):
    """
        const : 4 [byte] * 4 [block]
        key   : 4 [byte] * 8 [block]
        nonce : 4 [byte] * 3 [block]
        count : 4 [byte] * 1 [block]

        TOTAL : 4 [byte] * 16 [block]
    """

    ## initialize ##
    const = [0x64787061, 0x6e642033, 0x322d6279, 0x7465206b]
    count = [0 + cnt]
    state = const + key + count + nonce

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

    results = [0]*16
    for i in range(16):
        results[i] = text[i] ^ state[i]

    return results, state

# key = [0, 0, 0, 0, 0, 0, 0, 0]
# nonce = [0, 0, 0] 


# NOTE : chacha20の引数textは暗号化するメッセージを64bytesごとに区切ったもの(足りない部分は0パディング)
#        呼び出し側で区切ってあげる?
#        Crypto.Cipher.AESでは16 * n bytesになっていれば問題ないので, クラス化して CIPHER_CLASS.encrypt(key, text)
#        みたいな感じにしてencrypt内で16bytesに区切って暗号化
#
# TODO : Nonceの生成. NonceはTLSのシーケンス番号(8 [byte])に0パディングして12 [byte]長にしてから
#        Master Secret によって生成される12 [byte]のWriteIVとXORをとって生成. 
# TODO : 
#
#
#

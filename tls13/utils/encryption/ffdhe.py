### https://tools.ietf.org/html/rfc7919#appendix-A ###

# DONE : FFDHEに使用するMudulus(素数)を取得する関数の定義
# TODO : 公開鍵``α''とクライアント/サーバの秘密鍵生成部分

### Description ###

# p = 2^b - 2^{b-64} + {[2^{b-130} e] + X } * 2^64 - 1 ;
#   where b is the number of bits, e is base of natural logarithm, 
# X is lowest number that is satisfied p is safe prime.
# [ ] means floor function.


# Public key MUST be chosen [2, ..., p-2]
# Secret keys (ServerSecretKey, ClientSecretKey) also will be [2, ..., p-2]

import binascii
from get_modulus_ffdhe import *
from ...utils.type import Uint8, Uint16, Type # Uint16のインポート
#from type import Uint8, Uint16, Type

functions = {
        Uint16(0x0100) : ffdhe2048, # ffdhe2048 = Uint16(0x0100)
        Uint16(0x0101) : ffdhe3072, # ffdge3072 = Uint16(0x0101)
        Uint16(0x0102) : ffdhe4096, # ffdhe4096 = Uint16(0x0102)
        Uint16(0x0103) : ffdhe6144, # ffdhe6144 = Uint16(0x0103)
        Uint16(0x0104) : ffdhe8192, # ffdhe8192 = Uint16(0x0104)
    }

class FFDHE:

    ## dhe = FFDHE(NamedGroup.ffdhe2048) 
    ##  みたいな感じでインスタンス化
    ##
    ##  client.py/server.py の方で key_share.extension_data. ... 
    ##  と拡張から辿っていって
    ##  dhe = FFDHE(... .ffdhe2048) ができるように
    ##

    def __init__(self, func_val=Uint16(0x0100)):
        self.p = functions[func_val]()

        # TODO : 以下をどうするか
        # self.ClientSecretKey
        # self.ServerSecretKey
        # self.PublicKey

    def get_p_bytes(self):
        return binascii.unhexlify(hex(self.p)[2:])

    def get_p_int(self):
        return self.p



### https://tools.ietf.org/html/rfc7919#appendix-A ###

### Description ###

# p = 2^b - 2^{b-64} + {[2^{b-130} e] + X } * 2^64 - 1 ;
#   where b is the number of bits, e is base of natural logarithm,
# X is lowest number that is satisfied p is safe prime.
# [ ] means floor function.
#
# Public key MUST be chosen [2, ..., p-2]
# Secret keys (ServerSecretKey, ClientSecretKey) also will be [2, ..., p-2]

from .get_modulus_ffdhe import *
from ...metastruct import *
from Crypto.Util.number import long_to_bytes, bytes_to_long

from ..cryptomath import getRandomNumber

# FFDHEに使用するMudulus(素数)を取得する関数の定義
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
        # public key (g=2, modulus=p)
        self.p = functions[func_val]()
        self.g = 2

        # private key = [2, p-2]
        self.my_secret = getRandomNumber(2, self.p)

    def gen_public_key(self):
        public_key = pow(self.g, self.my_secret, self.p)
        return long_to_bytes(public_key)

    # gen_shared_key と同じ
    # 互換性のために作成
    # master secret という用語は RSA ではよく出てくるが DHE ではあまり出てこないので
    def gen_master_secret(self, **kwargs):
        self.gen_shared_secret(**kwargs)

    def gen_shared_key(self, peer_pub):
        """
            peer_pub  : g^PeerSecKey mod p
            self.my_secret : [2, ..., p-2]
        """
        # peer_pub, my_secret が bytes型 であった場合の変換処理
        if isinstance(peer_pub, bytes): peer_pub = bytes_to_long(peer_pub)

        master_secret = pow(peer_pub, self.my_secret, self.p)
        return long_to_bytes(master_secret)

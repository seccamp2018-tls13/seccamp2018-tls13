### https://tools.ietf.org/html/rfc7919#appendix-A ###

# DONE : FFDHEに使用するMudulus(素数)を取得する関数の定義
# TODO : 公開鍵``g''とクライアント/サーバの秘密鍵生成部分
#
# [Mako 7/12]
# RFC7919 の全ての ffdhe で The generator is: g = 2 と書かれているので，g = 2 は固定

### Description ###

# p = 2^b - 2^{b-64} + {[2^{b-130} e] + X } * 2^64 - 1 ;
#   where b is the number of bits, e is base of natural logarithm,
# X is lowest number that is satisfied p is safe prime.
# [ ] means floor function.
#
# Public key MUST be chosen [2, ..., p-2]
# Secret keys (ServerSecretKey, ClientSecretKey) also will be [2, ..., p-2]

from .get_modulus_ffdhe import *
from ...utils.type import Uint16
from Crypto.Util.number import long_to_bytes, bytes_to_long

from ..cryptomath import getRandomNumber

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
        self.g = 2

        #self.my_secret = [2, p-2]
        self.my_secret = getRandomNumber(2, self.p)

        # TODO : 以下をどうするか
        # self.ClientSecretKey
        # self.ServerSecretKey
        # self.PublicKey (g=2, modulus=p)
        #
        # [Mako 7/12]
        # FFDHEクラスのフィールドに my_secret というフィールド作ってインスタンス化するときに
        # 一緒に秘密値も生成して self.my_secret = ... みたいな感じが良さそう. 
        # そうすると公開値を作るメソッド gen_public_key() とかも作れそう．
        # 理想はこんな感じ：
        #    client_dhe = FFDHE(NamedGroup.ffdhe2048)
        #    server_dhe = FFDHE(NamedGroup.ffdhe2048)
        #    client_pub_key = client_dhe.gen_public_key()
        #    server_pub_key = server_dhe.gen_public_key()
        #    client_master_secret = client_dhe.gen_master_secret(server_pub_key)
        #    server_master_secret = server_dhe.gen_master_secret(client_pub_key)
        #    assert client_master_secret == server_master_secret

    def gen_public_key(self):
        public_key = pow(self.g, self.my_secret, self.p)
        return long_to_bytes(public_key)

    def gen_master_secret(self, peer_pub):
        """
            peer_pub  : g^PeerSecKey mod p
            self.my_secret : [2, ..., p-2]
        """
        # DONE : peer_pub, my_secret が bytes型 であった場合の変換処理をいい感じにしたい
        if isinstance(peer_pub, bytes): peer_pub = bytes_to_long(peer_pub)

        master_secret = pow(peer_pub, self.my_secret, self.p)
        return long_to_bytes(master_secret)



# B.4.  Cipher Suites
# https://tools.ietf.org/html/draft-ietf-tls-tls13-26#appendix-B.4

__all__ = [
    'CipherSuite',
]

import hashlib
from ..metastruct import *

class CipherSuite(Type):
    TLS_AES_128_GCM_SHA256       = Uint16(0x1301)
    TLS_AES_256_GCM_SHA384       = Uint16(0x1302)
    TLS_CHACHA20_POLY1305_SHA256 = Uint16(0x1303)
    TLS_AES_128_CCM_SHA256       = Uint16(0x1304)
    TLS_AES_128_CCM_8_SHA256     = Uint16(0x1305)
    _size = 2

    @classmethod
    def get_hash_algorithm(cls, cipher_suite):
        if cipher_suite == cls.TLS_AES_256_GCM_SHA384:
            return hashlib.sha384
        return hashlib.sha256

    @classmethod
    def get_hash_algo_name(cls, cipher_suite):
        if cipher_suite == cls.TLS_AES_256_GCM_SHA384:
            return 'sha384'
        return 'sha256'

    @classmethod
    def get_hash_algo_size(cls, cipher_suite):
        if cipher_suite == cls.TLS_AES_256_GCM_SHA384:
            return 48
        return 32

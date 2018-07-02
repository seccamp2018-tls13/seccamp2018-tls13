
# B.4.  Cipher Suites
# https://tools.ietf.org/html/draft-ietf-tls-tls13-26#appendix-B.4

from ..utils.type import Uint16

class CipherSuite:
    TLS_AES_128_GCM_SHA256       = Uint16(0x1301)
    TLS_AES_256_GCM_SHA384       = Uint16(0x1301)
    TLS_CHACHA20_POLY1305_SHA256 = Uint16(0x1301)
    TLS_AES_128_CCM_SHA256       = Uint16(0x1301)
    TLS_AES_128_CCM_8_SHA256     = Uint16(0x1301)

CipherSuite.labels = dict( (v,k) for k,v in CipherSuite.__dict__.items() )
CipherSuite.values = set( v for k,v in CipherSuite.__dict__.items() if type(v) == Uint16 )

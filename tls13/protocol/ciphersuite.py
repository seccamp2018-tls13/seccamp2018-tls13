
# B.4.  Cipher Suites
# https://tools.ietf.org/html/draft-ietf-tls-tls13-26#appendix-B.4

class CipherSuite:
    TLS_AES_128_GCM_SHA256       = b'\x13\x01'
    TLS_AES_256_GCM_SHA384       = b'\x13\x02'
    TLS_CHACHA20_POLY1305_SHA256 = b'\x13\x03'
    TLS_AES_128_CCM_SHA256       = b'\x13\x04'
    TLS_AES_128_CCM_8_SHA256     = b'\x13\x05'


# B.3.2.  Server Parameters Messages
# https://tools.ietf.org/html/draft-ietf-tls-tls13-26#appendix-B.3.2

__all__ = [
    'CertificateAuthoritiesExtension', 'OIDFilter', 'OIDFilterExtension',
    'PostHandshakeAuth', 'EncryptedExtensions', 'CertificateRequest',
]

from .messages import Extension
from ...metastruct import *

class CertificateAuthoritiesExtension:
    pass


class OIDFilter:
    pass


class OIDFilterExtension:
    pass


class PostHandshakeAuth:
    pass


class EncryptedExtensions(Struct):
    """
    struct {
      Extension extensions<0..2^16-1>;
    } EncryptedExtensions;
    """
    def __init__(self, extensions):
        self.extensions = extensions

        self.struct = Members(self, [
            Member(Listof(Extension), 'extensions', length_t=Uint16),
        ])

    @classmethod
    def from_bytes(cls, data):
        from ..handshake import HandshakeType
        reader = Reader(data)

        # ServerHelloのExtension構造を流用しただけなので正しく動くか不明。
        # 現在のところは extension=[] のように空の配列しか入らないので問題なく動く。
        extensions = Extension.get_list_from_bytes(
            reader.get_rest(),
            msg_type=HandshakeType.server_hello)

        return cls(extensions=extensions)




class CertificateRequest:
    pass


# B.3.2.  Server Parameters Messages
# https://tools.ietf.org/html/draft-ietf-tls-tls13-26#appendix-B.3.2

__all__ = [
    'CertificateAuthoritiesExtension', 'OIDFilter', 'OIDFilterExtension',
    'PostHandshakeAuth', 'EncryptedExtensions', 'CertificateRequest',
]

from .messages import Extension
from ...utils.metastruct import Struct, Members, Member, Listof
from ...utils.type import Uint16


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


class CertificateRequest:
    pass

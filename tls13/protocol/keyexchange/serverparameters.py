
# B.3.2.  Server Parameters Messages
# https://tools.ietf.org/html/draft-ietf-tls-tls13-26#appendix-B.3.2

__all__ = [
    'CertificateAuthoritiesExtension', 'OIDFilter', 'OIDFilterExtension',
    'PostHandshakeAuth', 'EncryptedExtensions', 'CertificateRequest',
]


class CertificateAuthoritiesExtension:
    pass


class OIDFilter:
    pass


class OIDFilterExtension:
    pass


class PostHandshakeAuth:
    pass


class EncryptedExtensions:
    """
    struct {
      Extension extensions<0..2^16-1>;
    } EncryptedExtensions;
    """
    def __init__(self, extensions):
        self.extensions = extensions


class CertificateRequest:
    pass

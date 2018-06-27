
# B.3.2.  Server Parameters Messages
# https://tools.ietf.org/html/draft-ietf-tls-tls13-26#appendix-B.3.2

# class CertificateAuthoritiesExtension
# class OIDFilter
# class OIDFilterExtension
# class PostHandshakeAuth


class EncryptedExtensions:
    """
    struct {
      Extension extensions<0..2^16-1>;
    } EncryptedExtensions;
    """
    def __init__(self):
        self.extensions = []


# class CertificateRequest

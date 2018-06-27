
# B.3.3.  Authentication Messages
# https://tools.ietf.org/html/draft-ietf-tls-tls13-26#appendix-B.3.3

class CertificateType:
    """
    enum { ... } CertificateType
    """
    X509 = 0
    OpenPGP_RESERVED = 1
    RawPublicKey = 2
    _size = 1 # byte


class CertificateEntry:
    """
    struct {
      select (certificate_type) {
        case RawPublicKey:
          /* From RFC 7250 ASN.1_subjectPublicKeyInfo */
          opaque ASN1_subjectPublicKeyInfo<1..2^24-1>;
        case X509:
          opaque cert_data<1..2^24-1>;
      };
      Extension extensions<0..2^16-1>;
    } CertificateEntry;
    """
    def __init__(self):
        self._entry
        self.extensions = []


class Certificate:
    """
    struct {
      opaque certificate_request_context<0..2^8-1>;
      CertificateEntry certificate_list<0..2^24-1>;
    } Certificate;
    """
    def __init__(self):
        self.certificate_request_context
        self.certificate_list = []


class CertificateVerify:
    """
    struct {
      SignatureScheme algorithm;
      opaque signature<0..2^16-1>;
    } CertificateVerify;
    """
    def __init__(self):
        self.algorithm
        self.signature


class Finished:
    """
    struct {
      opaque verify_data[Hash.length];
    } Finished;
    """
    def __init__(self):
        self.verify_data

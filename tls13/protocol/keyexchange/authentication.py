
# B.3.3.  Authentication Messages
# https://tools.ietf.org/html/draft-ietf-tls-tls13-26#appendix-B.3.3

from ...utils.type import Uint8, Type

@Type.add_labels_and_values
class CertificateType:
    """
    enum { ... } CertificateType
    """
    X509 = Uint8(0)
    OpenPGP_RESERVED = Uint8(1)
    RawPublicKey = Uint8(2)
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
    def __init__(self, certificate_type, cert_data, extensions=[]):
        self.certificate_type = certificate_type
        assert certificate_type in CertificateType.values

        if self.certificate_type == CertificateType.RawPublicKey:
            self.ASN1_subjectPublicKeyInfo = cert_data
        elif self.certificate_type == CertificateType.X509:
            self.cert_data = cert_data
        else:
            raise RuntimeError()
        self.extensions = extensions


class Certificate:
    """
    struct {
      opaque certificate_request_context<0..2^8-1>;
      CertificateEntry certificate_list<0..2^24-1>;
    } Certificate;
    """
    def __init__(self, certificate_request_context, certificate_list=[]):
        self.certificate_request_context = certificate_request_context
        self.certificate_list = certificate_list


class CertificateVerify:
    """
    struct {
      SignatureScheme algorithm;
      opaque signature<0..2^16-1>;
    } CertificateVerify;
    """
    def __init__(self, algorithm, signature):
        self.algorithm = algorithm
        self.signature = signature


class Finished:
    """
    struct {
      opaque verify_data[Hash.length];
    } Finished;
    """
    def __init__(self, verify_data):
        self.verify_data = verify_data

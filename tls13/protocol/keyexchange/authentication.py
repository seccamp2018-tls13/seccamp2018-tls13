
# B.3.3.  Authentication Messages
# https://tools.ietf.org/html/draft-ietf-tls-tls13-26#appendix-B.3.3

__all__ = [
    'CertificateType', 'CertificateEntry', 'Certificate',
    'CertificateVerify', 'Finished',
]

import collections

from .messages import Extension
from .signature import SignatureScheme
from ...utils.codec import Reader, Writer
from ...utils.type import Uint8, Uint16, Uint24, Type
from ...utils.repr import make_format
from ...utils.struct import Struct, Members, Member, Listof


@Type.add_labels_and_values
class CertificateType(Type):
    """
    enum { ... } CertificateType
    """
    X509 = Uint8(0)
    OpenPGP_RESERVED = Uint8(1)
    RawPublicKey = Uint8(2)
    _size = 1 # byte


class CertificateEntry(Struct):
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
    def __init__(self, cert_data, extensions=[]):
        assert type(cert_data) in (bytes, bytearray)
        self.cert_data = bytes(cert_data)
        self.extensions = extensions

        self.struct = Members(self, [
            Member(bytes, 'cert_data', length_t=Uint24),
            Member(Listof(Extension), 'extensions', length_t=Uint16),
        ])

    @classmethod
    def from_bytes(cls, data=b'', reader=None):
        is_given_reader = bool(reader)
        if not is_given_reader:
            reader = Reader(data)

        cert_data  = reader.get(bytes, length_t=Uint24)
        extensions = reader.get(bytes, length_t=Uint16)

        # extensions に入る拡張は status_request か signed_certificate_timestamp
        # extensions のバイト列はパースが面倒 & 重要度が低いので後回しにする
        obj = cls(cert_data=cert_data, extensions=[])

        if is_given_reader:
            return (obj, reader)
        return obj


class Certificate(Struct):
    """
    struct {
      opaque certificate_request_context<0..2^8-1>;
      CertificateEntry certificate_list<0..2^24-1>;
    } Certificate;
    """
    def __init__(self, certificate_request_context=b'', certificate_list=[]):
        self.certificate_request_context = bytes(certificate_request_context)
        self.certificate_list = certificate_list

        self.struct = Members(self, [
            Member(bytes, 'certificate_request_context', length_t=Uint8),
            Member(Listof(CertificateEntry), 'certificate_list', length_t=Uint24),
        ])

    @classmethod
    def from_bytes(cls, data):
        reader = Reader(data)
        certificate_request_context = reader.get(bytes, length_t=Uint8)
        certificate_list_bytes = reader.get(bytes, length_t=Uint24)
        certificate_list = []

        reader = Reader(certificate_list_bytes)
        while reader.get_rest_length() > 0:
            entry, reader = CertificateEntry.from_bytes(reader=reader)
            certificate_list.append(entry)

        return cls(certificate_request_context, certificate_list)


class CertificateVerify(Struct):
    """
    struct {
      SignatureScheme algorithm;
      opaque signature<0..2^16-1>;
    } CertificateVerify;
    """
    def __init__(self, algorithm, signature):
        self.algorithm = algorithm
        self.signature = signature

        self.struct = Members(self, [
            Member(SignatureScheme, 'algorithm'),
            Member(bytes, 'signature', length_t=Uint16),
        ])

    @classmethod
    def from_bytes(cls, data):
        reader = Reader(data)
        algorithm = reader.get(Uint16)
        signature = reader.get(bytes, length_t=Uint16)
        return cls(algorithm=algorithm, signature=signature)


class Finished(Struct):
    """
    struct {
      opaque verify_data[Hash.length];
    } Finished;
    """
    def __init__(self, verify_data):
        self.verify_data = verify_data

        self.struct = Members(self, [
            Member(bytes, 'verify_data'),
        ])

    # TODO: ハッシュの求め方
    #
    # Hash = SignatureSchemeにあるハッシュ関数
    #
    # Transcript-Hash(M1, M2, ... MN) = Hash(M1 || M2 ... MN)
    #
    # finished_key = HKDF-Expand-Label(BaseKey, "finished", "", Hash.length)
    #
    # HKDF-Expand-Label(Secret, Label, Context, Length) =
    #     HKDF-Expand(Secret, HkdfLabel, Length)
    #
    #   Where HkdfLabel is specified as:
    #
    #      struct {
    #          uint16 length = Length;
    #          opaque label<7..255> = "tls13 " + Label;
    #          opaque context<0..255> = Context;
    #      } HkdfLabel;
    #
    # Derive-Secret(Secret, Label, Messages) =
    #     HKDF-Expand-Label(Secret, Label,
    #                       Transcript-Hash(Messages), Hash.length)
    #
    # HMAC = ハッシュを使うメッセージ認証符号
    #
    # verify_data = HMAC(finished_key,
    #                    Transcript-Hash(Handshake Context,
    #                                    Certificate*, CertificateVerify*))

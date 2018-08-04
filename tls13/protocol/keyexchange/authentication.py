
# B.3.3.  Authentication Messages
# https://tools.ietf.org/html/draft-ietf-tls-tls13-26#appendix-B.3.3

__all__ = [
    'CertificateType', 'CertificateEntry', 'Certificate',
    'CertificateVerify', 'Finished', 'Hash',
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
    # 証明書の種類
    """
    enum { ... } CertificateType
    """
    X509 = Uint8(0)
    OpenPGP_RESERVED = Uint8(1)
    RawPublicKey = Uint8(2)
    _size = 1 # byte


class CertificateEntry(Struct):
    # 証明書の内容
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
    def __init__(self, **kwargs):
        self.struct = Members(self, [
            Member(bytes, 'cert_data', length_t=Uint24),
            Member(Listof(Extension), 'extensions', length_t=Uint16),
        ])
        self.struct.set_args(**kwargs)

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
    # 証明書を送るときに使う
    """
    struct {
      opaque certificate_request_context<0..2^8-1>;
      CertificateEntry certificate_list<0..2^24-1>;
    } Certificate;
    """
    def __init__(self, **kwargs):
        self.struct = Members(self, [
            Member(bytes, 'certificate_request_context', length_t=Uint8),
            Member(Listof(CertificateEntry), 'certificate_list', length_t=Uint24),
        ])
        self.struct.set_default('certificate_request_context', b'')
        self.struct.set_args(**kwargs)

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

        return cls(certificate_request_context=certificate_request_context,
                   certificate_list=certificate_list)


class CertificateVerify(Struct):
    # 証明書の署名を送るときに使う
    """
    struct {
      SignatureScheme algorithm;
      opaque signature<0..2^16-1>;
    } CertificateVerify;
    """
    def __init__(self, **kwargs):
        self.struct = Members(self, [
            Member(SignatureScheme, 'algorithm'),
            Member(bytes, 'signature', length_t=Uint16),
        ])
        self.struct.set_args(**kwargs)

    @classmethod
    def from_bytes(cls, data):
        reader = Reader(data)
        algorithm = reader.get(Uint16)
        signature = reader.get(bytes, length_t=Uint16)
        return cls(algorithm=algorithm, signature=signature)


class Hash(bytes):
    _size = 32

    @classmethod
    def set_size(cls, size):
        cls._size = size


class Finished(Struct):
    # TLSハンドシェイクの完了を送るときに使う
    """
    struct {
      opaque verify_data[Hash.length];
    } Finished;
    """
    def __init__(self, **kwargs):
        self.struct = Members(self, [
            Member(Hash, 'verify_data'),
        ])
        self.struct.set_args(**kwargs)

    @classmethod
    def from_bytes(cls, data):
        reader = Reader(data)
        verify_data = reader.get(Hash)
        return cls(verify_data=verify_data)

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
    #
    # +-----------+----------------------------+--------------------------+
    # | Mode      | Handshake Context          | Base Key                 |
    # +-----------+----------------------------+--------------------------+
    # | Server    | ClientHello ... later of E | server_handshake_traffic |
    # |           | ncryptedExtensions/Certifi | _secret                  |
    # |           | cateRequest                |                          |
    # |           |                            |                          |
    # | Client    | ClientHello ... later of   | client_handshake_traffic |
    # |           | server                     | _secret                  |
    # |           | Finished/EndOfEarlyData    |                          |
    # |           |                            |                          |
    # | Post-     | ClientHello ... client     | client_application_traff |
    # | Handshake | Finished +                 | ic_secret_N              |
    # |           | CertificateRequest         |                          |
    # +-----------+----------------------------+--------------------------+

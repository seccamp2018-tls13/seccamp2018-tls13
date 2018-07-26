
# B.3.3.  Authentication Messages
# https://tools.ietf.org/html/draft-ietf-tls-tls13-26#appendix-B.3.3

import collections

from .signature import SignatureScheme
from ...utils.codec import Reader, Writer
from ...utils.type import Uint8, Uint16, Uint24, Type
from ...utils.repr import make_format

import pprint
import textwrap

@Type.add_labels_and_values
class CertificateType(Type):
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
    def __init__(self, cert_data, extensions=[]):
        assert type(cert_data) in (bytes, bytearray)
        self.cert_data = bytes(cert_data)
        self.extensions = extensions

    def __repr__(self):
        props = collections.OrderedDict(
            cert_data=bytes,
            extensions=list)
        return make_format(self, props)

    def __len__(self):
        return 3 + len(self.cert_data) + \
               2 + sum(map(len, self.extensions))

    def to_bytes(self):
        writer = Writer()
        writer.add_bytes(self.cert_data, length_t=Uint24)
        writer.add_list(self.extensions, length_t=Uint16)
        return writer.bytes

    @classmethod
    def from_bytes(self, data):
        reader = Reader(data)
        cert_data  = reader.get_var_bytes(3)
        extensions = reader.get_var_bytes(2)

        # extensions に入る拡張は status_request か signed_certificate_timestamp
        # extensions のバイト列はパースが面倒 & 重要度が低いので後回しにする
        return cls(cert_data=cert_data, extensions=[])


class Certificate:
    """
    struct {
      opaque certificate_request_context<0..2^8-1>;
      CertificateEntry certificate_list<0..2^24-1>;
    } Certificate;
    """
    def __init__(self, certificate_request_context=b'', certificate_list=[]):
        self.certificate_request_context = bytes(certificate_request_context)
        self.certificate_list = certificate_list

    def __repr__(self):
        props = collections.OrderedDict(
            certificate_request_context=bytes,
            certificate_list=list)
        return make_format(self, props)

    def __len__(self):
        return 1 + len(self.certificate_request_context) + \
               3 + sum(map(len, self.certificate_list))

    def to_bytes(self):
        writer = Writer()
        writer.add_bytes(self.certificate_request_context, length_t=Uint8)
        writer.add_list(self.certificate_list, length_t=Uint24)
        return writer.bytes

    @classmethod
    def from_bytes(cls, data):
        reader = Reader(data)
        certificate_request_context = reader.get_var_bytes(1)
        certificate_list_bytes = reader.get_var_bytes(3)
        certificate_list = []

        reader = Reader(certificate_list_bytes)
        while reader.get_rest_length() > 0:
            cert_data  = reader.get_var_bytes(3)
            extensions = reader.get_var_bytes(2)

            # extensions に入る拡張は status_request か signed_certificate_timestamp
            # extensions のバイト列はパースが面倒 & 重要度が低いので後回しにする
            entry = CertificateEntry(cert_data=cert_data, extensions=[])
            certificate_list.append(entry)

        return cls(certificate_request_context, certificate_list)


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

    def __len__(self):
        return len(self.algorithm) + 2 + len(self.signature)

    def __repr__(self):
        props = collections.OrderedDict(
            algorithm=SignatureScheme,
            signature=bytes)
        return make_format(self, props)

    def to_bytes(self):
        writer = Writer()
        writer.add_bytes(self.algorithm)
        writer.add_bytes(self.signature, length_t=Uint16)
        return writer.bytes

    @classmethod
    def from_bytes(cls, data):
        reader = Reader(data)
        algorithm = Uint16(reader.get(2))
        signature = reader.get_var_bytes(2)
        return cls(algorithm=algorithm, signature=signature)


class Finished:
    """
    struct {
      opaque verify_data[Hash.length];
    } Finished;
    """
    def __init__(self, verify_data):
        self.verify_data = verify_data

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

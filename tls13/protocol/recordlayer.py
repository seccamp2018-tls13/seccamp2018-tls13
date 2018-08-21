
# B.1.  Record Layer
# https://tools.ietf.org/html/draft-ietf-tls-tls13-26#appendix-B.1

__all__ = [
    'ContentType', 'TLSPlaintext', 'TLSInnerPlaintext', 'TLSCiphertext',
    'Data', 'TLSRawtext',
]

import collections

from .keyexchange.version import ProtocolVersion
from .alert import Alert
from ..utils import hexdump
from ..utils.type import Uint8, Uint16, Uint24, Uint32, Type
from ..utils.codec import Reader
from ..utils.repr import make_format
from ..utils.struct import Struct, Members, Member, Listof


@Type.add_labels_and_values
class ContentType(Type):
    """
    enum { ... } ContentType
    """
    invalid = Uint8(0)
    change_cipher_spec = Uint8(20)
    alert = Uint8(21)
    handshake = Uint8(22)
    application_data = Uint8(23)
    _size = 1 # byte


class TLSPlaintext(Struct):
    """
    struct {
      ContentType type;
      ProtocolVersion legacy_record_version;
      uint16 length;
      opaque fragment[TLSPlaintext.length];
    } TLSPlaintext;
    """
    def __init__(self, **kwargs):
        fragment = kwargs.get('fragment', b'')
        self.struct = Members(self, [
            Member(ContentType, 'type'),
            Member(ProtocolVersion, 'legacy_record_version'),
            Member(Uint16, 'length'),
            Member(Struct, 'fragment'),
        ])
        self.struct.set_default('legacy_record_version', Uint16(0x0303))
        self.struct.set_default('length', Uint16(len(fragment)))
        self.struct.set_args(**kwargs)

    def __getattr__(self, name):
        """
        self.fragment.msg の指名された属性の値を返す．
        このクラスでは self はrecord層，self.fragment はhandshake層を表していて，
        record層とhandshake層は通信の種類を区別するために必要だが，
        鍵共有等で使うデータ群は全てhandshake層より上の ClientHello や ServerHello にあるので，
        self.fragment.msg.foobar とする代わりに self.foobar で簡単にアクセスできるようにする．
        """
        if self.fragment is None or self.fragment.msg is None:
            raise AttributeError("'%s' object has no attribute '%s'" % \
                  (self.__class__.__name__, name))
        return getattr(self.fragment.msg, name)

    @classmethod
    def from_bytes(cls, data, mode=None):
        from .handshake import Handshake
        reader = Reader(data)
        type                  = reader.get(Uint8)
        legacy_record_version = reader.get(Uint16)
        # fragment              = reader.get(bytes, length_t=Uint16)
        # length = Uint16(len(fragment))
        length                = reader.get(Uint16)
        fragment              = reader.get(bytes)

        if mode:
            type = mode # e.g. mode=ContentType.handshake

        print("[+] type:", type, ContentType.labels[type])
        if type == ContentType.handshake:
            return cls(type=type, fragment=Handshake.from_bytes(fragment))
        elif type == ContentType.application_data:
            return cls(type=type, fragment=Data(fragment))
        elif type == ContentType.alert:
            return cls(type=type, fragment=Alert.from_bytes(fragment))
        else:
            raise NotImplementedError()


class Data(Struct):
    # TLSPlaintext.fragment にはTLS構造体や送信するデータなどが入るが Members で、
    # Member(Struct, 'fragment') と書いているので、Struct しか受け付けないように
    # なっていて、fragment に送信するデータ（バイト列）を入れるとエラーになる。
    # そこで、Struct を継承した Data というクラスを作る。
    # 使い方は：
    #
    #   TLSPlaintext(
    #       type=ContentType.application_data,
    #       fragment=Data(b'GET /index.html')
    #   )
    #
    def __init__(self, data):
        self.data = data

    def __repr__(self):
        return self.data.decode('utf-8')

    def __len__(self):
        return len(self.data)

    def hex(self):
        return self.data.hex()

    def to_bytes(self):
        return self.data

    @classmethod
    def from_bytes(self, data):
        return data


class TLSInnerPlaintext(Struct):
    """
    struct {
      opaque content[TLSPlaintext.length];
      ContentType type;
      uint8 zeros[length_of_padding];
    } TLSInnerPlaintext;
    """
    def __init__(self, content, type, length_of_padding):
        self.content = content # TLSPlaintext.fragment
        self.type = type
        self.zeros = b'\x00' * length_of_padding
        self._length_of_padding = length_of_padding

        self.struct = Members(self, [
            Member(bytes, 'content'),
            Member(ContentType, 'type'),
            Member(bytes, 'zeros'),
        ])

    @classmethod
    def from_bytes(cls, data):
        content, type, zeros = cls.split_pad(data)
        return cls(content=content, type=type, length_of_padding=len(zeros))

    @staticmethod
    def split_pad(data):
        for pos, value in zip(reversed(range(len(data))), reversed(data)):
            if value != 0:
                break
        return (data[:pos], Uint8(value), data[pos+1:]) # content, type, zeros

    @classmethod
    def create(cls, tlsplaintext, length_of_padding=None):
        if length_of_padding is None:
            # length_of_padding = 64 - len(tlsplaintext) % 64
            length_of_padding = 16 - len(tlsplaintext.fragment) % 16 - 1
        return cls(
            content=tlsplaintext.fragment.to_bytes(),
            type=tlsplaintext.type,
            length_of_padding=length_of_padding)


class TLSCiphertext(Struct):
    """
    struct {
      ContentType opaque_type = application_data; /* 23 */
      ProtocolVersion legacy_record_version = 0x0303; /* TLS v1.2 */
      uint16 length;
      opaque encrypted_record[TLSCiphertext.length];
    } TLSCiphertext;
    """
    def __init__(self, **kwargs):
        encrypted_record = kwargs.get('encrypted_record', b'')
        self.struct = Members(self, [
            Member(ContentType, 'opaque_type'),
            Member(ProtocolVersion, 'legacy_record_version'),
            Member(Uint16, 'length'),
            Member(bytes, 'encrypted_record'),
        ])
        self.struct.set_default('opaque_type', ContentType.application_data)
        self.struct.set_default('legacy_record_version', ProtocolVersion.TLS12)
        self.struct.set_default('length', Uint16(len(encrypted_record)))
        self.struct.set_args(**kwargs)

    @classmethod
    def from_bytes(cls, data):
        reader = Reader(data)
        opaque_type           = reader.get(Uint8)
        legacy_record_version = reader.get(Uint16)
        encrypted_record      = reader.get(bytes, length_t=Uint16)
        length = Uint16(len(encrypted_record))
        # length                = reader.get(Uint16)
        # encrypted_record      = reader.get(bytes)
        return cls(length=length, encrypted_record=encrypted_record)

    @classmethod
    def create(cls, tlsplaintext, crypto):
        # TLSPlaintext から TLSCiphertext を作るまでの処理
        app_data_inner = TLSInnerPlaintext.create(tlsplaintext)

        # additional_data =
        #   TLSCiphertext.opaque_type || .legacy_record_version || .length
        length = len(crypto.encrypt(app_data_inner.to_bytes(), nonce=crypto.iv)) + 16
        print("[+] length:", length)
        aad = b'\x17\x03\x03' + Uint16(length).to_bytes()
        print('[+] AAD:', aad.hex())

        encrypted_record = crypto.aead_encrypt(aad, app_data_inner.to_bytes())
        print('[+] encrypted_record:')
        print(encrypted_record.hex())
        app_data_cipher = TLSCiphertext(encrypted_record=encrypted_record)
        return app_data_cipher

    @classmethod
    def restore(cls, data, crypto, mode=None) -> TLSPlaintext:
        recved_app_data_cipher = TLSCiphertext.from_bytes(data)
        # print("[+] recved_app_data_cipher:")
        # print(recved_app_data_cipher)

        # additional_data =
        #   TLSCiphertext.opaque_type || .legacy_record_version || .length
        length = recved_app_data_cipher.length.value
        print("[+] length:", length)
        aad = b'\x17\x03\x03' + Uint16(length).to_bytes()
        print('[+] AAD:', aad.hex())
        # print('encrypted_record:', recved_app_data_cipher.encrypted_record.hex())

        # length から Alert かどうか判断する
        if length == 2:
            print("[-] Alert!")
            print(TLSPlaintext.from_bytes(data))
            raise RuntimeError("Alert!")

        print("[+] restore before:", recved_app_data_cipher.encrypted_record.hex())
        recved_app_data_inner_bytes = \
            crypto.aead_decrypt(aad, recved_app_data_cipher.encrypted_record)
        if recved_app_data_inner_bytes is None:
            raise RuntimeError('aead_decrypt Error')
        # print("restore after:", recved_app_data_inner_bytes.hex())
        print("[+] restore after:")
        print(hexdump(recved_app_data_inner_bytes))
        if mode == ContentType.application_data:
            content, type, zeros = \
                TLSInnerPlaintext.split_pad(recved_app_data_inner_bytes)
            print("content, type, zeros: ", content, type, zeros)
            return TLSRawtext(raw=content)

        recved_app_data_inner = \
            TLSInnerPlaintext.from_bytes(recved_app_data_inner_bytes)
        print("[+] recved_app_data_inner.content:")
        print(recved_app_data_inner.content.hex())
        recved_app_data = \
            TLSPlaintext.from_bytes(recved_app_data_inner.content, mode=mode)

        return recved_app_data

class TLSRawtext(Struct):
    """
    struct {
      ContentType opaque_type = application_data; /* 23 */
      ProtocolVersion legacy_record_version = 0x0303; /* TLS v1.2 */
      uint16 length;
      opaque raw[TLSCiphertext.length];
    } TLSCiphertext;
    """
    def __init__(self, **kwargs):
        self.struct = Members(self, [
            Member(ContentType, 'opaque_type'),
            Member(ProtocolVersion, 'legacy_record_version'),
            Member(bytes, 'raw', length_t=Uint16),
        ])
        self.struct.set_default('opaque_type', ContentType.application_data)
        self.struct.set_default('legacy_record_version', ProtocolVersion.TLS12)
        self.struct.set_args(**kwargs)

    @classmethod
    def from_bytes(cls, data):
        reader = Reader(data)
        opaque_type           = reader.get(Uint8)
        legacy_record_version = reader.get(Uint16)
        raw                   = reader.get(bytes, length_t=Uint16)
        return cls(raw=raw)

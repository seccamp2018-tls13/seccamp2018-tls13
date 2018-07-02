
# B.1.  Record Layer
# https://tools.ietf.org/html/draft-ietf-tls-tls13-26#appendix-B.1

import textwrap
from ..utils.type import Uint8, Uint16, Uint24, Uint32
from ..utils.codec import Reader
from ..utils import hexstr

class ContentType:
    """
    enum { ... } ContentType
    """
    invalid = Uint8(0)
    change_cipher_spec = Uint8(20)
    alert = Uint8(21)
    handshake = Uint8(22)
    application_data = Uint8(23)
    _size = 1 # byte

# inverted dict
# usage: ContentType.labels[Uint8(22)] # => 'handshake'
ContentType.labels = dict( (v,k) for k,v in ContentType.__dict__.items() )
ContentType.values = set( v for k,v in ContentType.__dict__.items() if type(v) == Uint8 )


class TLSPlaintext:
    """
    struct {
      ContentType type;
      ProtocolVersion legacy_record_version;
      uint16 length;
      opaque fragment[TLSPlaintext.length];
    } TLSPlaintext;
    """
    def __init__(self, _type, fragment, length=None):
        self.type = _type
        self.legacy_record_version = Uint16(0x0303)
        self.length = length or Uint16(len(fragment))
        self.fragment = fragment
        assert self.type in ContentType.values
        assert type(self.length) == Uint16

    def __repr__(self):
        return textwrap.dedent("""\
            %s:
            |type: %s == %s
            |legacy_record_version: %s
            |length: %s
            |fragment:
            """ % (
            self.__class__.__name__,
            self.type, ContentType.labels[self.type],
            self.legacy_record_version,
            self.length)) \
            + textwrap.indent(repr(self.fragment), prefix="    ")

    def __len__(self):
        return len(self.type) + len(self.legacy_record_version) + \
               len(self.length) + len(self.fragment)

    def to_bytes(self):
        byte_str = bytearray(0)
        byte_str += self.type.to_bytes()
        byte_str += self.legacy_record_version.to_bytes()
        byte_str += self.length.to_bytes()
        byte_str += self.fragment.to_bytes()
        return byte_str

    @classmethod
    def from_bytes(cls, data):
        from .handshake import Handshake
        reader = Reader(data)
        _type                 = Uint8(reader.get(1))
        legacy_record_version = Uint16(reader.get(2))
        length                = Uint16(reader.get(2))
        fragment              = reader.get_rest()

        assert length.value == len(fragment)

        if _type == ContentType.handshake:
            return cls(_type=_type, fragment=Handshake.from_bytes(fragment))
        else:
            raise NotImplementedError()


class TLSInnerPlaintext:
    """
    struct {
      opaque content[TLSPlaintext.length];
      ContentType type;
      uint8 zeros[length_of_padding];
    } TLSInnerPlaintext;
    """
    def __init__(self, content, _type, length_of_padding):
        self.content = content # TLSPlaintext.fragment
        self.type = _type
        self.zeros = b'\x00' * length_of_padding
        self._length_of_padding = length_of_padding


class TLSCiphertext:
    """
    struct {
      ContentType opaque_type = application_data; /* 23 */
      ProtocolVersion legacy_record_version = 0x0303; /* TLS v1.2 */
      uint16 length;
      opaque encrypted_record[TLSCiphertext.length];
    } TLSCiphertext;
    """
    def __init__(self, length, encrypted_record):
        self.opaque_type = 23
        self.legacy_record_version = Uint16(0x0303)
        self.length = length
        self.encrypted_record = encrypted_record

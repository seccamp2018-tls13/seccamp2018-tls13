
# B.1.  Record Layer
# https://tools.ietf.org/html/draft-ietf-tls-tls13-26#appendix-B.1

import textwrap
from ..utils import Uint8, Uint16, Uint24, Uint32

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


class TLSPlaintext:
    """
    struct {
      ContentType type;
      ProtocolVersion legacy_record_version;
      uint16 length;
      opaque fragment[TLSPlaintext.length];
    } TLSPlaintext;
    """
    def __init__(self, _type, length, fragment):
        self.type = _type
        self.legacy_record_version = b'\x03\x03'
        self.length = Uint16(length)
        self.fragment = fragment

    def __repr__(self):
        return textwrap.dedent("""\
            %s:
            |type: %s
            |legacy_record_version: %s
            |length: %s
            |fragment:
            """ % (
            self.__class__.__name__, self.type, self.legacy_record_version, \
            self.length)) \
            + textwrap.indent(repr(self.fragment), prefix="    ")

    def __len__(self):
        return len(self.type) + len(self.legacy_record_version) + \
               len(self.length) + len(self.fragment)


class TLSInnerPlaintext:
    """
    struct {
      opaque content[TLSPlaintext.length];
      ContentType type;
      uint8 zeros[length_of_padding];
    } TLSInnerPlaintext;
    """
    def __init__(self, content, _type, length_of_padding):
        self.content = content # TLSPLaintext.fragment
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
        self.legacy_record_version = b'\x03\x03'
        self.length = length
        self.encrypted_record = encrypted_record

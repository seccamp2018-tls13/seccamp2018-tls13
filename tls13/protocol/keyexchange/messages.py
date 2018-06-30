
# B.3.1.  Key Exchange Messages
# https://tools.ietf.org/html/draft-ietf-tls-tls13-26#appendix-B.3.1

import secrets
import textwrap
import pprint

from ...utils.type import Uint8, Uint16

class ClientHello:
    """
    struct {
      ProtocolVersion legacy_version = 0x0303;    /* TLS v1.2 */
      Random random;
      opaque legacy_session_id<0..32>;
      CipherSuite cipher_suites<2..2^16-2>;
      opaque legacy_compression_methods<1..2^8-1>;
      Extension extensions<8..2^16-1>;
    } ClientHello;
    """
    def __init__(self):
        self.legacy_version = Uint16(0x0303)
        self.random = secrets.token_bytes(32)
        self.legacy_session_id = secrets.token_bytes(32)
        self.cipher_suites = []
        self.legacy_compression_methods = [ Uint8(0x00) ]
        self.extensions = []

    def __repr__(self):
        return textwrap.dedent("""\
            %s:
            |legacy_version: %s
            |random: %s
            |legacy_session_id: %s
            |cipher_suites: %s
            |legacy_compression_methods: %s
            |extensions:
            """ % (
            self.__class__.__name__, self.legacy_version,
            self.random[0:10] + b'...',
            self.legacy_session_id[0:10] + b'...',
            self.cipher_suites,
            self.legacy_compression_methods)) \
            + textwrap.indent(pprint.pformat(self.extensions), prefix="    ")

    def __len__(self):
        return len(self.legacy_version) + len(self.random) + \
               1 + len(self.legacy_session_id) + \
               2 + sum(map(len, self.cipher_suites)) + \
               1 + sum(map(len, self.legacy_compression_methods)) + \
               2 + sum(map(len, self.extensions))

    def to_bytes(self):
        byte_str = bytearray(0)
        byte_str += self.legacy_version.to_bytes()
        byte_str += self.random
        # legacy_session_id
        byte_str += Uint8(len(self.legacy_session_id)).to_bytes()
        byte_str += self.legacy_session_id
        # cipher_suites
        byte_str += Uint16(sum(map(len, self.cipher_suites))).to_bytes()
        byte_str += b''.join(x.to_bytes() for x in self.cipher_suites)
        # legacy_compression_methods
        byte_str += Uint8(sum(map(len, self.legacy_compression_methods))).to_bytes()
        byte_str += b''.join(x.to_bytes() for x in self.legacy_compression_methods)
        # extensions
        byte_str += sum(map(len, self.extensions)).to_bytes(2, byteorder='big')
        byte_str += b''.join([ x.to_bytes() for x in self.extensions ])
        return byte_str


class ServerHello:
    """
    struct {
      ProtocolVersion legacy_version = 0x0303;    /* TLS v1.2 */
      Random random;
      opaque legacy_session_id_echo<0..32>;
      CipherSuite cipher_suite;
      uint8 legacy_compression_method = 0;
      Extension extensions<6..2^16-1>;
    } ServerHello;
    """
    def __init__(self):
        self.legacy_version = Uint16(0x0303)
        # TODO:
        self.random
        self.legacy_session_id_echo
        self.cipher_suite
        self.legacy_compression_method = 0 # uint8
        self.extensions = []


class Extension:
    """
    struct {
      ExtensionType extension_type;
      opaque extension_data<0..2^16-1>;
    } Extension;
    """
    def __init__(self, extension_type, extension_data):
        self.extension_type = extension_type
        self.extension_data = extension_data

    def __repr__(self):
        return textwrap.dedent("""\
            %s:
            |extension_type: %s
            |extension_data:
            """ % (self.__class__.__name__, self.extension_type)) \
            + textwrap.indent(repr(self.extension_data), prefix="    ")

    def __len__(self):
        return len(self.extension_type) + 2 + len(self.extension_data)

    def to_bytes(self):
        byte_str = bytearray(0)
        byte_str += self.extension_type.to_bytes()
        # extension_data
        byte_str += Uint16(len(self.extension_data)).to_bytes()
        byte_str += self.extension_data.to_bytes()
        return byte_str


class ExtensionType:
    """
    enum { ... } ExtensionType
    """
    server_name = Uint16(0)
    max_fragment_length = Uint16(1)
    status_request = Uint16(5)
    supported_groups = Uint16(10)
    signature_algorithms = Uint16(13)
    use_srtp = Uint16(14)
    heartbeat = Uint16(15)
    application_layer_protocol_negotiation = Uint16(16)
    signed_certificate_timestamp = Uint16(18)
    client_certificate_type = Uint16(19)
    server_certificate_type = Uint16(20)
    padding = Uint16(21)
    RESERVED = Uint16(40)
    pre_shared_key = Uint16(41)
    early_data = Uint16(42)
    supported_versions = Uint16(43)
    cookie = Uint16(44)
    psk_key_exchange_modes = Uint16(45)
    RESERVED = Uint16(46)
    certificate_authorities = Uint16(47)
    oid_filters = Uint16(48)
    post_handshake_auth = Uint16(49)
    signature_algorithms_cert = Uint16(50)
    key_share = Uint16(51)
    _size = 2 # byte


class KeyShareEntry:
    """
    struct {
      NamedGroup group;
      opaque key_exchange<1..2^16-1>;
    } KeyShareEntry;
    """
    def __init__(self, group, key_exchange):
        self.group = group
        self.key_exchange = key_exchange

    def __repr__(self):
        return textwrap.dedent("""\
            %s:
            |group: %s
            |key_exchange: %s""" % \
            (self.__class__.__name__, self.group,
             self.key_exchange[0:10] + b'...'))

    def __len__(self):
        return len(self.group) + 2 + len(self.key_exchange)

    def to_bytes(self):
        byte_str = bytearray(0)
        byte_str += self.group.to_bytes()
        byte_str += Uint16(len(self.key_exchange)).to_bytes()
        byte_str += self.key_exchange
        return byte_str


class KeyShareClientHello:
    """
    struct {
      KeyShareEntry client_shares<0..2^16-1>;
    } KeyShareClientHello;
    """
    def __init__(self, client_shares=[]):
        self.client_shares = client_shares

    def __repr__(self):
        return textwrap.dedent("""\
            %s:
            |client_shares:
            """ % (self.__class__.__name__)) \
            + textwrap.indent(repr(self.client_shares), prefix="    ")

    def __len__(self):
        return 2 + sum(map(len, self.client_shares))

    def to_bytes(self):
        byte_str = bytearray(0)
        byte_str += Uint16(len(self.client_shares)).to_bytes()
        byte_str += b''.join(x.to_bytes() for x in self.client_shares)
        return byte_str

# class KeyShareHelloRetryRequest
# class KeyShareServerHello:
# class UncompressedPointRepresentation
# class PskKeyExchangeMode
# class PskKeyExchangeModes
# class Empty
# class EarlyDataIndication
# class PskIdentity
# class OfferedPsks
# class PreSharedKeyExtension

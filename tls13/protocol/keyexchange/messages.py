
# B.3.1.  Key Exchange Messages
# https://tools.ietf.org/html/draft-ietf-tls-tls13-26#appendix-B.3.1

import secrets
import textwrap
import pprint
from binascii import hexlify

from .supportedgroups import NamedGroup
from ..ciphersuite import CipherSuite
from ...utils import hexstr
from ...utils.type import Uint8, Uint16, Uint24, Uint32, Type
from ...utils.codec import Reader


class HasExtension:
    def get_extension(self, extension_type):
        assert extension_type in ExtensionType.values
        assert type(self.extensions) == list
        for ext in self.extensions:
            if ext.extension_type == extension_type:
                return ext.extension_data
        return None


class ClientHello(HasExtension):
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
    def __init__(self, legacy_version=Uint16(0x0303),
                       random=secrets.token_bytes(32),
                       legacy_session_id=secrets.token_bytes(32),
                       cipher_suites=[],
                       extensions=[]):
        self.legacy_version = legacy_version
        self.random = random
        self.legacy_session_id = legacy_session_id
        self.cipher_suites = cipher_suites
        self.legacy_compression_methods = [ Uint8(0x00) ]
        self.extensions = extensions
        assert type(self.legacy_version) == Uint16
        assert type(self.random) in (bytes, bytearray)
        assert type(self.legacy_session_id) in (bytes, bytearray)
        assert type(self.extensions) == list
        assert all( type(ext) == Extension for ext in self.extensions )

    def __repr__(self):
        return textwrap.dedent("""\
            %s:
            |legacy_version: %s
            |random: %s (len=%d)
            |legacy_session_id: %s (len=%d)
            |cipher_suites: %s
            |legacy_compression_methods: %s
            |extensions:
            """ % (
            self.__class__.__name__, self.legacy_version,
            hexlify(self.random[0:10]) + b'...', len(self.random),
            hexlify(self.legacy_session_id[0:10]) + b'...', len(self.legacy_session_id),
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
        byte_str += Uint16(sum(map(len, self.extensions))).to_bytes()
        byte_str += b''.join([ x.to_bytes() for x in self.extensions ])
        return byte_str

    @classmethod
    def from_bytes(cls, data):
        from ..handshake import HandshakeType
        reader = Reader(data)
        legacy_version    = Uint16(reader.get(2))
        random            = reader.get_fix_bytes(32)
        legacy_session_id = reader.get_var_bytes(1)
        cipher_suites = \
            [Uint16(x) for x in reader.get_var_list(elem_length=2, length_length=2)]
        legacy_compression_methods = \
            [Uint8(x)  for x in reader.get_var_list(elem_length=1, length_length=1)]

        # Read extensions
        extensions = Extension.from_bytes(reader.get_rest(),
                                          msg_type=HandshakeType.client_hello)

        return cls(legacy_version=legacy_version,
                   random=random,
                   legacy_session_id=legacy_session_id,
                   cipher_suites=cipher_suites,
                   extensions=extensions)


class ServerHello(HasExtension):
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
    def __init__(self, legacy_version=Uint16(0x0303),
                       legacy_session_id_echo=secrets.token_bytes(32),
                       random=secrets.token_bytes(32),
                       cipher_suite=None, extensions=[]):
        self.legacy_version = Uint16(0x0303)
        self.random = random
        self.legacy_session_id_echo = legacy_session_id_echo
        self.cipher_suite = cipher_suite
        self.legacy_compression_method = Uint8(0x00)
        self.extensions = extensions
        assert type(self.random) in (bytes, bytearray)
        assert type(self.legacy_session_id_echo) in (bytes, bytearray)
        assert self.cipher_suite in CipherSuite.values
        assert type(self.extensions) == list
        assert all( type(ext) == Extension for ext in self.extensions )

    def __repr__(self):
        return textwrap.dedent("""\
            %s:
            |legacy_version: %s
            |random: %s (len=%d)
            |legacy_session_id_echo: %s (len=%d)
            |cipher_suite: %s
            |legacy_compression_method: %s
            |extensions:
            """ % (
            self.__class__.__name__, self.legacy_version,
            hexlify(self.random[0:10]) + b'...', len(self.random),
            hexlify(self.legacy_session_id_echo[0:10]) + b'...', len(self.legacy_session_id_echo),
            self.cipher_suite,
            self.legacy_compression_method)) \
            + textwrap.indent(pprint.pformat(self.extensions), prefix="    ")

    def __len__(self):
        return len(self.legacy_version) + len(self.random) + \
               1 + len(self.legacy_session_id_echo) + \
               len(self.cipher_suite) + \
               len(self.legacy_compression_method) + \
               2 + sum(map(len, self.extensions))

    def to_bytes(self):
        byte_str = bytearray(0)
        byte_str += self.legacy_version.to_bytes()
        byte_str += self.random
        # legacy_session_id_echo
        byte_str += Uint8(len(self.legacy_session_id_echo)).to_bytes()
        byte_str += self.legacy_session_id_echo
        # cipher_suites
        byte_str += self.cipher_suite.to_bytes()
        # legacy_compression_methods
        byte_str += self.legacy_compression_method.to_bytes()
        # extensions
        byte_str += Uint16(sum(map(len, self.extensions))).to_bytes()
        byte_str += b''.join([ x.to_bytes() for x in self.extensions ])
        return byte_str

    @classmethod
    def from_bytes(cls, data):
        from ..handshake import HandshakeType
        reader = Reader(data)
        legacy_version         = Uint16(reader.get(2))
        random                 = reader.get_fix_bytes(32)
        legacy_session_id_echo = reader.get_var_bytes(1)
        cipher_suite           = Uint16(reader.get(2))
        legacy_compression_methods = Uint8(reader.get(1))

        # Read extensions
        extensions = Extension.from_bytes(reader.get_rest(),
                                          msg_type=HandshakeType.server_hello)

        return cls(legacy_version=legacy_version,
                   random=random,
                   legacy_session_id_echo=legacy_session_id_echo,
                   cipher_suite=cipher_suite,
                   extensions=extensions)


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
        assert self.extension_type in ExtensionType.values

    def __repr__(self):
        return textwrap.dedent("""\
            %s:
            |extension_type: %s == %s
            |extension_data:
            """ % (
            self.__class__.__name__,
            self.extension_type, ExtensionType.labels[self.extension_type])) \
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

    @classmethod
    def from_bytes(cls, data, msg_type):
        from ..handshake import HandshakeType
        from .version import SupportedVersions
        from .supportedgroups import NamedGroupList
        from .signature import SignatureSchemeList
        reader = Reader(data)
        extensions = []
        extensions_length = reader.get(2)
        assert extensions_length == reader.get_rest_length()

        # Read extensions
        while reader.get_rest_length() != 0:
            extension_type = Uint16(reader.get(2))
            extension_data = reader.get_var_bytes(2)

            ExtClass = None
            kwargs = {}
            if extension_type == ExtensionType.supported_versions:
                ExtClass = SupportedVersions
                kwargs = {'msg_type': msg_type}
            elif extension_type == ExtensionType.supported_groups:
                ExtClass = NamedGroupList
            elif extension_type == ExtensionType.signature_algorithms:
                ExtClass = SignatureSchemeList
            elif extension_type == ExtensionType.key_share and \
                    msg_type == HandshakeType.client_hello:
                ExtClass = KeyShareClientHello
            elif extension_type == ExtensionType.key_share and \
                    msg_type == HandshakeType.server_hello:
                ExtClass = KeyShareServerHello
            else:
                raise NotImplementedError()

            extensions.append( cls(
                extension_type=extension_type,
                extension_data=ExtClass.from_bytes(extension_data, **kwargs)) )

        return extensions


@Type.add_labels_and_values
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
        assert self.group in NamedGroup.values
        assert type(self.key_exchange) in (bytes, bytearray)

    def __repr__(self):
        return textwrap.dedent("""\
            %s:
            |group: %s == %s
            |key_exchange: %s (len=%d)""" % ( \
            self.__class__.__name__,
            self.group, NamedGroup.labels[self.group],
            hexlify(self.key_exchange[0:10]) + b'...', len(self.key_exchange) ))

    def __len__(self):
        return len(self.group) + 2 + len(self.key_exchange)

    def to_bytes(self):
        byte_str = bytearray(0)
        byte_str += self.group.to_bytes()
        byte_str += Uint16(len(self.key_exchange)).to_bytes()
        byte_str += self.key_exchange
        return byte_str

    @classmethod
    def from_bytes(cls, data):
        reader = Reader(data)
        group = Uint16(reader.get(2))
        key_exchange = reader.get_var_bytes(2)
        return cls(group=group, key_exchange=key_exchange)


class KeyShareClientHello:
    """
    struct {
      KeyShareEntry client_shares<0..2^16-1>;
    } KeyShareClientHello;
    """
    def __init__(self, client_shares=[]):
        self.client_shares = client_shares
        assert type(self.client_shares) == list
        assert all( type(entry) == KeyShareEntry for entry in self.client_shares )

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
        byte_str += Uint16(sum(map(len, self.client_shares))).to_bytes()
        byte_str += b''.join(x.to_bytes() for x in self.client_shares)
        return byte_str

    @classmethod
    def from_bytes(cls, data):
        reader = Reader(data)

        # Read client_shares
        client_shares = []
        client_shares_length = reader.get(2)
        assert client_shares_length == reader.get_rest_length()

        while reader.get_rest_length() != 0:
            group = Uint16(reader.get(2))
            key_exchange = reader.get_var_bytes(2)
            client_shares.append( KeyShareEntry(group, key_exchange) )

        return cls(client_shares)

    def get_groups(self):
        return [client_share.group for client_share in self.client_shares]

    def get_key_exchange(self, group):
        assert group in NamedGroup.values
        assert type(self.client_shares) == list
        for client_share in self.client_shares:
            if client_share.group == group:
                return client_share.key_exchange
        return None


class KeyShareHelloRetryRequest:
    """
    struct {
      NamedGroup selected_group;
    } KeyShareHelloRetryRequest;
    """
    def __init__(self, selected_group):
        self.selected_group = selected_group
        assert self.selected_group in NamedGroup.values


class KeyShareServerHello:
    """
    struct {
      KeyShareEntry server_share;
    } KeyShareServerHello;
    """
    def __init__(self, server_share):
        self.server_share = server_share
        assert type(self.server_share) == KeyShareEntry

    def __repr__(self):
        return textwrap.dedent("""\
            %s:
            |server_share:
            """ % (self.__class__.__name__)) \
            + textwrap.indent(repr(self.server_share), prefix="    ")

    def __len__(self):
        return len(self.server_share)

    def to_bytes(self):
        return self.server_share.to_bytes()

    @classmethod
    def from_bytes(cls, data):
        return cls(server_share=KeyShareEntry.from_bytes(data))

    def get_group(self):
        return self.server_share.group

    def get_key_exchange(self):
        return self.server_share.key_exchange


class UncompressedPointRepresentation:
    """
    struct {
      uint8 legacy_form = 4;
      opaque X[coordinate_length];
      opaque Y[coordinate_length];
    } UncompressedPointRepresentation;
    """


@Type.add_labels_and_values
class PskKeyExchangeMode:
    """
    enum { psk_ke(0), psk_dhe_ke(1), (255) } PskKeyExchangeMode;
    """
    psk_ke = Uint8(0)
    psk_dhe_ke = Uint8(1)
    _size = 1


class PskKeyExchangeModes:
    """
    struct {
      PskKeyExchangeMode ke_modes<1..255>;
    } PskKeyExchangeModes;
    """
    def __init__(self, ke_modes=[]):
        self.ke_modes = ke_modes


class Empty:
    """
    struct {} Empty;
    """


class EarlyDataIndication:
    """
    struct {
      select (Handshake.msg_type) {
        case new_session_ticket:   uint32 max_early_data_size;
        case client_hello:         Empty;
        case encrypted_extensions: Empty;
      };
    } EarlyDataIndication;
    """
    def __init__(self, msg_type, max_early_data_size=Empty()):
        assert msg_type in HandshakeType.values
        self.msg_type = msg_type
        self.max_early_data_size = max_early_data_size
        if msg_type == Handshake.new_session_ticket:
            assert type(max_early_data_size) == Uint32


class PskIdentity:
    """
    struct {
      opaque identity<1..2^16-1>;
      uint32 obfuscated_ticket_age;
    } PskIdentity;
    """


class OfferedPsks:
    """
    struct {
      PskIdentity identities<7..2^16-1>;
      PskBinderEntry binders<33..2^16-1>;
    } OfferedPsks;
    """


class PreSharedKeyExtension:
    """
    struct {
      select (Handshake.msg_type) {
        case client_hello: OfferedPsks;
        case server_hello: uint16 selected_identity;
      };
    } PreSharedKeyExtension;
    """

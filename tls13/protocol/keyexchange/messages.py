
# B.3.1.  Key Exchange Messages
# https://tools.ietf.org/html/draft-ietf-tls-tls13-26#appendix-B.3.1

__all__ = [
    'ClientHello', 'ServerHello', 'Extension', 'ExtensionType',
    'KeyShareEntry', 'KeyShareClientHello', 'KeyShareHelloRetryRequest',
    'KeyShareServerHello', 'UncompressedPointRepresentation',
    'PskKeyExchangeMode', 'PskKeyExchangeModes', 'Empty', 'EarlyDataIndication',
    'PskIdentity', 'OfferedPsks', 'PreSharedKeyExtension'
]

import sys
import secrets
import collections
from .supportedgroups import NamedGroup
from .version import ProtocolVersion
from ..ciphersuite import CipherSuite
from ...metastruct import *

def find(lst, cond):
    assert isinstance(lst, collections.Iterable)
    return next((x for x in lst if cond(x)), None)


class Random(bytes):
    """ opaque Random[32]; """
    _size = 32


class HasExtension:
    """
    Mixin class HasExtension implements common operation about extension.
    """
    def get_extension(self, extension_type):
        assert extension_type in ExtensionType.values()
        ext = find(self.extensions, lambda ext: ext.extension_type == extension_type)
        return getattr(ext, 'extension_data', None)


class ClientHello(Struct, HasExtension):
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
    def __init__(self, **kwargs):
        self.struct = Members(self, [
            Member(ProtocolVersion, 'legacy_version'),
            Member(Random, 'random'),
            Member(bytes, 'legacy_session_id', length_t=Uint8),
            Member(Listof(CipherSuite), 'cipher_suites', length_t=Uint16),
            Member(Listof(Uint8), 'legacy_compression_methods', length_t=Uint8),
            Member(Listof(Extension), 'extensions', length_t=Uint16),
        ])
        self.struct.set_default('legacy_version', Uint16(0x0303))
        self.struct.set_default('random', secrets.token_bytes(32))
        self.struct.set_default('legacy_session_id', secrets.token_bytes(32))
        self.struct.set_default('legacy_compression_methods', [Uint8(0x00)])
        self.struct.set_args(**kwargs)

    @classmethod
    def from_bytes(cls, data):
        from ..handshake import HandshakeType
        reader = Reader(data)
        legacy_version    = reader.get(Uint16)
        random            = reader.get(Random)
        legacy_session_id = reader.get(bytes, length_t=Uint8)
        cipher_suites = reader.get(Listof(CipherSuite), length_t=Uint16)
        legacy_compression_methods = reader.get(Listof(Uint8), length_t=Uint8)

        # Read extensions
        extensions = Extension.get_list_from_bytes(
            reader.get_rest(),
            msg_type=HandshakeType.client_hello)

        return cls(legacy_version=legacy_version,
                   random=random,
                   legacy_session_id=legacy_session_id,
                   cipher_suites=cipher_suites,
                   extensions=extensions)


class ServerHello(Struct, HasExtension):
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
    def __init__(self, **kwargs):
        self.struct = Members(self, [
            Member(ProtocolVersion, 'legacy_version'),
            Member(Random, 'random'),
            Member(bytes, 'legacy_session_id_echo', length_t=Uint8),
            Member(CipherSuite, 'cipher_suite'),
            Member(Uint8, 'legacy_compression_method'),
            Member(Listof(Extension), 'extensions', length_t=Uint16),
        ])
        self.struct.set_default('legacy_version', Uint16(0x0303))
        self.struct.set_default('random', secrets.token_bytes(32))
        self.struct.set_default('legacy_session_id_echo', secrets.token_bytes(32))
        self.struct.set_default('legacy_compression_method', Uint8(0x00))
        self.struct.set_args(**kwargs)

    @classmethod
    def from_bytes(cls, data):
        from ..handshake import HandshakeType
        reader = Reader(data)
        legacy_version             = reader.get(Uint16)
        random                     = reader.get(Random)
        legacy_session_id_echo     = reader.get(bytes, length_t=Uint8)
        cipher_suite               = reader.get(Uint16)
        legacy_compression_methods = reader.get(Uint8)

        # Read extensions
        extensions = Extension.get_list_from_bytes(
            reader.get_rest(),
            msg_type=HandshakeType.server_hello)

        return cls(legacy_version=legacy_version,
                   random=random,
                   legacy_session_id_echo=legacy_session_id_echo,
                   cipher_suite=cipher_suite,
                   extensions=extensions)


class Extension(Struct):
    """
    struct {
      ExtensionType extension_type;
      opaque extension_data<0..2^16-1>;
    } Extension;
    """
    def __init__(self, **kwargs):
        self.struct = Members(self, [
            Member(ExtensionType, 'extension_type'),
            Member(Struct, 'extension_data', length_t=Uint16),
        ])
        self.struct.set_args(**kwargs)

    @classmethod
    def from_bytes(cls, data=b'', msg_type=None, reader=None):
        is_given_reader = bool(reader)
        if not is_given_reader:
            reader = Reader(data)

        extension_type = reader.get(Uint16)
        extension_data = reader.get(bytes, length_t=Uint16)

        ExtClass, kwargs = cls.get_extension_class(extension_type, msg_type)
        if ExtClass is None:
            obj = None
        else:
            obj = cls(
                extension_type=extension_type,
                extension_data=ExtClass.from_bytes(extension_data, **kwargs))

        if is_given_reader:
            return (obj, reader)
        return obj

    # バイト列から再構築するときにそれぞれの拡張を配列に入れて返す関数。
    # ClientHello や ServerHello などのあらゆるメッセージでは拡張は複数あり、
    # それぞれの拡張のバイト長は異なるので、他の from_bytes のように実装は簡単ではない。
    @classmethod
    def get_list_from_bytes(cls, data, msg_type=None):
        reader = Reader(data)
        extensions = []
        extensions_length = reader.get(2)
        assert extensions_length == reader.get_rest_length()

        # Read extensions
        while reader.get_rest_length() != 0:
            ext, reader = cls.from_bytes(reader=reader, msg_type=msg_type)
            if ext is None: continue
            extensions.append(ext)

        return extensions

    # 拡張の種類 extension_type から、それを構成するためのクラス ExtClass と kwargs を返す。
    # 辞書型 kwargs には、ExtClass.from_bytes を行うときにどちらの通信なのかを
    # 引数に与える必要がある場合、必要な引数を kwargs に入れて返す。
    # いくつかのクラスは client_hello か server_hello によって構造体の中身が変わるので、
    # どちらの通信なのかを引数 msg_type に設定する必要がある可能性がある。
    # もし必要なのに引数 msg_type が設定されていないときは RuntimeError を出す。
    @classmethod
    def get_extension_class(self, extension_type, msg_type=None):
        from ..handshake import HandshakeType
        from .version import SupportedVersions
        from .supportedgroups import NamedGroupList
        from .signature import SignatureSchemeList

        ExtClass = None
        kwargs = {}

        if extension_type == ExtensionType.supported_versions:
            if msg_type is None:
                raise RuntimeError("must be set msg_type to get_extension_class()")
            ExtClass = SupportedVersions
            kwargs = {'msg_type': msg_type}

        elif extension_type == ExtensionType.supported_groups:
            ExtClass = NamedGroupList

        elif extension_type == ExtensionType.signature_algorithms:
            ExtClass = SignatureSchemeList

        elif extension_type == ExtensionType.key_share:
            if msg_type == HandshakeType.client_hello:
                ExtClass = KeyShareClientHello
            elif msg_type == HandshakeType.server_hello:
                ExtClass = KeyShareServerHello
            else:
                raise RuntimeError("must be set msg_type to get_extension_class()")

        else:
            output = 'Extension: unknown extension: %s' % extension_type
            if extension_type in ExtensionType.labels:
                output += ' == %s' % ExtensionType.labels[extension_type]
            print(output, file=sys.stdout)
            return (None, None)

        return (ExtClass, kwargs)


class ExtensionType(Type):
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


class KeyShareEntry(Struct):
    """
    struct {
      NamedGroup group;
      opaque key_exchange<1..2^16-1>;
    } KeyShareEntry;
    """
    def __init__(self, **kwargs):
        self.struct = Members(self, [
            Member(NamedGroup, 'group'),
            Member(bytes, 'key_exchange', length_t=Uint16),
        ])
        self.struct.set_args(**kwargs)

    @classmethod
    def from_bytes(cls, data=b'', reader=None):
        is_given_reader = bool(reader)
        if not is_given_reader:
            reader = Reader(data)

        group = reader.get(Uint16)
        key_exchange = reader.get(bytes, length_t=Uint16)
        obj = cls(group=group, key_exchange=key_exchange)

        if is_given_reader:
            return (obj, reader)
        return obj


class KeyShareClientHello(Struct):
    """
    struct {
      KeyShareEntry client_shares<0..2^16-1>;
    } KeyShareClientHello;
    """
    def __init__(self, **kwargs):
        self.struct = Members(self, [
            Member(Listof(KeyShareEntry), 'client_shares', length_t=Uint16),
        ])
        self.struct.set_args(**kwargs)

    @classmethod
    def from_bytes(cls, data):
        reader = Reader(data)

        # Read client_shares
        client_shares = []
        client_shares_length = reader.get(2)
        assert client_shares_length == reader.get_rest_length()

        while reader.get_rest_length() != 0:
            entry, reader = KeyShareEntry.from_bytes(reader=reader)
            client_shares.append(entry)

        return cls(client_shares=client_shares)

    def get_groups(self):
        return [client_share.group for client_share in self.client_shares]

    def get_key_exchange(self, group):
        assert group in NamedGroup.values()
        cs = find(self.client_shares, lambda cs: cs.group == group)
        return getattr(cs, 'key_exchange', None)


class KeyShareHelloRetryRequest(Struct):
    """
    struct {
      NamedGroup selected_group;
    } KeyShareHelloRetryRequest;
    """
    def __init__(self, selected_group):
        self.selected_group = selected_group
        assert self.selected_group in NamedGroup.values()


class KeyShareServerHello(Struct):
    """
    struct {
      KeyShareEntry server_share;
    } KeyShareServerHello;
    """
    def __init__(self, server_share):
        self.server_share = server_share
        assert isinstance(self.server_share, KeyShareEntry)

        self.struct = Members(self, [
            Member(KeyShareEntry, 'server_share'),
        ])

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


class PskKeyExchangeMode(Type):
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

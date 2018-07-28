
# B.3.1.  Key Exchange Messages
# https://tools.ietf.org/html/draft-ietf-tls-tls13-26#appendix-B.3.1

__all__ = [
    'ClientHello', 'ServerHello', 'Extension', 'ExtensionType',
    'KeyShareEntry', 'KeyShareClientHello', 'KeyShareHelloRetryRequest',
    'KeyShareServerHello', 'UncompressedPointRepresentation',
    'PskKeyExchangeMode', 'PskKeyExchangeModes', 'Empty', 'EarlyDataIndication',
    'PskIdentity', 'OfferedPsks', 'PreSharedKeyExtension'
]

import secrets
import collections

from .supportedgroups import NamedGroup
from .version import ProtocolVersion
from ..ciphersuite import CipherSuite
from ...utils import hexstr, make_format, Uint8, Uint16, Type, Reader, Writer
from ...utils.struct import Struct, Members, Member, Listof


def find(lst, cond):
    assert isinstance(lst, collections.Iterable)
    return next((x for x in lst if cond(x)), None)


class HasExtension:
    """
    Mixin class HasExtension implements common operation about extension.
    """
    def get_extension(self, extension_type):
        assert extension_type in ExtensionType.values
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

        self.struct = Members(self, [
            Member(ProtocolVersion, 'legacy_version'),
            Member(bytes, 'random'),
            Member(bytes, 'legacy_session_id', length_t=Uint8),
            Member(Listof(CipherSuite), 'cipher_suites', length_t=Uint16),
            Member(Listof(Uint8), 'legacy_compression_methods', length_t=Uint8),
            Member(Listof(Extension), 'extensions', length_t=Uint16),
        ])

    @classmethod
    def from_bytes(cls, data):
        from ..handshake import HandshakeType
        reader = Reader(data)
        legacy_version    = reader.get(Uint16)
        random            = reader.get_fix_bytes(32)
        legacy_session_id = reader.get_var_bytes(1)
        cipher_suites = \
            reader.get_uint_var_list(elem=Uint16, length_length=2)
        legacy_compression_methods = \
            reader.get_uint_var_list(elem=Uint8, length_length=1)

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

        self.struct = Members(self, [
            Member(ProtocolVersion, 'legacy_version'),
            Member(bytes, 'random'),
            Member(bytes, 'legacy_session_id_echo', length_t=Uint8),
            Member(CipherSuite, 'cipher_suite'),
            Member(Uint8, 'legacy_compression_method'),
            Member(Listof(Extension), 'extensions', length_t=Uint16),
        ])

    @classmethod
    def from_bytes(cls, data):
        from ..handshake import HandshakeType
        reader = Reader(data)
        legacy_version             = reader.get(Uint16)
        random                     = reader.get_fix_bytes(32)
        legacy_session_id_echo     = reader.get_var_bytes(1)
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
    def __init__(self, extension_type, extension_data):
        self.extension_type = extension_type
        self.extension_data = extension_data
        assert self.extension_type in ExtensionType.values

        self.struct = Members(self, [
            Member(ExtensionType, 'extension_type'),
            Member(object, 'extension_data', length_t=Uint16),
        ])

    @classmethod
    def from_bytes(cls, data, msg_type=None):
        reader = Reader(data)
        extension_type = reader.get(Uint16)
        extension_data = reader.get_var_bytes(2)

        ExtClass, kwargs = cls.get_extension_class(extension_type, msg_type)

        return cls(
            extension_type=extension_type,
            extension_data=ExtClass.from_bytes(extension_data, **kwargs))

    @classmethod
    def get_list_from_bytes(cls, data, msg_type=None):
        """
        バイト列から再構築するときにそれぞれの拡張を配列に入れて返す関数．
        ClientHello や ServerHello などのあらゆるメッセージでは拡張は複数あり，
        それぞれの拡張のバイト長は異なるので，他の from_bytes のように実装は簡単ではない．
        """
        reader = Reader(data)
        extensions = []
        extensions_length = reader.get(2)
        assert extensions_length == reader.get_rest_length()

        # Read extensions
        while reader.get_rest_length() != 0:
            extension_type = reader.get(Uint16)
            extension_data = reader.get_var_bytes(2)

            # 拡張の種類から，拡張を表すクラスを取得する
            ExtClass, kwargs = cls.get_extension_class(extension_type, msg_type)

            extensions.append( cls(
                extension_type=extension_type,
                extension_data=ExtClass.from_bytes(extension_data, **kwargs)) )

        return extensions

    @classmethod
    def get_extension_class(self, extension_type, msg_type=None):
        """
        拡張の種類 extension_type から，それを構成するためのクラス ExtClass と kwargs を返す．
        辞書型 kwargs には，ExtClass.from_bytes を行うときにどちらの通信なのかを
        引数に与える必要がある場合，必要な引数を kwargs に入れて返す．
        いくつかのクラスは client_hello か server_hello によって構造体の中身が変わるので，
        どちらの通信なのかを引数 msg_type に設定する必要がある可能性がある．
        もし必要なのに引数 msg_type が設定されていないときは RuntimeError を出す．
        """
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
            raise NotImplementedError()

        return (ExtClass, kwargs)


@Type.add_labels_and_values
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
    def __init__(self, group, key_exchange=b''):
        self.group = group
        self.key_exchange = key_exchange
        assert self.group in NamedGroup.values

        self.struct = Members(self, [
            Member(NamedGroup, 'group'),
            Member(bytes, 'key_exchange', length_t=Uint16),
        ])

    @classmethod
    def from_bytes(cls, data):
        reader = Reader(data)
        group = reader.get(Uint16)
        key_exchange = reader.get_var_bytes(2)
        return cls(group=group, key_exchange=key_exchange)


class KeyShareClientHello(Struct):
    """
    struct {
      KeyShareEntry client_shares<0..2^16-1>;
    } KeyShareClientHello;
    """
    def __init__(self, client_shares=[]):
        self.client_shares = client_shares
        assert all(type(entry) == KeyShareEntry for entry in self.client_shares)

        self.struct = Members(self, [
            Member(Listof(KeyShareEntry), 'client_shares', length_t=Uint16),
        ])

    @classmethod
    def from_bytes(cls, data):
        reader = Reader(data)

        # Read client_shares
        client_shares = []
        client_shares_length = reader.get(2)
        assert client_shares_length == reader.get_rest_length()

        while reader.get_rest_length() != 0:
            group = reader.get(Uint16)
            key_exchange = reader.get_var_bytes(2)
            client_shares.append( KeyShareEntry(group, key_exchange) )

        return cls(client_shares)

    def get_groups(self):
        return [client_share.group for client_share in self.client_shares]

    def get_key_exchange(self, group):
        assert group in NamedGroup.values
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
        assert self.selected_group in NamedGroup.values


class KeyShareServerHello(Struct):
    """
    struct {
      KeyShareEntry server_share;
    } KeyShareServerHello;
    """
    def __init__(self, server_share):
        self.server_share = server_share
        assert type(self.server_share) == KeyShareEntry

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


@Type.add_labels_and_values
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


# B.3.1.  Key Exchange Messages
# https://tools.ietf.org/html/draft-ietf-tls-tls13-26#appendix-B.3.1

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
        self.legacy_version = b'\x03\x03'
        # TODO:
        self.random
        self.legacy_session_id
        self.cipher_suites = []
        self.legacy_compression_methods = 0
        self.extensions = []


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
        self.legacy_version = b'\x03\x03'
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
    def __init__(self, extension_type):
        self.extension_type = extension_type
        self.extension_data = extension_data


class ExtensionType:
    """
    enum { ... } ExtensionType
    """
    server_name = 0
    max_fragment_length = 1
    status_request = 5
    supported_groups = 10
    signature_algorithms = 13
    use_srtp = 14
    heartbeat = 15
    application_layer_protocol_negotiation = 16
    signed_certificate_timestamp = 18
    client_certificate_type = 19
    server_certificate_type = 20
    padding = 21
    RESERVED = 40
    pre_shared_key = 41
    early_data = 42
    supported_versions = 43
    cookie = 44
    psk_key_exchange_modes = 45
    RESERVED = 46
    certificate_authorities = 47
    oid_filters = 48
    post_handshake_auth = 49
    signature_algorithms_cert = 50
    key_share = 51
    _size = 2 # byte


class KeyShareEntry:
    """
    struct {
      NamedGroup group;
      opaque key_exchange<1..2^16-1>;
    } KeyShareEntry;
    """
    def __init__(self):
        self.group
        self.key_exchange


# class KeyShareClientHello:
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

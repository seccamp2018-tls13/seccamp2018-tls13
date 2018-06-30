
# B.2.  Alert Messages
# https://tools.ietf.org/html/draft-ietf-tls-tls13-26#appendix-B.2

from ..utils.type import Uint8

class AlertLevel:
    """
    enum { ... } AlertLevel
    """
    warning = Uint8(1)
    fatal = Uint8(2)
    _size = 1 # byte


class AlertDescription:
    """
    enum { ... } AlertDescription
    """
    close_notify = Uint8(0)
    unexpected_message = Uint8(10)
    bad_record_mac = Uint8(20)
    decryption_failed_RESERVED = Uint8(21)
    record_overflow = Uint8(22)
    decompression_failure_RESERVED = Uint8(30)
    handshake_failure = Uint8(40)
    no_certificate_RESERVED = Uint8(41)
    bad_certificate = Uint8(42)
    unsupported_certificate = Uint8(43)
    certificate_revoked = Uint8(44)
    certificate_expired = Uint8(45)
    certificate_unknown = Uint8(46)
    illegal_parameter = Uint8(47)
    unknown_ca = Uint8(48)
    access_denied = Uint8(49)
    decode_error = Uint8(50)
    decrypt_error = Uint8(51)
    export_restriction_RESERVED = Uint8(60)
    protocol_version = Uint8(70)
    insufficient_security = Uint8(71)
    internal_error = Uint8(80)
    inappropriate_fallback = Uint8(86)
    user_canceled = Uint8(90)
    no_renegotiation_RESERVED = Uint8(100)
    missing_extension = Uint8(109)
    unsupported_extension = Uint8(110)
    certificate_unobtainable = Uint8(111)
    unrecognized_name = Uint8(112)
    bad_certificate_status_response = Uint8(113)
    bad_certificate_hash_value = Uint8(114)
    unknown_psk_identity = Uint8(115)
    certificate_required = Uint8(116)
    no_application_protocol = Uint8(120)
    _size = 1 # byte


class Alert:
    """
    struct {
      AlertLevel level;
      AlertDescription description;
    } Alert;
    """
    def __init__(self, level, description):
        self.level = level
        self.description = description

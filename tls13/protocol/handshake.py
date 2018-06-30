
# B.3.  Handshake Protocol
# https://tools.ietf.org/html/draft-ietf-tls-tls13-26#appendix-B.3

from ..utils import Uint8, Uint16, Uint24, Uint32

class HandshakeType:
    """
    enum { ... } HandshakeType
    """
    hello_request_RESERVED = Uint16(0)
    client_hello = Uint16(1)
    server_hello = Uint16(2)
    hello_verify_request_RESERVED = Uint16(3)
    new_session_ticket = Uint16(4)
    end_of_early_data = Uint16(5)
    hello_retry_request_RESERVED = Uint16(6)
    encrypted_extensions = Uint16(8)
    certificate = Uint16(11)
    server_key_exchange_RESERVED = Uint16(12)
    certificate_request = Uint16(13)
    server_hello_done_RESERVED = Uint16(14)
    certificate_verify = Uint16(15)
    client_key_exchange_RESERVED = Uint16(16)
    finished = Uint16(20)
    key_update = Uint16(24)
    message_hash = Uint16(254)
    _size = 1 # byte


class Handshake:
    """
    struct {
      HandshakeType msg_type;    /* handshake type */
      uint24 length;             /* bytes in message */
      select (Handshake.msg_type) {
        case client_hello:          ClientHello;
        case server_hello:          ServerHello;
        case end_of_early_data:     EndOfEarlyData;
        case encrypted_extensions:  EncryptedExtensions;
        case certificate_request:   CertificateRequest;
        case certificate:           Certificate;
        case certificate_verify:    CertificateVerify;
        case finished:              Finished;
        case new_session_ticket:    NewSessionTicket;
        case key_update:            KeyUpdate;
      };
    } Handshake;
    """
    def __init__(self, msg_type, length, msg):
        self.msg_type = msg_type # HandshakeType
        self.length = Uint24(length)
        self.msg = msg

    def __len__(self):
        return len(self.msg_type) + len(self.length) + len(self.msg)

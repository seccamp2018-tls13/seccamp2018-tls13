
# B.3.  Handshake Protocol
# https://tools.ietf.org/html/draft-ietf-tls-tls13-26#appendix-B.3

class HandshakeType:
    """
    enum { ... } HandshakeType
    """
    hello_request_RESERVED = 0
    client_hello = 1
    server_hello = 2
    hello_verify_request_RESERVED = 3
    new_session_ticket = 4
    end_of_early_data = 5
    hello_retry_request_RESERVED = 6
    encrypted_extensions = 8
    certificate = 11
    server_key_exchange_RESERVED = 12
    certificate_request = 13
    server_hello_done_RESERVED = 14
    certificate_verify = 15
    client_key_exchange_RESERVED = 16
    finished = 20
    key_update = 24
    message_hash = 254
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
    def __init__(self, msg_type, length):
        self.msg_type = msg_type # HandshakeType
        self.length = length
        self._msg = None # TODO:

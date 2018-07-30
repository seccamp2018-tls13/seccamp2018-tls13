
# B.3.  Handshake Protocol
# https://tools.ietf.org/html/draft-ietf-tls-tls13-26#appendix-B.3

__all__ = ['HandshakeType', 'Handshake']

import collections

from ..utils.type import Uint8, Uint16, Uint24, Uint32, Type
from ..utils.codec import Reader
from ..utils.repr import make_format
from ..utils.struct import Struct, Members, Member, Listof


@Type.add_labels_and_values
class HandshakeType(Type):
    """
    enum { ... } HandshakeType
    """
    hello_request_RESERVED = Uint8(0)
    client_hello = Uint8(1)
    server_hello = Uint8(2)
    hello_verify_request_RESERVED = Uint8(3)
    new_session_ticket = Uint8(4)
    end_of_early_data = Uint8(5)
    hello_retry_request_RESERVED = Uint8(6)
    encrypted_extensions = Uint8(8)
    certificate = Uint8(11)
    server_key_exchange_RESERVED = Uint8(12)
    certificate_request = Uint8(13)
    server_hello_done_RESERVED = Uint8(14)
    certificate_verify = Uint8(15)
    client_key_exchange_RESERVED = Uint8(16)
    finished = Uint8(20)
    key_update = Uint8(24)
    message_hash = Uint8(254)
    _size = 1 # byte


class Handshake(Struct):
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
    def __init__(self, **kwargs):
        msg = kwargs.get('msg', b'')
        self.struct = Members(self, [
            Member(HandshakeType, 'msg_type'),
            Member(Uint24, 'length'),
            Member(Struct, 'msg'),
        ])
        self.struct.set_default('legacy_record_version', Uint16(0x0303))
        self.struct.set_default('length', Uint24(len(kwargs['msg'] or b'')))
        self.struct.set_args(**kwargs)

        assert self.msg_type in HandshakeType.values

    @classmethod
    def from_bytes(cls, data):
        from .keyexchange.messages import ClientHello, ServerHello
        from .keyexchange.authentication import Certificate
        reader = Reader(data)
        msg_type = reader.get(Uint8)
        length   = reader.get(Uint24)
        msg      = reader.get(bytes)

        assert length.value == len(msg)

        if msg_type == HandshakeType.client_hello:
            return cls(msg_type=msg_type, msg=ClientHello.from_bytes(msg))
        elif msg_type == HandshakeType.server_hello:
            return cls(msg_type=msg_type, msg=ServerHello.from_bytes(msg))
        elif msg_type == HandshakeType.certificate:
            return cls(msg_type=msg_type, msg=Certificate.from_bytes(msg))
        else:
            raise NotImplementedError()

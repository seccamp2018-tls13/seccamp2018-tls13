
# B.3.1.1.  Version Extension
# https://tools.ietf.org/html/draft-ietf-tls-tls13-26#appendix-B.3.1.1

__all__ = ['ProtocolVersion', 'SupportedVersions']

import collections

from ..handshake import HandshakeType
from ...utils.type import Uint8, Uint16, Type
from ...utils.codec import Reader, Writer
from ...utils.repr import make_format
from ...utils.struct import Struct, Members, Member, Listof


@Type.add_labels_and_values
class ProtocolVersion(Type):
    # TLSバージョン
    SSL3  = Uint16(0x0300)
    TLS10 = Uint16(0x0301)
    TLS11 = Uint16(0x0302)
    TLS12 = Uint16(0x0303)
    TLS13 = Uint16(0x0304)
    _size = 2


class SupportedVersions(Struct):
    # クライアントはどのTLSバージョンをサポートしているかを示すのに使う。
    # サーバはどのTLSバージョンで通信を行うかを示すのに使う。
    """
    struct {
      select (Handshake.msg_type) {
        case client_hello:
          ProtocolVersion versions<2..254>;
        case server_hello: /* and HelloRetryRequest */
          ProtocolVersion selected_version;
      };
    } SupportedVersions;
    """
    def __init__(self, msg_type, **kwargs):
        self.msg_type = msg_type
        if self.msg_type == HandshakeType.client_hello:
            member = Member(Listof(ProtocolVersion), 'versions', length_t=Uint8)
        elif self.msg_type == HandshakeType.server_hello:
            member = Member(ProtocolVersion, 'selected_version')
        else:
            raise RuntimeError("Unkown message type: %s" % msg_type)

        self.struct = Members(self, [member])
        self.struct.set_args(**kwargs)

    @classmethod
    def from_bytes(cls, data, msg_type):
        reader = Reader(data)
        if msg_type == HandshakeType.client_hello:
            versions = reader.get(Listof(ProtocolVersion), length_t=Uint8)
            return cls(msg_type=msg_type, versions=versions)
        elif msg_type == HandshakeType.server_hello:
            selected_version = reader.get(Uint16)
            return cls(msg_type=msg_type, selected_version=selected_version)
        else:
            raise RuntimeError("Unkown message type: %s" % msg_type)

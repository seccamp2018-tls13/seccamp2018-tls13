
# B.3.1.1.  Version Extension
# https://tools.ietf.org/html/draft-ietf-tls-tls13-26#appendix-B.3.1.1

from ..handshake import HandshakeType

class SupportedVersions:
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
    def __init__(self, msg_type, versions=[], selected_version=None):
        self.msg_type = msg_type
        if self.msg_type == HandshakeType.client_hello:
            self.versions = versions
        elif self.msg_type == HandshakeType.server_hello:
            self.selected_version = selected_version
        else:
            raise RuntimeError("Unkown message type: %s" % msg_type)

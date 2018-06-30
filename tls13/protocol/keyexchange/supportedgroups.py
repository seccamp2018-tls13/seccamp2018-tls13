
# B.3.1.4.  Supported Groups Extension
# https://tools.ietf.org/html/draft-ietf-tls-tls13-26#appendix-B.3.1.4

from ...utils import Uint16

class NamedGroup:
    """
    enum { ... } NamedGroup
    """
    # Elliptic Curve Groups (ECDHE)
    obsolete_RESERVED = (Uint16(0x0001), Uint16(0x0016))
    secp256r1 = Uint16(0x0017)
    secp384r1 = Uint16(0x0018)
    secp521r1 = Uint16(0x0019)
    obsolete_RESERVED = (Uint16(0x001A), Uint16(0x001C))
    x25519 = Uint16(0x001D)
    x448 = Uint16(0x001E)

    # Finite Field Groups (DHE)
    # https://tools.ietf.org/html/rfc7919#appendix-A
    ffdhe2048 = Uint16(0x0100)
    ffdhe3072 = Uint16(0x0101)
    ffdhe4096 = Uint16(0x0102)
    ffdhe6144 = Uint16(0x0103)
    ffdhe8192 = Uint16(0x0104)

    # Reserved Code Points
    ffdhe_private_use = (Uint16(0x01FC), Uint16(0x01FF))
    ecdhe_private_use = (Uint16(0xFE00), Uint16(0xFEFF))
    obsolete_RESERVED = (Uint16(0xFF01), Uint16(0xFF02))

    _size = 2 # byte


class NamedGroupList:
    """
    struct {
      NamedGroup named_group_list<2..2^16-1>;
    } NamedGroupList;
    """
    def __init__(self, named_group_list=[]):
        self.named_group_list = named_group_list

    def __len__(self):
        return 2 + sum(map(len, self.named_group_list))

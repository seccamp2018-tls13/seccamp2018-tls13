
# B.3.1.4.  Supported Groups Extension
# https://tools.ietf.org/html/draft-ietf-tls-tls13-26#appendix-B.3.1.4

class NamedGroup:
    """
    enum { ... } NamedGroup
    """
    # Elliptic Curve Groups (ECDHE)
    obsolete_RESERVED = (0x0001, 0x0016)
    secp256r1 = 0x0017
    secp384r1 = 0x0018
    secp521r1 = 0x0019
    obsolete_RESERVED = (0x001A, 0x001C)
    x25519 = 0x001D
    x448 = 0x001E

    # Finite Field Groups  = DHE)
    ffdhe2048 = 0x0100
    ffdhe3072 = 0x0101
    ffdhe4096 = 0x0102
    ffdhe6144 = 0x0103
    ffdhe8192 = 0x0104

    # Reserved Code Points
    ffdhe_private_use = (0x01FC, 0x01FF)
    ecdhe_private_use = (0xFE00, 0xFEFF)
    obsolete_RESERVED = (0xFF01, 0xFF02)

    _size = 2 # byte


class NamedGroupList:
    """
    struct {
      NamedGroup named_group_list<2..2^16-1>;
    } NamedGroupList;
    """
    def __init__(self):
        self.named_group_list = []

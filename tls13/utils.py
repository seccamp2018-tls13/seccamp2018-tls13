
from struct import pack

class Uint8:
    """
    an unsigned byte
    """
    def __init__(self, value):
        self.value = value

    def __repr__(self):
        return "{}(0x{:0{width}x})" \
               .format(self.__class__.__name__, self.value, width=len(self)*2)

    def __len__(self):
        return 1

    def to_bytes(self):
        return pack('>B', self.value)

class Uint16(Uint8):
    """
    uint8 uint24[3];
    """
    def __len__(self):
        return 2

    def to_bytes(self):
        return pack('>H', self.value)

class Uint24(Uint8):
    """
    uint8 uint24[3];
    """
    def __len__(self):
        return 3

    def to_bytes(self):
        return pack('>BH', self.value >> 16, self.value & 0xffff)

class Uint32(Uint8):
    """
    uint8 uint32[4];
    """
    def __len__(self):
        return 4

    def to_bytes(self):
        return pack('>I', self.value)


def hexdump(data) -> str:

    def chunks(seq, size):
        '''
        Generator that cuts bytes into chunks of given size.
        If `seq` length is not multiply of `size`, the lengh of the last chunk
        returned will be less than requested.

        >>> list( chunks([1,2,3,4,5,6,7], 3) )
        [[1, 2, 3], [4, 5, 6], [7]]
        '''
        d, m = divmod(len(seq), size)
        for i in range(d):
            yield seq[i*size:(i+1)*size]
        if m:
            yield seq[d*size:]

    def dump(binary, size=2, sep=' '):
        import binascii
        hexstr = binascii.hexlify(binary).decode('ascii')
        return sep.join(chunks(hexstr.upper(), size))

    def dumpgen(data):
        '''
        Generator that produces strings:
        '00000000: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................'
        '''
        generator = chunks(data, 16)
        for addr, d in enumerate(generator):
            # 00000000:
            line = '%08X: ' % (addr*16)
            # 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00
            dumpstr = dump(d)
            line += dumpstr[:8*3]
            if len(d) > 8:  # insert separator if needed
                line += ' ' + dumpstr[8*3:]
            # ................
            # calculate indentation, which may be different for the last line
            pad = 2
            if len(d) < 16:
                pad += 3 * (16 - len(d))
            if len(d) <= 8:
                pad += 1
            line += ' ' * pad

            for byte in d:
                # printable ASCII range 0x20 to 0x7E
                line += chr(byte) if 0x20 <= byte <= 0x7E else '.'
            yield line

    return '\n'.join(dumpgen(data))

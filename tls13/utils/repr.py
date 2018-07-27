
__all__ = ['make_format', 'hexstr', 'hexdump']

import binascii
import inspect
import textwrap
import pprint
from .type import Uint, Type

def make_format(obj, props):
    repr_str = ""
    repr_str += "%s:\n" % obj.__class__.__name__
    for prop, prop_type in list(props.items()):
        item = getattr(obj, prop)
        item_len = len(item)

        assert inspect.isclass(prop_type)

        if prop_type in (str, bytes, bytearray):
            if item_len > 15:
                item = item[0:10].hex() + '...'
            else:
                item = item.hex()
            repr_str += "|%s: %s (len=%d)\n" % (prop, item, item_len)
        elif prop_type == list and all(isinstance(x, Uint) for x in item):
            repr_str += "|%s: %s\n" % (prop, item)
        elif prop_type in (list, object):
            repr_str += "|%s:\n" % prop
            repr_str += textwrap.indent(pprint.pformat(item), prefix="    ")
            if prop_type == list: repr_str += "\n"
        elif issubclass(prop_type, Type):
            const_name = prop_type.labels[item]
            repr_str += "|%s: %s == %s\n" % (prop, item, const_name)
        elif prop_type == int and isinstance(item, Uint):
            repr_str += "|%s: %s == %s\n" % (prop, getattr(obj, prop), int(item))
        else:
            repr_str += "|%s: %s\n" % (prop, getattr(obj, prop))

    return repr_str.strip()


def hexstr(binary):
    return binascii.hexlify(binary).decode('ascii')


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
        return sep.join(chunks(hexstr(binary).upper(), size))

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

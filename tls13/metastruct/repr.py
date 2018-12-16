
__all__ = ['make_format', 'hexstr', 'hexdump']

import binascii
import inspect
import textwrap
import pprint
from .type import Uint, Type

# 一定の文字数を超えたら後ろの文字列を切り捨てる
def truncate(string, len_max):
    if len(string) > len_max:
        return string[0:len_max-5] + '...'
    else:
        return string

# 順序付き辞書を引数として取り、__repr__のために文字列を生成する
# 使い方：
#
#     props = collections.OrderedDict(
#         legacy_version=ProtocolVersion,
#         random=bytes,
#         legacy_session_id=bytes,
#         cipher_suites=list,
#         legacy_compression_methods=list,
#         extensions=list)
#     print(make_format(self, props))
#
def make_format(obj, props):
    from .metastruct import Struct # 循環参照の回避のため、ここでimportする

    repr_str = ""
    repr_str += "%s:\n" % obj.__class__.__name__
    for prop, prop_type in list(props.items()):
        item = getattr(obj, prop)
        item_len = len(item)

        assert inspect.isclass(prop_type)

        if issubclass(prop_type, (str, bytes, bytearray)):
            # 文字列のとき => 25文字以上なら切り捨てる => 1行で表示
            item = truncate(item.hex(), 25)
            repr_str += "|%s: %s (len=%d)\n" % (prop, item, item_len)
        elif issubclass(prop_type, list) and all(isinstance(x, Uint) for x in item):
            # Uintのリストのとき => 1行で表示
            repr_str += "|%s: %s\n" % (prop, item)
        elif issubclass(prop_type, (list, Struct)):
            # リストか構造体のとき => 複数行でインデントを付けて表示
            repr_str += "|%s:\n" % prop
            repr_str += textwrap.indent(pprint.pformat(item), prefix="    ")
            if prop_type == list: repr_str += "\n"
        elif issubclass(prop_type, Type):
            # TLSの定数のとき => 定数名を付けて表示
            const_name = prop_type.labels[item]
            repr_str += "|%s: %s == %s\n" % (prop, item, const_name)
        elif issubclass(prop_type, Uint):
            # Uintのとき => 10進数に変換したものを付けて表示
            repr_str += "|%s: %s == %s\n" % (prop, getattr(obj, prop), int(item))
        else:
            repr_str += "|%s: %s\n" % (prop, getattr(obj, prop))

    return repr_str.strip()

def hexstr(binary):
    return binascii.hexlify(binary).decode('ascii')

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
    00000000: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
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

def hexdump(data) -> str:
    return '\n'.join(dumpgen(data))

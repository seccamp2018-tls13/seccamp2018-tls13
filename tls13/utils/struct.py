
__all__ = ['Struct', 'Members', 'Member', 'Listof']

import collections

from .codec import Reader, Writer
from .type import Uint, Type
from .repr import make_format

# 構造体を表すためのクラス群
# 使い方：
#
# class ClientHello(Struct):
#
#     def __init__(self, ...):
#         self.struct = Members([
#             Member(ProtocolVersion, 'legacy_version'),
#             Member(bytes, 'random'),
#             Member(bytes, 'legacy_session_id', length_t=Uint8),
#             Member(Listof(CipherSuite), 'cipher_suites', length_t=Uint16),
#             Member(Listof(Uint8), 'legacy_compression_methods', length_t=Uint16),
#             Member(Listof(Extension), 'extensions', length_t=Uint16),
#         ])
#

# 全てのTLSの構造体はStructクラスを継承して、フィールドに self.struct を定義する。
# self.struct には Members, Member, Listof を使ってTLS構造体の構造を記述する。
class Struct:
    def __repr__(self):
        props = self.struct.get_props()
        return make_format(self, props)

    def __len__(self):
        return self.struct.get_length()

    def to_bytes(self):
        return self.struct.get_bytes()


class Members:
    def __init__(self, obj, members=[]):
        self.obj = obj
        self.members = members

    # __repr__のための順序付き辞書を返すメソッド
    #
    #     props = collections.OrderedDict(
    #         legacy_version=ProtocolVersion,
    #         random=bytes,
    #         legacy_session_id=bytes,
    #         cipher_suites=list,
    #         legacy_compression_methods=list,
    #         extensions=list)
    #
    def get_props(self):
        props = collections.OrderedDict()
        for member in self.members:
            if isinstance(member.type, Listof):
                props[member.name] = list
            else:
                props[member.name] = member.type

        return props

    # __len__のためのバイト列にしたときの長さを返すメソッド
    #
    #     return len(self.legacy_version) + len(self.random) + \
    #            1 + len(self.legacy_session_id) + \
    #            2 + sum(map(len, self.cipher_suites)) + \
    #            1 + sum(map(len, self.legacy_compression_methods)) + \
    #            2 + sum(map(len, self.extensions))
    #
    def get_length(self):
        length = 0
        for member in self.members:
            if member.length_t:
                length += member.length_t._size
            if isinstance(member.type, Listof):
                length += sum(map(len, getattr(self.obj, member.name)))
            else:
                length += len(getattr(self.obj, member.name))

        return length

    # to_bytesのためのバイト列を作る処理
    #
    #     writer = Writer()
    #     writer.add_bytes(self.legacy_version)
    #     writer.add_bytes(self.random)
    #     writer.add_bytes(self.legacy_session_id, length_t=Uint8)
    #     writer.add_list(self.cipher_suites, length_t=Uint16)
    #     writer.add_list(self.legacy_compression_methods, length_t=Uint8)
    #     writer.add_list(self.extensions, length_t=Uint16)
    #     return writer.bytes
    #
    def get_bytes(self):
        writer = Writer()
        for member in self.members:
            target = getattr(self.obj, member.name)
            kwargs = {}
            if member.length_t:
                kwargs['length_t'] = member.length_t

            if isinstance(member.type, Listof):
                writer.add_list(target, **kwargs)
            else:
                writer.add_bytes(target, **kwargs)

        return writer.bytes


class Member:
    def __init__(self, type, name, length_t=None):
        self.type = type # class
        self.name = name # str
        self.length_t = length_t # UintN

    def __repr__(self):
        return "<Member type={} name={} length_t={}>" \
               .format(self.type, self.name, self.length_t)


class Listof:
    def __init__(self, type):
        self.type = list # class
        self.subtype = type # class

    def __repr__(self):
        return "Listof({})".format(type)

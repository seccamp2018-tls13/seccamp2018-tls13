
__all__ = ['Struct', 'Members', 'Member', 'Listof']

import collections

from .codec import Reader, Writer
from .type import Uint, Type
from .repr import make_format

# 構造体を表すためのクラス群
# 使い方：
#
#     class ClientHello(Struct):
#         def __init__(self, ...):
#             self.struct = Members([
#                 Member(ProtocolVersion, 'legacy_version'),
#                 Member(bytes, 'random'),
#                 Member(bytes, 'legacy_session_id', length_t=Uint8),
#                 Member(Listof(CipherSuite), 'cipher_suites', length_t=Uint16),
#                 Member(Listof(Uint8), 'legacy_compression_methods', length_t=Uint16),
#                 Member(Listof(Extension), 'extensions', length_t=Uint16),
#             ])
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
        self.members_default = {}

    # __init__のために引数をフィールドに設定するメソッド
    # 例えば次のように書くと、引数に与えられた extension_type と extension_data を
    # self のフィールドの設定する。
    #
    #     def __init__(self, **kwargs):
    #         self.struct = Members(self, [
    #             Member(ExtensionType, 'extension_type'),
    #             Member(Struct, 'extension_data', length_t=Uint16),
    #         ])
    #         self.struct.set_args(**kwargs)
    #         # set_args を実行するのは以下と同じ
    #         #   self.extension_type = kwargs['extension_type']
    #         #   self.extension_data = kwargs['extension_data']
    #
    # kwargs に値が設定されていない時にデフォルト値を使いたい場合は、
    # set_args の前に set_default でデフォルト値を設定する。
    #
    #         self.struct.set_default('extension_type', Uint16(0x0123))
    #         self.struct.set_args(**kwargs)
    #         # このプログラムは以下と同じ
    #         #   self.extension_type = kwargs['extension_type'] or Uint16(0x0123)
    #
    def set_args(self, **kwargs):
        for member in self.members:
            key = member.name
            if key in kwargs.keys():
                value = kwargs[key]
            elif key in self.members_default.keys():
                value = self.members_default[key]
            else:
                value = self._get_default_from_type(member.type)

            StructAssert.my_assert(member, value)
            setattr(self.obj, key, value)

    def set_default(self, attr_name, default_value):
        self.members_default[attr_name] = default_value

    def _get_default_from_type(self, type):
        if isinstance(type, Listof):
            return list()
        if isinstance(type, (str, bytes, bytearray, int)):
            return type()
        return None

    # __repr__のために順序付き辞書を返すメソッド
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

    # __len__のためにバイト列にしたときの長さを返すメソッド
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

    # to_bytesのためにバイト列を作る処理
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

    # from_bytesのためにバイト列から構造体のフィールドを得る処理
    #
    #     reader = Reader(data)
    #     type                  = reader.get(Uint8)
    #     legacy_record_version = reader.get(Uint16)
    #     length                = reader.get(Uint16)
    #     fragment              = reader.get(bytes)
    #
    def get_props_from_bytes(self, data):
        import inspect
        props = {}
        reader = Reader(data)
        for member in self.members:
            length_t = getattr(member, 'length_t', None)
            type = member.type
            if inspect.isclass(member.type) and issubclass(member.type, Type):
                type = Uint.get_type(member.type._size)
            value = reader.get(type, length_t=length_t)
            props[member.name] = value

        return props


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
        return "Listof({})".format(self.subtype)


class Empty(Struct):
    def __init__(self):
        self.struct = Members([])


class StructAssert:
    @staticmethod
    def my_assert(member, value):
        if isinstance(member.type, Listof):
            return StructAssert.assert_listof(member, value)

        if issubclass(member.type, Type):
            if not value in member.type.values:
                raise RuntimeError('value "{}" is not in "{}"' \
                                   .format(member.name, member.type))

    def assert_listof(member, value):
        if issubclass(member.type.subtype, Type):
            UintN = Uint.get_type(member.type.subtype._size)
            if all(isinstance(x, UintN) for x in value):
                return True
            raise RuntimeError('list "{}" elements must have type "{}"' \
                               .format(member.name, UintN.__name__))

        if all(isinstance(x, member.type.subtype) for x in value):
            return True
        raise RuntimeError('list "{}" elements must have type "{}"' \
                           .format(member.name, member.type.subtype.__name__))

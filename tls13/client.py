
import socket
import secrets

from .protocol.recordlayer import TLSPlaintext, ContentType
from .protocol.handshake import Handshake, HandshakeType
from .protocol.ciphersuite import CipherSuite
from .protocol.keyexchange.messages import ClientHello, Extension, ExtensionType, \
    KeyShareEntry, KeyShareClientHello

# Extensions
from .protocol.keyexchange.version import SupportedVersions
from .protocol.keyexchange.supportedgroups import NamedGroup, NamedGroupList
from .protocol.keyexchange.signature import SignatureScheme, SignatureSchemeList

from .utils import Uint8, Uint16, Uint24, Uint32

def client_cmd(argv):
    print("client_cmd({})".format(", ".join(argv)))

    # ClientHello

    # 構造体の階層
    # TLSPlaintext
    # └─ Handshake
    #    └─ ClientHello
    #       └─ Extension (supported_groups, signature_algorithms, ...)

    supported_versions = Extension(
        extension_type=ExtensionType.supported_versions,
        extension_data=SupportedVersions(
            msg_type=HandshakeType.client_hello,
            versions=[b'\x03\x04'] ))

    supported_groups = Extension(
        extension_type=ExtensionType.supported_groups,
        extension_data=NamedGroupList(
            named_group_list=[
                NamedGroup.ffdhe2048 ] ))

    signature_algorithms = Extension(
        extension_type=ExtensionType.signature_algorithms,
        extension_data=SignatureSchemeList(
            supported_signature_algorithms=[
                SignatureScheme.rsa_pkcs1_sha256 ] ))

    key_share = Extension(
        extension_type=ExtensionType.key_share,
        extension_data=KeyShareClientHello(
            client_shares=[
                KeyShareEntry(
                    group=NamedGroup.ffdhe2048,
                    key_exchange=secrets.token_bytes(2048 // 8)) ] ))


    ch = ClientHello()
    ch.cipher_suites.append(CipherSuite.TLS_AES_128_GCM_SHA256)
    ch.extensions.append(supported_versions)
    ch.extensions.append(supported_groups)
    ch.extensions.append(signature_algorithms)
    ch.extensions.append(key_share)

    ch_handshake = Handshake(
        msg_type=HandshakeType.client_hello,
        length=len(ch),
        msg=ch
    )

    ch_plain = TLSPlaintext(
        _type=ContentType.handshake,
        length=len(ch_handshake),
        fragment=ch_handshake
    )

    # TODO: バイト列に変換したときの長さを求めるメソッド __len__ を実装する．
    #       可変長のデータがある場合は，先頭の1~3byteにデータ長，続くNbyteにデータが入るので，
    #       可変長のデータ長は合計 1~3 + N になることに注意．
    #       先頭のバイト数は例えば：
    #         <0..2^8-1> なら hex(2**8-1) == '0xff' なので 1byte
    #         <0..2^16-1> なら hex(2**16-1) == '0xffff' なので 2byte のように求める．
    # TODO: それぞれのクラスに .to_bytes() みたいなメソッドを作って再帰的に呼び出して
    #       送信用のバイト列を作る
    # TODO: socketを使ってバイト列をサーバに送る処理の実装
    #       send(ch_plain.to_bytes(), to=server)
    # TODO: .to_bytes() ができたら，その逆関数として TLSPlaintext.from_bytes() みたいな
    #       送られてきたバイト列から構造体を組み立てるメソッドをそれぞれのクラスに作る．
    #       .from_bytes() も再帰的に呼び出してインスタンスを再構築する．
    # TODO: 再構築した ch_plain の内容を pretty-print で出力したい（デバッグ用）


    # Finished

    # Application Data

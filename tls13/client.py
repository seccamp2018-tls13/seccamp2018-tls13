
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

from .utils import hexdump
from .utils.type import Uint8, Uint16, Uint24, Uint32

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
            versions=[ Uint16(0x0304) ] ))

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
        length=Uint24(len(ch)),
        msg=ch )

    ch_plain = TLSPlaintext(
        _type=ContentType.handshake,
        length=Uint16(len(ch_handshake)),
        fragment=ch_handshake )

    # ClientHello が入っている TLSPlaintext
    print(ch_plain)

    print("ClientHello bytes:")
    ch_bytes = ch_plain.to_bytes()
    print(hexdump(ch_bytes))

    # # バイト列から TLSPlaintext を再構築する（実際はサーバ側が行うが，デバッグなのでここで行う）
    # ch_plain_restructed = TLSPlaintext.from_bytes(ch_bytes)
    # # print(ch_plain_restructed)
    # # デバッグ用
    # before = repr(ch_plain)
    # after  = repr(ch_plain_restructed)
    # assert before == after
    # デバッグの処理は別のファイルで unittest したい

    # Server に ClientHello のバイト列を送信する
    print("[INFO] Connecting to server...")
    HOST = 'localhost' # The remote host
    PORT = 50007 # The same port as used by the server
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        s.sendall(ch_bytes)

    # DONE: バイト列に変換したときの長さを求めるメソッド __len__ を実装する．
    #       可変長のデータがある場合は，先頭の1~3byteにデータ長，続くNbyteにデータが入るので，
    #       可変長のデータ長は合計 1~3 + N になることに注意．
    #       先頭のバイト数は例えば：
    #         <0..2^8-1> なら hex(2**8-1) == '0xff' なので 1byte
    #         <0..2^16-1> なら hex(2**16-1) == '0xffff' なので 2byte のように求める．
    # DONE: それぞれのクラスに .to_bytes() みたいなメソッドを作って再帰的に呼び出して
    #       送信用のバイト列を作る
    # DONE: socketを使ってバイト列をサーバに送る処理の実装
    #       send(ch_plain.to_bytes(), to=server)
    # DONE: .to_bytes() ができたら，その逆関数として TLSPlaintext.from_bytes() みたいな
    #       送られてきたバイト列から構造体を組み立てるメソッドをそれぞれのクラスに作る．
    #       .from_bytes() も再帰的に呼び出してインスタンスを再構築する．
    # DONE: 再構築した ch_plain の内容を pretty-print で出力したい（デバッグ用）


    # Finished

    # Application Data

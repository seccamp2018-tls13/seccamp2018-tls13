
import secrets
from .utils import socket

from .protocol.recordlayer import TLSPlaintext, ContentType
from .protocol.handshake import Handshake, HandshakeType
from .protocol.ciphersuite import CipherSuite
from .protocol.keyexchange.messages import ServerHello, Extension, ExtensionType, \
    KeyShareEntry, KeyShareServerHello

# Extensions
from .protocol.keyexchange.version import SupportedVersions
from .protocol.keyexchange.supportedgroups import NamedGroup, NamedGroupList
from .protocol.keyexchange.signature import SignatureScheme, SignatureSchemeList

from .utils import hexdump, hexstr
from .utils.type import Uint8, Uint16, Uint24, Uint32

def server_cmd(argv):
    print("server_cmd({})".format(", ".join(argv)))

    # ClientHello のバイト列を受け取る
    server_conn = socket.ServerConnection()
    data = server_conn.recv_msg()

    ch_plain_restructed = TLSPlaintext.from_bytes(data)
    print(ch_plain_restructed)

    # ServerHello

    client_session_id = ch_plain_restructed.fragment.msg.legacy_session_id
    client_cipher_suites = ch_plain_restructed.fragment.msg.cipher_suites
    client_key_share_groups = ch_plain_restructed.fragment.msg \
        .get_extension(ExtensionType.key_share) \
        .get_groups()

    # パラメータの決定
    # 暗号化：受け取ったClientHelloの暗号スイートから選ぶ
    cipher_suite = client_cipher_suites[0] # TODO: 暗号スイート実装してから優先順位を決める
    # 鍵共有：ClientHelloのKeyShareEntryを見てどの方法で鍵共有するか決めてから，
    # パラメータ（group, key_exchange）を決める
    if NamedGroup.ffdhe2048 in client_key_share_groups:
        server_share_group = NamedGroup.ffdhe2048
        # TODO: DHEでは g^b mod p を相手に送るので，それをバイト列に変換して入れる
        server_share_key_exchange = secrets.token_bytes(2048 // 8)
    else:
        raise NotImplementedError()

    supported_versions = Extension(
        extension_type=ExtensionType.supported_versions,
        extension_data=SupportedVersions(
            msg_type=HandshakeType.server_hello,
            selected_version=Uint16(0x0304) ))

    key_share = Extension(
        extension_type=ExtensionType.key_share,
        extension_data=KeyShareServerHello(
            server_share=KeyShareEntry(
                group=server_share_group,
                key_exchange=server_share_key_exchange )))

    sh = ServerHello(legacy_session_id_echo=client_session_id,
                     cipher_suite=cipher_suite )
    sh.extensions.append(supported_versions)
    sh.extensions.append(key_share)

    sh_handshake = Handshake(
        msg_type=HandshakeType.server_hello,
        msg=sh )

    sh_plain = TLSPlaintext(
        _type=ContentType.handshake,
        fragment=sh_handshake )

    # ServerHello が入っている TLSPlaintext
    print(sh_plain)

    # print("ServerHello bytes:")
    sh_bytes = sh_plain.to_bytes()
    # print(hexdump(sh_bytes))

    server_conn.send_msg(sh_bytes)


    # -- create master_secret ---

    client_pub_key = \
        ch_plain_restructed.fragment.msg \
        .get_extension(extension_type=ExtensionType.key_share) \
        .get_key_exchange(group=NamedGroup.ffdhe2048)

    # print('client_pub_key:')
    # print(hexstr(client_pub_key)) # DHEのときは g^a mod p の値が入る

    def gen_master_secret(peer_pub, my_secret):
        # 実際の処理は utils/encryption/ffdhe.py などに書く
        return 0

    master_secret = gen_master_secret(client_pub_key, b'beef')


    # EncryptedExtensions

    # Certificate

    # CertificateVerify

    # Finished


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

from .utils import hexdump
from .utils.type import Uint8, Uint16, Uint24, Uint32

def server_cmd(argv):
    print("server_cmd({})".format(", ".join(argv)))

    # ClientHello のバイト列を受け取る
    data = socket.recv()

    ch_plain_restructed = TLSPlaintext.from_bytes(data)
    print(ch_plain_restructed)

    # ServerHello

    supported_versions = Extension(
        extension_type=ExtensionType.supported_versions,
        extension_data=SupportedVersions(
            msg_type=HandshakeType.server_hello,
            selected_version=Uint16(0x0304) ))

    key_share = Extension(
        extension_type=ExtensionType.key_share,
        extension_data=KeyShareServerHello(
            # TODO: ClientHelloのKeyShareEntryを見てどの方法で鍵共有するか決めてから，
            #       パラメータ（group, key_exchange）を決める
            server_share=KeyShareEntry(
                group=NamedGroup.ffdhe2048,
                key_exchange=secrets.token_bytes(2048 // 8) )))

    sh = ServerHello(
        # TODO: 受け取ったClientHelloのsesion_idを入れる
        legacy_session_id_echo=secrets.token_bytes(32),
        # TODO: 受け取ったClientHelloの暗号スイートから選ぶ
        cipher_suite=CipherSuite.TLS_AES_128_GCM_SHA256 )
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

    print("ServerHello bytes:")
    sh_plain = sh_plain.to_bytes()
    print(hexdump(sh_plain))

    # send()


    # EncryptedExtensions

    # Certificate

    # CertificateVerify

    # Finished

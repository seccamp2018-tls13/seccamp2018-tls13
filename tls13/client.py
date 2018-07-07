
import secrets
from .utils import socket

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
        msg=ch )

    ch_plain = TLSPlaintext(
        _type=ContentType.handshake,
        fragment=ch_handshake )

    # ClientHello が入っている TLSPlaintext
    print(ch_plain)

    print("ClientHello bytes:")
    ch_bytes = ch_plain.to_bytes()
    print(hexdump(ch_bytes))

    # Server に ClientHello のバイト列を送信する
    print("[INFO] Connecting to server...")
    client_conn = socket.ClientConnection()
    client_conn.send_msg(ch_bytes)

    data = client_conn.recv_msg()
    sh_plain_restructed = TLSPlaintext.from_bytes(data)
    print(sh_plain_restructed)

    # Finished

    # Application Data

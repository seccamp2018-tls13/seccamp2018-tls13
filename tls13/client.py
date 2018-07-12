
import secrets
from .utils import socket

from .protocol.recordlayer import TLSPlaintext, ContentType
from .protocol.handshake import Handshake, HandshakeType
from .protocol.ciphersuite import CipherSuite
from .protocol.keyexchange.messages import ClientHello, Extension, ExtensionType, \
    KeyShareEntry, KeyShareClientHello

# Extensions
from .protocol.keyexchange.version import ProtocolVersion, SupportedVersions
from .protocol.keyexchange.supportedgroups import NamedGroup, NamedGroupList
from .protocol.keyexchange.signature import SignatureScheme, SignatureSchemeList

from .utils import hexdump, hexstr

def client_cmd(argv):
    print("client_cmd({})".format(", ".join(argv)))

    # params

    versions = [ ProtocolVersion.TLS13 ]
    named_group_list = [ NamedGroup.ffdhe2048 ]
    supported_signature_algorithms = [ SignatureScheme.rsa_pkcs1_sha256 ]
    client_shares = [
        KeyShareEntry(
            group=NamedGroup.ffdhe2048,
            key_exchange=secrets.token_bytes(2048 // 8)),
    ]
    cipher_suites = [ CipherSuite.TLS_AES_128_GCM_SHA256 ]

    # >>> ClientHello >>>

    ch_plain = TLSPlaintext(
        _type=ContentType.handshake,
        fragment=Handshake(
            msg_type=HandshakeType.client_hello,
            msg=ClientHello(
                cipher_suites=cipher_suites,
                extensions=[
                    # supported_versions
                    Extension(
                        extension_type=ExtensionType.supported_versions,
                        extension_data=SupportedVersions(
                            msg_type=HandshakeType.client_hello,
                            versions=versions )),

                    # supported_groups
                    Extension(
                        extension_type=ExtensionType.supported_groups,
                        extension_data=NamedGroupList(
                            named_group_list=named_group_list )),

                    # signature_algorithms
                    Extension(
                        extension_type=ExtensionType.signature_algorithms,
                        extension_data=SignatureSchemeList(
                            supported_signature_algorithms)),

                    # key_share
                    Extension(
                        extension_type=ExtensionType.key_share,
                        extension_data=KeyShareClientHello(
                            client_shares=client_shares )),
                ] )))

    # ClientHello が入っている TLSPlaintext
    print(ch_plain)

    # print("ClientHello bytes:")
    ch_bytes = ch_plain.to_bytes()
    # print(hexdump(ch_bytes))

    # Server に ClientHello のバイト列を送信する
    print("[INFO] Connecting to server...")
    client_conn = socket.ClientConnection()
    client_conn.send_msg(ch_bytes)

    # <<< ClientHello <<<
    data = client_conn.recv_msg()
    sh_plain_restructed = TLSPlaintext.from_bytes(data)
    print(sh_plain_restructed)


    # -- create master_secret ---

    server_pub_key = sh_plain_restructed \
        .get_extension(extension_type=ExtensionType.key_share) \
        .get_key_exchange()

    # print('server_pub_key:')
    # print(hexstr(server_pub_key)) # DHEのときは g^b mod p の値が入る

    def gen_master_secret(peer_pub, my_secret):
        # 実際の処理は utils/encryption/ffdhe.py などに書く
        return 0

    master_secret = gen_master_secret(server_pub_key, b'dead')


    # >>> Finished >>>

    # >>> Application Data <<<

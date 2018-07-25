
import secrets
from .utils import socket

from .protocol.recordlayer import TLSPlaintext, ContentType
from .protocol.handshake import Handshake, HandshakeType
from .protocol.ciphersuite import CipherSuite
from .protocol.keyexchange.messages import ServerHello, Extension, ExtensionType, \
    KeyShareEntry, KeyShareServerHello
from .protocol.keyexchange.authentication import Certificate, CertificateEntry

# Extensions
from .protocol.keyexchange.version import ProtocolVersion, SupportedVersions
from .protocol.keyexchange.supportedgroups import NamedGroup, NamedGroupList
from .protocol.keyexchange.signature import SignatureScheme, SignatureSchemeList

# Crypto
from .utils.encryption.ffdhe import FFDHE

from .utils import hexdump, hexstr

def server_cmd(argv):
    print("server_cmd({})".format(", ".join(argv)))

    # <<< ClientHello <<<
    server_conn = socket.ServerConnection()
    data = server_conn.recv_msg()
    ch_plain_restructed = TLSPlaintext.from_bytes(data)
    print(ch_plain_restructed)

    # >>> ServerHello >>>

    # select params

    client_session_id = ch_plain_restructed.legacy_session_id
    client_cipher_suites = ch_plain_restructed.cipher_suites
    client_key_share_groups = ch_plain_restructed \
        .get_extension(ExtensionType.key_share) \
        .get_groups()

    # パラメータの決定
    # 暗号化：受け取ったClientHelloの暗号スイートから選ぶ
    cipher_suite = client_cipher_suites[0] # TODO: 暗号スイート実装してから優先順位を決める
    # 鍵共有：ClientHelloのKeyShareEntryを見てどの方法で鍵共有するか決めてから，
    # パラメータ（group, key_exchange）を決める
    if NamedGroup.ffdhe2048 in client_key_share_groups:
        server_share_group = NamedGroup.ffdhe2048
        ffdhe2048 = FFDHE(server_share_group)
        server_key_share_key_exchange = ffdhe2048.gen_public_key()
        client_key_share_key_exchange = ch_plain_restructed \
            .get_extension(ExtensionType.key_share) \
            .get_key_exchange(server_share_group)
        shared_key = ffdhe2048.gen_shared_key(client_key_share_key_exchange)
    else:
        raise NotImplementedError()

    print("shared_key: %s" % hexstr(shared_key))

    selected_version = ProtocolVersion.TLS13

    sh_plain = TLSPlaintext(
        _type=ContentType.handshake,
        fragment=Handshake(
            msg_type=HandshakeType.server_hello,
            msg=ServerHello(
                legacy_session_id_echo=client_session_id,
                cipher_suite=cipher_suite,
                extensions=[
                    # supported_versions
                    Extension(
                        extension_type=ExtensionType.supported_versions,
                        extension_data=SupportedVersions(
                            msg_type=HandshakeType.server_hello,
                            selected_version=selected_version )),

                    # key_share
                    Extension(
                        extension_type=ExtensionType.key_share,
                        extension_data=KeyShareServerHello(
                            server_share=KeyShareEntry(
                                group=server_share_group,
                                key_exchange=server_key_share_key_exchange ))),
                ] )))

    # ServerHello が入っている TLSPlaintext
    print(sh_plain)

    # print("ServerHello bytes:")
    sh_bytes = sh_plain.to_bytes()
    # print(hexdump(sh_bytes))

    server_conn.send_msg(sh_bytes)


    # -- create master_secret ---

    client_pub_key = ch_plain_restructed \
        .get_extension(extension_type=ExtensionType.key_share) \
        .get_key_exchange(group=NamedGroup.ffdhe2048)

    # print('client_pub_key:')
    # print(hexstr(client_pub_key)) # DHEのときは g^a mod p の値が入る

    def gen_master_secret(peer_pub, my_secret):
        # 実際の処理は utils/encryption/ffdhe.py などに書く
        return 0

    master_secret = gen_master_secret(client_pub_key, b'beef')


    # >>> EncryptedExtensions >>>


    # >>> server Certificate >>>

    with open('.ssh/server.crt', 'r') as f:
        cert_data = ''.join(f.readlines()[1:-1]).replace('\n', '')
        cert_data = bytes(cert_data, 'ascii')

    cert_plain = TLSPlaintext(
        _type=ContentType.handshake,
        fragment=Handshake(
            msg_type=HandshakeType.certificate,
            msg=Certificate(
                certificate_request_context=b'',
                certificate_list=[
                    CertificateEntry(cert_data=cert_data)
                ])))

    print(cert_plain)
    print(cert_plain.to_bytes())

    # print("server Certificate bytes:")
    cert_bytes = cert_plain.to_bytes()
    # print(hexdump(sh_bytes))

    server_conn.send_msg(cert_bytes)


    # >>> CertificateVerify >>>

    # >>> Finished >>>

    hash_algorithm = CipherSuite.get_hash_algorithm(cipher_suite)


    # >>> Application Data <<<

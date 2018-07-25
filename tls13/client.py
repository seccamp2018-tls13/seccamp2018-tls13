
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

# Crypto
from .utils.encryption.ffdhe import FFDHE

from .utils import hexdump, hexstr

def client_cmd(argv):
    print("client_cmd({})".format(", ".join(argv)))

    # params

    ffdhe2048 = FFDHE(NamedGroup.ffdhe2048)
    ffdhe2048_key_exchange = ffdhe2048.gen_public_key()
    # ffdhe3072 = FFDHE(NamedGroup.ffdhe3072)
    # ffdhe3078_key_exchange = ffdhe3072.gen_public_key()

    versions = [ ProtocolVersion.TLS13 ]
    named_group_list = [ NamedGroup.ffdhe2048 ]
    supported_signature_algorithms = [ SignatureScheme.rsa_pkcs1_sha256 ]
    client_shares = [
        KeyShareEntry(
            group=NamedGroup.ffdhe2048,
            key_exchange=ffdhe2048_key_exchange),
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

    # <<< ServerHello <<<
    data = client_conn.recv_msg()
    sh_plain_restructed = TLSPlaintext.from_bytes(data)
    print(sh_plain_restructed)


    # パラメータの決定
    server_cipher_suite = sh_plain_restructed.cipher_suite
    server_selected_version = sh_plain_restructed \
        .get_extension(ExtensionType.supported_versions) \
        .selected_version
    server_key_share_group = sh_plain_restructed \
        .get_extension(ExtensionType.key_share) \
        .get_group()
    server_key_share_key_exchange = sh_plain_restructed \
        .get_extension(ExtensionType.key_share) \
        .get_key_exchange()

    server_pub_key = server_key_share_key_exchange

    # shared_key の作成
    if server_key_share_group == NamedGroup.ffdhe2048:
        client_key_share_key_exchange = ffdhe2048_key_exchange
        shared_key = ffdhe2048.gen_shared_key(server_pub_key)
    elif server_key_share_group == NamedGroup.ffdge3072:
        pass # shared_key = ffdge3072.gen_shared_key(server_pub_key)
        raise NotImplementedError()
    else:
        raise NotImplementedError()

    print("shared_key: %s" % hexstr(shared_key))

    # -- HKDF ---

    # <<< server Certificate <<<
    data = client_conn.recv_msg()
    plain_restructed = TLSPlaintext.from_bytes(data)
    print(plain_restructed)


    # >>> Finished >>>

    hash_algorithm = CipherSuite.get_hash_algorithm(server_cipher_suite)


    # >>> Application Data <<<


import secrets
from ..utils import connection, cryptomath
from ..protocol import *
from ..metastruct import *

# Crypto
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, \
    X25519PublicKey
from ..encryption.ffdhe import FFDHE
from ..encryption import Cipher


# TODO: グローバル変数作るならこんな感じ
class Global:
    connect_side = "client"
    current_mode = ContentType.handshake


def client_cmd(argv):
    print("client_cmd({})".format(", ".join(argv)))

    messages = bytearray(0)

    # params

    ffdhe2048 = FFDHE(NamedGroup.ffdhe2048)
    ffdhe2048_key_exchange = ffdhe2048.gen_public_key()
    x25519 = X25519PrivateKey.generate()
    x25519_key_exchange = x25519.public_key().public_bytes()

    versions = [ ProtocolVersion.TLS13, ProtocolVersion.TLS13_DRAFT26 ]
    named_group_list = [ NamedGroup.x25519, NamedGroup.ffdhe2048 ]
    supported_signature_algorithms = [
        SignatureScheme.rsa_pss_pss_sha256,
        SignatureScheme.rsa_pss_pss_sha384,
        SignatureScheme.rsa_pss_pss_sha512,
        SignatureScheme.rsa_pss_rsae_sha256,
        SignatureScheme.rsa_pss_rsae_sha384,
        SignatureScheme.rsa_pss_rsae_sha512,
        SignatureScheme.ecdsa_secp256r1_sha256,
        SignatureScheme.ecdsa_secp384r1_sha384,
        SignatureScheme.ecdsa_secp512r1_sha512,
        SignatureScheme.ed25519,
        SignatureScheme.ed448,
    ]
    client_shares = [
        KeyShareEntry(
            group=NamedGroup.x25519,
            key_exchange=x25519_key_exchange),
        KeyShareEntry(
            group=NamedGroup.ffdhe2048,
            key_exchange=ffdhe2048_key_exchange),
    ]
    cipher_suites = [
        CipherSuite.TLS_CHACHA20_POLY1305_SHA256,
    ]

    # >>> ClientHello >>>

    clienthello = TLSPlaintext(
        type=ContentType.handshake,
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
                            supported_signature_algorithms=
                            supported_signature_algorithms)),

                    # key_share
                    Extension(
                        extension_type=ExtensionType.key_share,
                        extension_data=KeyShareClientHello(
                            client_shares=client_shares )),
                ] )))

    # Server に ClientHello のバイト列を送信する
    print("[INFO] Connecting to server...")
    client_conn = connection.ClientConnection()
    # ClientHello が入っている TLSPlaintext
    print(clienthello)
    client_conn.send_msg(clienthello.to_bytes())
    messages += clienthello.fragment.to_bytes()

    # <<< ServerHello <<<
    # TODO: ServerHello + ChangeCipherSpec + ApplicationData... が送られて来たときに、
    #       これらを別々にしてから TLSPlaintext.from_bytes に渡す処理が必要
    data = client_conn.recv_msg()
    recved_serverhello = TLSPlaintext.from_bytes(data)
    messages += data[5:len(recved_serverhello)]
    print(recved_serverhello)
    remain_data = data[len(recved_serverhello):]

    print("remove: change cipher spec")
    tmp = remain_data[6:]
    remain_data = tmp

    # パラメータの決定
    server_cipher_suite = recved_serverhello.cipher_suite
    server_selected_version = recved_serverhello \
        .get_extension(ExtensionType.supported_versions) \
        .selected_version
    server_key_share_group = recved_serverhello \
        .get_extension(ExtensionType.key_share) \
        .get_group()
    server_key_share_key_exchange = recved_serverhello \
        .get_extension(ExtensionType.key_share) \
        .get_key_exchange()

    server_pub_key = server_key_share_key_exchange

    # shared_key の作成
    if server_key_share_group == NamedGroup.ffdhe2048:
        shared_key = ffdhe2048.gen_shared_key(server_pub_key)
    elif server_key_share_group == NamedGroup.x25519:
        shared_key = x25519.exchange(
            X25519PublicKey.from_public_bytes(server_pub_key))
    else:
        raise NotImplementedError()

    print("shared_key: %s" % hexstr(shared_key))

    # -- HKDF ---

    # print("messages = ")
    # print(hexdump(messages))
    print("messages hash = " + cryptomath.secureHash(messages, 'sha256').hex())
    print()

    cipher_suite = server_cipher_suite

    hash_algo   = CipherSuite.get_hash_algo_name(cipher_suite)
    secret_size = CipherSuite.get_hash_algo_size(cipher_suite)
    secret = bytearray(secret_size)
    psk    = bytearray(secret_size)
    # early secret
    secret = cryptomath.HKDF_extract(secret, psk, hash_algo)
    print('early secret =', secret.hex())
    # handshake secret
    secret = cryptomath.derive_secret(secret, b"derived", b"")
    print('derive_secret =', secret.hex())
    secret = cryptomath.HKDF_extract(secret, shared_key, hash_algo)
    print('handshake secret =', secret.hex())
    client_handshake_traffic_secret = \
        cryptomath.derive_secret(secret, b"c hs traffic", messages)
    print('client_handshake_traffic_secret =', client_handshake_traffic_secret.hex())
    server_handshake_traffic_secret = \
        cryptomath.derive_secret(secret, b"s hs traffic", messages)
    print('server_handshake_traffic_secret =', server_handshake_traffic_secret.hex())
    # master secret
    secret = cryptomath.derive_secret(secret, b"derived", b"")
    print('derive_secret =', secret.hex())
    secret = cryptomath.HKDF_extract(secret, bytearray(secret_size), hash_algo)
    print('master secret =', secret.hex())
    client_application_traffic_secret = \
        cryptomath.derive_secret(secret, b"c ap traffic", messages)
    server_application_traffic_secret = \
        cryptomath.derive_secret(secret, b"s ap traffic", messages)
    print('client_application_traffic_secret =', client_application_traffic_secret.hex())
    print('server_application_traffic_secret =', server_application_traffic_secret.hex())

    if cipher_suite == CipherSuite.TLS_CHACHA20_POLY1305_SHA256:
        cipher_class = Cipher.Chacha20Poly1305
        key_size     = Cipher.Chacha20Poly1305.key_size
        nonce_size   = Cipher.Chacha20Poly1305.nonce_size
    else:
        raise NotImplementedError()

    server_write_key, server_write_iv = \
        cryptomath.gen_key_and_iv(server_handshake_traffic_secret,
                                  key_size, nonce_size, hash_algo)
    s_traffic_crypto = cipher_class(key=server_write_key, nonce=server_write_iv)

    client_write_key, client_write_iv = \
        cryptomath.gen_key_and_iv(client_handshake_traffic_secret,
                                  key_size, nonce_size, hash_algo)
    c_traffic_crypto = cipher_class(key=client_write_key, nonce=client_write_iv)

    print('server_write_key =', server_write_key.hex())
    print('server_write_iv =', server_write_iv.hex())
    print('client_write_key =', client_write_key.hex())
    print('client_write_iv =', client_write_iv.hex())

    # <<< EncryptedExtensions <<<
    print("=== EncryptedExtensions ===")
    if len(remain_data) > 0:
        data = remain_data
    else:
        data = client_conn.recv_msg()
    print(hexdump(data))
    datalen = len(TLSCiphertext.from_bytes(data))
    recved_encrypted_extensions = TLSCiphertext.restore(data,
            crypto=s_traffic_crypto, mode=ContentType.handshake)
    # messages += data[5:datalen]
    messages += recved_encrypted_extensions.fragment.to_bytes()
    print(recved_encrypted_extensions)
    remain_data = data[datalen:]
    # TODO:
    # len(recved_encrypted_extensions) と TLSCiphertext のときの len は異なるので、
    # 今の切り取り方 [5:len(recved_encrypted_extensions)] ではダメ

    # <<< server Certificate <<<
    print("=== server Certificate ===")
    if len(remain_data) > 0:
        data = remain_data
    else:
        data = client_conn.recv_msg()
    print(hexdump(data))
    datalen = len(TLSCiphertext.from_bytes(data))
    recved_certificate = TLSCiphertext.restore(data,
            crypto=s_traffic_crypto, mode=ContentType.handshake)
    # messages += data[5:datalen]
    messages += recved_certificate.fragment.to_bytes()
    print(recved_certificate)
    remain_data = data[datalen:]

    # <<< server CertificateVerify <<<
    print("=== CertificateVerify ===")
    if len(remain_data) > 0:
        data = remain_data
    else:
        data = client_conn.recv_msg()
    datalen = len(TLSCiphertext.from_bytes(data))
    recved_cert_verify = TLSCiphertext.restore(data,
            crypto=s_traffic_crypto, mode=ContentType.handshake)
    messages += recved_cert_verify.fragment.to_bytes()
    print(recved_cert_verify)
    remain_data = data[datalen:]

    # <<< recv Finished <<<
    print("=== recv Finished ===")
    hash_size = CipherSuite.get_hash_algo_size(cipher_suite)
    Hash.set_size(hash_size)
    if len(remain_data) > 0:
        data = remain_data
    else:
        data = client_conn.recv_msg()
    datalen = len(TLSCiphertext.from_bytes(data))
    recved_finished = TLSCiphertext.restore(data,
            crypto=s_traffic_crypto, mode=ContentType.handshake)
    messages += recved_finished.fragment.to_bytes()
    print(recved_finished)
    remain_data = data[datalen:]
    assert isinstance(recved_finished.fragment.msg, Finished)

    # print(hexdump(messages))
    client_application_traffic_secret = \
        cryptomath.derive_secret(secret, b"c ap traffic", messages)
    server_application_traffic_secret = \
        cryptomath.derive_secret(secret, b"s ap traffic", messages)

    server_app_write_key, server_app_write_iv = \
        cryptomath.gen_key_and_iv(server_application_traffic_secret,
                key_size, nonce_size, hash_algo)
    server_app_data_crypto = cipher_class(
            key=server_app_write_key, nonce=server_app_write_iv)
    client_app_write_key, client_app_write_iv = \
        cryptomath.gen_key_and_iv(client_application_traffic_secret,
                key_size, nonce_size, hash_algo)
    client_app_data_crypto = cipher_class(
            key=client_app_write_key, nonce=client_app_write_iv)

    print('client_application_traffic_secret =', client_application_traffic_secret.hex())
    print('server_application_traffic_secret =', server_application_traffic_secret.hex())
    print('server_app_write_key =', server_app_write_key.hex())
    print('server_app_write_iv =', server_app_write_iv.hex())

    print('client_app_write_key =', client_app_write_key.hex())
    print('client_app_write_iv =', client_app_write_iv.hex())

    # import sys
    # sys.exit(0)

    # >>> Finished >>>
    # client_handshake_traffic_secret を使って finished_key を作成する
    hash_algo = CipherSuite.get_hash_algo_name(cipher_suite)
    hash_size = CipherSuite.get_hash_algo_size(cipher_suite)
    finished_key = cryptomath.HKDF_expand_label(
        client_application_traffic_secret, b'finished', b'', hash_size, hash_algo)
    verify_data = cryptomath.secureHMAC(
        finished_key, cryptomath.transcript_hash(messages, hash_algo), hash_algo)
    finished = TLSPlaintext(
        type=ContentType.handshake,
        fragment=Handshake(
            msg_type=HandshakeType.finished,
            msg=Finished(verify_data=verify_data) ))

    print(finished)
    # client_conn.send_msg(finished.to_bytes())
    finished_cipher = TLSCiphertext.create(finished, crypto=c_traffic_crypto)
    client_conn.send_msg(finished_cipher.to_bytes())
    # messages.append(finished.fragment)
    # messages += finished.fragment.to_bytes()

    # <<< recv NewSessionTicket <<<
    data = client_conn.recv_msg()
    # TODO: 受け取って復号化するときにシークエンス番号をインクリメントする
    server_app_data_crypto.get_nonce() # Nonceを取得する時に seq_number += 1 される

    # >>> Application Data <<<
    print("=== Application Data ===")

    app_data = TLSPlaintext(
        type=ContentType.application_data,
        fragment=Data(b'GET /html/index.html HTTP/1.1\n'))
    app_data_cipher = TLSCiphertext.create(app_data,
        crypto=client_app_data_crypto)
    client_conn.send_msg(app_data_cipher.to_bytes())

    # recv response
    data = client_conn.recv_msg()
    recved_app_data = TLSCiphertext.restore(data,
        crypto=server_app_data_crypto,
        mode=ContentType.application_data)

    print(recved_app_data)
    print(hexdump(recved_app_data.to_bytes()))


import secrets
from .utils import socket

from .protocol import TLSPlaintext, ContentType, Handshake, HandshakeType, \
    CipherSuite, ServerHello, KeyShareEntry, KeyShareServerHello, \
    Extension, ExtensionType, \
    ProtocolVersion, SupportedVersions, \
    NamedGroup, NamedGroupList, \
    SignatureScheme, SignatureSchemeList, \
    Certificate, CertificateEntry, CertificateVerify, Finished

# Crypto
from .utils.encryption.ffdhe import FFDHE

from .utils import cryptomath, hexdump, hexstr

def server_cmd(argv):
    print("server_cmd({})".format(", ".join(argv)))

    messages = []

    # <<< ClientHello <<<
    server_conn = socket.ServerConnection()
    data = server_conn.recv_msg()
    recved_clienthello = TLSPlaintext.from_bytes(data)
    messages.append(recved_clienthello.fragment)
    print(recved_clienthello)

    # >>> ServerHello >>>

    # select params

    client_session_id = recved_clienthello.legacy_session_id
    client_cipher_suites = recved_clienthello.cipher_suites
    client_key_share_groups = recved_clienthello \
        .get_extension(ExtensionType.key_share) \
        .get_groups()
    client_signature_scheme_list = recved_clienthello \
        .get_extension(ExtensionType.signature_algorithms) \
        .supported_signature_algorithms
    client_key_share = recved_clienthello \
        .get_extension(ExtensionType.key_share)

    # パラメータの決定と shared_key の作成
    # 暗号化：受け取ったClientHelloの暗号スイートから選ぶ
    cipher_suite = client_cipher_suites[0] # TODO: 暗号スイート実装してから優先順位を決める

    # 鍵共有：ClientHelloのKeyShareEntryを見てどの方法で鍵共有するか決めてから、
    # パラメータ（group, key_exchange）を決める
    if NamedGroup.ffdhe2048 in client_key_share_groups:
        server_share_group = NamedGroup.ffdhe2048
        client_key_exchange = client_key_share.get_key_exchange(server_share_group)
        ffdhe2048 = FFDHE(server_share_group)
        server_key_share_key_exchange = ffdhe2048.gen_public_key()
        shared_key = ffdhe2048.gen_shared_key(client_key_exchange)
    else:
        raise NotImplementedError()

    print("shared_key: %s" % hexstr(shared_key))

    selected_version = ProtocolVersion.TLS13

    serverhello = TLSPlaintext(
        type=ContentType.handshake,
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
    print(serverhello)
    server_conn.send_msg(serverhello.to_bytes())
    messages.append(serverhello.fragment)


    # -- HKDF ---

    hash_algo   = CipherSuite.get_hash_algo_name(cipher_suite)
    secret_size = CipherSuite.get_hash_algo_size(cipher_suite)
    secret = bytearray(secret_size)
    psk    = bytearray(secret_size)
    # early secret
    secret = cryptomath.HKDF_extract(secret, psk, hash_algo)
    # handshake secret
    secret = cryptomath.derive_secret(secret, b"derive", b"")
    secret = cryptomath.HKDF_extract(secret, shared_key, hash_algo)
    client_handshake_traffic_secret = \
        cryptomath.derive_secret(secret, b"c hs traffic", messages)
    server_handshake_traffic_secret = \
        cryptomath.derive_secret(secret, b"s hs traffic", messages)

    # master secret
    secret = cryptomath.derive_secret(secret, b"derive", b"")
    secret = cryptomath.HKDF_extract(secret, bytearray(secret_size), hash_algo)

    client_application_traffic_secret = \
        cryptomath.derive_secret(secret, b"c ap traffic", messages)
    server_application_traffic_secret = \
        cryptomath.derive_secret(secret, b"s ap traffic", messages)

    print('client_application_traffic_secret =',
        hexstr(client_application_traffic_secret))
    print('server_application_traffic_secret =',
        hexstr(server_application_traffic_secret))

    # >>> EncryptedExtensions >>>


    # >>> server Certificate >>>

    with open('.ssh/server.crt', 'r') as f:
        cert_data = ''.join(f.readlines()[1:-1]).replace('\n', '')
        cert_data = bytes(cert_data, 'ascii')

    certificate = TLSPlaintext(
        type=ContentType.handshake,
        fragment=Handshake(
            msg_type=HandshakeType.certificate,
            msg=Certificate(
                certificate_request_context=b'',
                certificate_list=[
                    CertificateEntry(cert_data=cert_data)
                ])))

    print(certificate)
    server_conn.send_msg(certificate.to_bytes())
    messages.append(certificate.fragment)


    # >>> CertificateVerify >>>

    # デジタル署名アルゴリズム
    # 秘密鍵 .ssh/server.key を使って署名する
    from Crypto.Hash import SHA256
    from Crypto.PublicKey import RSA
    key = RSA.import_key(open('.ssh/server.key').read())
    if SignatureScheme.rsa_pkcs1_sha256 in client_signature_scheme_list:
        server_signature_scheme = SignatureScheme.rsa_pkcs1_sha256
        from Crypto.Signature import pkcs1_15
        message = b'\x20' * 64 + b'TLS 1.3, server CertificateVerify' + b'\x00' + cert_data
        h = SHA256.new(message)
        certificate_signature = pkcs1_15.new(key).sign(h)
    else:
        raise NotImplementedError()

    cert_verify = TLSPlaintext(
        type=ContentType.handshake,
        fragment=Handshake(
            msg_type=HandshakeType.certificate_verify,
            msg=CertificateVerify(
                algorithm=server_signature_scheme,
                signature=certificate_signature )))

    print(cert_verify)
    server_conn.send_msg(cert_verify.to_bytes())
    messages.append(cert_verify.fragment)


    # >>> Finished >>>
    # server_handshake_traffic_secret を使って finished_key を作成する
    hash_algo = CipherSuite.get_hash_algo_name(cipher_suite)
    hash_size = CipherSuite.get_hash_algo_size(cipher_suite)
    finished_key = cryptomath.HKDF_expand_label(
        server_handshake_traffic_secret, b'finished', b'', hash_size, hash_algo)
    verify_data = cryptomath.secureHMAC(
        finished_key, cryptomath.transcript_hash(messages, hash_algo), hash_algo)
    finished = TLSPlaintext(
        type=ContentType.handshake,
        fragment=Handshake(
            msg_type=HandshakeType.finished,
            msg=Finished(verify_data=verify_data) ))

    print(finished)
    server_conn.send_msg(finished.to_bytes())
    messages.append(finished.fragment)

    # <<< recv Finished <<<
    hash_size = CipherSuite.get_hash_algo_size(cipher_suite)
    data = server_conn.recv_msg()
    recved_finished = TLSPlaintext.from_bytes(data)
    messages.append(recved_finished.fragment)
    print(recved_finished)

    # >>> Application Data <<<

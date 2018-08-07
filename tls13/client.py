
import secrets
from .utils import socket

from .protocol import TLSPlaintext, ContentType, Handshake, HandshakeType, \
    CipherSuite, ClientHello, Extension, ExtensionType, \
    KeyShareEntry, KeyShareClientHello, \
    ProtocolVersion, SupportedVersions, \
    NamedGroup, NamedGroupList, \
    SignatureScheme, SignatureSchemeList, \
    Finished, Hash, \
    TLSInnerPlaintext, TLSCiphertext, Data

# Crypto
from .utils.encryption.ffdhe import FFDHE
from .utils.encryption import Cipher

from .utils import cryptomath, hexdump, hexstr, Uint16

def client_cmd(argv):
    print("client_cmd({})".format(", ".join(argv)))

    messages = []

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
    cipher_suites = [
        CipherSuite.TLS_AES_128_GCM_SHA256,
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
    client_conn = socket.ClientConnection()
    # ClientHello が入っている TLSPlaintext
    print(clienthello)
    client_conn.send_msg(clienthello.to_bytes())
    messages.append(clienthello.fragment)

    # <<< ServerHello <<<
    data = client_conn.recv_msg()
    recved_serverhello = TLSPlaintext.from_bytes(data)
    messages.append(recved_serverhello.fragment)
    print(recved_serverhello)

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
        client_key_share_key_exchange = ffdhe2048_key_exchange
        shared_key = ffdhe2048.gen_shared_key(server_pub_key)
    elif server_key_share_group == NamedGroup.ffdge3072:
        pass # shared_key = ffdge3072.gen_shared_key(server_pub_key)
        raise NotImplementedError()
    else:
        raise NotImplementedError()

    print("shared_key: %s" % hexstr(shared_key))

    # -- HKDF ---

    cipher_suite = server_cipher_suite

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

    # [Haruka 8/6] TEST chacha20poly1305
    client_write_key = cryptomath.HKDF_expand_label(secret, b'key',
            b'', Cipher.Chacha20Poly1305.key_size, hash_algo)
    client_write_iv  = cryptomath.HKDF_expand_label(secret, b'iv',
            b'', Cipher.Chacha20Poly1305.nonce_size, hash_algo)

    print('client_write_key = ', client_write_key)
    print('client_write_iv = ', client_write_iv)

    chachaPoly = Cipher.Chacha20Poly1305(key=client_write_key,
                                         nonce=client_write_iv)

    # <<< server Certificate <<<
    data = client_conn.recv_msg()
    recved_certificate = TLSPlaintext.from_bytes(data)
    messages.append(recved_certificate.fragment)
    print(recved_certificate)

    # <<< server CertificateVerify <<<
    data = client_conn.recv_msg()
    recved_cert_verify = TLSPlaintext.from_bytes(data)
    messages.append(recved_cert_verify.fragment)
    print(recved_cert_verify)

    # <<< recv Finished <<<
    hash_size = CipherSuite.get_hash_algo_size(cipher_suite)
    Hash.set_size(hash_size)
    data = client_conn.recv_msg()
    recved_finished = TLSPlaintext.from_bytes(data)
    messages.append(recved_finished.fragment)
    print(recved_finished)
    assert isinstance(recved_finished.fragment.msg, Finished)


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
    client_conn.send_msg(finished.to_bytes())
    messages.append(finished.fragment)


    # >>> Application Data <<<
    print("=== Application Data ===")

    app_data = TLSPlaintext(
        type=ContentType.application_data,
        fragment=Data(b'GET /index.html\n'))
    app_data_inner = TLSInnerPlaintext.create(app_data)

    # additional_data = TLSCiphertext.opaque_type || .legacy_record_version || .length
    additional_data = b'\x23\x03\x03' + Uint16(len(app_data_inner)).to_bytes()

    print(app_data)
    print(app_data_inner)
    encrypted_record = chachaPoly.encrypt(app_data_inner.to_bytes())
    app_data_cipher = TLSCiphertext(encrypted_record=encrypted_record)
    print(app_data_cipher)

    client_conn.send_msg(app_data_cipher.to_bytes())

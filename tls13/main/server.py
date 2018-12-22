
import time
import secrets
from ..utils import connection, cryptomath, http_parser
from ..protocol import *
from ..metastruct import *

# Crypto
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, \
    X25519PublicKey
from ..encryption.ffdhe import FFDHE
from ..encryption import Cipher


# TODO: グローバル変数作るならこんな感じ
class Global:
    connect_side = "server"
    current_mode = ContentType.handshake


class TLSServer:
    def __init__(self, server_conn):
        self.server_conn = server_conn

        messages = bytearray(0)

        # <<< ClientHello <<<
        data = server_conn.recv_msg()
        recved_clienthello = TLSPlaintext.from_bytes(data)
        # TLSPlaintext.fragment のバイト列を得るために
        # len(ContentType + ProtocolVersion + length) == 5 より後ろのバイト列を取る
        messages += data[5:]
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
        client_key_share = recved_clienthello.get_extension(ExtensionType.key_share)

        # パラメータの決定と shared_key の作成
        # 暗号化：受け取ったClientHelloの暗号スイートから選ぶ
        if CipherSuite.TLS_CHACHA20_POLY1305_SHA256 in client_cipher_suites:
            cipher_suite = CipherSuite.TLS_CHACHA20_POLY1305_SHA256
        else:
            raise NotImplementedError()

        # 鍵共有：ClientHelloのKeyShareEntryを見てどの方法で鍵共有するか決めてから、
        # パラメータ（group, key_exchange）を決める
        if NamedGroup.ffdhe2048 in client_key_share_groups:
            server_share_group = NamedGroup.ffdhe2048
            client_key_exchange = client_key_share.get_key_exchange(server_share_group)
            ffdhe2048 = FFDHE(server_share_group)
            server_key_share_key_exchange = ffdhe2048.gen_public_key()
            shared_key = ffdhe2048.gen_shared_key(client_key_exchange)
        elif NamedGroup.x25519 in client_key_share_groups:
            server_share_group = NamedGroup.x25519
            client_key_exchange = client_key_share.get_key_exchange(server_share_group)
            x25519 = X25519PrivateKey.generate()
            server_key_share_key_exchange = x25519.public_key().public_bytes()
            shared_key = \
                x25519.exchange(X25519PublicKey.from_public_bytes(client_key_exchange))
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
        messages += serverhello.fragment.to_bytes()

        # -- HKDF ---

        hash_algo   = CipherSuite.get_hash_algo_name(cipher_suite)
        secret_size = CipherSuite.get_hash_algo_size(cipher_suite)
        secret = bytearray(secret_size)
        psk    = bytearray(secret_size)

        # print("messages = ")
        # print(hexdump(messages))
        print("messages hash = " + cryptomath.secureHash(messages, 'sha256').hex())
        print()

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

        # >>> EncryptedExtensions >>>

        encrypted_extensions = TLSPlaintext(
            type=ContentType.handshake,
            fragment=Handshake(
                msg_type=HandshakeType.encrypted_extensions,
                msg=EncryptedExtensions(extensions=[]) ))

        print(encrypted_extensions)
        print(hexdump(encrypted_extensions.to_bytes()))
        encrypted_extensions_cipher = \
            TLSCiphertext.create(encrypted_extensions, crypto=s_traffic_crypto)
        print(encrypted_extensions_cipher)
        print(hexdump(encrypted_extensions_cipher.to_bytes()))
        server_conn.send_msg(encrypted_extensions_cipher.to_bytes())
        messages += encrypted_extensions.fragment.to_bytes()

        # >>> server Certificate >>>

        with open('.ssh/server.crt', 'r') as f:
            import ssl
            bytes_DER_encoded = ssl.PEM_cert_to_DER_cert(f.read())
            cert_data = bytes_DER_encoded

        certificate = TLSPlaintext(
            type=ContentType.handshake,
            fragment=Handshake(
                msg_type=HandshakeType.certificate,
                msg=Certificate(
                    certificate_request_context=b'',
                    certificate_list=[
                        CertificateEntry(cert_data=cert_data)
                    ])))

        print("=== Certificate ===")
        print(certificate)
        print(hexdump(certificate.to_bytes()))
        certificate_cipher = TLSCiphertext.create(certificate, crypto=s_traffic_crypto)
        print(hexdump(certificate_cipher.to_bytes()))
        server_conn.send_msg(certificate_cipher.to_bytes())
        messages += certificate.fragment.to_bytes()

        # >>> CertificateVerify >>>

        # デジタル署名アルゴリズム
        # 秘密鍵 .ssh/server.key を使って署名する
        from Crypto.Hash import SHA256
        from Crypto.PublicKey import RSA
        key = RSA.importKey(open('.ssh/server.key').read())
        if SignatureScheme.rsa_pss_pss_sha256 in client_signature_scheme_list:
            server_signature_scheme = SignatureScheme.rsa_pss_pss_sha256
            from Crypto.Signature import PKCS1_PSS
            message = b'\x20' * 64 + b'TLS 1.3, server CertificateVerify' + b'\x00' + cryptomath.transcript_hash(messages, hash_algo)
            print("message:")
            print(hexdump(message))
            h = SHA256.new(message)
            certificate_signature = PKCS1_PSS.new(key).sign(h)
        else:
            raise NotImplementedError()

        cert_verify = TLSPlaintext(
            type=ContentType.handshake,
            fragment=Handshake(
                msg_type=HandshakeType.certificate_verify,
                msg=CertificateVerify(
                    algorithm=server_signature_scheme,
                    signature=certificate_signature )))

        print("=== CertificateVerify ===")
        print(cert_verify)
        # server_conn.send_msg(cert_verify.to_bytes())
        cert_verify_cipher = TLSCiphertext.create(cert_verify, crypto=s_traffic_crypto)
        server_conn.send_msg(cert_verify_cipher.to_bytes())
        # messages.append(cert_verify.fragment)
        messages += cert_verify.fragment.to_bytes()

        # >>> Finished >>>

        # server_handshake_traffic_secret を使って finished_key を作成する
        hash_algo = CipherSuite.get_hash_algo_name(cipher_suite)
        hash_size = CipherSuite.get_hash_algo_size(cipher_suite)
        Hash.set_size(hash_size)
        finished_key = cryptomath.HKDF_expand_label(
            server_handshake_traffic_secret, b'finished', b'', hash_size, hash_algo)
        verify_data = cryptomath.secureHMAC(
            finished_key, cryptomath.transcript_hash(messages, hash_algo), hash_algo)
        finished = TLSPlaintext(
            type=ContentType.handshake,
            fragment=Handshake(
                msg_type=HandshakeType.finished,
                msg=Finished(verify_data=verify_data) ))

        print("=== Finished ===")
        print(finished)
        print(hexdump(finished.to_bytes()))
        finished_cipher = TLSCiphertext.create(finished, crypto=s_traffic_crypto)
        server_conn.send_msg(finished_cipher.to_bytes())
        messages += finished.fragment.to_bytes()

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

        self.server_app_data_crypto = server_app_data_crypto
        self.client_app_data_crypto = client_app_data_crypto

        print('client_application_traffic_secret =', client_application_traffic_secret.hex())
        print('server_application_traffic_secret =', server_application_traffic_secret.hex())
        print('server_app_write_key =', server_app_write_key.hex())
        print('server_app_write_iv =', server_app_write_iv.hex())

        print('client_app_write_key =', client_app_write_key.hex())
        print('client_app_write_iv =', client_app_write_iv.hex())

        # import sys
        # sys.exit(0)

        # <<< recv Finished <<<
        print("=== recv Finished ===")
        hash_size = CipherSuite.get_hash_algo_size(cipher_suite)
        data = server_conn.recv_msg()
        print(hexdump(data))
        if len(data) == 7: # Alertのとき
            print(TLSPlaintext.from_bytes(data))
            raise RuntimeError("Alert!")
        # TODO: 複数のメッセージ（例えば ChangeCipherSpec + Finished）が
        #       同時に送られて来たときの処理が必要
        if data[6:] == b'\x14\x03\x03\x00\x01\x01':
            print("remove: change cipher spec")
            trimed_data = data[6:] # change cipher spec (14 03 03 00 01 01) を取り除く
        else:
            trimed_data = data
        print(hexdump(trimed_data))

        # # recved_finished = TLSPlaintext.from_bytes(data)
        # Cipher.Cipher.seq_number = 0
        # recved_finished = TLSCiphertext.restore(trimed_data, crypto=c_traffic_crypto)
        # # messages.append(recved_finished.fragment)
        # messages += recved_finished.fragment.to_bytes()
        # print(recved_finished)
        # assert isinstance(recved_finished.fragment.msg, Finished)
        recved_finished = TLSRawtext.from_bytes(trimed_data)
        print(recved_finished)

        from ..protocol.ticket import NewSessionTicket
        # dummy
        new_session_ticket = TLSPlaintext(
            type=ContentType.handshake,
            fragment=Handshake(
                msg_type=HandshakeType.new_session_ticket,
                msg=NewSessionTicket(
                    ticket_lifetime=Uint32(0),
                    ticket_age_add=Uint32(0),
                    ticket_nonce=b'nonce',
                    ticket=b'foobar',
                    extensions=[] )))

        Cipher.Cipher.seq_number = 0

        print("=== NewSessionTicket ===")
        print(new_session_ticket)
        new_session_ticket_cipher = TLSCiphertext.create(
                new_session_ticket, crypto=server_app_data_crypto)
        server_conn.send_msg(new_session_ticket_cipher.to_bytes())
        # messages += new_session_ticket.fragment.to_bytes()


    def recv(self):
        while True:
            data = self.server_conn.recv_msg()
            if len(data) != 0:
                break
            time.sleep(0.5)

        print("* [recv] raw")
        print(hexdump(data))
        recved_app_data = TLSCiphertext.restore(data,
                crypto=self.client_app_data_crypto,
                mode=ContentType.application_data)
        print("* [recv] app_data")
        print(recved_app_data)
        print(str(recved_app_data.raw))

        return recved_app_data.raw

    def send(self, send_bytes):
        app_data = TLSPlaintext(
            type=ContentType.application_data,
            fragment=Data(send_bytes))
        app_data_cipher = TLSCiphertext.create(app_data,
            crypto=self.server_app_data_crypto)
        self.server_conn.send_msg(app_data_cipher.to_bytes())
        print("* [send]")
        print(hexdump(app_data_cipher.to_bytes()))

        return len(app_data_cipher)


def server_cmd(argv):
    print("server_cmd({})".format(", ".join(argv)))

    # from http.server import HTTPServer, SimpleHTTPRequestHandler
    # http_server = HTTPServer(('localhost', 50007), SimpleHTTPRequestHandler)
    #
    # def wrap_socket(sock):
    #     server_conn = socket.ServerConnection(socket=http_server.socket)
    #     tls_server = TLSServer(server_conn)
    #     return tls_server.my_socket()
    #
    # http_server.socket = wrap_socket(http_server.sock)
    # http_server.serve_forever()

    server_conn = connection.ServerConnection()
    server = TLSServer(server_conn)

    while True:
        data = server.recv()

        try:
            params = http_parser.parse(data.decode())
            filename = params['request_url']
            print("filename:", filename)
        except Exception as e:
            print("[-] invalid request")
            print(e)
            data = b'HTTP/1.1 404 Not Found\r\n\r\n'
            server.send(data)
            break

        try:
            # TODO: insecure!
            with open(filename, 'r') as f:
                data = f.read().encode()
        except FileNotFoundError as e:
            print("[-] file not found: %s" % filename)
            data = b'HTTP/1.1 404 Not Found\r\n\r\n'

        server.send(data)

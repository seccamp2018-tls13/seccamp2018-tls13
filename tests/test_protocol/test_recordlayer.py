
import unittest
import secrets

from tls13.protocol import *
from tls13.utils.type import *

from .common import TypeTestMixin


class ContentTypeTest(unittest.TestCase, TypeTestMixin):

    def setUp(self):
        self.target = ContentType


class TLSPlaintextTest(unittest.TestCase):

    def setUp(self):
        # ClientHello in TLSPlaintext
        self.ch_plain = TLSPlaintext(
            type=ContentType.handshake,
            fragment=Handshake(
                msg_type=HandshakeType.client_hello,
                msg=ClientHello(
                    cipher_suites=[CipherSuite.TLS_AES_128_GCM_SHA256],
                    extensions=[
                        Extension(
                            extension_type=ExtensionType.supported_versions,
                            extension_data=SupportedVersions(
                                msg_type=HandshakeType.client_hello,
                                versions=[ Uint16(0x0304) ] )),
                        Extension(
                            extension_type=ExtensionType.supported_groups,
                            extension_data=NamedGroupList(
                                named_group_list=[
                                    NamedGroup.ffdhe2048 ] )),
                        Extension(
                            extension_type=ExtensionType.signature_algorithms,
                            extension_data=SignatureSchemeList(
                                supported_signature_algorithms=[
                                    SignatureScheme.rsa_pkcs1_sha256 ] )),
                        Extension(
                            extension_type=ExtensionType.key_share,
                            extension_data=KeyShareClientHello(
                                client_shares=[
                                    KeyShareEntry(
                                        group=NamedGroup.ffdhe2048,
                                        key_exchange=secrets.token_bytes(2048 // 8)) ] )), ]) ))
        #
        # ServerHello in TLSPlaintext
        self.sh_plain = TLSPlaintext(
            type=ContentType.handshake,
            fragment=Handshake(
                msg_type=HandshakeType.server_hello,
                msg=ServerHello(
                    legacy_session_id_echo=secrets.token_bytes(32),
                    cipher_suite=CipherSuite.TLS_AES_128_GCM_SHA256,
                    extensions=[
                        Extension(
                            extension_type=ExtensionType.supported_versions,
                            extension_data=SupportedVersions(
                                msg_type=HandshakeType.server_hello,
                                selected_version=Uint16(0x0304) )),
                        Extension(
                            extension_type=ExtensionType.key_share,
                            extension_data=KeyShareServerHello(
                                server_share=KeyShareEntry(
                                    group=NamedGroup.ffdhe2048,
                                    key_exchange=secrets.token_bytes(2048 // 8) ))) ] )))

    # --- ClientHello ---

    def test_clienthello_length(self):
        self.assertEqual(
            type(self.ch_plain.length), Uint16,
            'should be Uint16')
        self.assertEqual(
            self.ch_plain.length, Uint16(len(self.ch_plain.fragment)),
            'should be correct length')

    def test_clienthello_fragment(self):
        self.assertEqual(
            type(self.ch_plain.fragment), Handshake, 'should be Handshake')

    def test_restruct_clienthello_from_bytes(self):
        ch_bytes = self.ch_plain.to_bytes()
        ch_plain_restructed = TLSPlaintext.from_bytes(ch_bytes)
        self.assertEqual(
            repr(self.ch_plain), repr(ch_plain_restructed),
            'should be same structure')

    # --- ServerHello ---

    def test_serverhello_length(self):
        self.assertEqual(
            type(self.ch_plain.length), Uint16,
            'should be Uint16')
        self.assertEqual(
            self.ch_plain.length, Uint16(len(self.ch_plain.fragment)),
            'should be correct length')

    def test_serverhello_fragment(self):
        self.assertEqual(
            type(self.ch_plain.fragment), Handshake, 'should be Handshake')

    def test_restruct_serverhello_from_bytes(self):
        sh_bytes = self.sh_plain.to_bytes()
        sh_plain_restructed = TLSPlaintext.from_bytes(sh_bytes)
        self.assertEqual(
            repr(self.sh_plain), repr(sh_plain_restructed),
            'should be same structure')


    # --- TLSPlaintext methods ---

    def test_getattr(self):
        self.assertEqual(
            self.ch_plain.fragment.msg.cipher_suites, self.ch_plain.cipher_suites)
        self.assertEqual(
            self.ch_plain.fragment.msg.extensions, self.ch_plain.extensions)
        self.assertEqual(
            self.ch_plain.fragment.msg \
                         .get_extension(extension_type=ExtensionType.key_share),
            self.ch_plain.get_extension(extension_type=ExtensionType.key_share))

    def test_getattr_with_no_handshake_obj(self):
        self.ch_plain.fragment = None
        self.assertRaises(AttributeError, lambda: self.ch_plain.cipher_suite)

    def test_getattr_with_no_msg_obj(self):
        self.ch_plain.fragment.msg = None
        self.assertRaises(AttributeError, lambda: self.ch_plain.cipher_suite)

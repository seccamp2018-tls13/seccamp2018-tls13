
import secrets
import unittest

from tls13.protocol import *
from tls13.utils.type import *

from ..common import TypeTestMixin, StructTestMixin


class ClientHelloTest(unittest.TestCase, StructTestMixin):

    def setUp(self):
        self.target = ClientHello
        self.obj = ClientHello(
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
                                key_exchange=secrets.token_bytes(2048 // 8)) ] )), ])

    def test_wrong_args(self):
        self.assertRaises(Exception, lambda:
            ClientHello(cipher_suites=[Uint32(0x00)]))

    def test_get_extension(self):
        ext = self.obj.get_extension(extension_type=ExtensionType.supported_groups)
        self.assertTrue(ext)
        ext = self.obj.get_extension(extension_type=Uint.get_type(ExtensionType._size)(0x00))
        self.assertEqual(ext, None)


class ServerHelloTest(unittest.TestCase, StructTestMixin):

    def setUp(self):
        self.target = ServerHello
        self.obj = ServerHello(
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
                            key_exchange=secrets.token_bytes(2048 // 8) ))) ] )

    def test_get_extension(self):
        ext = self.obj.get_extension(extension_type=ExtensionType.supported_versions)
        self.assertTrue(ext)
        ext = self.obj.get_extension(extension_type=Uint.get_type(ExtensionType._size)(0x00))
        self.assertEqual(ext, None)


class ExtensionTypeTest(unittest.TestCase, TypeTestMixin):

    def setUp(self):
        self.target = ExtensionType


class ExtensionTest(unittest.TestCase, StructTestMixin):

    def setUp(self):
        self.target = Extension
        self.obj = Extension(
            extension_type=ExtensionType.supported_versions,
            extension_data=SupportedVersions(
                msg_type=HandshakeType.server_hello,
                selected_version=Uint16(0x0304) ))

    def test_restruct(self):
        restructed = Extension.from_bytes(self.obj.to_bytes(),
                                          msg_type=HandshakeType.server_hello)
        self.assertEqual(repr(self.obj), repr(restructed))

    def test_from_bytes__error_when_unset_msg_type(self):
        self.assertRaises(Exception, lambda: Extension.from_bytes(self.obj.to_bytes()))


class KeyShareEntryTest(unittest.TestCase, StructTestMixin):

    def setUp(self):
        self.target = KeyShareEntry
        self.obj = KeyShareEntry(
            group=NamedGroup.secp256r1,
            key_exchange=b'1234567890foobar')


class KeyShareClientHelloTest(unittest.TestCase, StructTestMixin):

    def setUp(self):
        self.target = KeyShareClientHello
        self.my_key_exchange = secrets.token_bytes(2048 // 8)
        self.obj = KeyShareClientHello(
            client_shares=[
                KeyShareEntry(
                    group=NamedGroup.ffdhe2048,
                    key_exchange=self.my_key_exchange ),
                KeyShareEntry(
                    group=NamedGroup.ffdhe3072,
                    key_exchange=secrets.token_bytes(3072 // 8))
            ])

    def test_get_key_exchange(self):
        key_exchange = self.obj.get_key_exchange(group=NamedGroup.ffdhe2048)
        self.assertEqual(key_exchange, self.my_key_exchange)
        self.assertTrue(type(key_exchange) == bytes)


class KeyShareServerHelloTest(unittest.TestCase, StructTestMixin):

    def setUp(self):
        self.target = KeyShareServerHello
        self.my_key_exchange = secrets.token_bytes(2048 // 8)
        self.obj = KeyShareServerHello(
            server_share=KeyShareEntry(
                group=NamedGroup.ffdhe2048,
                key_exchange=self.my_key_exchange ))

    def test_get_key_exchange(self):
        key_exchange = self.obj.get_key_exchange()
        self.assertEqual(key_exchange, self.my_key_exchange)
        self.assertTrue(type(key_exchange) == bytes)

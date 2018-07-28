
import secrets
import unittest

from tls13.protocol import *
from tls13.utils.type import *

from ..common import TypeTestMixin


class ClientHelloTest(unittest.TestCase):

    def setUp(self):
        self.ch = ClientHello(
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

    def test_length(self):
        obj = self.ch
        self.assertEqual(len(obj), len(obj.to_bytes()))

    def test_restruct(self):
        restructed = ClientHello.from_bytes(self.ch.to_bytes())
        self.assertEqual(repr(self.ch), repr(restructed))

    def test_get_extension(self):
        ext = self.ch.get_extension(extension_type=ExtensionType.supported_groups)
        self.assertTrue(ext)
        ext = self.ch.get_extension(extension_type=Uint.get_type(ExtensionType._size)(0x00))
        self.assertEqual(ext, None)


class ServerHelloTest(unittest.TestCase):

    def setUp(self):
        self.sh = ServerHello(
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

    def test_length(self):
        obj = self.sh
        self.assertEqual(len(obj), len(obj.to_bytes()))

    def test_restruct(self):
        restructed = ServerHello.from_bytes(self.sh.to_bytes())
        self.assertEqual(repr(self.sh), repr(restructed))

    def test_get_extension(self):
        ext = self.sh.get_extension(extension_type=ExtensionType.supported_versions)
        self.assertTrue(ext)
        ext = self.sh.get_extension(extension_type=Uint.get_type(ExtensionType._size)(0x00))
        self.assertEqual(ext, None)


class ExtensionTypeTest(unittest.TestCase, TypeTestMixin):

    def setUp(self):
        self.target = ExtensionType


class ExtensionTest(unittest.TestCase):

    def setUp(self):
        self.ext = Extension(
            extension_type=ExtensionType.supported_versions,
            extension_data=SupportedVersions(
                msg_type=HandshakeType.server_hello,
                selected_version=Uint16(0x0304) ))

    def test_length(self):
        obj = self.ext
        self.assertEqual(len(obj), len(obj.to_bytes()))

    def test_restruct(self):
        restructed = Extension.from_bytes(self.ext.to_bytes(),
                                          msg_type=HandshakeType.server_hello)
        self.assertEqual(repr(self.ext), repr(restructed))

    def test_from_bytes__error_when_unset_msg_type(self):
        self.assertRaises(Exception, lambda: Extension.from_bytes(self.ext.to_bytes()))


class KeyShareEntryTest(unittest.TestCase):

    def setUp(self):
        self.key_share_entry = KeyShareEntry(
            group=NamedGroup.secp256r1,
            key_exchange=b'1234567890foobar'
        )

    def test_length(self):
        obj = self.key_share_entry
        self.assertEqual(len(obj), len(obj.to_bytes()))

    def test_restruct(self):
        restructed = KeyShareEntry.from_bytes(self.key_share_entry.to_bytes())
        self.assertEqual(repr(self.key_share_entry), repr(restructed))


class KeyShareClientHelloTest(unittest.TestCase):

    def setUp(self):
        self.my_key_exchange = secrets.token_bytes(2048 // 8)
        self.ch = ClientHello(
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
                                key_exchange=self.my_key_exchange ),
                            KeyShareEntry(
                                group=NamedGroup.ffdhe3072,
                                key_exchange=secrets.token_bytes(3072 // 8))
                                ] )), ])

    def test_get_key_exchange(self):
        key_exchange = \
            self.ch.get_extension(extension_type=ExtensionType.key_share) \
            .get_key_exchange(group=NamedGroup.ffdhe2048)
        self.assertEqual(key_exchange, self.my_key_exchange)
        self.assertTrue(type(key_exchange) == bytes)


class KeyShareServerHelloTest(unittest.TestCase):

    def setUp(self):
        self.my_key_exchange = secrets.token_bytes(2048 // 8)
        self.sh = ServerHello(
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
                            key_exchange=self.my_key_exchange ))) ] )

    def test_get_key_exchange(self):
        key_exchange = \
            self.sh.get_extension(extension_type=ExtensionType.key_share) \
            .get_key_exchange()
        self.assertEqual(key_exchange, self.my_key_exchange)
        self.assertTrue(type(key_exchange) == bytes)

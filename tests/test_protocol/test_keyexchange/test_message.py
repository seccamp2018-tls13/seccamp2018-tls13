
import unittest

from tls13.protocol.keyexchange.messages import *
from tls13.protocol.keyexchange.version import *
from tls13.protocol.keyexchange.supportedgroups import *
from tls13.protocol.keyexchange.signature import *
from tls13.utils.type import *

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


class ExtensionTypeTest(unittest.TestCase):

    def test_size(self):
        self.assertTrue(hasattr(ExtensionType, '_size'))

    def test_values(self):
        UintN = Uint.get_type(size=ExtensionType._size)
        self.assertTrue(all( type(v) == UintN for v in ExtensionType.values ))

    def test_labels(self):
        self.assertTrue(all( ExtensionType.labels[v] for v in ExtensionType.values ))


class ExtensionTest(unittest.TestCase):

    @unittest.skip('empty')
    def test_(self):
        pass


class KeyShareEntryTest(unittest.TestCase):

    @unittest.skip('empty')
    def test_(self):
        pass


class KeyShareClientHelloTest(unittest.TestCase):

    @unittest.skip('empty')
    def test_(self):
        pass


class KeyShareServerHelloTest(unittest.TestCase):

    @unittest.skip('empty')
    def test_(self):
        pass


import unittest
import socket
import secrets

from tls13.protocol.recordlayer import TLSPlaintext, ContentType
from tls13.protocol.handshake import Handshake, HandshakeType
from tls13.protocol.ciphersuite import CipherSuite
from tls13.protocol.keyexchange.messages import ClientHello, Extension, ExtensionType, \
    KeyShareEntry, KeyShareClientHello

# Extensions
from tls13.protocol.keyexchange.version import SupportedVersions
from tls13.protocol.keyexchange.supportedgroups import NamedGroup, NamedGroupList
from tls13.protocol.keyexchange.signature import SignatureScheme, SignatureSchemeList

from tls13.utils.type import Uint8, Uint16, Uint24, Uint32


class ContentTypeTest(unittest.TestCase):

    @unittest.skip('empty')
    def test_(self):
        pass


class TLSPlaintextTest(unittest.TestCase):

    def setUp(self):
        # ClientHello in TLSPlaintext
        self.ch_plain = TLSPlaintext(
            _type=ContentType.handshake,
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

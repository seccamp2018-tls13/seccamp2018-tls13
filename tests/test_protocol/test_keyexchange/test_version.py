
import unittest

from tls13.protocol.handshake import HandshakeType
from tls13.protocol.keyexchange.version import *
from tls13.utils.type import Uint16, Uint


class ProtocolVersionTest(unittest.TestCase):

    def test_size(self):
        self.assertTrue(hasattr(ProtocolVersion, '_size'))

    def test_values(self):
        UintN = Uint.get_type(size=ProtocolVersion._size)
        self.assertTrue(all( type(v) == UintN for v in ProtocolVersion.values ))

    def test_labels(self):
        self.assertTrue(all( ProtocolVersion.labels[v] for v in ProtocolVersion.values ))


class SupportedVersionsTest(unittest.TestCase):

    def setUp(self):
        self.supported_versions_ch = \
            SupportedVersions(msg_type=HandshakeType.client_hello,
                              versions=[Uint16(0x0303), Uint16(0x0302)])

        self.supported_versions_sh = \
            SupportedVersions(msg_type=HandshakeType.server_hello,
                              selected_version=Uint16(0x0303) )

    def test_length(self):
        obj = self.supported_versions_ch
        self.assertEqual(len(obj), len(obj.to_bytes()))

        obj = self.supported_versions_sh
        self.assertEqual(len(obj), len(obj.to_bytes()))

    def test_restruct(self):
        restructed = \
            SupportedVersions.from_bytes(self.supported_versions_ch.to_bytes(),
                                         msg_type=HandshakeType.client_hello)
        self.assertEqual(repr(self.supported_versions_ch), repr(restructed))

        restructed = \
            SupportedVersions.from_bytes(self.supported_versions_sh.to_bytes(),
                                         msg_type=HandshakeType.server_hello)
        self.assertEqual(repr(self.supported_versions_sh), repr(restructed))

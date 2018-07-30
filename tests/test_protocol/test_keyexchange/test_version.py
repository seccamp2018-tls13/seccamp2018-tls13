
import unittest

from tls13.protocol.handshake import HandshakeType
from tls13.protocol.keyexchange.version import *
from tls13.utils.type import Uint16, Uint
from ..common import TypeTestMixin, StructTestMixin


class ProtocolVersionTest(unittest.TestCase, TypeTestMixin):

    def setUp(self):
        self.target = ProtocolVersion


class SupportedVersionsTest(unittest.TestCase):

    def setUp(self):
        self.target = SupportedVersions
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

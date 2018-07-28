
import unittest

from tls13.protocol.handshake import *
from tls13.protocol.keyexchange.messages import *
from tls13.utils.type import *

from .common import TypeTestMixin


class HandshakeTypeTest(unittest.TestCase, TypeTestMixin):

    def setUp(self):
        self.target = HandshakeType


class HandshakeTest(unittest.TestCase):

    def setUp(self):
        self.handshake = Handshake(
            msg_type=HandshakeType.client_hello,
            msg=ClientHello())

    def test_length(self):
        obj = self.handshake
        self.assertEqual(len(obj), len(obj.to_bytes()))

    def test_restruct(self):
        restructed = Handshake.from_bytes(self.handshake.to_bytes())
        self.assertEqual(repr(self.handshake), repr(restructed))

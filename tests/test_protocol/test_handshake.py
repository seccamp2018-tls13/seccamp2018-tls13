
import unittest

from tls13.protocol.handshake import *
from tls13.protocol.keyexchange.messages import *
from tls13.utils.type import *

class HandshakeTypeTest(unittest.TestCase):

    def test_size(self):
        self.assertTrue(hasattr(HandshakeType, '_size'))

    def test_values(self):
        UintN = Uint.get_type(size=HandshakeType._size)
        self.assertTrue(all( type(v) == UintN for v in HandshakeType.values ))

    def test_labels(self):
        self.assertTrue(all( HandshakeType.labels[v] for v in HandshakeType.values ))


class HandshakeTest(unittest.TestCase):

    def test_restruct_handshake(self):
        handshake = Handshake(
            msg_type=HandshakeType.client_hello,
            msg=ClientHello())

        restructed_handshake = Handshake.from_bytes(handshake.to_bytes())

        self.assertEqual(repr(handshake), repr(restructed_handshake))

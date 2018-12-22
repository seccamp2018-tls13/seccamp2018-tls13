
import unittest

from tls13.protocol.handshake import *
from tls13.protocol.keyexchange.messages import *
from tls13.metastruct.type import *

from .common import TypeTestMixin, StructTestMixin


class HandshakeTypeTest(unittest.TestCase, TypeTestMixin):

    def setUp(self):
        self.target = HandshakeType


class HandshakeTest(unittest.TestCase, StructTestMixin):

    def setUp(self):
        self.target = Handshake
        self.obj = Handshake(
            msg_type=HandshakeType.client_hello,
            msg=ClientHello())

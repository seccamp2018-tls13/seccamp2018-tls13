
import unittest

from tls13.protocol.keyexchange.messages import *
from tls13.utils.type import *

class ClientHelloTest(unittest.TestCase):

    @unittest.skip('empty')
    def test_(self):
        pass


class ServerHelloTest(unittest.TestCase):

    @unittest.skip('empty')
    def test_(self):
        pass


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

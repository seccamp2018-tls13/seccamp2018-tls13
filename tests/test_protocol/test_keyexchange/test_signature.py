
import unittest

from tls13.protocol.keyexchange.signature import *
from tls13.utils.type import *

class SignatureSchemeTest(unittest.TestCase):

    def test_size(self):
        self.assertTrue(hasattr(SignatureScheme, '_size'))

    def test_values(self):
        UintN = Uint.get_type(size=SignatureScheme._size)
        self.assertTrue(all( type(v) == UintN for v in SignatureScheme.values ))

    def test_labels(self):
        self.assertTrue(all( SignatureScheme.labels[v] for v in SignatureScheme.values ))


class SignatureSchemeListTest(unittest.TestCase):

    @unittest.skip('empty')
    def test_(self):
        pass

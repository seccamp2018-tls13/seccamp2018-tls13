
import unittest

from tls13.protocol.keyexchange.supportedgroups import *
from tls13.utils.type import *

class NamedGroupTest(unittest.TestCase):

    def test_size(self):
        self.assertTrue(hasattr(NamedGroup, '_size'))

    def test_values(self):
        UintN = Uint.get_type(size=NamedGroup._size)
        self.assertTrue(all( type(v) == UintN for v in NamedGroup.values ))

    def test_labels(self):
        self.assertTrue(all( NamedGroup.labels[v] for v in NamedGroup.values ))


class NamedGroupListTest(unittest.TestCase):

    @unittest.skip('empty')
    def test_(self):
        pass

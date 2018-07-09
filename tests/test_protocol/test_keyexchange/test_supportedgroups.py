
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

    def setUp(self):
        self.named_group_list = \
            NamedGroupList(named_group_list=[NamedGroup.secp256r1,
                                             NamedGroup.ffdhe4096,
                                             NamedGroup.x25519] )

    def test_length(self):
        obj = self.named_group_list
        self.assertEqual(len(obj), len(obj.to_bytes()))

    def test_restruct(self):
        restructed = NamedGroupList.from_bytes(self.named_group_list.to_bytes())
        self.assertEqual(repr(self.named_group_list), repr(restructed))

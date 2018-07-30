
import unittest

from tls13.protocol.keyexchange.supportedgroups import *
from tls13.utils.type import *
from ..common import TypeTestMixin, StructTestMixin


class NamedGroupTest(unittest.TestCase, TypeTestMixin):

    def setUp(self):
        self.target = NamedGroup


class NamedGroupListTest(unittest.TestCase, StructTestMixin):

    def setUp(self):
        self.target = NamedGroupList
        self.obj = \
            NamedGroupList(named_group_list=[NamedGroup.secp256r1,
                                             NamedGroup.ffdhe4096,
                                             NamedGroup.x25519] )

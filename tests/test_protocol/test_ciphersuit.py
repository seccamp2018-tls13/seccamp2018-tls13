
import unittest

from tls13.protocol.ciphersuite import *
from tls13.utils.type import *

class CipherSuiteTest(unittest.TestCase):

    def test_size(self):
        self.assertTrue(hasattr(CipherSuite, '_size'))

    def test_values(self):
        UintN = Uint.get_type(size=CipherSuite._size)
        self.assertTrue(all( type(v) == UintN for v in CipherSuite.values ))

    def test_labels(self):
        self.assertTrue(all( CipherSuite.labels[v] for v in CipherSuite.values ))

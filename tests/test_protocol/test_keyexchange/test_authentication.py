
import unittest

from tls13.protocol.keyexchange.authentication import *
from tls13.utils.type import *

class CertificateTypeTest(unittest.TestCase):

    def test_size(self):
        self.assertTrue(hasattr(CertificateType, '_size'))

    def test_values(self):
        UintN = Uint.get_type(size=CertificateType._size)
        self.assertTrue(all( type(v) == UintN for v in CertificateType.values ))

    def test_labels(self):
        self.assertTrue(all( CertificateType.labels[v] for v in CertificateType.values ))


class CertificateEntryTest(unittest.TestCase):
    pass


class CertificateTest(unittest.TestCase):
    pass


class CertificateVerifyTest(unittest.TestCase):
    pass


class FinishedTest(unittest.TestCase):
    pass

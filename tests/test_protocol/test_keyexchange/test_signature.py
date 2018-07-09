
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

    def setUp(self):
        algos = [SignatureScheme.rsa_pkcs1_sha256,
                 SignatureScheme.rsa_pss_rsae_sha512,
                 SignatureScheme.rsa_pss_pss_sha512]
        self.sigschemelist = SignatureSchemeList(supported_signature_algorithms=algos)

    def test_length(self):
        obj = self.sigschemelist
        self.assertEqual(len(obj), len(obj.to_bytes()))

    def test_restruct(self):
        restructed = SignatureSchemeList.from_bytes(self.sigschemelist.to_bytes())
        self.assertEqual(repr(self.sigschemelist), repr(restructed))


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

    def setUp(self):
        certificate_request_context = b''
        certificate_list = [
            CertificateEntry(cert_data=b'1234567890abcdef'), # TODO: read file.crt
        ]
        self.certificate = Certificate(
            certificate_request_context=certificate_request_context,
            certificate_list=certificate_list)

    def test_length(self):
        obj = self.certificate
        self.assertEqual(len(obj), len(obj.to_bytes()))

    def test_restruct(self):
        restructed = Certificate.from_bytes(self.certificate.to_bytes())
        self.assertEqual(repr(self.certificate), repr(restructed))


class CertificateVerifyTest(unittest.TestCase):
    pass


class FinishedTest(unittest.TestCase):
    pass

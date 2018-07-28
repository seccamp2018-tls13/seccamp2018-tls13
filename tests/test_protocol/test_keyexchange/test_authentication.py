
import unittest

from tls13.protocol.keyexchange.signature import *
from tls13.protocol.keyexchange.authentication import *
from tls13.utils.type import *

from ..common import TypeTestMixin


class CertificateTypeTest(unittest.TestCase, TypeTestMixin):

    def setUp(self):
        self.target = CertificateType


class CertificateEntryTest(unittest.TestCase):
    pass


class CertificateTest(unittest.TestCase):

    def setUp(self):
        certificate_request_context = b''
        certificate_list = [
            CertificateEntry(cert_data=b'1234567890abcdef'), # read file.crt
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

    def setUp(self):
        self.certificate_verify = CertificateVerify(
            algorithm=SignatureScheme.rsa_pkcs1_sha256,
            signature=b'58db140f')

    def test_length(self):
        obj = self.certificate_verify
        self.assertEqual(len(obj), len(obj.to_bytes()))

    def test_restruct(self):
        restructed = CertificateVerify.from_bytes(self.certificate_verify.to_bytes())
        self.assertEqual(repr(self.certificate_verify), repr(restructed))


class FinishedTest(unittest.TestCase):
    pass

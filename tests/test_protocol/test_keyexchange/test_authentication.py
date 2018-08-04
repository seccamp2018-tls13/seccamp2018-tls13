
import unittest

from tls13.protocol.keyexchange.signature import *
from tls13.protocol.keyexchange.authentication import *
from tls13.utils.type import *

from ..common import TypeTestMixin, StructTestMixin


class CertificateTypeTest(unittest.TestCase, TypeTestMixin):

    def setUp(self):
        self.target = CertificateType


class CertificateEntryTest(unittest.TestCase, StructTestMixin):

    def setUp(self):
        self.target = CertificateEntry
        self.obj = CertificateEntry(cert_data=b'foobar')


class CertificateTest(unittest.TestCase, StructTestMixin):

    def setUp(self):
        certificate_request_context = b''
        certificate_list = [
            CertificateEntry(cert_data=b'1234567890abcdef'), # read file.crt
        ]
        self.target = Certificate
        self.obj = Certificate(
            certificate_request_context=certificate_request_context,
            certificate_list=certificate_list)


class CertificateVerifyTest(unittest.TestCase, StructTestMixin):

    def setUp(self):
        self.target = CertificateVerify
        self.obj = CertificateVerify(
            algorithm=SignatureScheme.rsa_pkcs1_sha256,
            signature=b'58db140f')


class FinishedTest(unittest.TestCase):

    def setUp(self):
        self.target = Finished
        self.obj = Finished(
            verify_data=b'012345678901234567890123456789ab')

    def test_length(self):
        self.assertEqual(len(self.obj), len(self.obj.to_bytes()))

    def test_restruct(self):
        from tls13.protocol.keyexchange.authentication import Hash
        hash_size = 32
        Hash.set_size(hash_size)
        restructed = self.target.from_bytes(self.obj.to_bytes())
        self.assertEqual(repr(self.obj), repr(restructed))

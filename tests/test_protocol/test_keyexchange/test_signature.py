
import unittest

from tls13.protocol.keyexchange.signature import *
from tls13.metastruct.type import *
from ..common import TypeTestMixin, StructTestMixin


class SignatureSchemeTest(unittest.TestCase, TypeTestMixin):

    def setUp(self):
        self.target = SignatureScheme


class SignatureSchemeListTest(unittest.TestCase, StructTestMixin):

    def setUp(self):
        algos = [SignatureScheme.rsa_pkcs1_sha256,
                 SignatureScheme.rsa_pss_rsae_sha512,
                 SignatureScheme.rsa_pss_pss_sha512]
        self.target = SignatureSchemeList
        self.obj = SignatureSchemeList(supported_signature_algorithms=algos)

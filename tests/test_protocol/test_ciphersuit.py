
import unittest

from tls13.protocol.ciphersuite import *
from tls13.utils.type import *
from .common import TypeTestMixin


class CipherSuiteTest(unittest.TestCase, TypeTestMixin):

    def setUp(self):
        self.target = CipherSuite

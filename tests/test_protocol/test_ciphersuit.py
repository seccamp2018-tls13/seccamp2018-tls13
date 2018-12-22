
import unittest

from tls13.protocol import *
from tls13.metastruct import *
from .common import TypeTestMixin


class CipherSuiteTest(unittest.TestCase, TypeTestMixin):

    def setUp(self):
        self.target = CipherSuite

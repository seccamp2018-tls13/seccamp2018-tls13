
import unittest

from tls13.protocol import *
from tls13.encryption.ffdhe import *

class FFDHETest(unittest.TestCase):

    def test_key_exchange(self):
        client_dhe = FFDHE(NamedGroup.ffdhe2048)
        server_dhe = FFDHE(NamedGroup.ffdhe2048)
        client_public_key = client_dhe.gen_public_key()
        server_public_key = server_dhe.gen_public_key()
        client_shared_key = client_dhe.gen_shared_key(server_public_key)
        server_shared_key = server_dhe.gen_shared_key(client_public_key)
        self.assertEqual(client_shared_key, server_shared_key)

    def test_key_exchange__wrong_public_key(self):
        client_dhe = FFDHE(NamedGroup.ffdhe2048)
        server_dhe = FFDHE(NamedGroup.ffdhe2048)
        client_public_key = client_dhe.gen_public_key()
        server_public_key = server_dhe.gen_public_key()
        client_shared_key = client_dhe.gen_shared_key(server_public_key[1:])
        server_shared_key = server_dhe.gen_shared_key(client_public_key)
        self.assertNotEqual(client_shared_key, server_shared_key)


import unittest

from tls13.protocol.keyexchange.supportedgroups import *
from tls13.utils.encryption.ffdhe import *

class FFDHETest(unittest.TestCase):

    def test_FFDHE_key_exchange(self):
        client_dhe = FFDHE(NamedGroup.ffdhe2048)
        server_dhe = FFDHE(NamedGroup.ffdhe2048)
        client_public_key = client_dhe.gen_public_key()
        server_public_key = server_dhe.gen_public_key()
        client_shared_key = client_dhe.gen_shared_key(server_public_key)
        server_shared_key = server_dhe.gen_shared_key(client_public_key)
        assert client_shared_key == server_shared_key

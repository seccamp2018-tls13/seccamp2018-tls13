
from .utils import socket

from .protocol.recordlayer import TLSPlaintext, ContentType

def server_cmd(argv):
    print("server_cmd({})".format(", ".join(argv)))

    # ClientHello のバイト列を受け取る
    data = socket.recv()

    ch_plain_restructed = TLSPlaintext.from_bytes(data)
    print(ch_plain_restructed)

    # ServerHello

    # EncryptedExtensions

    # Certificate

    # CertificateVerify

    # Finished

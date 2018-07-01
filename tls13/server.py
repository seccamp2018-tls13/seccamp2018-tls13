
import socket

from .protocol.recordlayer import TLSPlaintext, ContentType

def server_cmd(argv):
    print("server_cmd({})".format(", ".join(argv)))

    HOST = ''    # Symbolic name meaning all available interfaces
    PORT = 50007 # Arbitrary non-privileged port

    # クライアントからの ClientHello のバイト列を受け取る
    data = bytearray(0)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen(1)
        conn, addr = s.accept()
        with conn:
            print('Connected by', addr)
            # NOTE: ハードウェアおよびネットワークの現実に最大限マッチするように、
            #       bufsize の値は比較的小さい2の累乗、たとえば 4096、にすべきです。
            data = conn.recv(2**14) # TLSPlaintext の最大の大きさが 2^14 byte

    ch_plain_restructed = TLSPlaintext.from_bytes(data)
    print(ch_plain_restructed)

    # ServerHello

    # EncryptedExtensions

    # Certificate

    # CertificateVerify

    # Finished

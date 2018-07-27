
__all__ = [
    'ClientConnection', 'ServerConnection',
]

import socket

# ネットワーク通信部分の機能

HOST = 'localhost' # The remote host
PORT = 50007

class ClientConnection:
    def __init__(self, host=HOST, port=PORT):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((host, port))

    def send_msg(self, byte_str):
        self.sock.sendall(byte_str)

    def recv_msg(self):
        # NOTE: ハードウェアおよびネットワークの現実に最大限マッチするように、
        #       bufsize の値は比較的小さい2の累乗、たとえば 4096、にすべきです。
        data = self.sock.recv(2**14) # TLSPlaintext の最大の大きさが 2^14 byte
        return data


class ServerConnection:
    def __init__(self, host=HOST, port=PORT):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # prevent "Address already in use" error
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((host, port))
        self.sock.listen(1)
        conn, addr = self.sock.accept()
        self.conn = conn
        self.addr = addr
        print('Connected by', self.addr)

    def send_msg(self, byte_str):
        self.conn.sendall(byte_str)

    def recv_msg(self):
        # NOTE: ハードウェアおよびネットワークの現実に最大限マッチするように、
        #       bufsize の値は比較的小さい2の累乗、たとえば 4096、にすべきです。
        data = self.conn.recv(2**14) # TLSPlaintext の最大の大きさが 2^14 byte
        return data

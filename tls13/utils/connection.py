
__all__ = [
    'ClientConnection', 'ServerConnection',
]

import socket

# ネットワーク通信部分の機能

HOST = 'localhost' # The remote host
PORT = 50007

class Connection:
    def send_msg(self, byte_str):
        self.socket.sendall(byte_str)

    def recv_msg(self):
        # TLSPlaintext の最大の大きさが 2^14 byte
        return self.socket.recv(2**14 * 8)


class ClientConnection(Connection):
    def __init__(self, host=HOST, port=PORT):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((host, port))
        self.socket = self.sock


class ServerConnection(Connection):
    def __init__(self, host=HOST, port=PORT):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # prevent "Address already in use" error
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((host, port))
        self.sock.listen(1)
        conn, addr = self.sock.accept()
        self.socket = conn
        self.addr = addr
        print('Connected by', self.addr)

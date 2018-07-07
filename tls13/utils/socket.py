
import socket

HOST = 'localhost' # The remote host
PORT = 50007

def send(byte_str, host=HOST, port=PORT):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))
        s.sendall(byte_str)

    return True

def recv(host='', port=PORT):
    # クライアントからの ClientHello のバイト列を受け取る
    data = bytearray(0)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, port))
        s.listen(1)
        conn, addr = s.accept()
        with conn:
            print('Connected by', addr)
            # NOTE: ハードウェアおよびネットワークの現実に最大限マッチするように、
            #       bufsize の値は比較的小さい2の累乗、たとえば 4096、にすべきです。
            data = conn.recv(2**14) # TLSPlaintext の最大の大きさが 2^14 byte

    return data

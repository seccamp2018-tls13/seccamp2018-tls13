
import socket
from .protocol.recordlayer import TLSPlaintext, ContentType
from .protocol.handshake import Handshake, HandshakeType
from .protocol.ciphersuit import CipherSuite
from .protocol.keyexchange.messages import ClientHello

def client_cmd(argv):
    print("client_cmd({})".format(", ".join(argv)))

    # ClientHello

    # 構造体の階層
    # TLSPlaintext
    # └─ Handshake
    #    └─ ClientHello
    #       └─ Extension (supported_groups, signature_algorithms, ...)

    ch = ClientHello()
    ch.cipher_suites.append(CipherSuite.TLS_AES_128_GCM_SHA256)
    ch.extensions.append(0xbeef) # TODO: 拡張（Extension）の追加

    ch_handshake = Handshake(
        msg_type=HandshakeType.client_hello,
        length=len(ch),
        msg=ch
    )

    ch_plain = TLSPlaintext(
        _type=ContentType.handshake,
        length=len(ch_handshake),
        fragment=ch_handshake
    )

    # send(ch_plain.to_bytes(), to=server) # TODO: socketを使ってサーバに送る処理


    # Finished

    # Application Data

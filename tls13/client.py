
import socket
from .protocol import recordlayer
from .protocol import handshake
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
    ch.cipher_suites.append(0xdead) # TODO: 暗号スイートの追加
    ch.extensions.append(0xbeef) # TODO: 拡張（Extension）の追加

    ch_handshake = handshake.Handshake(
        msg_type=handshake.HandshakeType.client_hello,
        length=len(ch),
        msg=ch
    )

    ch_plain = recordlayer.TLSPlaintext(
        _type=recordlayer.ContentType.handshake,
        length=len(ch_handshake),
        fragment=ch_handshake
    )

    # send(ch_plain.to_bytes(), to=server) # TODO: socketを使ってサーバに送る処理


    # Finished

    # Application Data


実装のメモ
======================

TLSPlaintext からの構造体の階層
-----------------------------

構造体はネストしているので，それぞれPythonのクラスで表す．

    構造体の階層
    TLSPlaintext
    └─ Handshake
       └─ ClientHello
          └─ Extension (supported_groups, signature_algorithms, ...)

TLSPlaintextクラスのフィールドfragmentに，Handshakeのインスタンスを代入して，
Handshakeクラスのフィールドclient_helloに，ClientHelloのインスタンスを代入して...
という感じのコードを愚直に書くと下のようになる．

    tlsplaintext = TLSPlaintext()
    tlsplaintext.fragment = Handshake()
    tlsplaintext.fragment.client_hello = ClientHello()

実際のプログラムではコンストラクタの引数に渡すようにしている．

    tlsplaintext = TLSPlaintext(
        fragment=Handshake(
            client_hello=ClientHello()
        )
    )


構造体の表現 `__repr__`
-----------------------------

デバッグしやすいように，構造体クラスにそれぞれ `__repr__` を実装した．
`FooBar:` は構造体クラス名, `|foobar:` はフィールド名を表す．
フィールドが配列や構造体クラスを持つときはインデントするようにした．

    ClientHello:
    |cipher_suites: [Uint16(0x1301)]
    |extensions: <== ClientHelloのフィールド（配列）
        [Extension:
        |extension_type: Uint16(0x002b) == supported_versions
        |extension_data: <== Extensionのフィールド（構造体クラス SupportedVersions）
            SupportedVersions:
            |versions: [Uint16(0x0304)],
         ...
         ]


構造体 <=> バイト文字列の変換
-----------------------------

### `__len__`

バイト列に変換したときの長さを求めるメソッド `__len__` を実装した．

可変長のデータをバイト文字列にするときには，データ長を求める必要がある．
可変長のデータは，先頭の1~3byteにデータ長，続くNbyteにデータが入るので，
可変長のデータ長は合計 1~3 + N になることに注意．
先頭のバイト数は例えば：
* `<0..2^8-1>` なら hex(2**8-1) == '0xff' なので 1byte
* `<0..2^16-1>` なら hex(2**16-1) == '0xffff' なので 2byte
のように求める．

### `to_bytes`, `from_bytes`

to_bytes() メソッドで構造体をバイト文字列に変換する．
構造体クラス.from_bytes() でバイト文字列から構造体を作る．
それぞれのクラスに .to_bytes() みたいなメソッドを作って再帰的に呼び出して送信用のバイト列を作る．
.from_bytes() も再帰的に呼び出してインスタンスを再構築し，送られてきたバイト列から構造体を組み立てる．

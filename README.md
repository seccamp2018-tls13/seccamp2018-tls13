# seccamp2018-tls13

## TODOs

- [ ] プロトコルの構造体をクラスにする
- [ ] 構造体 <=> バイト文字列の変換（to_bytes, from_bytes）
    - [x] ClientHello
    - [ ] ServerHello
    - [ ] Application Data
- [ ] ネットワーク通信部分の分離/ライブラリ化（send, recv）
- [ ] ユニットテスト（`pip install -U . && python test.py`）
- [ ] 鍵共有（最低限 Diffie-Hellman ができる）
- [ ] 暗号化（chacha/poly やりたい）


## Requirements

- Python3


## Usage

サーバ側のプログラムの起動（ポートは50007）

```
./main.py server
```

クライアント側のプログラムの開始

```
./main.py client
```

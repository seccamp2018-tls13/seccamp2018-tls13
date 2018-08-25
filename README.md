# seccamp2018-tls13

<a href="https://circleci.com/gh/seccamp2018-tls13/seccamp2018-tls13"><img src="https://circleci.com/gh/seccamp2018-tls13/seccamp2018-tls13/tree/master.svg?style=shield&circle-token=8cba96a486a4be89b38a9bbe356555d237d307eb"></a>
<a href="https://codeclimate.com/github/seccamp2018-tls13/seccamp2018-tls13/maintainability"><img src="https://api.codeclimate.com/v1/badges/22925422e5e90c48b254/maintainability" /></a>


## Requirements

- Python3
- PyCrypto (pip install pycrypto)
- PyCryptodome (pip install pycryptodome)
- cryptography (pip install cryptography)

Install all requirements

```
pip install -r requirements.txt
```


## Usage

サーバ側のプログラムの起動（ポートは50007）

```
./main.py server
```

クライアント側のプログラムの開始

```
./main.py client
```

---

openssl で TLS 1.3 サーバ

```
~/local/bin/openssl s_server -accept 50007 -cert ./.ssh/server.crt -key ./.ssh/server.key -tls1_3 -state -debug
```

openssl で TLS 1.3 クライアント

```
~/local/bin/openssl s_client -connect localhost:50007 -tls1_3 -state -debug
```

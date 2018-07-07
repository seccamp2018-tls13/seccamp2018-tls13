#!/bin/bash -u

# TLSの通信をするために, サーバ起動してクライアント起動するスクリプト
# サーバとクライアントの実行結果をそれぞれファイルに保存する

python3 main.py server &> do-server.log &
python3 main.py client &> do-client.log &

wait

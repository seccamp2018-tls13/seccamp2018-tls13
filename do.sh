#!/bin/bash -u

# TLSの通信をするために, サーバ起動してクライアント起動するスクリプト
# サーバとクライアントの実行結果をそれぞれファイルに保存する

python3 main.py server &> do-server.log &
python3 main.py client &> do-client.log &

wait

# logファイルに Error: があればエラーを表示する
log_search_result=$(grep -F 'Error: ' <(cat do-server.log do-client.log))
if [[ $? -eq 0 ]]; then
  echo "Detect Error!"
  echo "$log_search_result"
fi

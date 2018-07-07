
## GitHub Flow

小さい変更のときは直接 master に push してもいいけど、
大きい変更は開発メンバーに知らせるという意味でも Pull Request をするようにしたい。

GitHub Flow の流れ：

1. masterブランチから説明的な名前を付けたブランチを切る
  - `git checkout -b my_branch`
2. 開発が終わったら、作成したブランチにローカルでcommitし、サーバー上の同名ブランチにpushする
  - `git commit -m "作業内容"`
  - `git push origin my_branch`
3. コードレビューをしてもらいたい時や、ブランチをマージする時に Pull Request を出す
  - このとき必ず Reviewers や Assignees を指定して通知が行くようにすること
  - やったこと or これからやること をリストにしておくと、あとで読みやすい
4. 必要があればコードを修正して再度 commit と push
5. 再度コードレビューをしてもらってOKが出たら、masterブランチにマージする

Issue と Pull Request が重複しそうなときは手順1でブランチを切った後に
`git commit --allow-empty -m "Issueの内容"` で空のコミットを作って push して、
Pull Request すると重複しない。
